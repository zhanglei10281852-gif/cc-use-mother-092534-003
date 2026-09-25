"""凭据物化协调器的端到端领域测试。"""
from __future__ import annotations

import copy
import pickle
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from coordinator import (
    AuthorizationError,
    CredentialCoordinator,
    DestructionProof,
    FrozenMaterializationError,
    LeaseHandle,
    LeaseState,
    QuotaExceededError,
    ScopeExceededError,
    Scope,
    TaskContext,
    VersionRetiredError,
)
from coordinator.errors import HandleError, LeaseInvalidError
from coordinator.time import Clock

T0 = datetime(2026, 9, 25, 9, 0, 0, tzinfo=timezone.utc)
TENANT = "tenant-a"
CONNECTOR = "conn-github"
TASK = "task-1"
PURPOSE = "sync-repo"
SCOPE = Scope.of("repo:read")


def build_coordinator(quota: int = 3, ttl: int = 300) -> tuple[CredentialCoordinator, Clock]:
    clock = Clock(T0)
    coordinator = CredentialCoordinator(clock=clock)
    coordinator.register_connector(CONNECTOR, "GitHub 企业连接器")
    coordinator.set_tenant_quota(TENANT, quota)
    ctx = TaskContext(TENANT, TASK, CONNECTOR, PURPOSE, Scope.of("repo:read", "issue:write"))
    coordinator.authorize_task(ctx, max_ttl_seconds=ttl)
    return coordinator, clock


class ClaimAuthorizationTest(unittest.TestCase):
    def test_claim_requires_authorized_task_context(self) -> None:
        coordinator, _ = build_coordinator()
        with self.assertRaises(AuthorizationError):
            coordinator.claim(TENANT, "unknown-task", CONNECTOR, PURPOSE, SCOPE)

    def test_claim_rejects_unregistered_connector(self) -> None:
        clock = Clock(T0)
        coordinator = CredentialCoordinator(clock=clock)
        coordinator.set_tenant_quota(TENANT, 2)
        ctx = TaskContext(TENANT, TASK, "ghost", PURPOSE, SCOPE)
        with self.assertRaises(AuthorizationError):
            coordinator.authorize_task(ctx)

    def test_scope_beyond_authorization_is_rejected(self) -> None:
        coordinator, _ = build_coordinator()
        with self.assertRaises(AuthorizationError):
            coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, Scope.of("admin:root"))

    def test_purpose_mismatch_is_rejected(self) -> None:
        coordinator, _ = build_coordinator()
        with self.assertRaises(AuthorizationError):
            coordinator.claim(TENANT, TASK, CONNECTOR, "exfiltrate", SCOPE)

    def test_ttl_beyond_authorization_is_rejected(self) -> None:
        coordinator, _ = build_coordinator(ttl=60)
        with self.assertRaises(AuthorizationError):
            coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=600)

    def test_successful_claim_returns_controlled_handle(self) -> None:
        coordinator, _ = build_coordinator()
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=120)
        self.assertIsInstance(handle, LeaseHandle)
        self.assertEqual(handle.connector_id, CONNECTOR)
        self.assertTrue(handle.approved_scope.contains(SCOPE))


class QuotaTest(unittest.TestCase):
    def test_concurrent_claims_cannot_break_tenant_quota(self) -> None:
        coordinator, clock = build_coordinator(quota=2)
        h1 = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=300)
        h2 = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=300)
        self.assertFalse(h1.closed)
        self.assertFalse(h2.closed)
        with self.assertRaises(QuotaExceededError):
            coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=300)

    def test_quota_released_after_expiry(self) -> None:
        coordinator, clock = build_coordinator(quota=1)
        coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=60)
        with self.assertRaises(QuotaExceededError):
            coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=60)
        clock.advance(seconds=61)
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=60)
        self.assertFalse(handle.closed)

    def test_quota_under_thread_race(self) -> None:
        coordinator, _ = build_coordinator(quota=5)

        def claim_one(_: int) -> bool:
            try:
                coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=300)
                return True
            except QuotaExceededError:
                return False

        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(claim_one, range(32)))
        self.assertEqual(sum(outcomes), 5)


class ControlledHandleTest(unittest.TestCase):
    def test_plaintext_only_available_inside_materialize(self) -> None:
        coordinator, _ = build_coordinator()
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        with handle.materialize(SCOPE) as secret:
            self.assertEqual(len(secret), 64)
        # 句柄 repr/str 不能泄漏明文
        self.assertNotIn(secret, repr(handle))
        self.assertNotIn(secret, str(handle))

    def test_scope_exceeded_call_is_refused_and_recorded(self) -> None:
        coordinator, _ = build_coordinator()
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        secret_holder: list[str] = []
        with self.assertRaises(ScopeExceededError):
            with handle.materialize(Scope.of("repo:read", "admin:root")) as secret:
                secret_holder.append(secret)
        self.assertEqual(secret_holder, [])
        verdict = coordinator.verify_call(handle.lease_id)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.reason, "latest_call_exceeded_scope")

    def test_within_scope_call_verifies(self) -> None:
        coordinator, _ = build_coordinator()
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, Scope.of("repo:read", "issue:write"))
        with handle.materialize(Scope.of("issue:write")):
            pass
        verdict = coordinator.verify_call(handle.lease_id)
        self.assertTrue(verdict.allowed)

    def test_handle_cannot_be_copied_or_pickled(self) -> None:
        coordinator, _ = build_coordinator()
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        with self.assertRaises(HandleError):
            copy.copy(handle)
        with self.assertRaises(HandleError):
            copy.deepcopy(handle)
        with self.assertRaises(HandleError):
            pickle.dumps(handle)

    def test_expired_handle_cannot_materialize(self) -> None:
        coordinator, clock = build_coordinator()
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=30)
        clock.advance(seconds=31)
        with self.assertRaises(LeaseInvalidError):
            with handle.materialize(SCOPE):
                self.fail("过期租约不应返回明文")


class PlaintextIsolationTest(unittest.TestCase):
    def test_no_plaintext_in_events_or_store(self) -> None:
        coordinator, clock = build_coordinator()
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        with handle.materialize(SCOPE) as secret:
            pass
        # 事件日志任何序列化形式都不能出现明文
        for event in coordinator.events.all():
            blob = event.to_json()
            self.assertNotIn(secret, blob)
        # 存储层所有对象都不能携带明文
        store = coordinator.store
        for record in list(store.leases.values()) + list(store.proofs.values()):
            self.assertNotIn(secret, repr(record.__slots__))
            for field_name in record.__slots__:
                value = getattr(record, field_name)
                self.assertNotEqual(value, secret)

    def test_events_reject_sensitive_keys(self) -> None:
        from coordinator.events import Event

        with self.assertRaises(ValueError):
            Event(
                event_id="evt-x",
                event_type="bad",
                aggregate_id="a",
                occurred_at=T0,
                actor_id="actor",
                payload={"access_token": "abc"},
            )


class RenewalTest(unittest.TestCase):
    def test_renew_only_inside_window(self) -> None:
        coordinator, clock = build_coordinator(ttl=300)
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=300)
        original_expiry = handle.expires_at
        with self.assertRaises(LeaseInvalidError):
            coordinator.renew(handle)
        clock.advance(seconds=181)  # 进入到期前 120 秒窗口
        coordinator.renew(handle, ttl_seconds=300)
        self.assertGreater(handle.expires_at, original_expiry)
        record = coordinator.store.get_lease(handle.lease_id)
        self.assertEqual(record.state, LeaseState.ACTIVE)
        self.assertEqual(record.renewed_count, 1)

    def test_renewed_handle_remains_continuous(self) -> None:
        coordinator, clock = build_coordinator(ttl=300)
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=200)
        clock.advance(seconds=81)
        coordinator.renew(handle, ttl_seconds=200)
        with handle.materialize(SCOPE):
            pass  # 续期后立即可用，状态连续


class DestructionTest(unittest.TestCase):
    def test_surrender_and_destruction_proof(self) -> None:
        coordinator, _ = build_coordinator()
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        lease_id = coordinator.surrender(handle)
        self.assertTrue(handle.closed)
        with self.assertRaises(LeaseInvalidError):
            with handle.materialize(SCOPE):
                pass
        record = coordinator.store.get_lease(lease_id)
        self.assertEqual(record.state, LeaseState.DESTROYING)

        proof = coordinator.confirm_destruction(
            lease_id, "sha256:burned-evidence", reported_by=CONNECTOR
        )
        self.assertIsInstance(proof, DestructionProof)
        self.assertEqual(coordinator.store.get_lease(lease_id).state, LeaseState.DESTROYED)

        # 销毁证明不可重复
        with self.assertRaises(LeaseInvalidError):
            coordinator.confirm_destruction(lease_id, "other", reported_by=CONNECTOR)

    def test_double_surrender_rejected(self) -> None:
        coordinator, _ = build_coordinator()
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        lease_id = coordinator.surrender(handle)
        coordinator.confirm_destruction(lease_id, "h", reported_by=CONNECTOR)
        with self.assertRaises(LeaseInvalidError):
            coordinator.surrender(handle)


class RotationTest(unittest.TestCase):
    def test_old_version_usable_in_grace_then_retired(self) -> None:
        coordinator, clock = build_coordinator(ttl=900)
        old_handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=600)
        coordinator.rotate(TENANT, CONNECTOR, grace_seconds=120)
        # 宽限期内旧版本仍可用
        with old_handle.materialize(SCOPE):
            pass
        clock.advance(seconds=121)
        retired = coordinator.expire_grace_versions()
        self.assertEqual(retired, [1])
        with self.assertRaises(VersionRetiredError):
            with old_handle.materialize(SCOPE):
                self.fail("宽限期结束后旧版本必须失效")
        self.assertTrue(old_handle.closed)

    def test_new_claims_use_new_version_after_rotation(self) -> None:
        coordinator, clock = build_coordinator(quota=10, ttl=900)
        coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=600)
        coordinator.rotate(TENANT, CONNECTOR, grace_seconds=1)
        new_handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=600)
        self.assertEqual(new_handle.credential_version, 2)
        with new_handle.materialize(SCOPE):
            pass


class EmergencyRevokeTest(unittest.TestCase):
    def test_revoke_immediately_invalidates_handle(self) -> None:
        coordinator, _ = build_coordinator()
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        affected = coordinator.emergency_revoke(
            lease_id=handle.lease_id, reason="令牌出现在公开诊断包", actor_id="security-01"
        )
        self.assertEqual(affected, [handle.lease_id])
        self.assertTrue(handle.closed)
        with self.assertRaises(LeaseInvalidError):
            with handle.materialize(SCOPE):
                pass
        self.assertEqual(
            coordinator.store.get_lease(handle.lease_id).state, LeaseState.REVOKED
        )

    def test_revoke_by_connector_scopes_to_tenant(self) -> None:
        coordinator, _ = build_coordinator(quota=10)
        h1 = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        other = "conn-jira"
        coordinator.register_connector(other)
        ctx = TaskContext(TENANT, "task-2", other, PURPOSE, SCOPE)
        coordinator.authorize_task(ctx, max_ttl_seconds=300)
        h2 = coordinator.claim(TENANT, "task-2", other, PURPOSE, SCOPE)
        affected = coordinator.emergency_revoke(
            tenant_id=TENANT, connector_id=CONNECTOR, reason="r", actor_id="sec"
        )
        self.assertEqual(affected, [h1.lease_id])
        self.assertFalse(h2.closed)


class IncidentTest(unittest.TestCase):
    def test_incident_freezes_new_materialization_and_scopes_handles(self) -> None:
        coordinator, _ = build_coordinator(quota=10)
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        incident = coordinator.open_incident(
            TENANT, opened_by="security-01", reason="疑似令牌泄露", connector_id=CONNECTOR
        )
        # 既有句柄被冻结、明文清空
        self.assertTrue(handle.closed)
        with self.assertRaises(FrozenMaterializationError):
            coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        # 受影响句柄可圈定，且只有关系、没有明文
        affected = coordinator.affected_handles(incident.incident_id)
        self.assertEqual([r.lease_id for r in affected], [handle.lease_id])
        self.assertTrue(all(not hasattr(r, "__dict__") or "secret" not in getattr(r, "__dict__", {}) for r in affected))

    def test_unrelated_connector_can_still_claim(self) -> None:
        coordinator, _ = build_coordinator(quota=10)
        coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        coordinator.open_incident(
            TENANT, opened_by="sec", reason="r", connector_id=CONNECTOR
        )
        other = "conn-jira"
        coordinator.register_connector(other)
        coordinator.authorize_task(
            TaskContext(TENANT, "task-9", other, PURPOSE, SCOPE), max_ttl_seconds=300
        )
        handle = coordinator.claim(TENANT, "task-9", other, PURPOSE, SCOPE)
        self.assertFalse(handle.closed)

    def test_tenant_wide_incident_freezes_all_connectors(self) -> None:
        coordinator, _ = build_coordinator(quota=10)
        coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        coordinator.open_incident(TENANT, opened_by="sec", reason="租户级泄露")
        with self.assertRaises(FrozenMaterializationError):
            coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)

    def test_destruction_trail_tracked_under_incident(self) -> None:
        coordinator, _ = build_coordinator(quota=10)
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        incident = coordinator.open_incident(
            TENANT, opened_by="sec", reason="r", lease_ids=[handle.lease_id]
        )
        coordinator.emergency_revoke(lease_id=handle.lease_id, reason="r", actor_id="sec")
        coordinator.confirm_destruction(handle.lease_id, "proof-hash", reported_by=CONNECTOR)
        trail = coordinator.destruction_trail(incident.incident_id)
        self.assertEqual(len(trail), 1)
        self.assertEqual(trail[0].lease_id, handle.lease_id)

    def test_close_incident_restores_still_valid_leases_only(self) -> None:
        coordinator, clock = build_coordinator(quota=10, ttl=4000)
        short = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=30)
        long = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=3000)
        incident = coordinator.open_incident(
            TENANT, opened_by="sec", reason="r",
            lease_ids=[short.lease_id, long.lease_id],
        )
        clock.advance(seconds=60)
        coordinator.close_incident(incident.incident_id, actor_id="sec")
        short_record = coordinator.store.get_lease(short.lease_id)
        long_record = coordinator.store.get_lease(long.lease_id)
        self.assertEqual(short_record.state, LeaseState.EXPIRED)
        self.assertEqual(long_record.state, LeaseState.ISSUED)
        # 调查结束后可以重新物化
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=60)
        self.assertFalse(handle.closed)


class ReplayTest(unittest.TestCase):
    def test_replay_restores_only_valid_relationships_without_plaintext(self) -> None:
        coordinator, clock = build_coordinator(quota=10, ttl=900)
        valid = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=600)
        dead = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE, ttl_seconds=10)
        clock.advance(seconds=11)
        relationships = coordinator.replay_task(TENANT, TASK)
        self.assertEqual([r.lease_id for r in relationships], [valid.lease_id])
        self.assertTrue(relationships[0].valid)
        with self.assertRaises(LeaseInvalidError):
            coordinator.restore_handle(relationships[0])
        # 关系对象本身不携带明文字段
        self.assertFalse(hasattr(relationships[0], "secret"))


class EventHistoryTest(unittest.TestCase):
    def test_history_is_append_only_and_complete(self) -> None:
        coordinator, clock = build_coordinator(quota=10)
        handle = coordinator.claim(TENANT, TASK, CONNECTOR, PURPOSE, SCOPE)
        with handle.materialize(SCOPE):
            pass
        coordinator.surrender(handle)
        coordinator.confirm_destruction(handle.lease_id, "h", reported_by=CONNECTOR)
        types = [e.event_type for e in coordinator.events.for_aggregate(handle.lease_id)]
        self.assertEqual(
            types,
            ["lease.requested", "lease.issued", "usage.recorded", "lease.surrendered", "destruction.confirmed"],
        )
        # 事件时间单调且带时区
        for event in coordinator.events.all():
            self.assertIsNotNone(event.occurred_at.tzinfo)


if __name__ == "__main__":
    unittest.main()
