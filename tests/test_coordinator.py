"""凭据物化协调器的端到端行为测试。"""
from __future__ import annotations

import json
import pickle
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from coordinator import (
    CredentialCoordinator,
    ControlledHandle,
    FreezeError,
    GracePeriodClosedError,
    LeaseStateError,
    QuotaExceededError,
    ReplayError,
    ScopeExceededError,
)
from coordinator.clock import FixedClock
from coordinator.errors import AuthorizationError
from coordinator.handle import SecretRedactor
from coordinator.projection import Projection
from coordinator.storage import EventStore, SecretRegistry

T0 = datetime(2026, 9, 25, 2, 0, 0, tzinfo=timezone.utc)
SECRET_V1 = "pat-token-v1-9f8e7d"
SECRET_V2 = "pat-token-v2-1a2b3c"


def build_service(clock: FixedClock | None = None, *, quota: int = 3) -> CredentialCoordinator:
    clock = clock or FixedClock(T0)
    service = CredentialCoordinator(clock=clock, default_quota=quota)
    service.register_connector_credential(
        "conn-gitlab",
        "v1",
        SECRET_V1,
        capabilities=["read:repo", "write:repo", "read:ci"],
    )
    service.authorize_task(
        task_id="task-1",
        tenant_id="tenant-a",
        connector_id="conn-gitlab",
        purpose="nightly-sync",
        approved_scope=["read:repo", "read:ci"],
        capabilities=["connector.run"],
    )
    return service


class AuthorizationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = build_service()

    def test_requires_authorized_task_context(self) -> None:
        with self.assertRaises(AuthorizationError):
            self.service.request_materialization(task_id="unknown-task")

    def test_scope_must_be_within_task_approval(self) -> None:
        with self.assertRaises(AuthorizationError):
            self.service.request_materialization(task_id="task-1", scope=["write:repo"])

    def test_scope_must_be_within_connector_capabilities(self) -> None:
        self.service.authorize_task(
            task_id="task-wide",
            tenant_id="tenant-a",
            connector_id="conn-gitlab",
            purpose="audit",
            approved_scope=["read:repo", "admin:all"],
        )
        with self.assertRaises(AuthorizationError):
            self.service.request_materialization(task_id="task-wide", scope=["admin:all"])

    def test_subset_scope_is_issued(self) -> None:
        handle = self.service.request_materialization(task_id="task-1", scope=["read:repo"])
        self.assertEqual(handle.approved_scope, frozenset({"read:repo"}))


class QuotaTest(unittest.TestCase):
    def test_concurrent_requests_cannot_break_tenant_quota(self) -> None:
        clock = FixedClock(T0)
        service = build_service(clock, quota=3)
        handles: list[ControlledHandle] = []
        failures: list[Exception] = []
        lock = threading.Lock()

        def apply() -> None:
            try:
                handle = service.request_materialization(task_id="task-1", ttl_seconds=600)
                with lock:
                    handles.append(handle)
            except QuotaExceededError as exc:
                with lock:
                    failures.append(exc)

        threads = [threading.Thread(target=apply) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(handles), 3)
        self.assertEqual(len(failures), 7)
        self.assertEqual(service.lease_view(handles[0].lease_id).tenant_id, "tenant-a")

    def test_quota_released_after_destruction(self) -> None:
        service = build_service(quota=1)
        handle = service.request_materialization(task_id="task-1")
        with self.assertRaises(QuotaExceededError):
            service.request_materialization(task_id="task-1")
        service.destroy(handle)
        # 额度释放后可再次申请
        another = service.request_materialization(task_id="task-1")
        self.assertTrue(another.lease_id)

    def test_other_tenant_quota_is_independent(self) -> None:
        service = build_service(quota=1)
        self.service = service
        service.request_materialization(task_id="task-1")  # tenant-a 占满
        service.authorize_task(
            task_id="task-2",
            tenant_id="tenant-b",
            connector_id="conn-gitlab",
            purpose="sync",
            approved_scope=["read:repo"],
        )
        handle = service.request_materialization(task_id="task-2")
        self.assertEqual(handle.tenant_id, "tenant-b")


class HandleAndLeakPreventionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = build_service()

    def test_plaintext_only_available_inside_use(self) -> None:
        handle = self.service.request_materialization(task_id="task-1")
        seen = handle.use(["read:repo"], call=lambda secret: secret.decode())
        self.assertEqual(seen, SECRET_V1)
        self.assertNotIn(SECRET_V1, repr(handle))
        self.assertNotIn(SECRET_V1, str(handle))

    def test_handle_is_not_picklable(self) -> None:
        handle = self.service.request_materialization(task_id="task-1")
        with self.assertRaises(TypeError):
            pickle.dumps(handle)

    def test_event_log_never_contains_plaintext(self) -> None:
        handle = self.service.request_materialization(task_id="task-1")
        handle.use(["read:repo"], call=lambda secret: secret.decode())
        self.service.rotate_credential("conn-gitlab", "v2", SECRET_V2, grace_seconds=10)
        blob = json.dumps([event.to_dict() for event in self.service.store.load_all()], ensure_ascii=False)
        self.assertNotIn(SECRET_V1, blob)
        self.assertNotIn(SECRET_V2, blob)

    def test_event_store_file_contains_no_plaintext(self) -> None:
        with TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "events.db")
            clock = FixedClock(T0)
            store = EventStore(db_path)
            service = CredentialCoordinator(store=store, clock=clock, default_quota=3)
            service.register_connector_credential("c", "v1", SECRET_V1, capabilities=["read:repo"])
            service.authorize_task(task_id="t", tenant_id="tn", connector_id="c", purpose="p",
                                   approved_scope=["read:repo"])
            service.request_materialization(task_id="t")
            store.close()
            raw = Path(db_path).read_bytes()
            self.assertNotIn(SECRET_V1.encode(), raw)

    def test_secret_redactor_filters_diagnostic_payloads(self) -> None:
        clean = SecretRedactor.redact(
            {
                "task_id": "task-1",
                "access_token": SECRET_V1,
                "nested": {"credential": SECRET_V2, "ok": True},
                "tokens": [SECRET_V1, "scope-a"],
            }
        )
        serialized = json.dumps(clean, ensure_ascii=False)
        self.assertNotIn(SECRET_V1, serialized)
        self.assertNotIn(SECRET_V2, serialized)
        self.assertEqual(clean["task_id"], "task-1")
        self.assertTrue(clean["nested"]["ok"])

    def test_destruction_zeroizes_plaintext_without_affecting_master(self) -> None:
        first = self.service.request_materialization(task_id="task-1", ttl_seconds=900)
        second = self.service.request_materialization(task_id="task-1", ttl_seconds=900)
        material_ref = first.secret_ref
        self.service.destroy(first)
        # 租约副本被清零
        self.assertFalse(self.service.secrets.is_live(material_ref))
        # 另一租约与主凭据仍可用
        self.assertEqual(second.use(call=lambda s: s.decode()), SECRET_V1)
        with self.assertRaises(LeaseStateError):
            first.use()


class RotationAndGraceTest(unittest.TestCase):
    def test_old_version_works_within_grace_and_fails_after(self) -> None:
        clock = FixedClock(T0)
        service = build_service(clock)
        old_handle = service.request_materialization(task_id="task-1", ttl_seconds=10_000)
        service.rotate_credential("conn-gitlab", "v2", SECRET_V2, grace_seconds=3600)

        # 宽限期内旧版本仍可使用
        self.assertEqual(old_handle.use(call=lambda s: s.decode()), SECRET_V1)

        clock.advance(3601)
        service.sweep()
        with self.assertRaises(GracePeriodClosedError):
            old_handle.use(call=lambda s: s.decode())

    def test_renewal_switches_to_new_version_and_purges_old_copy(self) -> None:
        clock = FixedClock(T0)
        service = build_service(clock)
        handle = service.request_materialization(task_id="task-1", ttl_seconds=600)
        old_ref = handle.secret_ref
        service.rotate_credential("conn-gitlab", "v2", SECRET_V2, grace_seconds=3600)

        new_expiry = service.renew(handle, ttl_seconds=600)
        self.assertEqual(handle.credential_version, "v2")
        self.assertGreater(new_expiry, T0)
        self.assertEqual(handle.use(call=lambda s: s.decode()), SECRET_V2)
        # 旧副本已随续期切换清零
        self.assertFalse(service.secrets.is_live(old_ref))

    def test_retired_version_cannot_be_renewed(self) -> None:
        clock = FixedClock(T0)
        service = build_service(clock)
        handle = service.request_materialization(task_id="task-1", ttl_seconds=10_000)
        service.rotate_credential("conn-gitlab", "v2", SECRET_V2, grace_seconds=10)
        clock.advance(11)
        service.sweep()
        with self.assertRaises((LeaseStateError, GracePeriodClosedError)):
            service.renew(handle, ttl_seconds=600)

    def test_expired_lease_cannot_renew(self) -> None:
        clock = FixedClock(T0)
        service = build_service(clock)
        handle = service.request_materialization(task_id="task-1", ttl_seconds=100)
        clock.advance(101)
        service.sweep()
        with self.assertRaises(LeaseStateError):
            service.renew(handle, ttl_seconds=600)


class RevocationTest(unittest.TestCase):
    def test_revoke_denies_handle_and_purges_copy(self) -> None:
        service = build_service()
        handle = service.request_materialization(task_id="task-1")
        ref = handle.secret_ref
        service.revoke(handle, reason="task-aborted")
        self.assertFalse(service.secrets.is_live(ref))
        with self.assertRaises(LeaseStateError):
            handle.use()
        self.assertEqual(service.lease_view(handle.lease_id).status, "revoked")

    def test_emergency_revoke_connector_covers_all_leases_and_master(self) -> None:
        service = build_service()
        h1 = service.request_materialization(task_id="task-1")
        service.authorize_task(
            task_id="task-2", tenant_id="tenant-b", connector_id="conn-gitlab",
            purpose="sync", approved_scope=["read:repo"],
        )
        h2 = service.request_materialization(task_id="task-2")
        revoked = service.emergency_revoke_connector("conn-gitlab", reason="credential-leak")
        self.assertEqual(sorted(revoked), sorted([h1.lease_id, h2.lease_id]))
        for handle in (h1, h2):
            with self.assertRaises(LeaseStateError):
                handle.use()
        # 主凭据被清零后，新的物化也无法再进行
        with self.assertRaises(LeaseStateError):
            service.request_materialization(task_id="task-1")


class DestructionProofTest(unittest.TestCase):
    def test_proof_chain_is_complete_and_tamper_evident(self) -> None:
        service = build_service()
        h1 = service.request_materialization(task_id="task-1")
        h2 = service.request_materialization(task_id="task-1")
        proof1 = service.destroy(h1)
        proof2 = service.destroy(h2)
        results = service.verify_destruction_chain()
        self.assertEqual([item["lease_id"] for item in results], [h1.lease_id, h2.lease_id])
        self.assertTrue(all(item["valid"] for item in results))
        self.assertEqual(proof1.lease_id, h1.lease_id)
        self.assertEqual(proof2.lease_id, h2.lease_id)

        # 篡改任一证明即被重算发现
        connection = service.store._connection  # noqa: SLF001
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "update event_log set payload = json_set(payload, '$.proof', 'tampered') where event_id = ?",
            (proof1.event_id,),
        )
        connection.execute("COMMIT")
        results = service.verify_destruction_chain()
        self.assertFalse(results[0]["valid"])

    def test_every_plaintext_purge_path_leaves_a_verifiable_proof(self) -> None:
        clock = FixedClock(T0)
        service = build_service(clock, quota=20)

        # 续期切换：旧副本 reason=rotated
        rotated = service.request_materialization(task_id="task-1", ttl_seconds=10_000)
        service.rotate_credential("conn-gitlab", "v2", SECRET_V2, grace_seconds=100)
        service.renew(rotated, ttl_seconds=10_000)

        # 主动吊销：reason=revoked
        revoked_h = service.request_materialization(task_id="task-1", ttl_seconds=10_000)
        service.revoke(revoked_h, reason="x")

        # 过期 + 宽限退役：expired 与 grace_retired(master)
        expired_h = service.request_materialization(task_id="task-1", ttl_seconds=10)
        clock.advance(200)
        service.sweep()

        # 紧急吊销：emergency（material + master）
        service.rotate_credential("conn-gitlab", "v3", "pat-token-v3", grace_seconds=100_000)
        emergency_h = service.request_materialization(task_id="task-1", ttl_seconds=10_000)
        service.emergency_revoke_connector("conn-gitlab", reason="leak")

        # 手动核销：manual
        service.register_connector_credential("conn-other", "v1", "pat-other", capabilities=["read:repo"])
        service.authorize_task(
            task_id="task-o", tenant_id="tenant-a", connector_id="conn-other",
            purpose="p", approved_scope=["read:repo"],
        )
        manual_h = service.request_materialization(task_id="task-o", ttl_seconds=1000)
        service.destroy(manual_h)

        results = service.verify_destruction_chain()
        self.assertTrue(results, "应当至少有销毁证明")
        self.assertTrue(all(item["valid"] for item in results))
        reasons = {item["reason"] for item in results}
        self.assertEqual(
            reasons,
            {"rotated", "revoked", "expired", "grace_retired", "emergency", "manual"},
        )
        kinds = {item["kind"] for item in results}
        self.assertEqual(kinds, {"material", "master"})

        # 注册表中不应再有任何上述租约副本/主凭据明文
        self.assertFalse(service.secrets.is_live(revoked_h.secret_ref))
        self.assertFalse(service.secrets.is_live(expired_h.secret_ref))
        self.assertFalse(service.secrets.is_live(emergency_h.secret_ref))

    def test_persisted_events_survive_restart_but_plaintext_does_not_reappear(self) -> None:
        with TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "events.db")
            clock = FixedClock(T0)
            store = EventStore(db_path)
            service = CredentialCoordinator(store=store, clock=clock)
            service.register_connector_credential("c", "v1", SECRET_V1, capabilities=["read:repo"])
            service.authorize_task(
                task_id="t", tenant_id="tn", connector_id="c", purpose="p",
                approved_scope=["read:repo"],
            )
            handle = service.request_materialization(task_id="t", ttl_seconds=900)
            lease_id = handle.lease_id
            store.close()

            # 模拟进程重启：事件流仍在，但秘密注册表为空
            store2 = EventStore(db_path)
            registry2 = SecretRegistry()
            service2 = CredentialCoordinator(store=store2, secrets=registry2, clock=clock)
            # 租约关系可从事件重建
            self.assertEqual(service2.lease_view(lease_id).status, "active")
            # 但明文不会重新暴露：没有可恢复的句柄
            with self.assertRaises(ReplayError):
                service2.replay_task("t")
            store2.close()


class ReplayTest(unittest.TestCase):
    def test_replay_restores_only_still_valid_relationships(self) -> None:
        clock = FixedClock(T0)
        service = build_service(clock)
        live = service.request_materialization(task_id="task-1", ttl_seconds=900)
        expired = service.request_materialization(task_id="task-1", ttl_seconds=10)
        revoked = service.request_materialization(task_id="task-1", ttl_seconds=900)
        clock.advance(11)
        service.sweep()  # expired 终止并清零
        service.revoke(revoked, reason="x")

        restored = service.replay_task("task-1")
        self.assertEqual([handle.lease_id for handle in restored], [live.lease_id])
        # 恢复的是同一条租约关系，不是新签发
        self.assertEqual(restored[0].use(call=lambda s: s.decode()), SECRET_V1)

    def test_replay_never_reexposes_destroyed_plaintext(self) -> None:
        service = build_service()
        handle = service.request_materialization(task_id="task-1")
        service.destroy(handle)
        with self.assertRaises(ReplayError):
            service.replay_task("task-1")

    def test_replay_skips_lease_when_registry_lost_secret(self) -> None:
        service = build_service()
        good = service.request_materialization(task_id="task-1", ttl_seconds=900)
        ghost = service.request_materialization(task_id="task-1", ttl_seconds=900)
        # 模拟进程边界丢失：事件关系仍在，但明文已不在注册表
        service.secrets.revoke(ghost.secret_ref)
        restored = service.replay_task("task-1")
        self.assertEqual([handle.lease_id for handle in restored], [good.lease_id])


class UsageScopeVerificationTest(unittest.TestCase):
    def test_every_call_is_recorded_and_verifiable(self) -> None:
        service = build_service()
        handle = service.request_materialization(task_id="task-1", scope=["read:repo", "read:ci"])
        handle.use(["read:repo"], call=lambda s: s.decode())
        handle.use(["read:repo", "read:ci"], call=lambda s: s.decode())
        with self.assertRaises(ScopeExceededError):
            handle.use(["write:repo"])
        receipts = service.verify_usage(handle.lease_id)
        self.assertEqual(len(receipts), 3)
        self.assertTrue(receipts[0]["within_approval"])
        self.assertTrue(receipts[1]["within_approval"])
        self.assertFalse(receipts[2]["within_approval"])
        self.assertEqual(receipts[2]["result"], "denied")
        # 越权调用没有产生明文使用：前两次 ok，第三次 denied
        self.assertEqual([receipt["result"] for receipt in receipts], ["ok", "ok", "denied"])
        with self.assertRaises(AssertionError):
            service.assert_all_calls_within_scope()

    def test_clean_system_passes_global_assertion(self) -> None:
        service = build_service()
        handle = service.request_materialization(task_id="task-1")
        handle.use(call=lambda s: s.decode())
        service.assert_all_calls_within_scope()


class IncidentTest(unittest.TestCase):
    def test_incident_scopes_handles_freezes_and_tracks_destruction(self) -> None:
        service = build_service()
        target = service.request_materialization(task_id="task-1", ttl_seconds=900)
        other = service.request_materialization(task_id="task-1", ttl_seconds=900)
        incident_id = service.open_incident(
            tenant_id="tenant-a",
            suspected_refs=[target.secret_ref],
            scope_note="diagnostic bundle exfiltrated",
        )
        affected = service.affected_handles(incident_id)
        self.assertEqual([item.handle_id for item in affected], [target.handle_id])
        snapshot = affected[0].to_dict()
        self.assertNotIn(SECRET_V1, json.dumps(snapshot))

        # 冻结期间新的物化被拒绝
        with self.assertRaises(FreezeError):
            service.request_materialization(task_id="task-1")

        # 追踪销毁证明：先销毁再查询
        service.destroy(target)
        tracking = service.destruction_tracking(incident_id)
        self.assertEqual(len(tracking), 1)
        self.assertEqual(tracking[0].secret_ref, target.secret_ref)

        service.close_incident(incident_id)
        # 解冻后恢复签发；未受影响的 other 全程可用
        new_handle = service.request_materialization(task_id="task-1", ttl_seconds=900)
        self.assertTrue(new_handle.lease_id)
        self.assertEqual(other.use(call=lambda s: s.decode()), SECRET_V1)

    def test_closing_one_incident_keeps_freeze_when_another_stays_open(self) -> None:
        service = build_service()
        first = service.open_incident(tenant_id="tenant-a", scope_note="a")
        second = service.open_incident(tenant_id="tenant-a", scope_note="b")
        service.close_incident(first)
        with self.assertRaises(FreezeError):
            service.request_materialization(task_id="task-1")
        service.close_incident(second)
        self.assertTrue(service.request_materialization(task_id="task-1").lease_id)

    def test_global_freeze_covers_other_tenants(self) -> None:
        service = build_service()
        service.authorize_task(
            task_id="task-b", tenant_id="tenant-b", connector_id="conn-gitlab",
            purpose="sync", approved_scope=["read:repo"],
        )
        service.open_incident(tenant_id="tenant-a", scope_note="platform-wide", scope="global")
        with self.assertRaises(FreezeError):
            service.request_materialization(task_id="task-1")
        with self.assertRaises(FreezeError):
            service.request_materialization(task_id="task-b")

    def test_state_denials_are_recorded_as_usage_receipts(self) -> None:
        clock = FixedClock(T0)
        service = build_service(clock)
        handle = service.request_materialization(task_id="task-1", ttl_seconds=10)
        clock.advance(11)
        service.sweep()
        with self.assertRaises(LeaseStateError):
            handle.use(["read:repo"])
        receipts = service.verify_usage(handle.lease_id)
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["result"], "denied")

    def test_destroyed_handle_still_scoped_by_investigation(self) -> None:
        service = build_service()
        handle = service.request_materialization(task_id="task-1")
        ref = handle.secret_ref
        service.destroy(handle)
        incident_id = service.open_incident(
            tenant_id="tenant-a", suspected_refs=[ref], freeze=False
        )
        affected = service.affected_handles(incident_id)
        self.assertEqual(len(affected), 1)
        self.assertEqual(affected[0].state, "destroyed")
        self.assertEqual(len(service.destruction_tracking(incident_id)), 1)


class EventSourcingTest(unittest.TestCase):
    def test_state_is_fully_reconstructable_from_events(self) -> None:
        service = build_service()
        handle = service.request_materialization(task_id="task-1")
        service.rotate_credential("conn-gitlab", "v2", SECRET_V2, grace_seconds=3600)
        events = service.store.load_all()
        rebuilt = Projection.fold(events)
        lease = rebuilt.leases[handle.lease_id]
        self.assertEqual(lease.status, "active")
        self.assertEqual(rebuilt.connectors["conn-gitlab"].current_version, "v2")
        self.assertIn("v1", rebuilt.connectors["conn-gitlab"].grace)

    def test_event_types_match_domain_contract(self) -> None:
        contract = json.loads(Path(__file__).resolve().parents[1].joinpath("domain/contract.json").read_text())
        from coordinator.events import EVENT_TYPES

        self.assertEqual(set(contract["event_types"]), set(EVENT_TYPES))


if __name__ == "__main__":
    unittest.main()
