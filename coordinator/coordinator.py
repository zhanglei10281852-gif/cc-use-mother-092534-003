"""凭据物化协调器核心。

职责闭环：

* **领取**：连接器只能凭已授权的任务上下文申请，系统按租户/连接器/
  用途/能力范围签发短期租约，明文仅出现在受控句柄中。
* **续期/核销**：租约时间连续；核销后等待连接器提交销毁证明。
* **轮换**：新版本签发，旧版本进入宽限期，宽限结束强制退役、拒绝使用。
* **紧急吊销**：立即清空句柄明文、终止租约。
* **泄露调查**：圈定受影响句柄、冻结新物化、追踪销毁证明。
* **范围验证**：每次连接调用实时校验实际范围不超过原批准，并留回执。
* **失败重放**：只能恢复仍有效的租约关系（无明文），不能重新暴露明文。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from threading import RLock
from typing import Optional

from .crypto import new_fingerprint, issue_secret
from .errors import (
    AuthorizationError,
    FrozenMaterializationError,
    LeaseInvalidError,
    QuotaExceededError,
    ScopeExceededError,
    VersionRetiredError,
)
from .events import Event, EventLog
from .handles import HandlePolicy, LeaseHandle
from .models import (
    Authorization,
    CredentialVersionRecord,
    CredentialVersionState,
    DestructionProof,
    Incident,
    IncidentState,
    LeaseRecord,
    LeaseRelationship,
    LeaseState,
    Scope,
    TaskContext,
    UsageReceipt,
    UsageVerdict,
)
from .store import LeaseStore
from .time import Clock

_DEFAULT_TTL_SECONDS = 900          # 15 分钟短期租约
_RENEW_WINDOW_SECONDS = 120         # 到期前 2 分钟进入续期窗口
_DEFAULT_GRACE_SECONDS = 600        # 轮换宽限 10 分钟


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


class CredentialCoordinator(HandlePolicy):
    def __init__(
        self,
        store: Optional[LeaseStore] = None,
        event_log: Optional[EventLog] = None,
        clock: Optional[Clock] = None,
    ) -> None:
        self.store = store or LeaseStore()
        self.events = event_log or EventLog()
        self.clock = clock or Clock()
        # handle_id -> 活跃句柄；吊销/退役时据此清空明文
        self._handles: dict[str, LeaseHandle] = {}
        # 所有状态变更串行化，保证"额度校验 + 租约落库"的原子性
        self._lock = RLock()

    # ------------------------------------------------------------------
    # 配置：连接器、租户额度、任务授权
    # ------------------------------------------------------------------

    def register_connector(self, connector_id: str, description: str = "") -> None:
        self.store.register_connector(connector_id, description)

    def set_tenant_quota(self, tenant_id: str, max_active_leases: int) -> None:
        self.store.set_quota(tenant_id, max_active_leases)

    def authorize_task(
        self,
        context: TaskContext,
        *,
        max_ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        allowed_purposes: Optional[frozenset[str]] = None,
    ) -> Authorization:
        if context.connector_id not in self.store.connectors:
            raise AuthorizationError(f"连接器未登记：{context.connector_id}")
        purposes = allowed_purposes or frozenset({context.purpose})
        if context.purpose not in purposes:
            raise AuthorizationError("任务用途不在允许的用途集合内")
        if max_ttl_seconds < 1:
            raise AuthorizationError("租约 TTL 必须为正数")
        authorization = Authorization(
            context=context,
            max_ttl_seconds=max_ttl_seconds,
            allowed_purposes=purposes,
        )
        self.store.save_authorization(authorization)
        self._record(
            "task.authorized",
            context.identity,
            context.task_id,
            {
                "tenant_id": context.tenant_id,
                "connector_id": context.connector_id,
                "purpose": context.purpose,
                "authorized_scope": context.authorized_scope.as_sorted(),
                "max_ttl_seconds": max_ttl_seconds,
            },
        )
        return authorization

    # ------------------------------------------------------------------
    # 领取（claim）：授权任务上下文 -> 短期租约 + 受控句柄
    # ------------------------------------------------------------------

    def claim(
        self,
        tenant_id: str,
        task_id: str,
        connector_id: str,
        purpose: str,
        scope: Scope,
        *,
        ttl_seconds: Optional[int] = None,
    ) -> LeaseHandle:
        with self._lock:
            now = self.clock.now()
            self._sweep_expired(now)

            # 1) 调查冻结优先：开放中的调查冻结该租户/连接器的新物化
            self._assert_not_frozen(tenant_id, connector_id)

            # 2) 任务上下文必须经过授权
            authorization = self.store.get_authorization(tenant_id, task_id, connector_id)
            if authorization is None:
                raise AuthorizationError("任务上下文未授权，不能申请凭据")
            context = authorization.context
            if purpose != context.purpose or purpose not in authorization.allowed_purposes:
                raise AuthorizationError(f"用途 {purpose!r} 未获授权")
            if not context.authorized_scope.contains(scope):
                raise AuthorizationError(
                    f"申请范围 {scope.as_sorted()} 超出授权能力 "
                    f"{context.authorized_scope.as_sorted()}"
                )

            # 3) 并发额度：同一任务并发申请不得突破租户额度
            ttl = ttl_seconds if ttl_seconds is not None else min(
                authorization.max_ttl_seconds, _DEFAULT_TTL_SECONDS
            )
            if ttl > authorization.max_ttl_seconds:
                raise AuthorizationError(
                    f"TTL {ttl}s 超过授权上限 {authorization.max_ttl_seconds}s"
                )
            quota = self.store.quotas.get(tenant_id)
            if quota is None:
                raise AuthorizationError(f"租户未配置额度：{tenant_id}")
            active = [
                r
                for r in self.store.leases_for_tenant(tenant_id)
                if r.state.counts_against_quota and r.expires_at > now
            ]
            if len(active) >= quota.max_active_leases:
                self._record(
                    "lease.quota_denied",
                    f"{tenant_id}:{task_id}:{connector_id}",
                    connector_id,
                    {
                        "tenant_id": tenant_id,
                        "active_lease_count": len(active),
                        "quota": quota.max_active_leases,
                    },
                )
                raise QuotaExceededError(
                    f"租户 {tenant_id} 有效租约已达额度 {quota.max_active_leases}"
                )

            # 4) 取/建凭据当前版本，生成一次性明文（协调器不留存明文）
            credential_id = self.store.credential_key(tenant_id, connector_id)
            version_record = self.store.current_version(credential_id)
            if version_record is None:
                plaintext, fingerprint = issue_secret()
                version_record = CredentialVersionRecord(
                    credential_id=credential_id,
                    tenant_id=tenant_id,
                    connector_id=connector_id,
                    version=1,
                    state=CredentialVersionState.CURRENT,
                    fingerprint=fingerprint,
                    created_at=now,
                )
                self.store.save_credential_version(version_record)
                self._record(
                    "credential.provisioned",
                    credential_id,
                    connector_id,
                    {
                        "tenant_id": tenant_id,
                        "connector_id": connector_id,
                        "version": 1,
                        "fingerprint": fingerprint,
                    },
                )
            else:
                # 租约持有一次性明文；凭据版本只保存首个明文指纹，用于版本退役比对
                plaintext, fingerprint = issue_secret()
            lease_id = _new_id("lease")
            handle_id = _new_id("handle")
            expires_at = now + timedelta(seconds=ttl)
            record = LeaseRecord(
                lease_id=lease_id,
                tenant_id=tenant_id,
                connector_id=connector_id,
                task_id=task_id,
                purpose=purpose,
                credential_id=credential_id,
                credential_version=version_record.version,
                fingerprint=fingerprint,
                scope=scope,
                state=LeaseState.ISSUED,
                issued_at=now,
                expires_at=expires_at,
                ttl_seconds=ttl,
            )
            self.store.save_lease(record)
            self.store.register_handle(lease_id, handle_id)

            self._record(
                "lease.requested",
                lease_id,
                connector_id,
                {
                    "tenant_id": tenant_id,
                    "task_id": task_id,
                    "purpose": purpose,
                    "scope": scope.as_sorted(),
                    "ttl_seconds": ttl,
                },
            )

            handle = LeaseHandle(
                handle_id=handle_id,
                lease_id=lease_id,
                tenant_id=tenant_id,
                task_id=task_id,
                connector_id=connector_id,
                purpose=purpose,
                credential_id=credential_id,
                credential_version=version_record.version,
                approved_scope=scope,
                issued_at=now,
                expires_at=expires_at,
                secret=plaintext,
                fingerprint=fingerprint,
                policy=self,
            )
            self._handles[handle_id] = handle

            self._record(
                "lease.issued",
                lease_id,
                connector_id,
                {
                    "handle_id": handle_id,
                    "credential_id": credential_id,
                    "credential_version": version_record.version,
                    "fingerprint": fingerprint,
                    "expires_at": expires_at.isoformat(),
                },
            )
            return handle

    # ------------------------------------------------------------------
    # 续期
    # ------------------------------------------------------------------

    def renew(self, handle: LeaseHandle, ttl_seconds: Optional[int] = None) -> LeaseHandle:
        with self._lock:
            record = self._require_live_lease(handle.lease_id)
            now = self.clock.now()
            authorization = self.store.get_authorization(
                record.tenant_id, record.task_id, record.connector_id
            )
            if authorization is None:
                raise AuthorizationError("任务授权已不存在，不能续期")
            window_start = record.expires_at - timedelta(seconds=_RENEW_WINDOW_SECONDS)
            if now < window_start:
                raise LeaseInvalidError("尚未进入续期窗口")
            ttl = ttl_seconds or record.ttl_seconds or _DEFAULT_TTL_SECONDS
            if ttl > authorization.max_ttl_seconds:
                raise AuthorizationError("续期 TTL 超过授权上限")
            new_expiry = now + timedelta(seconds=ttl)

            record.state = LeaseState.RENEWING
            self.store.save_lease(record)
            self._record(
                "lease.renewed",
                record.lease_id,
                record.connector_id,
                {
                    "renewed_count": record.renewed_count + 1,
                    "old_expires_at": record.expires_at.isoformat(),
                    "new_expires_at": new_expiry.isoformat(),
                },
            )
            record.renewed_count += 1
            record.expires_at = new_expiry
            record.state = LeaseState.ACTIVE
            record.last_used_at = now
            self.store.save_lease(record)
            handle.renew_until(new_expiry)
            return handle

    # ------------------------------------------------------------------
    # 核销 + 销毁证明
    # ------------------------------------------------------------------

    def surrender(self, handle: LeaseHandle, *, reported_by: Optional[str] = None) -> str:
        """连接器主动核销：进入 destroying，等待销毁证明。返回租约标识。"""
        with self._lock:
            record = self.store.get_lease(handle.lease_id)
            if record is None:
                raise LeaseInvalidError("租约不存在")
            if record.state in (LeaseState.DESTROYED, LeaseState.REVOKED, LeaseState.EXPIRED):
                raise LeaseInvalidError(f"租约已处于终态 {record.state.value}")
            record.state = LeaseState.DESTROYING
            self.store.save_lease(record)
            handle.invalidate()
            self._handles.pop(handle.handle_id, None)
            self._record(
                "lease.surrendered",
                record.lease_id,
                reported_by or record.connector_id,
                {"fingerprint": record.fingerprint},
            )
            return record.lease_id

    def confirm_destruction(
        self,
        lease_id: str,
        proof_hash: str,
        *,
        reported_by: str,
        destroyed_at: Optional[datetime] = None,
    ) -> DestructionProof:
        with self._lock:
            record = self.store.get_lease(lease_id)
            if record is None:
                raise LeaseInvalidError("租约不存在")
            if record.state == LeaseState.DESTROYED:
                raise LeaseInvalidError("销毁证明已存在，不可重复确认")
            if record.state not in (LeaseState.DESTROYING, LeaseState.REVOKED, LeaseState.EXPIRED, LeaseState.FROZEN):
                # 连接器尚未核销句柄就上报销毁：先收敛到 destroying
                self._invalidate_handle_for(lease_id)
                record.state = LeaseState.DESTROYING
            now = self.clock.now()
            when = destroyed_at or now
            proof = DestructionProof(
                proof_id=_new_id("proof"),
                lease_id=lease_id,
                fingerprint=record.fingerprint,
                destroyed_at=when,
                reported_by=reported_by,
                proof_hash=proof_hash,
            )
            self.store.save_proof(proof)
            record.state = LeaseState.DESTROYED
            record.destroyed_at = when
            record.destruction_confirmed_by = reported_by
            self.store.save_lease(record)
            self._record(
                "destruction.confirmed",
                lease_id,
                reported_by,
                {
                    "proof_id": proof.proof_id,
                    "fingerprint": record.fingerprint,
                    "proof_hash": proof_hash,
                    "destroyed_at": when.isoformat(),
                },
            )
            return proof

    # ------------------------------------------------------------------
    # 轮换：新版本 + 旧版本宽限 + 到期强制退役
    # ------------------------------------------------------------------

    def rotate(
        self,
        tenant_id: str,
        connector_id: str,
        *,
        grace_seconds: int = _DEFAULT_GRACE_SECONDS,
    ) -> CredentialVersionRecord:
        with self._lock:
            now = self.clock.now()
            credential_id = self.store.credential_key(tenant_id, connector_id)
            current = self.store.current_version(credential_id)
            if current is None:
                raise LeaseInvalidError("凭据尚未签发，无需轮换")
            if grace_seconds < 0:
                raise ValueError("宽限时间不能为负")
            # 新版本只建立指纹锚点；真正的明文在下次 claim 时一次性生成
            new_version = CredentialVersionRecord(
                credential_id=credential_id,
                tenant_id=tenant_id,
                connector_id=connector_id,
                version=current.version + 1,
                state=CredentialVersionState.CURRENT,
                fingerprint=new_fingerprint(),
                created_at=now,
            )
            current.state = CredentialVersionState.GRACE
            current.grace_until = now + timedelta(seconds=grace_seconds)
            self.store.save_credential_version(current)
            self.store.save_credential_version(new_version)
            self._record(
                "credential.rotated",
                credential_id,
                connector_id,
                {
                    "tenant_id": tenant_id,
                    "old_version": current.version,
                    "new_version": new_version.version,
                    "grace_until": current.grace_until.isoformat(),
                },
            )
            return new_version

    def expire_grace_versions(self) -> list[int]:
        """推进时间：宽限期结束的旧版本必须退役，关联句柄立即失效。"""
        with self._lock:
            now = self.clock.now()
            retired: list[int] = []
            for credential_id, versions in self.store.credentials.items():
                for version_record in versions:
                    if (
                        version_record.state == CredentialVersionState.GRACE
                        and version_record.grace_until is not None
                        and now >= version_record.grace_until
                    ):
                        version_record.state = CredentialVersionState.RETIRED
                        retired.append(version_record.version)
                        self._record(
                            "credential.version_retired",
                            credential_id,
                            version_record.connector_id,
                            {"version": version_record.version},
                        )
                        # 旧版本上的活跃租约立即终止并清空句柄
                        for lease in self.store.leases_for_connector(version_record.connector_id):
                            if (
                                lease.credential_id == credential_id
                                and lease.credential_version == version_record.version
                                and lease.state.counts_against_quota
                            ):
                                lease.state = LeaseState.EXPIRED
                                self.store.save_lease(lease)
                                self._invalidate_handle_for(lease.lease_id)
                                self._record(
                                    "lease.expired",
                                    lease.lease_id,
                                    lease.connector_id,
                                    {"reason": "credential_version_retired"},
                                )
            return retired

    # ------------------------------------------------------------------
    # 紧急吊销
    # ------------------------------------------------------------------

    def emergency_revoke(
        self,
        *,
        lease_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        connector_id: Optional[str] = None,
        reason: str,
        actor_id: str,
    ) -> list[str]:
        """按租约/租户/连接器紧急吊销，立即清空句柄明文。返回受影响租约。"""
        with self._lock:
            now = self.clock.now()
            self._sweep_expired(now)
            targets = self._select_leases(lease_id, tenant_id, connector_id, active_only=True)
            affected: list[str] = []
            for record in targets:
                record.state = LeaseState.REVOKED
                record.revoke_reason = reason
                self.store.save_lease(record)
                self._invalidate_handle_for(record.lease_id)
                affected.append(record.lease_id)
                self._record(
                    "lease.revoked",
                    record.lease_id,
                    actor_id,
                    {
                        "reason": reason,
                        "fingerprint": record.fingerprint,
                        "revoked_at": now.isoformat(),
                    },
                )
            return affected

    # ------------------------------------------------------------------
    # 泄露调查：圈定、冻结、追踪销毁证明
    # ------------------------------------------------------------------

    def open_incident(
        self,
        tenant_id: str,
        *,
        opened_by: str,
        reason: str,
        connector_id: Optional[str] = None,
        lease_ids: Optional[list[str]] = None,
    ) -> Incident:
        with self._lock:
            now = self.clock.now()
            incident = Incident(
                incident_id=_new_id("incident"),
                tenant_id=tenant_id,
                opened_at=now,
                state=IncidentState.OPEN,
                opened_by=opened_by,
                reason=reason,
            )
            # 圈定受影响句柄：显式租约优先，否则按连接器/租户扫描
            scoped: list[LeaseRecord]
            if lease_ids:
                scoped = [
                    r
                    for lid in lease_ids
                    if (r := self.store.get_lease(lid)) is not None and r.tenant_id == tenant_id
                ]
            elif connector_id:
                scoped = [
                    r for r in self.store.leases_for_connector(connector_id)
                    if r.tenant_id == tenant_id
                ]
                incident.affected_connectors.add(connector_id)
            else:
                # 租户级调查：圈定全部句柄，并冻结该租户所有连接器的新物化
                scoped = self.store.leases_for_tenant(tenant_id)
                incident.freeze_all_connectors = True
            for record in scoped:
                incident.affected_lease_ids.add(record.lease_id)
                incident.affected_connectors.add(record.connector_id)
                # 冻结活跃租约：记忆原状态，调查结束恢复
                if record.state in (LeaseState.ISSUED, LeaseState.ACTIVE, LeaseState.RENEWING):
                    incident.frozen_lease_states[record.lease_id] = record.state.value
                    record.state = LeaseState.FROZEN
                    self.store.save_lease(record)
                    self._invalidate_handle_for(record.lease_id)
            self.store.save_incident(incident)
            self._record(
                "incident.opened",
                incident.incident_id,
                opened_by,
                {
                    "tenant_id": tenant_id,
                    "reason": reason,
                    "affected_lease_count": len(incident.affected_lease_ids),
                    "affected_connectors": sorted(incident.affected_connectors),
                    "freeze_all_connectors": incident.freeze_all_connectors,
                    "freeze_new_materialization": True,
                },
            )
            return incident

    def close_incident(self, incident_id: str, *, actor_id: str) -> Incident:
        with self._lock:
            incident = self.store.get_incident(incident_id)
            if incident is None:
                raise LeaseInvalidError("调查不存在")
            if incident.state == IncidentState.RESOLVED:
                return incident
            now = self.clock.now()
            # 恢复仍有效的租约关系；冻结期间到期的不恢复
            for lease_id, state_value in incident.frozen_lease_states.items():
                record = self.store.get_lease(lease_id)
                if record is None:
                    continue
                if record.state != LeaseState.FROZEN:
                    # 调查期间被紧急吊销/核销的，保持终态
                    continue
                if record.expires_at > now:
                    record.state = LeaseState(state_value)
                else:
                    record.state = LeaseState.EXPIRED
                self.store.save_lease(record)
            incident.state = IncidentState.RESOLVED
            incident.closed_at = now
            self.store.save_incident(incident)
            self._record(
                "incident.closed",
                incident.incident_id,
                actor_id,
                {"resolved_at": now.isoformat()},
            )
            return incident

    def affected_handles(self, incident_id: str) -> list[LeaseRelationship]:
        """圈定受影响句柄（以租约关系形式呈现，不含明文）。"""
        incident = self.store.get_incident(incident_id)
        if incident is None:
            raise LeaseInvalidError("调查不存在")
        now = self.clock.now()
        result = []
        for lease_id in sorted(incident.affected_lease_ids):
            record = self.store.get_lease(lease_id)
            if record is not None:
                result.append(self._relationship(record, now))
        return result

    def destruction_trail(self, incident_id: str) -> list[DestructionProof]:
        """追踪受影响租约已完成的销毁证明。"""
        incident = self.store.get_incident(incident_id)
        if incident is None:
            raise LeaseInvalidError("调查不存在")
        return self.store.proofs_for_leases(sorted(incident.affected_lease_ids))

    # ------------------------------------------------------------------
    # 失败重放：只恢复仍有效的租约关系，绝不重新暴露明文
    # ------------------------------------------------------------------

    def replay_task(self, tenant_id: str, task_id: str) -> list[LeaseRelationship]:
        now = self.clock.now()
        relationships = []
        for record in self.store.leases_for_task(tenant_id, task_id):
            relationships.append(self._relationship(record, now))
        return [r for r in relationships if r.valid]

    def restore_handle(self, relationship: LeaseRelationship) -> LeaseHandle:
        """重放禁止重建句柄：明文无法恢复。显式拒绝。"""
        raise LeaseInvalidError(
            "任务重放只能恢复租约关系，不能重新物化明文；请重新 claim"
        )

    # ------------------------------------------------------------------
    # 连接调用的实时范围验证（HandlePolicy 实现）
    # ------------------------------------------------------------------

    def authorize_use(self, handle: LeaseHandle, used_scope: Scope) -> UsageReceipt:
        with self._lock:
            now = self.clock.now()
            record = self.store.get_lease(handle.lease_id)
            verdict_allowed = True
            reason = "ok"
            if record is None:
                verdict_allowed, reason = False, "lease_missing"
            else:
                if record.state == LeaseState.FROZEN:
                    verdict_allowed, reason = False, "frozen_by_incident"
                elif record.state in (LeaseState.REVOKED,):
                    verdict_allowed, reason = False, "revoked"
                elif record.state in (LeaseState.DESTROYED, LeaseState.DESTROYING):
                    verdict_allowed, reason = False, "destroyed"
                elif record.expires_at <= now:
                    verdict_allowed, reason = False, "expired"
                else:
                    version_record = self.store.find_version(
                        record.credential_id, record.credential_version
                    )
                    if version_record is not None and version_record.state == CredentialVersionState.RETIRED:
                        verdict_allowed, reason = False, "credential_version_retired"
                    elif not handle.approved_scope.contains(used_scope):
                        verdict_allowed, reason = False, "scope_exceeded"
            within_scope = verdict_allowed
            receipt = UsageReceipt(
                receipt_id=_new_id("receipt"),
                lease_id=handle.lease_id,
                connector_id=handle.connector_id,
                used_scope=used_scope,
                approved_scope=handle.approved_scope,
                within_scope=within_scope,
                at=now,
                credential_version=handle.credential_version,
            )
            self.store.append_receipt(receipt)
            self._record(
                "usage.recorded",
                handle.lease_id,
                handle.connector_id,
                {
                    "receipt_id": receipt.receipt_id,
                    "used_scope": used_scope.as_sorted(),
                    "approved_scope": handle.approved_scope.as_sorted(),
                    "within_scope": within_scope,
                    "verdict_reason": reason,
                    "credential_version": handle.credential_version,
                },
            )
            if not verdict_allowed:
                if reason == "frozen_by_incident":
                    raise FrozenMaterializationError("调查冻结期间禁止使用凭据")
                if reason == "revoked":
                    raise LeaseInvalidError("租约已紧急吊销")
                if reason == "destroyed":
                    raise LeaseInvalidError("租约已核销/销毁")
                if reason == "expired":
                    raise LeaseInvalidError("租约已过期")
                if reason == "credential_version_retired":
                    raise VersionRetiredError("凭据版本宽限期已结束，旧版本必须拒绝")
                if reason == "scope_exceeded":
                    raise ScopeExceededError(
                        f"实际使用范围 {used_scope.as_sorted()} 超过原批准 "
                        f"{handle.approved_scope.as_sorted()}"
                    )
                raise LeaseInvalidError(reason)
            if record is not None:
                record.state = LeaseState.ACTIVE
                record.last_used_at = now
                self.store.save_lease(record)
            return receipt

    def invalidate_handle(self, handle: LeaseHandle) -> None:
        self._handles.pop(handle.handle_id, None)

    def verify_call(self, lease_id: str) -> UsageVerdict:
        """安全接口：核验某租约最近一次连接调用是否在批准范围内。"""
        receipts = self.store.receipts_for_lease(lease_id)
        if not receipts:
            return UsageVerdict(allowed=False, reason="no_usage_recorded")
        latest = receipts[-1]
        if not latest.within_scope:
            return UsageVerdict(
                allowed=False, reason="latest_call_exceeded_scope", receipt_id=latest.receipt_id
            )
        return UsageVerdict(allowed=True, reason="within_approved_scope", receipt_id=latest.receipt_id)

    def receipts_for(self, lease_id: str) -> list[UsageReceipt]:
        return self.store.receipts_for_lease(lease_id)

    def audit_connector_calls(self, connector_id: str) -> list[UsageReceipt]:
        """安全接口：列出某连接器全部连接调用回执，用于审计实际范围。"""
        return self.store.receipts_for_connector(connector_id)

    def lease_snapshot(self, lease_id: str) -> Optional[LeaseRelationship]:
        """只读快照：查询某租约当前关系与状态（不含明文）。"""
        record = self.store.get_lease(lease_id)
        if record is None:
            return None
        return self._relationship(record, self.clock.now())

    # ------------------------------------------------------------------
    # 内部辅助
    # ------------------------------------------------------------------

    def _require_live_lease(self, lease_id: str) -> LeaseRecord:
        record = self.store.get_lease(lease_id)
        if record is None:
            raise LeaseInvalidError("租约不存在")
        if record.state not in (LeaseState.ISSUED, LeaseState.ACTIVE, LeaseState.RENEWING):
            raise LeaseInvalidError(f"租约状态 {record.state.value} 不可续期")
        if record.expires_at <= self.clock.now():
            raise LeaseInvalidError("租约已过期，请重新申请")
        return record

    def _relationship(self, record: LeaseRecord, now: datetime) -> LeaseRelationship:
        valid = (
            record.state in (LeaseState.ISSUED, LeaseState.ACTIVE, LeaseState.RENEWING)
            and record.expires_at > now
        )
        return LeaseRelationship.from_record(record, valid)

    def _assert_not_frozen(self, tenant_id: str, connector_id: str) -> None:
        for incident in self.store.open_incidents(tenant_id):
            if incident.freeze_all_connectors or connector_id in incident.affected_connectors:
                raise FrozenMaterializationError(
                    f"调查 {incident.incident_id} 进行中，已冻结该连接器新的凭据物化"
                )

    def _sweep_expired(self, now: datetime) -> None:
        """把已到期但未推进的租约标记为 expired 并清空句柄，释放额度。"""
        for record in self.store.leases.values():
            if record.state.counts_against_quota and record.expires_at <= now:
                record.state = LeaseState.EXPIRED
                self.store.save_lease(record)
                self._invalidate_handle_for(record.lease_id)
                self._record(
                    "lease.expired",
                    record.lease_id,
                    record.connector_id,
                    {"reason": "ttl_elapsed"},
                )

    def _select_leases(
        self,
        lease_id: Optional[str],
        tenant_id: Optional[str],
        connector_id: Optional[str],
        *,
        active_only: bool,
    ) -> list[LeaseRecord]:
        candidates: list[LeaseRecord]
        if lease_id is not None:
            record = self.store.get_lease(lease_id)
            candidates = [record] if record is not None else []
        elif connector_id is not None:
            candidates = self.store.leases_for_connector(connector_id)
            if tenant_id is not None:
                candidates = [r for r in candidates if r.tenant_id == tenant_id]
        elif tenant_id is not None:
            candidates = self.store.leases_for_tenant(tenant_id)
        else:
            raise ValueError("至少提供 lease_id / tenant_id / connector_id 之一")
        if active_only:
            candidates = [
                r for r in candidates
                if r.state in (LeaseState.ISSUED, LeaseState.ACTIVE, LeaseState.RENEWING, LeaseState.FROZEN)
            ]
        return candidates

    def _invalidate_handle_for(self, lease_id: str) -> None:
        handle_id = self.store.current_handle_id(lease_id)
        if handle_id and handle_id in self._handles:
            self._handles[handle_id].invalidate()
            self._handles.pop(handle_id, None)

    def _record(
        self,
        event_type: str,
        aggregate_id: str,
        actor_id: str,
        payload: Optional[dict] = None,
    ) -> Event:
        event = Event(
            event_id=_new_id("evt"),
            event_type=event_type,
            aggregate_id=aggregate_id,
            occurred_at=self.clock.now(),
            actor_id=actor_id,
            payload=payload or {},
        )
        self.events.append(event)
        return event
