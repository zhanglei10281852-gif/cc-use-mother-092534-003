"""凭据物化协调器应用服务。

核心保证：

1. 连接器只能凭**已授权任务上下文**申请凭据，申请范围必须是任务批准范围与
   连接器能力的子集；
2. 签发按 *租户 / 连接器 / 用途 / 能力范围* 形成短期租约，明文只进入进程内
   秘密注册表，对外只给 :class:`~coordinator.handle.ControlledHandle`；
3. 领取→签发→物化→续期→（过期/吊销）→销毁 是同一条事件链上的连续状态；
4. 租户有效租约有并发额度，检查与签发在同一个 ``BEGIN IMMEDIATE`` 事务内；
5. 轮换产生新版本，旧版本只在宽限期内可用，到期由清扫器正式退役并拒绝；
6. 任务重放只恢复仍有效的租约关系，注册表中已不存在明文时绝不重新暴露；
7. 安全人员可开调查、圈定句柄、冻结新物化、追踪销毁证明，并通过回执核验
   每次连接调用的实际范围。
"""
from __future__ import annotations

import hashlib
import hmac
import threading
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from coordinator.clock import Clock, SystemClock
from coordinator.errors import (
    AuthorizationError,
    FreezeError,
    LeaseStateError,
    QuotaExceededError,
    ReplayError,
)
from coordinator.events import DomainEvent
from coordinator.handle import ControlledHandle, HandleSnapshot
from coordinator.projection import (
    DestructionProof,
    IncidentState,
    LeaseState,
    Projection,
)
from coordinator.storage import EventStore, SecretRegistry

DEFAULT_TTL_SECONDS = 900
DEFAULT_GRACE_SECONDS = 3600
DEFAULT_TENANT_QUOTA = 5


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("时间必须带时区")
    return value.astimezone(timezone.utc)


class CredentialCoordinator:
    def __init__(
        self,
        store: EventStore | None = None,
        secrets: SecretRegistry | None = None,
        clock: Clock | None = None,
        tenant_quotas: dict[str, int] | None = None,
        default_quota: int = DEFAULT_TENANT_QUOTA,
    ) -> None:
        self.store = store or EventStore(":memory:")
        self.secrets = secrets or SecretRegistry()
        self.clock = clock or SystemClock()
        self._tenant_quotas = dict(tenant_quotas or {})
        self._default_quota = default_quota
        self._handles: dict[str, ControlledHandle] = {}
        self._lock = threading.RLock()

    # ---- 内部工具 ----

    def _now(self) -> datetime:
        return _utc(self.clock.now())

    def _projection(self, connection=None) -> Projection:
        del connection
        return Projection.fold(self.store.load_all())

    def _next_events(
        self,
        projection: Projection,
        specs: list[tuple[str, str, str, dict]],
        *,
        at: datetime | None = None,
    ) -> list[DomainEvent]:
        """specs 元素为 (aggregate_id, event_type, tenant_id, payload)。"""
        events: list[DomainEvent] = []
        seq: dict[str, int] = {}
        occurred_at = (at or self._now()).isoformat()
        for aggregate_id, event_type, tenant_id, payload in specs:
            existing = max(
                (event.sequence for event in self.store.load_stream(aggregate_id)),
                default=0,
            )
            sequence = max(seq.get(aggregate_id, 0), existing) + 1
            seq[aggregate_id] = sequence
            events.append(
                DomainEvent(
                    event_id=self.store.next_identity("evt"),
                    event_type=event_type,
                    aggregate_id=aggregate_id,
                    tenant_id=tenant_id,
                    occurred_at=occurred_at,
                    sequence=sequence,
                    payload=payload,
                )
            )
        return events

    # ---- 任务授权 ----

    def authorize_task(
        self,
        *,
        task_id: str,
        tenant_id: str,
        connector_id: str,
        purpose: str,
        approved_scope: Sequence[str],
        capabilities: Sequence[str] = (),
    ) -> None:
        """登记一条经过授权的任务上下文。连接器凭据申请必须引用它。"""
        if not approved_scope:
            raise AuthorizationError("任务上下文必须批准至少一个范围")
        payload = {
            "connector_id": connector_id,
            "purpose": purpose,
            "approved_scope": sorted(approved_scope),
            "capabilities": sorted(capabilities),
        }
        with self.store.write_transaction() as connection:
            projection = self._projection(connection)
            if task_id in projection.tasks:
                raise AuthorizationError(f"任务上下文已存在：{task_id}")
            event = self._next_events(
                projection,
                [(task_id, "task.authorized", tenant_id, payload)],
            )
            self.store.append(connection, event)

    # ---- 连接器凭据登记与轮换 ----

    def register_connector_credential(
        self,
        connector_id: str,
        version: str,
        plaintext: str | bytes,
        *,
        capabilities: Sequence[str] = (),
    ) -> None:
        """登记连接器的首个凭据版本（明文仅入进程内注册表）并声明连接器能力。"""
        secret_ref = self.secrets.register(plaintext)
        with self.store.write_transaction() as connection:
            projection = self._projection(connection)
            connector = projection.connectors.get(connector_id)
            if connector is not None and connector.current_version:
                self.secrets.revoke(secret_ref)
                raise AuthorizationError(f"连接器 {connector_id} 已有凭据版本，请走轮换")
            event = self._next_events(
                projection,
                [
                    (
                        connector_id,
                        "credential.rotated",
                        "_system",
                        {
                            "old_version": "",
                            "new_version": version,
                            "new_ref": secret_ref,
                            "capabilities": sorted(capabilities),
                            "grace_ends_at": self._now().isoformat(),
                        },
                    )
                ],
            )
            self.store.append(connection, event)

    def _materialize_for_lease(self, master_ref: str, lease_id: str, version: str, purpose: str) -> str:
        """为租约物化一份**独立缓冲**的凭据副本并单独注册。

        - 副本字节内容与主凭据相同（下游系统据此认证），但属于独立注册表条目；
        - 核销单条租约只清零该副本，不影响主凭据与其他租约；紧急吊销连接器时
          才连主凭据一起吊销；
        - 副本与租约/版本/用途的绑定不由字节内容承担，而由受控句柄的范围校验、
          租约状态与版本宽限强制（见 :class:`ControlledHandle`）。
        """
        del lease_id, version, purpose
        material = bytes(self.secrets.reveal(master_ref))
        return self.secrets.register(material)

    def rotate_credential(
        self,
        connector_id: str,
        new_version: str,
        plaintext: str | bytes,
        *,
        grace_seconds: int = DEFAULT_GRACE_SECONDS,
    ) -> datetime:
        """签发新版本凭据；旧版本进入宽限期，宽限结束后所有旧版本句柄必须失效。"""
        secret_ref = self.secrets.register(plaintext)
        grace_ends = self._now() + timedelta(seconds=grace_seconds)
        try:
            with self.store.write_transaction() as connection:
                projection = self._projection(connection)
                connector = projection.connectors.get(connector_id)
                if connector is None or not connector.current_version:
                    raise LeaseStateError(f"连接器 {connector_id} 尚未登记凭据")
                if new_version in connector.versions:
                    raise AuthorizationError(f"凭据版本已存在：{new_version}")
                old_version = connector.current_version
                event = self._next_events(
                    projection,
                    [
                        (
                            connector_id,
                            "credential.rotated",
                            "_system",
                            {
                                "old_version": old_version,
                                "new_version": new_version,
                                "new_ref": secret_ref,
                                "grace_ends_at": grace_ends.isoformat(),
                            },
                        )
                    ],
                )
                self.store.append(connection, event)
        except BaseException:
            # 校验失败 / 事务回滚时，不得在注册表残留新版本明文
            self.secrets.revoke(secret_ref)
            raise
        return grace_ends

    def sweep(self) -> list[str]:
        """时间推进：过期租约、超出宽限期的旧版本统一在此转为终态事件。

        转为终态的同时，对应进程内存文明文立即清零并出具销毁证明，
        句柄标记为不可用。
        """
        settled: list[str] = []
        now = self._now()
        with self.store.write_transaction() as connection:
            projection = self._projection(connection)
            specs: dict[tuple[str, str], tuple[str, str, str, dict]] = {}
            # (lease_id, tenant_id, handle_id, material_ref)
            expired_materials: list[tuple[str, str, str, str]] = []
            # (connector_id, master_ref, version)
            retired_masters: list[tuple[str, str, str]] = []

            def add(aggregate_id: str, event_type: str, tenant_id: str, payload: dict) -> None:
                specs[(aggregate_id, event_type)] = (aggregate_id, event_type, tenant_id, payload)

            for lease in projection.leases.values():
                if lease.is_live and lease.expires_at is not None and now >= lease.expires_at:
                    add(lease.lease_id, "lease.expired", lease.tenant_id, {"at": now.isoformat()})
                    settled.append(lease.lease_id)
                    if lease.secret_ref:
                        expired_materials.append(
                            (lease.lease_id, lease.tenant_id, lease.handle_id or "", lease.secret_ref)
                        )
            for connector in projection.connectors.values():
                for version, grace_end in list(connector.grace.items()):
                    if now >= grace_end and version not in connector.retired:
                        add(
                            connector.connector_id,
                            "credential.version_retired",
                            "_system",
                            {"version": version, "at": now.isoformat()},
                        )
                        # 宽限结束：旧版本主凭据立即失效
                        old_master = connector.versions.get(version)
                        if old_master:
                            retired_masters.append((connector.connector_id, old_master, version))
                        # 仍绑定旧版本的有效租约一并终止
                        for lease in projection.leases.values():
                            if (
                                lease.is_live
                                and lease.connector_id == connector.connector_id
                                and lease.credential_version == version
                                and lease.lease_id not in settled
                            ):
                                add(
                                    lease.lease_id,
                                    "lease.expired",
                                    lease.tenant_id,
                                    {"at": now.isoformat()},
                                )
                                settled.append(lease.lease_id)
                                if lease.secret_ref:
                                    expired_materials.append(
                                        (lease.lease_id, lease.tenant_id, lease.handle_id or "", lease.secret_ref)
                                    )
            if specs:
                self.store.append(connection, self._next_events(projection, list(specs.values()), at=now))
            # 状态事件落库后重算链头，再为每个被清零的秘密出具销毁证明
            if expired_materials or retired_masters:
                projection = self._projection(connection)
                items: list[tuple[str, str, str, str, str, str]] = []
                for lease_id, tenant_id, handle_id, ref in expired_materials:
                    items.append((lease_id, tenant_id, handle_id, ref, "material", "expired"))
                for connector_id, ref, version in retired_masters:
                    items.append((connector_id, "_system", f"version:{version}", ref, "master", "grace_retired"))
                self._append_destructions(connection, projection, items, at=now)
            purged = [item[3] for item in expired_materials] + [item[1] for item in retired_masters]
        for lease_id in settled:
            handle = self._handles.get(lease_id)
            if handle is not None:
                handle.invalidate()
        for ref in purged:
            self.secrets.revoke(ref)
        return settled

    # ---- 凭据物化（领取） ----

    def request_materialization(
        self,
        *,
        task_id: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        scope: Sequence[str] | None = None,
    ) -> ControlledHandle:
        """连接器凭授权任务上下文申请短期凭据，返回受控句柄。"""
        if ttl_seconds <= 0:
            raise AuthorizationError("租约 TTL 必须为正")
        now = self._now()
        with self.store.write_transaction() as connection:
            projection = self._projection(connection)
            task = projection.tasks.get(task_id)
            if task is None:
                raise AuthorizationError("任务上下文未经授权，拒绝签发凭据")
            if projection.has_open_freeze(task.tenant_id):
                raise FreezeError("泄露调查进行中，新的凭据物化已被冻结")
            requested_scope = frozenset(scope) if scope else task.approved_scope
            if not requested_scope:
                raise AuthorizationError("申请范围不能为空")
            if not requested_scope <= task.approved_scope:
                raise AuthorizationError("申请范围超出任务已批准范围")
            connector = projection.connectors.get(task.connector_id)
            if connector is None or not connector.current_version:
                raise AuthorizationError("连接器未登记凭据，拒绝签发")
            if not requested_scope <= connector.capabilities:
                raise AuthorizationError("申请范围超出连接器能力范围")
            quota = self._tenant_quotas.get(task.tenant_id, self._default_quota)
            if projection.active_lease_count(task.tenant_id) >= quota:
                raise QuotaExceededError(
                    f"租户 {task.tenant_id} 有效租约已达额度 {quota}，并发申请被拒绝"
                )
            version = connector.current_version
            master_ref = connector.current_ref
            if not self.secrets.is_live(master_ref):
                raise LeaseStateError("连接器凭据在秘密注册表中不可用，拒绝物化")
            lease_id = self.store.next_identity("lease")
            handle_id = self.store.next_identity("handle")
            expires_at = now + timedelta(seconds=ttl_seconds)
            # 租约级独立物化副本：单租约核销不影响主凭据与其他租约
            material_ref = self._materialize_for_lease(master_ref, lease_id, version, task.purpose)
            try:
                events = self._next_events(
                    projection,
                    [
                        (
                            lease_id,
                            "lease.requested",
                            task.tenant_id,
                            {
                                "task_id": task_id,
                                "connector_id": task.connector_id,
                                "purpose": task.purpose,
                            },
                        ),
                        (
                            lease_id,
                            "lease.issued",
                            task.tenant_id,
                            {
                                "connector_id": task.connector_id,
                                "purpose": task.purpose,
                                "approved_scope": sorted(requested_scope),
                                "capabilities": sorted(task.capabilities),
                                "expires_at": expires_at.isoformat(),
                                "ttl_seconds": ttl_seconds,
                                "secret_ref": material_ref,
                                "master_ref": master_ref,
                                "credential_version": version,
                                "quota_charge": 1,
                                "issue_epoch": 1,
                            },
                        ),
                        (
                            lease_id,
                            "secret.materialized",
                            task.tenant_id,
                            {
                                "handle_id": handle_id,
                                "secret_ref": material_ref,
                                "materialized_at": now.isoformat(),
                            },
                        ),
                    ],
                )
                self.store.append(connection, events)
            except BaseException:
                self.secrets.revoke(material_ref)
                raise
            handle = self._build_handle(
                lease_id=lease_id,
                handle_id=handle_id,
                tenant_id=task.tenant_id,
                connector_id=task.connector_id,
                purpose=task.purpose,
                approved_scope=requested_scope,
                capabilities=task.capabilities,
                version=version,
                expires_at=expires_at,
                secret_ref=material_ref,
            )
            self._handles[lease_id] = handle
            return handle

    # ---- 续期 ----

    def renew(self, handle: ControlledHandle, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> datetime:
        """延长同一条租约关系；若连接器已轮换，续期自动切到新版本凭据。"""
        if ttl_seconds <= 0:
            raise AuthorizationError("续期 TTL 必须为正")
        now = self._now()
        purged_old = ""
        with self.store.write_transaction() as connection:
            projection = self._projection(connection)
            lease = projection.leases.get(handle.lease_id)
            if lease is None:
                raise LeaseStateError("租约不存在")
            if lease.status == "revoked":
                raise LeaseStateError("租约已吊销，不能续期")
            if lease.status in {"expired", "destroyed"}:
                raise LeaseStateError(f"租约已{lease.status}，不能续期")
            if lease.expires_at and now >= lease.expires_at:
                raise LeaseStateError("租约已到期，请重新申请而非续期")
            connector = projection.connectors.get(lease.connector_id)
            new_master_ref = ""
            new_material_ref = ""
            old_material_ref = ""
            new_version = lease.credential_version
            if connector is not None and connector.current_version != lease.credential_version:
                if lease.credential_version in connector.retired:
                    raise LeaseStateError("旧凭据版本已退役，不能基于旧版本续期")
                new_master_ref = connector.current_ref
                new_version = connector.current_version
                if not self.secrets.is_live(new_master_ref):
                    raise LeaseStateError("新版本凭据在秘密注册表中不可用")
                # 为新版本物化新的租约级副本，旧副本在续期成功后核销
                new_material_ref = self._materialize_for_lease(
                    new_master_ref, lease.lease_id, new_version, lease.purpose
                )
                old_material_ref = lease.secret_ref
            expires_at = now + timedelta(seconds=ttl_seconds)
            payload = {
                "expires_at": expires_at.isoformat(),
                "ttl_seconds": ttl_seconds,
            }
            if new_material_ref:
                payload.update(
                    secret_ref=new_material_ref,
                    master_ref=new_master_ref,
                    credential_version=new_version,
                )
            try:
                event = self._next_events(
                    projection,
                    [(handle.lease_id, "lease.renewed", lease.tenant_id, payload)],
                )
                self.store.append(connection, event)
                if old_material_ref:
                    # 旧版本副本随续期切换立即核销清零（宽限只保护尚未续期的租约），
                    # 并出具销毁证明；此时租约已绑定新 ref，证明不影响其 active 状态。
                    projection = self._projection(connection)
                    self._append_destructions(
                        connection,
                        projection,
                        [(handle.lease_id, lease.tenant_id, handle.handle_id, old_material_ref, "material", "rotated")],
                        at=now,
                    )
            except BaseException:
                if new_material_ref:
                    self.secrets.revoke(new_material_ref)
                raise
            purged_old = old_material_ref
        if purged_old:
            self.secrets.revoke(purged_old)
        handle.bind_renewal(
            expires_at=expires_at,
            secret_ref=new_material_ref or lease.secret_ref,
            credential_version=new_version,
        )
        return expires_at

    # ---- 核销 / 紧急吊销 ----

    def revoke(self, handle: ControlledHandle, *, reason: str, emergency: bool = False) -> None:
        secret_ref = ""
        moment = self._now()
        with self.store.write_transaction() as connection:
            projection = self._projection(connection)
            lease = projection.leases.get(handle.lease_id)
            if lease is None:
                raise LeaseStateError("租约不存在")
            if lease.status in {"revoked", "destroyed"}:
                raise LeaseStateError(f"租约已处于终态 {lease.status}")
            event = self._next_events(
                projection,
                [
                    (
                        handle.lease_id,
                        "lease.revoked",
                        lease.tenant_id,
                        {"reason": reason, "emergency": emergency, "actor_id": "security"},
                    )
                ],
                at=moment,
            )
            self.store.append(connection, event)
            secret_ref = lease.secret_ref
            projection = self._projection(connection)
            self._append_destructions(
                connection,
                projection,
                [
                    (
                        handle.lease_id,
                        lease.tenant_id,
                        handle.handle_id,
                        secret_ref,
                        "material",
                        "emergency" if emergency else "revoked",
                    )
                ],
                at=moment,
            )
        self.secrets.revoke(secret_ref)
        handle.invalidate()

    def emergency_revoke_connector(self, connector_id: str, *, reason: str) -> list[str]:
        """安全紧急动作：吊销某连接器全部有效租约并清零其主凭据，返回被吊销租约。

        被清零的每个物化副本与主凭据都出具销毁证明（reason=emergency）。
        """
        revoked: list[str] = []
        # (aggregate_id, tenant_id, handle_id, ref)
        materials: list[tuple[str, str, str, str]] = []
        masters: list[str] = []
        moment = self._now()
        with self.store.write_transaction() as connection:
            projection = self._projection(connection)
            connector = projection.connectors.get(connector_id)
            if connector is not None:
                masters = [ref for ref in connector.versions.values() if self.secrets.is_live(ref)]
            specs: list[tuple[str, str, str, dict]] = []
            for lease in projection.leases.values():
                if lease.connector_id == connector_id and lease.is_live:
                    specs.append(
                        (
                            lease.lease_id,
                            "lease.revoked",
                            lease.tenant_id,
                            {"reason": reason, "emergency": True, "actor_id": "security"},
                        )
                    )
                    revoked.append(lease.lease_id)
                    if lease.secret_ref and self.secrets.is_live(lease.secret_ref):
                        materials.append(
                            (lease.lease_id, lease.tenant_id, lease.handle_id or "", lease.secret_ref)
                        )
            if specs:
                self.store.append(connection, self._next_events(projection, specs, at=moment))
            if materials or masters:
                projection = self._projection(connection)
                items: list[tuple[str, str, str, str, str, str]] = [
                    (lease_id, tenant_id, handle_id, ref, "material", "emergency")
                    for lease_id, tenant_id, handle_id, ref in materials
                ]
                items.extend(
                    (connector_id, "_system", "", ref, "master", "emergency") for ref in masters
                )
                self._append_destructions(connection, projection, items, at=moment)
            purged = [item[3] for item in materials] + masters
        for lease_id in revoked:
            handle = self._handles.get(lease_id)
            if handle is not None:
                handle.invalidate()
        for ref in purged:
            self.secrets.revoke(ref)
        return revoked

    # ---- 销毁证明 ----

    def _append_destructions(
        self,
        connection,
        projection: Projection,
        items: list[tuple[str, str, str, str, str, str]],
        *,
        at: datetime,
    ) -> None:
        """在当前事务内为每个被清零的秘密追加哈希链销毁事件。

        item = (aggregate_id, tenant_id, handle_id, secret_ref, kind, reason)。
        多条证明在一次调用内顺序链接；任何路径清零明文都必须经过这里，
        保证“有清零必有可追踪证明”。
        """
        specs: list[tuple[str, str, str, dict]] = []
        head = projection.proof_chain_head
        stamp = at.isoformat()
        for aggregate_id, tenant_id, handle_id, secret_ref, kind, reason in items:
            if not secret_ref:
                continue
            proof = hashlib.sha256(
                "|".join([head, aggregate_id, secret_ref, stamp, reason]).encode("utf-8")
            ).hexdigest()
            head = proof
            specs.append(
                (
                    aggregate_id,
                    "destruction.confirmed",
                    tenant_id,
                    {
                        "handle_id": handle_id,
                        "secret_ref": secret_ref,
                        "destroyed_at": stamp,
                        "proof": proof,
                        "kind": kind,
                        "reason": reason,
                    },
                )
            )
        if specs:
            self.store.append(connection, self._next_events(projection, specs, at=at))

    def destroy(self, handle: ControlledHandle) -> DestructionProof:
        """核销句柄并产生销毁证明；明文在注册表中就地清零。"""
        now = self._now()
        with self.store.write_transaction() as connection:
            projection = self._projection(connection)
            lease = projection.leases.get(handle.lease_id)
            if lease is None:
                raise LeaseStateError("租约不存在")
            if not lease.is_live:
                raise LeaseStateError(f"租约已处于终态 {lease.status}，不能再核销")
            secret_ref = lease.secret_ref
            self._append_destructions(
                connection,
                projection,
                [(lease.lease_id, lease.tenant_id, handle.handle_id, secret_ref, "material", "manual")],
                at=now,
            )
        self.secrets.revoke(secret_ref)
        handle.mark_destroyed()
        return self._projection().proof_for(handle.lease_id)  # type: ignore[return-value]

    # ---- 使用留痕与范围核验 ----

    def _record_usage(
        self,
        handle: ControlledHandle,
        used_scope: frozenset[str],
        at: datetime,
        ok: bool,
        response_digest: str | None,
    ) -> None:
        with self.store.write_transaction() as connection:
            projection = self._projection(connection)
            lease = projection.leases.get(handle.lease_id)
            approved = lease.approved_scope if lease else handle.approved_scope
            within = used_scope <= approved
            event = self._next_events(
                projection,
                [
                    (
                        handle.lease_id,
                        "usage.recorded",
                        handle.tenant_id,
                        {
                            "handle_id": handle.handle_id,
                            "used_scope": sorted(used_scope),
                            "result": "ok" if ok else "denied",
                            "scope_within_approval": within and ok,
                            "response_digest": response_digest,
                        },
                    )
                ],
                at=_utc(at),
            )
            self.store.append(connection, event)

    def verify_usage(self, lease_id: str) -> list[dict]:
        """供安全人员核验：每次连接调用实际使用范围是否未超过原批准。"""
        projection = self._projection()
        lease = projection.leases.get(lease_id)
        if lease is None:
            raise LeaseStateError("租约不存在")
        receipts: list[dict] = []
        for receipt in projection.usage_for(lease_id):
            receipts.append(
                {
                    "event_id": receipt.event_id,
                    "handle_id": receipt.handle_id,
                    "at": receipt.at.isoformat(),
                    "approved_scope": sorted(lease.approved_scope),
                    "used_scope": sorted(receipt.used_scope),
                    "within_approval": receipt.used_scope <= lease.approved_scope,
                    "result": "ok" if receipt.ok else "denied",
                }
            )
        return receipts

    def assert_all_calls_within_scope(self) -> None:
        """调查接口：断言全系统每一次调用都未越权，发现越权即抛断言错误。"""
        projection = self._projection()
        violations = [
            receipt
            for receipt in projection.usages
            if not receipt.used_scope <= projection.leases[receipt.lease_id].approved_scope
        ]
        if violations:
            ids = ", ".join(receipt.event_id for receipt in violations)
            raise AssertionError(f"发现超过原批准范围的连接调用：{ids}")

    # ---- 任务失败重放 ----

    def replay_task(self, task_id: str) -> list[ControlledHandle]:
        """任务失败重放：只恢复**仍有效**的租约关系。

        - 已过期 / 已吊销 / 已销毁 / 旧版本已退役的租约不恢复；
        - 明文不会重新签发或重新暴露：仅当进程内秘密注册表仍持有原 ``secret_ref``
          时，才重新给出绑定同一秘密的句柄，否则跳过该租约。
        """
        with self._lock:
            self.sweep()
            projection = self._projection()
            if task_id not in projection.tasks:
                raise ReplayError("任务上下文不存在，无法重放")
            restored: list[ControlledHandle] = []
            for lease in projection.leases.values():
                if lease.task_id != task_id or not lease.is_live or not lease.handle_id:
                    continue
                if not self.secrets.is_live(lease.secret_ref):
                    # 明文已不在注册表中：绝不重新签发、绝不重新暴露
                    continue
                existing = self._handles.get(lease.lease_id)
                if existing is not None and not existing.is_destroyed:
                    restored.append(existing)
                    continue
                handle = self._build_handle(
                    lease_id=lease.lease_id,
                    handle_id=lease.handle_id,  # type: ignore[arg-type]
                    tenant_id=lease.tenant_id,
                    connector_id=lease.connector_id,
                    purpose=lease.purpose,
                    approved_scope=lease.approved_scope,
                    capabilities=lease.capabilities,
                    version=lease.credential_version,
                    expires_at=lease.expires_at,  # type: ignore[arg-type]
                    secret_ref=lease.secret_ref,
                )
                self._handles[lease.lease_id] = handle
                restored.append(handle)
            if not restored:
                raise ReplayError("没有仍有效的租约关系可恢复，任务需重新授权申请")
            return restored

    # ---- 泄露调查 ----

    def open_incident(
        self,
        *,
        tenant_id: str,
        suspected_refs: Sequence[str] | None = None,
        scope_note: str = "",
        freeze: bool = True,
        scope: str = "tenant",
    ) -> str:
        """安全人员发起疑似泄露调查：圈定受影响句柄并冻结新的物化。

        ``scope="tenant"`` 只冻结该租户；``scope="global"`` 冻结全部新物化，
        用于怀疑连接器级或平台级泄露。
        """
        if scope not in {"tenant", "global"}:
            raise ValueError("冻结范围只能是 tenant 或 global")
        incident_id = self.store.next_identity("incident")
        now = self._now()
        with self.store.write_transaction() as connection:
            projection = self._projection(connection)
            specs: list[tuple[str, str, str, dict]] = [
                (
                    incident_id,
                    "incident.opened",
                    tenant_id,
                    {
                        "incident_id": incident_id,
                        "suspected_refs": sorted(suspected_refs or []),
                        "scope_note": scope_note,
                        "freeze": freeze,
                        "freeze_scope": scope,
                        "opened_at": now.isoformat(),
                    },
                )
            ]
            if freeze:
                specs.append(
                    (
                        incident_id,
                        "materialization.frozen",
                        tenant_id,
                        {"scope": scope, "at": now.isoformat()},
                    )
                )
            self.store.append(connection, self._next_events(projection, specs))
        return incident_id

    def affected_handles(self, incident_id: str) -> list[HandleSnapshot]:
        """圈定调查涉及的句柄（含当前状态，不含任何明文）。"""
        projection = self._projection()
        incident = projection.incidents.get(incident_id)
        if incident is None:
            raise LeaseStateError("调查不存在")
        snapshots: list[HandleSnapshot] = []
        for lease in projection.affected_handles(incident.suspected_refs):
            handle = self._handles.get(lease.lease_id)
            snapshots.append(handle.snapshot() if handle else _snapshot_from_lease(lease))
        return snapshots

    def destruction_tracking(self, incident_id: str) -> list[DestructionProof]:
        """追踪受影响秘密已完成的销毁证明（哈希链，可离线验证）。

        既匹配租约物化副本，也匹配连接器主凭据（kind=master）。
        """
        projection = self._projection()
        incident = projection.incidents.get(incident_id)
        if incident is None:
            raise LeaseStateError("调查不存在")
        refs = set(incident.suspected_refs)
        return [proof for proof in projection.proofs if proof.secret_ref in refs]

    def close_incident(self, incident_id: str, *, unfreeze: bool = True) -> None:
        now = self._now()
        with self.store.write_transaction() as connection:
            projection = self._projection(connection)
            incident = projection.incidents.get(incident_id)
            if incident is None:
                raise LeaseStateError("调查不存在")
            specs: list[tuple[str, str, str, dict]] = [
                (incident_id, "incident.closed", incident.tenant_id, {"incident_id": incident_id, "at": now.isoformat()})
            ]
            if unfreeze and incident.freeze:
                # 仅当没有其他进行中的冻结调查仍覆盖该范围时才解冻，
                # 避免关闭一个调查提前解除另一个调查施加的冻结。
                others = [
                    other
                    for other in projection.open_incidents()
                    if other.incident_id != incident_id and other.freeze
                ]
                still_frozen = any(
                    other.freeze_scope == "global"
                    or (incident.freeze_scope == "tenant" and other.tenant_id == incident.tenant_id)
                    for other in others
                )
                if not still_frozen:
                    specs.append(
                        (
                            incident_id,
                            "materialization.unfrozen",
                            incident.tenant_id,
                            {"scope": incident.freeze_scope, "at": now.isoformat()},
                        )
                    )
            self.store.append(connection, self._next_events(projection, specs))

    # ---- 只读查询 ----

    def lease_view(self, lease_id: str) -> LeaseState:
        return self._projection().leases[lease_id]

    def incident_view(self, incident_id: str) -> IncidentState:
        return self._projection().incidents[incident_id]

    def verify_destruction_chain(self) -> list[dict]:
        """按事件顺序重算销毁哈希链，验证每份销毁证明未被篡改。

        返回每条销毁事件的核验结果；任何一环不匹配即标记 ``valid=False``。
        证明链只引用不透明标识与时间，不含明文。
        """
        head = "GENESIS"
        results: list[dict] = []
        for event in self.store.load_chain():
            if event.event_type != "destruction.confirmed":
                continue
            payload = event.payload
            expected = hashlib.sha256(
                "|".join(
                    [
                        head,
                        event.aggregate_id,
                        payload["secret_ref"],
                        payload["destroyed_at"],
                        payload.get("reason", "manual"),
                    ]
                ).encode("utf-8")
            ).hexdigest()
            valid = hmac.compare_digest(expected, payload["proof"])
            results.append(
                {
                    "event_id": event.event_id,
                    "lease_id": event.aggregate_id,
                    "handle_id": payload["handle_id"],
                    "secret_ref": payload["secret_ref"],
                    "kind": payload.get("kind", "material"),
                    "reason": payload.get("reason", "manual"),
                    "destroyed_at": payload["destroyed_at"],
                    "valid": valid,
                }
            )
            head = payload["proof"]
        return results

    # ---- 句柄装配 ----

    def _build_handle(
        self,
        *,
        lease_id: str,
        handle_id: str,
        tenant_id: str,
        connector_id: str,
        purpose: str,
        approved_scope,
        capabilities,
        version: str,
        expires_at: datetime,
        secret_ref: str,
    ) -> ControlledHandle:
        def state_provider(lid: str, current_version: str) -> tuple[str, str | None, datetime | None]:
            projection = self._projection()
            lease = projection.leases.get(lid)
            if lease is None:
                return "destroyed", None, None
            connector = projection.connectors.get(lease.connector_id)
            grace_end = connector.grace.get(current_version) if connector else None
            if connector and current_version in connector.retired:
                return "version_retired", None, grace_end
            return lease.status, None, grace_end

        return ControlledHandle(
            handle_id=handle_id,
            lease_id=lease_id,
            tenant_id=tenant_id,
            connector_id=connector_id,
            purpose=purpose,
            approved_scope=tuple(approved_scope),
            capabilities=tuple(capabilities),
            credential_version=version,
            expires_at=expires_at,
            secret_ref=secret_ref,
            secret_provider=self.secrets.reveal,
            usage_recorder=self._record_usage,  # type: ignore[arg-type]
            state_provider=state_provider,
            clock=self._now,
        )


def _snapshot_from_lease(lease: LeaseState) -> HandleSnapshot:
    """在当前进程没有活动句柄对象时（如重放到新进程），由租约读模型生成非敏感视图。"""
    return HandleSnapshot(
        handle_id=lease.handle_id or "",
        lease_id=lease.lease_id,
        tenant_id=lease.tenant_id,
        connector_id=lease.connector_id,
        purpose=lease.purpose,
        approved_scope=lease.approved_scope,
        credential_version=lease.credential_version,
        expires_at=lease.expires_at or datetime.min.replace(tzinfo=timezone.utc),
        state=lease.status,
    )
