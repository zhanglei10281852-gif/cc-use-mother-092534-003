"""读模型：把事件流折叠为当前状态。所有状态均由事件重放得到，不另行持久化。"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from coordinator.events import DomainEvent


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


@dataclass
class TaskState:
    task_id: str
    tenant_id: str
    connector_id: str
    purpose: str
    approved_scope: frozenset[str]
    capabilities: frozenset[str]
    authorized_at: datetime


@dataclass
class LeaseState:
    lease_id: str
    tenant_id: str
    task_id: str
    connector_id: str
    purpose: str
    approved_scope: frozenset[str] = frozenset()
    capabilities: frozenset[str] = frozenset()
    status: str = "requested"  # requested/issued/active/renewing/expired/revoked/destroying/destroyed
    credential_version: str = ""
    issue_epoch: int = 0
    secret_ref: str = ""
    expires_at: datetime | None = None
    handle_id: str | None = None
    renewals: int = 0
    revoked_reason: str | None = None
    emergency: bool = False
    last_event_at: datetime | None = None

    @property
    def is_live(self) -> bool:
        return self.status in {"requested", "issued", "active", "renewing"}


@dataclass
class UsageReceipt:
    event_id: str
    lease_id: str
    handle_id: str
    used_scope: frozenset[str]
    at: datetime
    ok: bool
    scope_within_approval: bool
    response_digest: str | None = None


@dataclass
class DestructionProof:
    event_id: str
    lease_id: str  # 对主凭据为连接器聚合标识
    handle_id: str
    secret_ref: str
    destroyed_at: datetime
    proof: str  # 哈希链证明，不含明文
    kind: str = "material"  # material=租约物化副本，master=连接器主凭据
    reason: str = "manual"  # manual/revoked/emergency/expired/rotated/grace_retired


@dataclass
class IncidentState:
    incident_id: str
    tenant_id: str
    opened_at: datetime
    suspected_refs: frozenset[str]
    scope_note: str
    freeze: bool
    freeze_scope: str = "tenant"
    closed_at: datetime | None = None


@dataclass
class ConnectorState:
    connector_id: str
    current_version: str = ""
    current_ref: str = ""
    capabilities: frozenset[str] = frozenset()
    versions: dict[str, str] = field(default_factory=dict)  # version -> 主凭据 secret_ref
    # 旧版本宽限截止时间
    grace: dict[str, datetime] = field(default_factory=dict)
    retired: set[str] = field(default_factory=set)


class Projection:
    def __init__(self) -> None:
        self.tasks: dict[str, TaskState] = {}
        self.leases: dict[str, LeaseState] = {}
        self.connectors: dict[str, ConnectorState] = {}
        self.incidents: dict[str, IncidentState] = {}
        self.usages: list[UsageReceipt] = []
        self.proofs: list[DestructionProof] = []
        self.frozen_tenants: set[str] = set()
        self.global_frozen: bool = False
        self.proof_chain_head: str = "GENESIS"
        self._lease_index_by_ref: dict[str, str] = {}

    # ---- 折叠 ----

    def apply(self, event: DomainEvent) -> None:
        et = event.event_type
        p = event.payload
        if et == "task.authorized":
            self.tasks[event.aggregate_id] = TaskState(
                task_id=event.aggregate_id,
                tenant_id=event.tenant_id,
                connector_id=p["connector_id"],
                purpose=p["purpose"],
                approved_scope=frozenset(p["approved_scope"]),
                capabilities=frozenset(p.get("capabilities", ())),
                authorized_at=_parse(event.occurred_at),
            )
        elif et == "lease.requested":
            lease = self.leases.get(event.aggregate_id)
            if lease is None:
                self.leases[event.aggregate_id] = LeaseState(
                    lease_id=event.aggregate_id,
                    tenant_id=event.tenant_id,
                    task_id=p["task_id"],
                    connector_id=p["connector_id"],
                    purpose=p["purpose"],
                    status="requested",
                    last_event_at=_parse(event.occurred_at),
                )
        elif et == "lease.issued":
            lease = self.leases[event.aggregate_id]
            lease.approved_scope = frozenset(p["approved_scope"])
            lease.capabilities = frozenset(p.get("capabilities", ()))
            lease.status = "issued"
            lease.credential_version = p["credential_version"]
            lease.issue_epoch = p.get("issue_epoch", 1)
            lease.secret_ref = p["secret_ref"]
            lease.expires_at = _parse(p["expires_at"])
            lease.last_event_at = _parse(event.occurred_at)
            self._lease_index_by_ref[p["secret_ref"]] = lease.lease_id
        elif et == "secret.materialized":
            lease = self.leases[event.aggregate_id]
            lease.status = "active"
            lease.handle_id = p["handle_id"]
            lease.last_event_at = _parse(event.occurred_at)
        elif et == "lease.renewed":
            lease = self.leases[event.aggregate_id]
            lease.status = "active"
            lease.renewals += 1
            lease.expires_at = _parse(p["expires_at"])
            if p.get("secret_ref"):
                self._lease_index_by_ref.pop(lease.secret_ref, None)
                lease.secret_ref = p["secret_ref"]
                lease.credential_version = p["credential_version"]
                self._lease_index_by_ref[p["secret_ref"]] = lease.lease_id
            lease.last_event_at = _parse(event.occurred_at)
        elif et == "lease.revoked":
            lease = self.leases[event.aggregate_id]
            lease.status = "revoked"
            lease.revoked_reason = p.get("reason")
            lease.emergency = bool(p.get("emergency"))
            lease.last_event_at = _parse(event.occurred_at)
        elif et == "lease.expired":
            lease = self.leases[event.aggregate_id]
            lease.status = "expired"
            lease.last_event_at = _parse(event.occurred_at)
        elif et == "credential.rotated":
            connector = self.connectors.setdefault(event.aggregate_id, ConnectorState(event.aggregate_id))
            old_version = p["old_version"]
            if old_version:
                connector.grace[old_version] = _parse(p["grace_ends_at"])
            elif p.get("capabilities"):
                # 首次登记时声明连接器能力范围
                connector.capabilities = frozenset(p["capabilities"])
            connector.current_version = p["new_version"]
            connector.current_ref = p["new_ref"]
            connector.versions[p["new_version"]] = p["new_ref"]
        elif et == "credential.version_retired":
            connector = self.connectors[event.aggregate_id]
            connector.retired.add(p["version"])
            connector.grace.pop(p["version"], None)
        elif et == "destruction.confirmed":
            lease = self.leases.get(event.aggregate_id)
            kind = p.get("kind", "material")
            reason = p.get("reason", "manual")
            # 只有对仍活租约的手动核销才把租约置为 destroyed；
            # 吊销/过期/续期切换/主凭据退役各自由其自身事件表达终态，
            # 销毁证明只负责证明“明文已清零”，不篡改租约状态。
            if (
                lease is not None
                and kind == "material"
                and reason == "manual"
                and lease.is_live
                and lease.secret_ref == p["secret_ref"]
            ):
                lease.status = "destroyed"
            # 保留 handle_id 与 ref 索引：销毁后调查仍需圈定句柄与关联销毁证明，
            # 这些字段都不含明文。
            proof = DestructionProof(
                event_id=event.event_id,
                lease_id=event.aggregate_id,
                handle_id=p["handle_id"],
                secret_ref=p["secret_ref"],
                destroyed_at=_parse(p["destroyed_at"]),
                proof=p["proof"],
                kind=kind,
                reason=reason,
            )
            self.proofs.append(proof)
            self.proof_chain_head = p["proof"]
            if lease is not None:
                lease.last_event_at = proof.destroyed_at
        elif et == "usage.recorded":
            lease = self.leases[event.aggregate_id]
            self.usages.append(
                UsageReceipt(
                    event_id=event.event_id,
                    lease_id=event.aggregate_id,
                    handle_id=p["handle_id"],
                    used_scope=frozenset(p["used_scope"]),
                    at=_parse(event.occurred_at),
                    ok=bool(p.get("result") == "ok"),
                    scope_within_approval=bool(p["scope_within_approval"]),
                    response_digest=p.get("response_digest"),
                )
            )
        elif et == "incident.opened":
            self.incidents[p["incident_id"]] = IncidentState(
                incident_id=p["incident_id"],
                tenant_id=event.tenant_id,
                opened_at=_parse(event.occurred_at),
                suspected_refs=frozenset(p.get("suspected_refs", ())),
                scope_note=p.get("scope_note", ""),
                freeze=bool(p.get("freeze")),
                freeze_scope=p.get("freeze_scope", "tenant"),
            )
        elif et == "materialization.frozen":
            if p.get("scope") == "global":
                self.global_frozen = True
            else:
                self.frozen_tenants.add(event.tenant_id)
        elif et == "materialization.unfrozen":
            if p.get("scope") == "global":
                self.global_frozen = False
            else:
                self.frozen_tenants.discard(event.tenant_id)
        elif et == "incident.closed":
            incident = self.incidents.get(p["incident_id"])
            if incident is not None:
                incident.closed_at = _parse(event.occurred_at)

    @classmethod
    def fold(cls, events: list[DomainEvent]) -> "Projection":
        projection = cls()
        for event in events:
            projection.apply(event)
        return projection

    # ---- 查询 ----

    def active_lease_count(self, tenant_id: str) -> int:
        return sum(1 for lease in self.leases.values() if lease.tenant_id == tenant_id and lease.is_live)

    def lease_for_ref(self, secret_ref: str) -> LeaseState | None:
        lease_id = self._lease_index_by_ref.get(secret_ref)
        return self.leases[lease_id] if lease_id else None

    def affected_handles(self, suspected_refs: frozenset[str]) -> list[LeaseState]:
        result = []
        for ref in suspected_refs:
            lease = self.lease_for_ref(ref)
            if lease is not None and lease.handle_id:
                result.append(lease)
        return result

    def usage_for(self, lease_id: str) -> list[UsageReceipt]:
        return [receipt for receipt in self.usages if receipt.lease_id == lease_id]

    def proof_for(self, lease_id: str) -> DestructionProof | None:
        for proof in reversed(self.proofs):
            if proof.lease_id == lease_id:
                return proof
        return None

    def open_incidents(self) -> list[IncidentState]:
        return [incident for incident in self.incidents.values() if incident.closed_at is None]

    def has_open_freeze(self, tenant_id: str) -> bool:
        """该租户当前是否被任一进行中的调查冻结（租户级或全局级）。"""
        for incident in self.open_incidents():
            if not incident.freeze:
                continue
            if incident.freeze_scope == "global":
                return True
            if incident.tenant_id == tenant_id:
                return True
        return False
