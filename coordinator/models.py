"""领域值对象与持久化记录。

所有记录字段均不含凭据明文：凭据只有 ``fingerprint``（SHA-256），
恢复任务时只能拿到 :class:`LeaseRelationship`，即"仍有效的租约关系"，
明文不会被重新暴露。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import FrozenSet, Optional


class LeaseState(str, Enum):
    REQUESTED = "requested"
    ISSUED = "issued"          # 已签发，句柄尚未进入活跃使用
    ACTIVE = "active"          # 连接器正在使用
    RENEWING = "renewing"      # 续期窗口内
    REVOKED = "revoked"        # 紧急吊销（终态）
    EXPIRED = "expired"        # 自然过期（终态）
    DESTROYING = "destroying"  # 已核销，等待销毁确认
    DESTROYED = "destroyed"    # 销毁证明已确认（终态）
    FROZEN = "frozen"          # 调查冻结：不可签发新物化，旧租约保持原状

    @property
    def is_terminal(self) -> bool:
        return self in (LeaseState.REVOKED, LeaseState.EXPIRED, LeaseState.DESTROYED)

    @property
    def can_materialize(self) -> bool:
        """该状态的租约是否允许凭据被（重新）物化。"""
        return self in (LeaseState.ISSUED, LeaseState.ACTIVE, LeaseState.RENEWING)

    @property
    def counts_against_quota(self) -> bool:
        """是否计入租户并发额度。"""
        return self in (LeaseState.ISSUED, LeaseState.ACTIVE, LeaseState.RENEWING)


class CredentialVersionState(str, Enum):
    CURRENT = "current"
    GRACE = "grace"        # 已轮换，宽限期内仍可用
    RETIRED = "retired"    # 宽限期结束，必须拒绝


class IncidentState(str, Enum):
    OPEN = "open"          # 调查中：冻结新物化
    RESOLVED = "resolved"  # 解除冻结


@dataclass(frozen=True, slots=True)
class Scope:
    """批准的能力范围，只能是字符串集合的子集关系。"""

    capabilities: FrozenSet[str]

    def __post_init__(self) -> None:
        if not self.capabilities:
            raise ValueError("能力范围不能为空")
        if any(not isinstance(c, str) or not c for c in self.capabilities):
            raise ValueError("能力项必须是非空字符串")

    @classmethod
    def of(cls, *capabilities: str) -> "Scope":
        return cls(frozenset(capabilities))

    def contains(self, requested: "Scope") -> bool:
        return requested.capabilities <= self.capabilities

    def as_sorted(self) -> list[str]:
        return sorted(self.capabilities)


@dataclass(frozen=True, slots=True)
class TaskContext:
    """经过授权的任务上下文。"""

    tenant_id: str
    task_id: str
    connector_id: str
    purpose: str
    authorized_scope: Scope

    @property
    def identity(self) -> str:
        return f"{self.tenant_id}:{self.task_id}:{self.connector_id}"


@dataclass(frozen=True, slots=True)
class Authorization:
    """任务上下文被授权后可申请的租约参数。"""

    context: TaskContext
    max_ttl_seconds: int
    allowed_purposes: FrozenSet[str]


@dataclass(slots=True)
class CredentialVersionRecord:
    credential_id: str
    tenant_id: str
    connector_id: str
    version: int
    state: CredentialVersionState
    fingerprint: Optional[str]
    created_at: datetime
    grace_until: Optional[datetime] = None  # 进入 grace 时设置


@dataclass(slots=True)
class LeaseRecord:
    lease_id: str
    tenant_id: str
    connector_id: str
    task_id: str
    purpose: str
    credential_id: str
    credential_version: int
    fingerprint: str
    scope: Scope
    state: LeaseState
    issued_at: datetime
    expires_at: datetime
    ttl_seconds: int = 0
    renewed_count: int = 0
    last_used_at: Optional[datetime] = None
    revoke_reason: Optional[str] = None
    destroyed_at: Optional[datetime] = None
    destruction_confirmed_by: Optional[str] = None
    incident_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class LeaseRelationship:
    """任务失败重放时恢复的对象：只有关系，没有明文。"""

    lease_id: str
    tenant_id: str
    task_id: str
    connector_id: str
    purpose: str
    credential_id: str
    credential_version: int
    scope: Scope
    state: LeaseState
    expires_at: datetime
    valid: bool

    @classmethod
    def from_record(cls, record: LeaseRecord, valid: bool) -> "LeaseRelationship":
        return cls(
            lease_id=record.lease_id,
            tenant_id=record.tenant_id,
            task_id=record.task_id,
            connector_id=record.connector_id,
            purpose=record.purpose,
            credential_id=record.credential_id,
            credential_version=record.credential_version,
            scope=record.scope,
            state=record.state,
            expires_at=record.expires_at,
            valid=valid,
        )


@dataclass(frozen=True, slots=True)
class UsageReceipt:
    """每次连接调用的回执，供安全人员核验实际使用范围。"""

    receipt_id: str
    lease_id: str
    connector_id: str
    used_scope: Scope
    approved_scope: Scope
    within_scope: bool
    at: datetime
    credential_version: int


@dataclass(frozen=True, slots=True)
class UsageVerdict:
    """对单次连接调用的验证结论。"""

    allowed: bool
    reason: str
    receipt_id: Optional[str] = None


@dataclass(slots=True)
class DestructionProof:
    proof_id: str
    lease_id: str
    fingerprint: str
    destroyed_at: datetime
    reported_by: str
    proof_hash: str  # 连接器提交的销毁证据哈希（非明文）


@dataclass(slots=True)
class Incident:
    incident_id: str
    tenant_id: str
    opened_at: datetime
    state: IncidentState
    opened_by: str
    reason: str
    affected_lease_ids: set[str] = field(default_factory=set)
    affected_connectors: set[str] = field(default_factory=set)
    # 全租户调查：未点名连接器也要冻结新物化
    freeze_all_connectors: bool = False
    # 租约被冻结前的状态，调查结束后原样恢复
    frozen_lease_states: dict[str, str] = field(default_factory=dict)
    closed_at: Optional[datetime] = None


@dataclass(frozen=True, slots=True)
class TenantQuota:
    tenant_id: str
    max_active_leases: int
