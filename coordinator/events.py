"""领域事件定义。

事件载荷中**绝不出现明文密钥**：明文存于独立的进程内存秘密注册表，事件流里
只保存不可反推明文的 ``secret_ref``（随机不透明标识）。所有事件均为不可变
追加记录，状态只能由事件重放得到。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Mapping


@dataclass(frozen=True)
class DomainEvent:
    event_id: str
    event_type: str
    aggregate_id: str
    tenant_id: str
    occurred_at: str  # ISO 8601 带时区
    sequence: int
    payload: Mapping[str, Any] = field(default_factory=dict)
    # 父事件（如续期/核销关联的签发事件），用于重建连续状态链
    causation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


#: 全部已知事件类型。语义见各文档注释与 :mod:`coordinator.projection`。
EVENT_TYPES: frozenset[str] = frozenset(
    {
        # 任务上下文授权。payload：connector_id、purpose、approved_scope、capabilities
        "task.authorized",
        # 租约生命周期
        "lease.requested",  # payload：task_id、connector_id、purpose
        "lease.issued",  # payload：approved_scope、capabilities、expires_at、ttl_seconds、
        #                  secret_ref（租约物化副本）、master_ref（主凭据）、
        #                  credential_version、quota_charge、issue_epoch
        "lease.renewed",  # payload：expires_at、ttl_seconds；跨版本续期时含
        #                  secret_ref/master_ref/credential_version
        "lease.revoked",  # payload：reason、emergency、actor_id
        "lease.expired",
        # 凭据版本轮换
        "credential.rotated",  # payload：old_version、new_version、new_ref、
        #                       grace_ends_at；首次登记时含 capabilities
        "credential.version_retired",  # payload：version
        # 受控物化与销毁
        "secret.materialized",  # payload：handle_id、secret_ref、materialized_at
        "destruction.confirmed",  # payload：handle_id、secret_ref、destroyed_at、proof
        # 使用回执
        "usage.recorded",  # payload：handle_id、used_scope、result、
        #                  scope_within_approval、response_digest
        # 泄露调查
        "incident.opened",  # payload：incident_id、suspected_refs、scope_note、freeze
        "materialization.frozen",  # payload：scope=tenant/global
        "materialization.unfrozen",
        "incident.closed",  # payload：incident_id
    }
)
