"""端到端演练：凭据物化协调器的完整生命周期。

运行：python3 examples/walkthrough.py
脚本只打印状态与指纹，绝不打印凭据明文。
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from coordinator import (  # noqa: E402
    CredentialCoordinator,
    Scope,
    TaskContext,
    VersionRetiredError,
)
from coordinator.errors import FrozenMaterializationError, LeaseInvalidError  # noqa: E402
from coordinator.time import Clock  # noqa: E402


def main() -> None:
    clock = Clock(datetime(2026, 9, 25, 9, 0, tzinfo=timezone.utc))
    coord = CredentialCoordinator(clock=clock)

    # 1) 登记连接器、租户额度、授权任务上下文
    coord.register_connector("conn-github", "GitHub 企业连接器")
    coord.set_tenant_quota("tenant-a", max_active_leases=2)
    coord.authorize_task(
        TaskContext(
            tenant_id="tenant-a",
            task_id="task-sync",
            connector_id="conn-github",
            purpose="sync-repo",
            authorized_scope=Scope.of("repo:read", "issue:write"),
        ),
        max_ttl_seconds=600,
    )

    # 2) 领取短期凭据：明文只在 with 块内出现
    handle = coord.claim(
        "tenant-a", "task-sync", "conn-github", "sync-repo",
        Scope.of("repo:read"), ttl_seconds=300,
    )
    print(f"[领取] lease={handle.lease_id} version={handle.credential_version} "
          f"scope={handle.approved_scope.as_sorted()}")
    with handle.materialize(Scope.of("repo:read")):
        print("[调用] 在批准范围内完成一次连接调用（明文未离开 with 块）")
    print(f"[核验] 最近一次调用: {coord.verify_call(handle.lease_id)}")

    # 3) 轮换：旧版本进入宽限期，结束后强制退役
    coord.rotate("tenant-a", "conn-github", grace_seconds=120)
    print("[轮换] 新版本已发布，旧版本进入 120 秒宽限期")
    clock.advance(seconds=121)
    retired = coord.expire_grace_versions()
    print(f"[退役] 已退役版本: {retired}")
    try:
        with handle.materialize(Scope.of("repo:read")):
            pass
    except VersionRetiredError:
        print("[拒绝] 宽限期结束，旧版本调用被拒绝且句柄已失效")

    # 4) 重新领取新版本凭据并紧急核销/销毁
    handle = coord.claim(
        "tenant-a", "task-sync", "conn-github", "sync-repo",
        Scope.of("repo:read"), ttl_seconds=300,
    )
    lease_id = coord.surrender(handle)
    proof = coord.confirm_destruction(lease_id, "sha256:burn-log", reported_by="conn-github")
    print(f"[销毁] 租约 {lease_id} 销毁证明 {proof.proof_id} 已确认")

    # 5) 疑似泄露：圈定句柄、冻结新物化
    handle = coord.claim(
        "tenant-a", "task-sync", "conn-github", "sync-repo",
        Scope.of("repo:read"), ttl_seconds=300,
    )
    incident = coord.open_incident(
        "tenant-a", opened_by="security-01",
        reason="访问令牌出现在外发诊断包", connector_id="conn-github",
    )
    print(f"[调查] {incident.incident_id} 圈定 {len(incident.affected_lease_ids)} 个句柄，"
          f"冻结新物化")
    try:
        coord.claim(
            "tenant-a", "task-sync", "conn-github", "sync-repo",
            Scope.of("repo:read"), ttl_seconds=300,
        )
    except FrozenMaterializationError:
        print("[冻结] 调查期间新的凭据物化被拒绝")
    coord.emergency_revoke(lease_id=handle.lease_id, reason="泄露处置", actor_id="security-01")
    coord.confirm_destruction(handle.lease_id, "sha256:revoked-burn", reported_by="conn-github")
    trail = coord.destruction_trail(incident.incident_id)
    print(f"[追踪] 受影响租约已完成销毁证明 {len(trail)} 份")

    # 6) 调查结束，恢复正常，重新领取用于后续任务
    coord.close_incident(incident.incident_id, actor_id="security-01")
    print("[解除] 调查结束，物化冻结解除")
    coord.claim(
        "tenant-a", "task-sync", "conn-github", "sync-repo",
        Scope.of("repo:read"), ttl_seconds=300,
    )

    # 7) 失败重放：只恢复租约关系，不能重新暴露明文
    relationships = coord.replay_task("tenant-a", "task-sync")
    print(f"[重放] 可恢复的有效租约关系 {len(relationships)} 个（不含明文）")
    try:
        coord.restore_handle(relationships[0])
    except LeaseInvalidError as exc:
        print(f"[重放] 重建句柄被拒绝: {exc}")


if __name__ == "__main__":
    main()
