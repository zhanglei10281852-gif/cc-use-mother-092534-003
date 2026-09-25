"""凭据物化协调器完整生命周期走查（可运行）。

运行：python3 examples/walkthrough.py

演示：授权任务上下文 → 凭证物化 → 受控使用/越权拦截 → 额度 →
轮换与宽限 → 续期 → 过期 → 销毁证明 → 任务重放 → 泄露调查/冻结/范围核验。
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from coordinator import CredentialCoordinator, ScopeExceededError
from coordinator.clock import FixedClock
from coordinator.errors import FreezeError, QuotaExceededError


def main() -> None:
    clock = FixedClock(datetime(2026, 9, 25, 2, 0, tzinfo=timezone.utc))
    coordinator = CredentialCoordinator(clock=clock, default_quota=2)

    # 1) 登记连接器凭据与能力；明文只进入进程内注册表
    coordinator.register_connector_credential(
        "conn-gitlab",
        "v2026.09.01",
        "glpat-EXAMPLE-MASTER-SECRET",
        capabilities=["read:repo", "write:repo", "read:ci"],
    )

    # 2) 登记经授权的任务上下文（租户/连接器/用途/批准范围）
    coordinator.authorize_task(
        task_id="task-nightly-0001",
        tenant_id="tenant-zhihuishu",
        connector_id="conn-gitlab",
        purpose="nightly-repo-sync",
        approved_scope=["read:repo", "read:ci"],
        capabilities=["connector.run"],
    )

    # 3) 连接器领取短期凭据，拿到的是受控句柄而非明文
    handle = coordinator.request_materialization(task_id="task-nightly-0001", ttl_seconds=900)
    print("领取句柄:", handle.handle_id, "范围:", sorted(handle.approved_scope))

    # 4) 在受控边界内使用
    def downstream_call(secret: bytes) -> dict:
        # 真实场景：用 secret 向连接器发起一次 API 调用
        return {"status": 200, "used": secret.decode()[:8] + "..."}

    response = handle.use(["read:repo"], call=downstream_call)
    print("连接调用:", response)

    # 5) 越范围调用被拒绝并留痕，明文绝不被取出
    try:
        handle.use(["write:repo"])
    except ScopeExceededError as exc:
        print("越权拦截:", exc)

    # 6) 租户并发额度
    coordinator.request_materialization(task_id="task-nightly-0001", ttl_seconds=900)
    try:
        coordinator.request_materialization(task_id="task-nightly-0001", ttl_seconds=900)
    except QuotaExceededError as exc:
        print("额度拦截:", exc)

    # 7) 轮换：新版本生效，旧版本进入宽限期
    coordinator.rotate_credential(
        "conn-gitlab", "v2026.09.02", "glpat-NEW-MASTER-SECRET", grace_seconds=3600
    )
    # 宽限期内旧句柄仍可用
    print("宽限期内旧版本:", handle.use(["read:repo"], call=lambda s: "accepted"))
    # 续期把同一条租约切到新版本
    coordinator.renew(handle, ttl_seconds=7200)
    print("续期后版本:", handle.credential_version)

    # 8) 宽限结束：旧版本句柄全部失效
    clock.advance(3601)
    coordinator.sweep()

    # 9) 销毁证明（哈希链，可离线重算验证）
    proof = coordinator.destroy(handle)
    print("销毁证明:", proof.proof[:16], "原因:", proof.reason)

    # 10) 任务重放：只恢复仍有效的租约关系
    fresh = coordinator.request_materialization(task_id="task-nightly-0001", ttl_seconds=1800)
    restored = coordinator.replay_task("task-nightly-0001")
    print("重放恢复:", [item.handle_id for item in restored])

    # 11) 安全调查：圈定句柄、冻结新物化、追踪销毁证明
    incident_id = coordinator.open_incident(
        tenant_id="tenant-zhihuishu",
        suspected_refs=[fresh.secret_ref],
        scope_note="诊断包疑似被批量带走",
    )
    print("受影响句柄:", [item.handle_id for item in coordinator.affected_handles(incident_id)])
    try:
        coordinator.request_materialization(task_id="task-nightly-0001")
    except FreezeError as exc:
        print("冻结拦截:", exc)
    coordinator.destroy(fresh)
    print("销毁追踪:", len(coordinator.destruction_tracking(incident_id)), "份证明")
    coordinator.close_incident(incident_id)

    # 12) 范围核验：每次连接调用实际范围 vs 原批准
    receipts = coordinator.verify_usage(handle.lease_id)
    print(json.dumps(receipts, ensure_ascii=False, indent=2))

    # 13) 校验销毁哈希链完整
    chain = coordinator.verify_destruction_chain()
    assert all(item["valid"] for item in chain)
    print("销毁链证明数:", len(chain), "全部有效")

    # 14) 事件流中不存在任何明文
    blob = json.dumps([e.to_dict() for e in coordinator.store.load_all()], ensure_ascii=False)
    assert "glpat-" not in blob
    print("事件流无明文：OK")


if __name__ == "__main__":
    main()
