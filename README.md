# 凭据物化与销毁协调器

企业连接器的访问令牌不得为了任务重试而写入普通配置或诊断包。本协调器让连接器
**只能凭经过授权的任务上下文申请短期凭据**，系统按租户、连接器、用途和能力范围
签出租约，凭据返回值只允许在受控句柄中使用，并对领取、续期、核销、轮换、紧急
吊销、任务重放与泄露调查提供连续、可审计的状态语义。

## 设计要点

- **事件溯源**：所有状态由不可变事件重放得到（`coordinator/events.py`、
  `coordinator/projection.py`），存储为 SQLite 追加事件流（`coordinator/storage.py`）。
- **明文边界**：明文只存在于进程内 `SecretRegistry`（生产可替换为 KMS / 机密飞地）；
  事件流、任务参数、诊断包、日志中只有不透明 `secret_ref`。对外只发放
  `ControlledHandle`：不可序列化、`repr` 不泄密、明文仅在 `use()` 调用瞬间取出。
- **租约级物化副本**：签发时从连接器主凭据物化一份独立缓冲副本绑定该租约；
  核销单条租约只清零该副本，不影响其他租约；紧急吊销连接器才连主凭据一起吊销。
- **租户并发额度**：额度检查与签发在同一个 `BEGIN IMMEDIATE` 串行化事务内，
  并发申请无法突破租户额度。
- **轮换与宽限**：轮换产生新版本，旧版本仅在宽限期内可用；`sweep()` 到期后将
  旧版本退役、终止仍绑定旧版本的租约并拒绝一切旧版本使用。
- **连续生命周期**：`requested → issued → active →（renewed×N）→ expired/revoked
  → destroyed`，跨版本续期不改变租约标识，只切换绑定的凭据版本。
- **任务失败重放**：`replay_task` 只恢复仍有效的租约关系；注册表中已不存在的
  明文绝不重新签发或暴露。
- **销毁即留证**：任何明文清零路径（手动核销、吊销、紧急吊销、过期、续期切换、
  宽限退役）都追加哈希链 `destruction.confirmed` 证明，可离线重算、防篡改。
- **泄露调查**：安全人员可圈定受影响句柄、按租户/全局冻结新物化、追踪销毁证明；
  `verify_usage` 逐次给出“实际使用范围 ⊆ 原批准范围”的核验结果，越权调用
  即使被拦截也会留痕。
- **日志脱敏**：`SecretRedactor` 用于诊断包/日志，过滤令牌字段与句柄对象。

## 目录

- `coordinator/`：协调器实现
  - `service.py`：应用服务（授权、物化、续期、吊销、轮换、清扫、重放、调查、核验）
  - `handle.py`：受控句柄、范围校验、日志脱敏
  - `events.py` / `projection.py`：领域事件与读模型
  - `storage.py`：SQLite 事件存储与进程内秘密注册表
  - `errors.py` / `clock.py`：错误类型与可替换时间源
- `domain/contract.json`：实体、状态、事件类型与业务规则
- `domain/policies.json`：可机读策略（授权绑定、明文边界、额度、宽限、重放等）
- `examples/events.json`：按时间排序的事件样例
- `examples/walkthrough.py`：完整生命周期可运行走查
- `tools/validate_contract.py`：领域资料一致性校验

## 快速开始

```bash
# 编译检查
python3 -m compileall -q .

# 测试
python3 -m unittest discover -s tests -v

# 资料校验
python3 tools/validate_contract.py

# 生命周期走查
python3 examples/walkthrough.py
```

所有命令均使用 Python 标准库，无需启动外部数据库或缓存。

## 最小用法

```python
from coordinator import CredentialCoordinator

coordinator = CredentialCoordinator(default_quota=5)

# 登记连接器凭据与能力（明文只入进程内注册表）
coordinator.register_connector_credential(
    "conn-gitlab", "v1", "glpat-...",
    capabilities=["read:repo", "write:repo"],
)

# 登记经授权的任务上下文
coordinator.authorize_task(
    task_id="task-1", tenant_id="tenant-a", connector_id="conn-gitlab",
    purpose="nightly-sync", approved_scope=["read:repo"],
)

# 领取：只拿到受控句柄
handle = coordinator.request_materialization(task_id="task-1", ttl_seconds=900)

# 使用：范围必须是批准范围子集，明文不离开 use()
handle.use(["read:repo"], call=lambda secret: downstream_api(secret))

# 核销：出具哈希链销毁证明并就地清零明文
coordinator.destroy(handle)
```

## 安全操作

```python
# 紧急吊销整个连接器（全部有效租约 + 主凭据，均留销毁证明）
coordinator.emergency_revoke_connector("conn-gitlab", reason="suspected leak")

# 发起泄露调查：圈定句柄 + 冻结新物化
incident_id = coordinator.open_incident(
    tenant_id="tenant-a", suspected_refs=[handle.secret_ref],
    scope_note="诊断包疑似外泄", scope="tenant",   # scope="global" 为全局冻结
)
coordinator.affected_handles(incident_id)           # 圈定受影响句柄（无明文）
coordinator.destruction_tracking(incident_id)       # 追踪销毁证明
coordinator.verify_destruction_chain()              # 离线重算哈希链
coordinator.verify_usage(lease_id)                  # 逐次核验调用范围
coordinator.close_incident(incident_id)             # 无其他覆盖调查时才解冻
```
