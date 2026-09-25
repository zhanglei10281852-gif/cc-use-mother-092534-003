# 凭据物化与销毁协调器

企业连接器访问令牌的申请、短期物化、轮换、租约核销、泄露处置与调用核验。
连接器只能凭**经过授权的任务上下文**申请短期凭据；系统按租户、连接器、
用途和能力范围签出租约；明文只允许出现在**受控句柄**中，不得进入持久化
任务参数、诊断包、审计事件或日志。

## 安全不变量

1. **授权绑定**：凭据只能凭已授权任务上下文领取，用途与能力范围不得超出授权。
2. **明文隔离**：明文只在 `LeaseHandle.materialize(...)` 的 `with` 块内可取；
   句柄不可复制、不可序列化；事件与存储只保存 SHA-256 指纹。
3. **并发额度**：租户有效租约原子计数，同一任务并发申请不能突破租户额度；
   租约到期或终止立即释放额度。
4. **连续状态**：`issued → active → renewing → destroying → destroyed`，
   以及 `revoked / expired / frozen`，终态不可逆。
5. **版本轮换**：旧版本进入宽限期仍可用，宽限结束强制 `retired` 并使关联句柄立即失效。
6. **销毁可证**：核销进入 `destroying`，连接器提交销毁证明后才是 `destroyed`，证明可追踪。
7. **失败重放**：只能恢复**仍有效的租约关系**（无明文），重建句柄被显式拒绝。
8. **泄露处置**：安全人员可圈定受影响句柄、冻结新的物化、追踪销毁证明。
9. **调用核验**：每次连接调用实时校验实际范围不超过原批准，并保存回执，
   可通过接口验证任意一次调用。

## 目录

- `coordinator/`：协调器实现（仅依赖 Python 标准库，3.11+）。
  - `models.py`：实体、状态机与值对象（全部不含明文字段）。
  - `handles.py`：受控句柄，明文唯一允许存在的进程内边界。
  - `coordinator.py`：领取、续期、核销、轮换、吊销、调查、重放、调用核验。
  - `events.py` / `store.py`：只追加的审计事件与无明文存储。
  - `crypto.py` / `time.py`：一次性明文与指纹、可注入时钟。
- `domain/contract.json`：实体、状态、事件类型与业务规则。
- `domain/policies.json`：可被程序读取的策略。
- `examples/events.json`：完整生命周期事件样例。
- `examples/walkthrough.py`：可运行的端到端演练。
- `tools/validate_contract.py`：领域资料一致性离线校验。
- `tests/`：领域资料校验与协调器全链路测试（32 项）。

## 快速使用

```python
from coordinator import CredentialCoordinator, Scope, TaskContext

coord = CredentialCoordinator()
coord.register_connector("conn-github")
coord.set_tenant_quota("tenant-a", max_active_leases=2)
coord.authorize_task(
    TaskContext("tenant-a", "task-1", "conn-github", "sync-repo",
                Scope.of("repo:read")),
    max_ttl_seconds=300,
)

handle = coord.claim("tenant-a", "task-1", "conn-github", "sync-repo",
                     Scope.of("repo:read"), ttl_seconds=300)
with handle.materialize(Scope.of("repo:read")) as secret:
    ...  # 明文只在这个块内可用，离开即释放

coord.verify_call(handle.lease_id)          # 安全接口：核验最近一次调用范围
lease_id = coord.surrender(handle)          # 核销 -> destroying
coord.confirm_destruction(lease_id, proof_hash="sha256:...",
                          reported_by="conn-github")  # -> destroyed
```

疑似泄露时：

```python
incident = coord.open_incident(
    "tenant-a", opened_by="security-01",
    reason="令牌出现在外发诊断包", connector_id="conn-github")
coord.affected_handles(incident.incident_id)   # 圈定受影响句柄（只有关系）
coord.destruction_trail(incident.incident_id)  # 追踪销毁证明
coord.close_incident(incident.incident_id, actor_id="security-01")
```

任务失败重放时：

```python
rels = coord.replay_task("tenant-a", "task-1")  # 只有仍有效的租约关系
coord.restore_handle(rels[0])                   # LeaseInvalidError：禁止重新暴露明文
```

## 构建、测试与演练

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
python3 tools/validate_contract.py
python3 examples/walkthrough.py
```

所有命令都在项目根目录执行，不需要数据库、缓存或其他外部服务。
