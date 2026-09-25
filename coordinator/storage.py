"""持久化边界。

- :class:`EventStore`：SQLite 事件存储。只保存领域事件，事件载荷中**没有明文密钥**，
  凭据以不透明 ``secret_ref`` 关联；采用 ``(aggregate_id, sequence)`` 乐观并发，
  写事务以 ``BEGIN IMMEDIATE`` 串行化，保证租户额度检查与签发原子完成。
- :class:`SecretRegistry`：进程内存秘密注册表，是系统中唯一允许持有明文的位置。
  生产部署中这里应由 KMS / 机密计算飞地支撑；明文使用可变字节保存以便核销时
  就地清零，注册表本身不出现在任何日志或持久化文件中。
"""
from __future__ import annotations

import contextlib
import json
import secrets
import sqlite3
import threading
from collections.abc import Iterator
from datetime import datetime

from coordinator.events import DomainEvent, EVENT_TYPES


class ConcurrencyError(RuntimeError):
    """事件流被并发写入修改（乐观并发失败）。"""


class EventStore:
    def __init__(self, database: str = ":memory:") -> None:
        self._database = database
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(database, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._create_schema()

    def _create_schema(self) -> None:
        with self._connection:
            self._connection.execute(
                """
                create table if not exists event_log (
                    event_id text primary key,
                    event_type text not null,
                    aggregate_id text not null,
                    tenant_id text not null,
                    occurred_at text not null,
                    sequence integer not null,
                    payload text not null,
                    causation_id text,
                    unique (aggregate_id, sequence)
                )
                """
            )
            self._connection.execute(
                "create index if not exists idx_event_tenant on event_log(tenant_id, occurred_at)"
            )

    @contextlib.contextmanager
    def write_transaction(self) -> Iterator[sqlite3.Connection]:
        """串行化的写事务；额度检查与事件追加必须在同一事务内完成。"""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def append(self, connection: sqlite3.Connection, events: list[DomainEvent]) -> None:
        for event in events:
            if event.event_type not in EVENT_TYPES:
                raise ValueError(f"未知事件类型：{event.event_type}")
            datetime.fromisoformat(event.occurred_at)
            try:
                connection.execute(
                    "insert into event_log values (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event.event_id,
                        event.event_type,
                        event.aggregate_id,
                        event.tenant_id,
                        event.occurred_at,
                        event.sequence,
                        json.dumps(event.payload, ensure_ascii=False, sort_keys=True),
                        event.causation_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:  # 重放/并发冲突
                raise ConcurrencyError(str(exc)) from exc

    def _load(self, where: str, params: tuple, *, order: str = "aggregate_id, sequence") -> list[DomainEvent]:
        rows = self._connection.execute(
            f"select * from event_log {where} order by {order}",
            params,
        ).fetchall()
        result: list[DomainEvent] = []
        for row in rows:
            result.append(
                DomainEvent(
                    event_id=row["event_id"],
                    event_type=row["event_type"],
                    aggregate_id=row["aggregate_id"],
                    tenant_id=row["tenant_id"],
                    occurred_at=row["occurred_at"],
                    sequence=row["sequence"],
                    payload=json.loads(row["payload"]),
                    causation_id=row["causation_id"],
                )
            )
        return result

    def load_stream(self, aggregate_id: str) -> list[DomainEvent]:
        return self._load("where aggregate_id = ?", (aggregate_id,))

    def load_tenant(self, tenant_id: str) -> list[DomainEvent]:
        return self._load("where tenant_id = ?", (tenant_id,))

    def load_all(self) -> list[DomainEvent]:
        # 全局写入序（rowid）：同一事务内跨聚合事件也保持追加顺序，
        # 状态折叠与销毁哈希链据此获得一致的全序。
        return self._load("", (), order="rowid")

    def load_chain(self) -> list[DomainEvent]:
        return self.load_all()

    def next_identity(self, prefix: str) -> str:
        return f"{prefix}-{secrets.token_hex(8)}"

    def close(self) -> None:
        with self._lock:
            self._connection.close()


class SecretRegistry:
    """进程内存秘密注册表（唯一允许存放明文的边界）。

    明文以可变字节保存，核销时执行内存清零；注册表不提供任何序列化接口，
    防止秘密进入持久化任务参数、诊断包或日志。
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._secrets: dict[str, bytearray] = {}
        self._revoked: set[str] = set()

    def register(self, plaintext: bytes | str) -> str:
        data = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        secret_ref = "ref-" + secrets.token_hex(16)
        with self._lock:
            self._secrets[secret_ref] = bytearray(data)
        return secret_ref

    def reveal(self, secret_ref: str) -> bytes:
        """仅受控句柄在连接调用瞬间可调用；返回的是内部缓冲副本。"""
        with self._lock:
            if secret_ref in self._revoked:
                raise KeyError("秘密已核销")
            try:
                return bytes(self._secrets[secret_ref])
            except KeyError:
                raise

    def revoke(self, secret_ref: str) -> None:
        with self._lock:
            buffer = self._secrets.pop(secret_ref, None)
            self._revoked.add(secret_ref)
        if buffer is not None:
            for index in range(len(buffer)):
                buffer[index] = 0

    def is_live(self, secret_ref: str) -> bool:
        with self._lock:
            return secret_ref in self._secrets

    def __len__(self) -> int:
        with self._lock:
            return len(self._secrets)
