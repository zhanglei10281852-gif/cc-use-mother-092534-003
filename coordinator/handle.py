"""受控句柄。

凭据申请成功后，连接器拿到的不是明文字符串，而是 :class:`ControlledHandle`。
明文只在 :meth:`ControlledHandle.use` 调用瞬间从进程内注册表取出、用后即弃；
句柄：

- 不可序列化（``pickle``/``repr``/字符串化都不暴露明文）；
- 强制范围检查，实际使用范围必须是批准范围的子集，否则抛
  :class:`~coordinator.errors.ScopeExceededError`，且该次越权调用仍会留痕；
- 与租约状态、凭据版本宽限期、调查冻结联动，失效后立即拒绝；
- 显式 :meth:`destroy` 产生销毁证明。
"""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Sequence

from coordinator.errors import (
    GracePeriodClosedError,
    LeaseStateError,
    ScopeExceededError,
)


class SecretRedactor:
    """日志/诊断包过滤器：把疑似凭据的内容替换为 ``[REDACTED]``。"""

    _PATTERNS = ("secret", "token", "password", "credential", "plaintext", "凭据", "明文", "令牌")

    @classmethod
    def redact(cls, mapping: Mapping[str, Any]) -> dict[str, Any]:
        clean: dict[str, Any] = {}
        for key, value in mapping.items():
            lowered = str(key).lower()
            if any(pattern in lowered for pattern in cls._PATTERNS):
                clean[key] = "[REDACTED]"
            elif isinstance(value, Mapping):
                clean[key] = cls.redact(value)
            elif isinstance(value, (list, tuple)):
                clean[key] = [
                    cls.redact(item) if isinstance(item, Mapping) else "[REDACTED]" if cls._looks_like_secret(item) else item
                    for item in value
                ]
            else:
                clean[key] = "[REDACTED]" if cls._looks_like_secret(value) else value
        return clean

    @staticmethod
    def _looks_like_secret(value: Any) -> bool:
        # 句柄本身、字节串一律不进入日志
        return isinstance(value, (ControlledHandle, bytes, bytearray))


@dataclass(frozen=True)
class UsageResult:
    ok: bool
    used_scope: frozenset[str]
    at: datetime
    response_digest: str | None = None


@dataclass
class HandleSnapshot:
    """句柄的非敏感视图，可安全进入审计载荷。"""

    handle_id: str
    lease_id: str
    tenant_id: str
    connector_id: str
    purpose: str
    approved_scope: frozenset[str]
    credential_version: str
    expires_at: datetime
    state: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "handle_id": self.handle_id,
            "lease_id": self.lease_id,
            "tenant_id": self.tenant_id,
            "connector_id": self.connector_id,
            "purpose": self.purpose,
            "approved_scope": sorted(self.approved_scope),
            "credential_version": self.credential_version,
            "expires_at": self.expires_at.isoformat(),
            "state": self.state,
        }


class _HandleState(enum.Enum):
    LIVE = "live"
    DESTROYED = "destroyed"
    # 服务端使句柄失效（租约过期 / 宽限结束 / 被吊销），明文已在注册表清零
    INVALIDATED = "invalidated"


class ControlledHandle:
    """连接器在任务执行期间持有的唯一凭据载体。"""

    def __init__(
        self,
        *,
        handle_id: str,
        lease_id: str,
        tenant_id: str,
        connector_id: str,
        purpose: str,
        approved_scope: Sequence[str],
        capabilities: Sequence[str],
        credential_version: str,
        expires_at: datetime,
        secret_ref: str,
        secret_provider: Callable[[str], bytes],
        usage_recorder: Callable[["ControlledHandle", frozenset[str], datetime, bool, str | None], None],
        state_provider: Callable[[str, str], tuple[str, str | None, datetime | None]],
        clock: Callable[[], datetime],
    ) -> None:
        self._handle_id = handle_id
        self._lease_id = lease_id
        self._tenant_id = tenant_id
        self._connector_id = connector_id
        self._purpose = purpose
        self._approved_scope = frozenset(approved_scope)
        self._capabilities = frozenset(capabilities)
        self._credential_version = credential_version
        self._expires_at = expires_at
        self._secret_ref = secret_ref
        self._secret_provider = secret_provider
        self._usage_recorder = usage_recorder
        self._state_provider = state_provider
        self._clock = clock
        self._state = _HandleState.LIVE
        self._last_used_scope: frozenset[str] | None = None

    def bind_renewal(self, *, expires_at: datetime, secret_ref: str, credential_version: str) -> None:
        """续期生效后把句柄指向新的到期时间与凭据版本（明文仍只在注册表中）。"""
        self._expires_at = expires_at
        self._secret_ref = secret_ref
        self._credential_version = credential_version

    # ---- 防泄漏基础 ----

    def __repr__(self) -> str:
        return (
            f"ControlledHandle(handle_id={self._handle_id!r}, lease_id={self._lease_id!r}, "
            f"state={self._state.value!r})"
        )

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("受控句柄不可序列化，禁止跨进程或落盘传递")

    def __getstate__(self):
        raise TypeError("受控句柄不可序列化，禁止跨进程或落盘传递")

    @property
    def secret_ref(self) -> str:
        return self._secret_ref

    @property
    def handle_id(self) -> str:
        return self._handle_id

    @property
    def lease_id(self) -> str:
        return self._lease_id

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def connector_id(self) -> str:
        return self._connector_id

    @property
    def purpose(self) -> str:
        return self._purpose

    @property
    def approved_scope(self) -> frozenset[str]:
        return self._approved_scope

    @property
    def credential_version(self) -> str:
        return self._credential_version

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    @property
    def is_destroyed(self) -> bool:
        return self._state is not _HandleState.LIVE

    def snapshot(self) -> HandleSnapshot:
        lease_state, _, _ = self._state_provider(self._lease_id, self._credential_version)
        if self._state is _HandleState.LIVE:
            shown = lease_state
        elif self._state is _HandleState.DESTROYED:
            shown = "destroyed"
        else:
            shown = lease_state if lease_state in {"expired", "revoked", "version_retired"} else "invalidated"
        return HandleSnapshot(
            handle_id=self._handle_id,
            lease_id=self._lease_id,
            tenant_id=self._tenant_id,
            connector_id=self._connector_id,
            purpose=self._purpose,
            approved_scope=self._approved_scope,
            credential_version=self._credential_version,
            expires_at=self._expires_at,
            state=shown,
        )

    def mark_destroyed(self) -> None:
        """显式核销（销毁证明已出具）。"""
        self._state = _HandleState.DESTROYED

    def invalidate(self) -> None:
        """服务端使其失效（过期 / 宽限结束 / 吊销）；具体原因经租约状态判定。"""
        if self._state is _HandleState.LIVE:
            self._state = _HandleState.INVALIDATED

    def _guard(self) -> None:
        if self._state is _HandleState.DESTROYED:
            raise LeaseStateError("句柄已核销，明文不再可用")
        now = self._clock()
        lease_state, _, grace_ends_at = self._state_provider(self._lease_id, self._credential_version)
        if lease_state == "version_retired":
            raise GracePeriodClosedError("凭据版本宽限期已结束，旧版本必须失效")
        if lease_state == "revoked":
            raise LeaseStateError("租约已吊销，句柄拒绝使用")
        if lease_state == "expired" or now >= self._expires_at:
            raise LeaseStateError("租约已过期，句柄拒绝使用")
        if grace_ends_at is not None and now >= grace_ends_at:
            raise GracePeriodClosedError("凭据版本宽限期已结束，旧版本必须失效")
        if self._state is _HandleState.INVALIDATED:
            raise LeaseStateError("句柄已被服务端失效，明文不再可用")

    def use(self, used_scope: Sequence[str] | None = None, *, call: Callable[[bytes], Any] | None = None) -> Any:
        """在受控边界内使用凭据完成一次连接调用。

        - ``used_scope``：本次调用实际触达的范围，必须是批准范围子集；
        - ``call``：接收明文字节的实际连接函数，明文不经过任何中间变量落盘。
        """
        requested = frozenset(used_scope) if used_scope else self._approved_scope
        now = self._clock()
        within = requested <= self._approved_scope
        if not within:
            exceeded = sorted(requested - self._approved_scope)
            # 越权尝试也要留痕，但绝不取出明文
            self._usage_recorder(self, requested, now, False, None)
            raise ScopeExceededError(f"使用范围超出原批准：{', '.join(exceeded)}")
        try:
            self._guard()
        except Exception:
            # 状态拒绝（过期/吊销/宽限结束/已核销）同样留痕，供审计追踪
            self._usage_recorder(self, requested, now, False, None)
            raise
        plaintext = self._secret_provider(self._secret_ref)
        self._last_used_scope = requested
        try:
            response = call(plaintext) if call is not None else None
        finally:
            # 用后即弃：清除本次调用栈内明文引用（CPython 引用计数下立即释放）
            del plaintext
        digest = None
        if response is not None:
            digest = hashlib.sha256(repr(response).encode("utf-8")).hexdigest()
        self._usage_recorder(self, requested, now, True, digest)
        return response
