"""受控句柄：凭据明文在进程内唯一允许存在的边界。

安全约定：

* 明文只在 :meth:`LeaseHandle.materialize` 的 ``with`` 块内可取，
  退出块即视为本次使用结束；句柄关闭后引用被清空。
* 句柄不可复制、不可序列化（``pickle``/``copy`` 直接抛错），
  因此无法被偷偷塞进任务参数、消息队列或诊断包。
* 每次取用都经过协调器回调实时校验租约状态、凭据版本、
  调查冻结与能力范围，越权调用不会返回明文并留下拒绝回执。

说明：CPython 的 ``str`` 不可变、无法覆写清零，框架能强制的是
"明文不落盘、不序列化、不进日志/事件，且句柄确定性关闭"，
连接器代码也必须遵守"明文不离开 ``with`` 块"的契约。
"""
from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Iterator, Optional, Protocol, runtime_checkable

from .errors import HandleError, LeaseInvalidError, ScopeExceededError
from .models import Scope, UsageReceipt


@runtime_checkable
class HandlePolicy(Protocol):
    """协调器实现的实时策略校验接口。"""

    def authorize_use(self, handle: "LeaseHandle", used_scope: Scope) -> UsageReceipt:
        """校验通过返回回执；失败抛出对应领域异常，不得返回明文。"""
        ...

    def invalidate_handle(self, handle: "LeaseHandle") -> None:
        ...


class _MaterialAccess:
    """``materialize()`` 的上下文对象，``with`` 外不暴露明文。"""

    __slots__ = ("_handle", "_scope", "_secret")

    def __init__(self, handle: "LeaseHandle", used_scope: Scope, secret: str) -> None:
        self._handle = handle
        self._scope = used_scope
        self._secret = secret

    def __enter__(self) -> str:
        return self._secret

    def __exit__(self, exc_type, exc, tb) -> None:
        # 明文引用随上下文对象释放；句柄本身仍受租约时间约束。
        self._secret = None
        self._handle._note_use_finished()

    def __repr__(self) -> str:
        return "<MaterialAccess redacted>"


class LeaseHandle:
    """绑定到具体租约的受控句柄，严禁复制与持久化。"""

    __slots__ = (
        "handle_id",
        "lease_id",
        "tenant_id",
        "task_id",
        "connector_id",
        "purpose",
        "credential_id",
        "credential_version",
        "approved_scope",
        "issued_at",
        "expires_at",
        "fingerprint",
        "_secret",
        "_policy",
        "_closed",
        "_active_uses",
        "__weakref__",
    )

    def __init__(
        self,
        *,
        handle_id: str,
        lease_id: str,
        tenant_id: str,
        task_id: str,
        connector_id: str,
        purpose: str,
        credential_id: str,
        credential_version: int,
        approved_scope: Scope,
        issued_at: datetime,
        expires_at: datetime,
        secret: str,
        fingerprint: str,
        policy: HandlePolicy,
    ) -> None:
        if issued_at.tzinfo is None or expires_at.tzinfo is None:
            raise ValueError("句柄时间必须带时区")
        if expires_at <= issued_at:
            raise ValueError("租约到期时间必须晚于签发时间")
        self.handle_id = handle_id
        self.lease_id = lease_id
        self.tenant_id = tenant_id
        self.task_id = task_id
        self.connector_id = connector_id
        self.purpose = purpose
        self.credential_id = credential_id
        self.credential_version = credential_version
        self.approved_scope = approved_scope
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.fingerprint = fingerprint
        self._secret: Optional[str] = secret
        self._policy = policy
        self._closed = False
        self._active_uses = 0

    # --- 受控取用 -------------------------------------------------

    @contextlib.contextmanager
    def materialize(self, used_scope: Scope) -> Iterator[str]:
        """在批准范围内取一次明文；越界、失效或冻结都会被拒绝。"""
        if not isinstance(used_scope, Scope):
            raise TypeError("used_scope 必须是 Scope")
        # 先让协调器实时判定：即使句柄已被失效，也要给出精确原因
        # （版本退役 / 吊销 / 冻结 / 过期 / 越界），而不是笼统的"已关闭"。
        receipt = self._policy.authorize_use(self, used_scope)
        if self._closed or self._secret is None:
            raise LeaseInvalidError("句柄已关闭或租约已终止")
        if not receipt.within_scope:
            raise ScopeExceededError(
                f"申请能力 {used_scope.as_sorted()} 超出批准范围 "
                f"{self.approved_scope.as_sorted()}"
            )
        self._active_uses += 1
        access = _MaterialAccess(self, used_scope, self._secret)
        try:
            with access as material:
                yield material
        finally:
            self._active_uses = max(0, self._active_uses - 1)

    def _note_use_finished(self) -> None:
        pass

    # --- 生命周期 -------------------------------------------------

    def renew_until(self, new_expires_at: datetime) -> None:
        if self._closed:
            raise LeaseInvalidError("句柄已关闭，不能续期")
        if new_expires_at.tzinfo is None:
            raise ValueError("时间必须带时区")
        if new_expires_at <= self.expires_at:
            raise ValueError("续期只能延后到期时间")
        self.expires_at = new_expires_at

    def invalidate(self) -> None:
        """由协调器在吊销、过期、版本退役时紧急清空明文引用。"""
        self._secret = None
        self._closed = True
        with contextlib.suppress(Exception):
            self._policy.invalidate_handle(self)

    def close(self) -> None:
        """连接器正常核销句柄。"""
        if self._active_uses:
            raise HandleError("句柄仍在使用中，不能关闭")
        self._secret = None
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def identity(self) -> str:
        return f"{self.tenant_id}:{self.task_id}:{self.connector_id}:{self.lease_id}"

    # --- 防扩散 ---------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"LeaseHandle(handle_id={self.handle_id!r}, lease_id={self.lease_id!r}, "
            f"connector={self.connector_id!r}, purpose={self.purpose!r}, "
            f"version={self.credential_version}, closed={self._closed}, "
            f"scope={self.approved_scope.as_sorted()})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def __copy__(self):
        raise HandleError("受控句柄不允许复制")

    def __deepcopy__(self, memo):
        raise HandleError("受控句柄不允许复制")

    def __reduce__(self):
        raise HandleError("受控句柄不允许序列化")

    def __reduce_ex__(self, protocol):
        raise HandleError("受控句柄不允许序列化")

    def __getstate__(self):
        raise HandleError("受控句柄不允许序列化")

    def __getattr__(self, name: str) -> None:
        # slots 之外的可疑属性（如 pickle 探测）统一拒绝，避免明文被兜底取出。
        if name.startswith("__"):
            raise AttributeError(name)
        raise AttributeError(name)
