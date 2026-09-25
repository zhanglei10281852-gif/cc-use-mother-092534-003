"""凭据物化与销毁协调器。

对外只导出协调器、受控句柄与异常类型。任何凭据明文只会出现在
:class:`~coordinator.handles.LeaseHandle` 实例内部，不会进入事件、
持久化记录或日志。
"""
from __future__ import annotations

from .coordinator import CredentialCoordinator
from .errors import (
    AuthorizationError,
    CoordinatorError,
    DestructionPendingError,
    FrozenMaterializationError,
    HandleError,
    LeaseInvalidError,
    QuotaExceededError,
    ScopeExceededError,
    VersionRetiredError,
)
from .handles import LeaseHandle
from .models import (
    Authorization,
    CredentialVersionRecord,
    CredentialVersionState,
    DestructionProof,
    Incident,
    IncidentState,
    LeaseRelationship,
    LeaseState,
    Scope,
    TaskContext,
    UsageReceipt,
    UsageVerdict,
)
from .store import LeaseStore
from .time import Clock

__all__ = [
    "CredentialCoordinator",
    "LeaseStore",
    "LeaseHandle",
    "LeaseRelationship",
    "UsageVerdict",
    "UsageReceipt",
    "Scope",
    "TaskContext",
    "Authorization",
    "CredentialVersionRecord",
    "DestructionProof",
    "Incident",
    "LeaseState",
    "LeaseRelationship",
    "CredentialVersionState",
    "IncidentState",
    "Clock",
    "CoordinatorError",
    "AuthorizationError",
    "QuotaExceededError",
    "LeaseInvalidError",
    "VersionRetiredError",
    "DestructionPendingError",
    "FrozenMaterializationError",
    "ScopeExceededError",
    "HandleError",
]
