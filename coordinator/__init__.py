"""凭据物化协调器。

对外主要入口：

- :class:`coordinator.service.CredentialCoordinator`：协调器应用服务；
- :class:`coordinator.handle.ControlledHandle`：受控凭据句柄；
- :class:`coordinator.storage.EventStore`：事件存储（SQLite）。
"""
from __future__ import annotations

from coordinator.service import CredentialCoordinator
from coordinator.handle import ControlledHandle, SecretRedactor
from coordinator.errors import (
    CoordinatorError,
    AuthorizationError,
    QuotaExceededError,
    LeaseStateError,
    GracePeriodClosedError,
    FreezeError,
    ScopeExceededError,
    ReplayError,
)

__all__ = [
    "CredentialCoordinator",
    "ControlledHandle",
    "SecretRedactor",
    "CoordinatorError",
    "AuthorizationError",
    "QuotaExceededError",
    "LeaseStateError",
    "GracePeriodClosedError",
    "FreezeError",
    "ScopeExceededError",
    "ReplayError",
]
