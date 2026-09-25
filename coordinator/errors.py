"""协调器错误类型。所有错误消息都只包含非敏感标识，绝不携带明文或句柄令牌。"""
from __future__ import annotations


class CoordinatorError(Exception):
    """所有协调器错误的基类。"""


class AuthorizationError(CoordinatorError):
    """任务上下文未经授权，或申请范围超出已批准能力。"""


class QuotaExceededError(CoordinatorError):
    """并发申请会突破租户有效租约额度。"""


class LeaseStateError(CoordinatorError):
    """操作不满足租约当前状态（如核销已终结租约、续期已吊销租约）。"""


class GracePeriodClosedError(CoordinatorError):
    """轮换宽限期已结束，旧凭据版本必须失效。"""


class FreezeError(CoordinatorError):
    """泄露调查进行中，新的凭据物化已被冻结。"""


class ScopeExceededError(CoordinatorError):
    """连接调用实际使用的范围超过原批准范围。"""


class ReplayError(CoordinatorError):
    """任务重放试图恢复已失效的租约关系。"""
