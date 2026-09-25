"""协调器领域异常。"""
from __future__ import annotations


class CoordinatorError(Exception):
    """所有协调器错误的基类。"""


class AuthorizationError(CoordinatorError):
    """任务上下文未获授权，或申请范围超出授权能力。"""


class QuotaExceededError(CoordinatorError):
    """并发申请会突破租户有效租约额度。"""


class LeaseInvalidError(CoordinatorError):
    """租约不存在、已核销、已过期或已被紧急吊销。"""


class VersionRetiredError(CoordinatorError):
    """轮换宽限期结束，旧凭据版本必须拒绝使用。"""


class DestructionPendingError(CoordinatorError):
    """租约已终止，但销毁证明尚未被连接器确认。"""


class FrozenMaterializationError(CoordinatorError):
    """泄露调查进行中，新的凭据物化已被冻结。"""


class ScopeExceededError(CoordinatorError):
    """连接调用实际使用的范围超过原批准范围。"""


class HandleError(CoordinatorError):
    """受控句柄被复制、关闭或跨任务传递。"""
