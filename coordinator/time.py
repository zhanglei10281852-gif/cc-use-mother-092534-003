"""可注入的时钟，保证宽限期、租约到期在测试中可判定。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional


class Clock:
    def __init__(self, fixed: Optional[datetime] = None) -> None:
        self._fixed = fixed
        self._override: Callable[[], datetime] | None = None

    def now(self) -> datetime:
        if self._override is not None:
            value = self._override()
        elif self._fixed is not None:
            value = self._fixed
        else:
            value = datetime.now(timezone.utc)
        if value.tzinfo is None:
            raise ValueError("时间必须带时区")
        return value

    def set(self, value: datetime) -> None:
        if value.tzinfo is None:
            raise ValueError("时间必须带时区")
        self._fixed = value
        self._override = None

    def advance(self, seconds: float = 0, **kwargs: float) -> None:
        from datetime import timedelta

        delta = timedelta(seconds=seconds, **{k: float(v) for k, v in kwargs.items()})
        if self._fixed is None:
            self._fixed = datetime.now(timezone.utc)
        self._fixed = self._fixed + delta
        self._override = None
