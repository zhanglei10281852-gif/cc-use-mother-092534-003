"""时间源。协调器内所有时间判断都经由此抽象，便于测试宽限期与过期。"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock:
    """测试用固定时钟。"""

    def __init__(self, moment: datetime) -> None:
        if moment.tzinfo is None:
            raise ValueError("时间必须带时区")
        self._moment = moment

    def now(self) -> datetime:
        return self._moment

    def advance(self, seconds: float) -> datetime:
        from datetime import timedelta

        self._moment += timedelta(seconds=seconds)
        return self._moment
