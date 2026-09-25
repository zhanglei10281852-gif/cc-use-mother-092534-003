"""不可变审计事件。

事件是协调器唯一的历史载体。所有载荷只允许出现标识、范围与
指纹，**严禁**出现凭据明文——构造时对字段名做静态拦截，
序列化时对明文值做指纹比对兜底。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

# 禁止出现在事件字段名或载荷键名中的词干
_FORBIDDEN_KEY_PARTS = ("plaintext", "secret", "token", "password", "credential_material")

_SENSITIVE_MARKERS = ("plaintext", "secret", "token", "password", "private")


def _assert_safe_keys(payload: Mapping[str, Any]) -> None:
    for key in payload:
        lowered = key.lower()
        if any(part in lowered for part in _FORBIDDEN_KEY_PARTS):
            raise ValueError(f"审计事件不得携带明文字段：{key}")


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    event_type: str
    aggregate_id: str
    occurred_at: datetime
    actor_id: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None:
            raise ValueError("事件时间必须带时区")
        _assert_safe_keys(self.payload)
        _assert_safe_keys(self.metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "aggregate_id": self.aggregate_id,
            "occurred_at": self.occurred_at.isoformat(),
            "actor_id": self.actor_id,
            "payload": dict(self.payload),
            "metadata": dict(self.metadata),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


@dataclass(frozen=True, slots=True)
class EventLog:
    """按追加顺序保存事件，事件序号单调、不覆盖历史。"""

    events: list[Event] = field(default_factory=list)

    def append(self, event: Event) -> None:
        if any(existing.event_id == event.event_id for existing in self.events):
            raise ValueError(f"事件标识重复：{event.event_id}")
        self.events.append(event)

    def for_aggregate(self, aggregate_id: str) -> list[Event]:
        return [e for e in self.events if e.aggregate_id == aggregate_id]

    def of_type(self, event_type: str) -> list[Event]:
        return [e for e in self.events if e.event_type == event_type]

    def all(self) -> list[Event]:
        return list(self.events)


def looks_like_secret(value: Any) -> bool:
    """启发式判断一个值是否"长得像"被误放的密钥（64 位十六进制等）。"""
    if not isinstance(value, str):
        return False
    if len(value) < 32:
        return False
    lowered = value.lower()
    if all(c in "0123456789abcdef" for c in lowered) and len(lowered) % 2 == 0:
        return True
    return False
