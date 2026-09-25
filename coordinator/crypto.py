"""凭据明文与指纹工具。

明文只在签发瞬间生成一次，仅通过受控句柄返回；持久层只保存
SHA-256 指纹，指纹不可逆且足以支撑销毁比对与审计。
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

_TOKEN_BYTES = 32


def issue_secret() -> tuple[str, str]:
    """生成 (短期凭据明文, 指纹)。明文不再由协调器留存。"""
    raw = secrets.token_bytes(_TOKEN_BYTES)
    plaintext = raw.hex()
    return plaintext, fingerprint_of(plaintext)


def new_fingerprint() -> str:
    """只为凭据版本生成指纹锚点，不生成任何明文。"""
    return hashlib.sha256(secrets.token_bytes(_TOKEN_BYTES)).hexdigest()


def fingerprint_of(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
