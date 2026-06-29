"""核心加密模块。

设计：
- 主密钥由主密码经 Argon2id 派生，salt 单独存储，参数可配置。
- 主密钥**永不落盘**，仅在进程内存中持有。
- 凭证使用 AES-256-GCM 加密，每条凭证独立 nonce，nonce 与密文一同存储。
- 凭证明文使用后主动清零。
"""

from __future__ import annotations

import os
import time
import ctypes
from dataclasses import dataclass
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# 主密钥长度（32 字节 = 256 位，用于 AES-256）
MASTER_KEY_LEN = 32
# Argon2 输出盐长度
SALT_LEN = 16
# AES-GCM nonce 长度
NONCE_LEN = 12


def _zero(buf: bytearray) -> None:
    """安全清零内存缓冲区。"""
    if not buf:
        return
    try:
        ctypes.memset(
            (ctypes.c_char * len(buf)).from_buffer(buf),
            0,
            len(buf),
        )
    except Exception:
        for i in range(len(buf)):
            buf[i] = 0


@dataclass
class Argon2Params:
    """Argon2 派生参数，初始化后固定。"""

    salt: bytes  # 16 字节
    time_cost: int
    memory_cost: int
    parallelism: int

    def to_dict(self) -> dict:
        return {
            "salt": self.salt.hex(),
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Argon2Params":
        return cls(
            salt=bytes.fromhex(d["salt"]),
            time_cost=int(d["time_cost"]),
            memory_cost=int(d["memory_cost"]),
            parallelism=int(d["parallelism"]),
        )


class CryptoVault:
    """主密钥持有者 + 加解密入口。

    一个进程内通常只有一个实例，由 `keyhub.runtime` 持有。
    """

    def __init__(self, params: Argon2Params, master_key: bytes):
        if len(master_key) != MASTER_KEY_LEN:
            raise ValueError(f"master_key must be {MASTER_KEY_LEN} bytes")
        self._params = params
        # master_key 以 bytearray 持有，便于清零
        self._key = bytearray(master_key)
        self._aes = AESGCM(bytes(self._key))

    @property
    def params(self) -> Argon2Params:
        return self._params

    def encrypt(self, plaintext: str | bytes) -> bytes:
        """加密为 bytes = nonce(12) || ciphertext。"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        nonce = os.urandom(NONCE_LEN)
        ct = self._aes.encrypt(nonce, plaintext, associated_data=None)
        return nonce + ct

    def decrypt(self, blob: bytes) -> str:
        """解密，返回 utf-8 字符串。"""
        if len(blob) < NONCE_LEN + 16:  # GCM tag = 16
            raise ValueError("ciphertext too short")
        nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
        pt = self._aes.decrypt(nonce, ct, associated_data=None)
        return pt.decode("utf-8")

    def decrypt_bytes(self, blob: bytes) -> bytes:
        """解密，返回原始 bytes（适用于二进制凭证）。"""
        nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
        return self._aes.decrypt(nonce, ct, associated_data=None)

    def zero(self) -> None:
        """清零主密钥。进程退出或锁定时调用。"""
        _zero(self._key)
        self._aes = None  # type: ignore[assignment]


# ===== 主密钥派生 =====

def derive_master_key(
    master_password: str,
    params: Argon2Params,
) -> bytes:
    """由主密码 + Argon2 参数派生 32 字节主密钥。"""
    key = hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=params.salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=MASTER_KEY_LEN,
        type=Type.ID,
    )
    return key


def new_argon2_params(
    time_cost: int = 3,
    memory_cost: int = 65536,
    parallelism: int = 4,
) -> Argon2Params:
    """生成新的 Argon2 参数（含随机 salt），仅在首次初始化时调用。"""
    return Argon2Params(
        salt=os.urandom(SALT_LEN),
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
    )


# ===== 主密码哈希（用于登录校验，独立于派生） =====

_pw_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
)


def hash_master_password(password: str) -> str:
    """生成主密码的 Argon2 校验哈希（PHC 字符串）。"""
    return _pw_hasher.hash(password)


def verify_master_password(password: str, phc_hash: str) -> bool:
    """校验主密码是否匹配。"""
    try:
        return _pw_hasher.verify(phc_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def needs_rehash(phc_hash: str) -> bool:
    """检查主密码哈希是否需要按当前参数重算。"""
    return _pw_hasher.check_needs_rehash(phc_hash)


# ===== 便捷工具 =====

def secure_zero_string(s: str) -> None:
    """尽力清零字符串（Python 字符串不可变，仅做 best-effort）。"""
    # CPython 中字符串内部 buffer 无法安全清零，
    # 这里仅作为占位提醒：敏感字符串应尽快离开作用域。
    del s


# ===== 密码生成器 =====

def generate_password(
    length: int = 20,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_similar: bool = False,
) -> str:
    """生成密码学安全的随机密码。使用 secrets 模块。"""
    import secrets as _s
    import string as _st
    chars = ""
    similar = set("0O1lI|`oO")
    if upper:
        chars += _st.ascii_uppercase
    if lower:
        chars += _st.ascii_lowercase
    if digits:
        chars += _st.digits
    if symbols:
        chars += "!@#$%^&*()-_=+[]{};:,.<>?"
    if exclude_similar:
        chars = "".join(c for c in chars if c not in similar)
    if not chars:
        chars = _st.ascii_letters + _st.digits
    return "".join(_s.choice(chars) for _ in range(max(length, 4)))


def password_strength(password: str) -> dict:
    """评估密码强度。返回 {score: 0-4, label: str, entropy_bits: float, issues: list[str]}。"""
    import math
    if not password:
        return {"score": 0, "label": "极弱", "entropy_bits": 0, "issues": ["空密码"]}
    issues = []
    charset_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 32
    if charset_size == 0:
        charset_size = 1
    entropy = len(password) * math.log2(charset_size)
    if len(password) < 8:
        issues.append("长度过短（建议至少 8 位）")
    if not has_lower:
        issues.append("缺少小写字母")
    if not has_upper:
        issues.append("缺少大写字母")
    if not has_digit:
        issues.append("缺少数字")
    if not has_symbol:
        issues.append("缺少特殊符号")
    # 常见弱密码模式
    common = ["123456", "password", "qwerty", "abc123", "111111", "000000"]
    if password.lower() in common:
        issues.append("常见弱密码")
        entropy = min(entropy, 10)
    if password.isdigit():
        issues.append("纯数字密码")
        entropy = min(entropy, len(password) * math.log2(10))
    # 评分
    if entropy < 28:
        score, label = 0, "极弱"
    elif entropy < 36:
        score, label = 1, "弱"
    elif entropy < 60:
        score, label = 2, "中等"
    elif entropy < 80:
        score, label = 3, "强"
    else:
        score, label = 4, "很强"
    if len(password) < 8:
        score = min(score, 1)
    return {"score": score, "label": label, "entropy_bits": round(entropy, 2), "issues": issues}


# ===== TOTP (RFC 6238) =====

_TOTP_STEP = 30
_TOTP_DIGITS = 6

def _b32_decode(secret: str) -> bytes:
    """base32 解码，自动补齐 padding。"""
    import base64 as _b64
    s = secret.upper().replace(" ", "").rstrip("=")
    pad = (8 - len(s) % 8) % 8
    s = s + "=" * pad
    return _b64.b32decode(s)

def _hotp(secret_bytes: bytes, counter: int) -> str:
    """HOTP 算法（RFC 4226）。"""
    import hmac as _hmac
    import hashlib as _hl
    import struct
    msg = struct.pack(">Q", counter)
    digest = _hmac.new(secret_bytes, msg, _hl.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    code = code_int % (10 ** _TOTP_DIGITS)
    return str(code).zfill(_TOTP_DIGITS)

def generate_totp_secret() -> str:
    """生成 32 字节 base32 编码的 TOTP 密钥。"""
    import base64 as _b64
    return _b64.b32encode(os.urandom(32)).decode("ascii")

def generate_totp_uri(secret: str, account: str, issuer: str = "KeyHub") -> str:
    """生成 otpauth:// URI。"""
    from urllib.parse import quote
    label = quote(f"{issuer}:{account}", safe=":")
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret}"
        f"&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1"
        f"&digits={_TOTP_DIGITS}"
        f"&period={_TOTP_STEP}"
    )

def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """验证 TOTP 码。window=1 允许前后各 30 秒偏差。使用恒定时间比较。"""
    import hmac as _hmac
    if not code or not code.isdigit() or len(code) != _TOTP_DIGITS:
        return False
    try:
        secret_bytes = _b32_decode(secret)
    except Exception:
        return False
    counter = int(time.time()) // _TOTP_STEP
    for offset in range(-window, window + 1):
        candidate = _hotp(secret_bytes, counter + offset)
        if _hmac.compare_digest(candidate, code):
            return True
    return False
