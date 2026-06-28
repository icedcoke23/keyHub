"""核心加密模块。

设计：
- 主密钥由主密码经 Argon2id 派生，salt 单独存储，参数可配置。
- 主密钥**永不落盘**，仅在进程内存中持有。
- 凭证使用 AES-256-GCM 加密，每条凭证独立 nonce，nonce 与密文一同存储。
- 凭证明文使用后主动清零。
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import math
import os
import secrets
import struct
import time
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

# 默认符号集
_PASSWORD_SYMBOLS = "!@#$%^&*()-_=+"
# 易混淆字符（exclude_similar=True 时排除）
_PASSWORD_SIMILAR = set("0Oo1lI")
# 基础字符集
_PASSWORD_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_PASSWORD_LOWER = "abcdefghijklmnopqrstuvwxyz"
_PASSWORD_DIGITS = "0123456789"


def generate_password(
    length: int = 20,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_similar: bool = True,
) -> str:
    """生成密码学安全的随机密码。

    使用 secrets 模块保证随机源安全，可配置长度与字符集，
    并确保每种选定的字符集至少出现一个字符。

    Args:
        length: 密码长度，最小为 4。
        upper: 是否包含大写字母。
        lower: 是否包含小写字母。
        digits: 是否包含数字。
        symbols: 是否包含符号。
        exclude_similar: 是否排除易混淆字符（0/O/o、1/l/I 等）。

    Returns:
        生成的密码字符串。
    """
    if length < 4:
        raise ValueError("length 最小为 4")

    def _filter(chars: str) -> str:
        if exclude_similar:
            return "".join(c for c in chars if c not in _PASSWORD_SIMILAR)
        return chars

    pools: list[str] = []
    if upper:
        pools.append(_filter(_PASSWORD_UPPER))
    if lower:
        pools.append(_filter(_PASSWORD_LOWER))
    if digits:
        pools.append(_filter(_PASSWORD_DIGITS))
    if symbols:
        pools.append(_PASSWORD_SYMBOLS)

    # 过滤后某个字符集可能为空，剔除空集
    pools = [p for p in pools if p]
    if not pools:
        raise ValueError("当前字符集配置无效，至少需要保留一种字符集")

    # 每种字符集至少取一个，保证多样性
    chosen: list[str] = [secrets.choice(p) for p in pools]
    all_chars = "".join(pools)
    for _ in range(length - len(chosen)):
        chosen.append(secrets.choice(all_chars))

    # 打乱顺序，避免固定前缀暴露字符集结构
    secrets.SystemRandom().shuffle(chosen)
    return "".join(chosen)


# ===== 密码强度评估 =====

# 常见弱密码 / 序列（小写匹配）
_COMMON_SEQUENCES = (
    "1234", "2345", "3456", "4567", "5678", "6789", "7890",
    "12345", "123456", "1234567", "12345678",
    "abcd", "bcde", "cdef", "abcdef", "abcdefg",
    "qwerty", "qwertz", "azerty", "asdf", "asdfgh", "zxcv", "zxcvbn",
    "password", "passwd", "p@ssw0rd", "admin", "root", "letmein",
    "welcome", "iloveyou", "monkey", "dragon", "login",
    "1111", "0000", "aaaa", "abc123",
)
_STRENGTH_LABELS = ("很弱", "弱", "中等", "强", "很强")


def password_strength(password: str) -> dict:
    """评估密码强度。

    综合考虑长度、字符集多样性、熵值以及常见弱密码模式，
    返回 0-4 的评分、中文标签、熵值（比特）与问题列表。

    Returns:
        {"score": int, "label": str, "entropy_bits": float, "issues": [str]}
    """
    if not password:
        return {
            "score": 0,
            "label": _STRENGTH_LABELS[0],
            "entropy_bits": 0.0,
            "issues": ["密码为空"],
        }

    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    # 字符集大小估算
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 33  # 常见可打印符号近似数量

    entropy_bits = math.log2(charset_size) * length if charset_size > 1 else 0.0

    issues: list[str] = []
    if length < 8:
        issues.append("密码过短")
    elif length < 12:
        issues.append("密码长度偏短")
    if not has_lower:
        issues.append("缺少小写字母")
    if not has_upper:
        issues.append("缺少大写字母")
    if not has_digit:
        issues.append("缺少数字")
    if not has_symbol:
        issues.append("缺少符号")
    if entropy_bits < 28:
        issues.append("熵值过低")
    elif entropy_bits < 50:
        issues.append("熵值偏低")

    # 常见序列 / 弱密码检测
    has_common = False
    lower_pw = password.lower()
    for seq in _COMMON_SEQUENCES:
        if seq in lower_pw:
            has_common = True
            issues.append("包含常见序列")
            break

    diversity = sum((has_lower, has_upper, has_digit, has_symbol))

    # 基础评分（基于熵 + 多样性 + 长度）
    if entropy_bits >= 100 and diversity >= 3 and length >= 16:
        score = 4
    elif entropy_bits >= 60 and diversity >= 3:
        score = 3
    elif entropy_bits >= 36 and diversity >= 2:
        score = 2
    elif entropy_bits >= 20:
        score = 1
    else:
        score = 0

    # 惩罚项
    if has_common:
        score = min(score, 2)
    if length < 8:
        score = min(score, 1)
    if diversity <= 1 and length < 12:
        score = min(score, 1)

    score = max(0, min(4, score))
    return {
        "score": score,
        "label": _STRENGTH_LABELS[score],
        "entropy_bits": round(entropy_bits, 2),
        "issues": issues,
    }


# ===== TOTP（RFC 6238，HMAC-SHA1，30 秒步长，6 位数字） =====

_TOTP_STEP = 30
_TOTP_DIGITS = 6


def _b32_decode(secret: str) -> bytes:
    """解码 base32 密钥，自动去除空格、大写并补齐填充。"""
    s = secret.replace(" ", "").replace("-", "").upper()
    pad = (-len(s)) % 8
    if pad:
        s = s + ("=" * pad)
    return base64.b32decode(s)


def _hotp(secret_bytes: bytes, counter: int) -> str:
    """HOTP 核心算法：HMAC-SHA1 + 动态截取 → 6 位数字字符串。"""
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    # 动态截取（RFC 4226）
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
    return base64.b32encode(os.urandom(32)).decode("ascii")


def generate_totp_uri(
    secret: str,
    account: str,
    issuer: str = "KeyHub",
) -> str:
    """生成 otpauth:// URI，可供二维码扫描导入到验证器 App。"""
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
    """验证 TOTP 码。

    Args:
        secret: base32 编码的 TOTP 密钥。
        code: 待验证的 6 位数字码。
        window: 允许的时间窗口偏移步数（每步 30 秒），
            window=1 表示允许前后各 30 秒偏差。

    Returns:
        验证是否通过。使用恒定时间比较以防时序攻击。
    """
    if not code or not code.isdigit() or len(code) != _TOTP_DIGITS:
        return False
    try:
        secret_bytes = _b32_decode(secret)
    except Exception:
        return False
    counter = int(time.time()) // _TOTP_STEP
    for offset in range(-window, window + 1):
        candidate = _hotp(secret_bytes, counter + offset)
        if hmac.compare_digest(candidate, code):
            return True
    return False
