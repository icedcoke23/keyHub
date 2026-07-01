"""核心加密模块。

设计：
- 主密钥由主密码 + pepper（服务端密钥）经 Argon2id 派生，salt 单独存储，参数可配置。
- 主密钥**永不落盘**，仅在进程内存中持有。
- 凭证使用 AES-256-GCM 加密，每条凭证独立 nonce，nonce 与密文一同存储。
- v1 格式：AAD 绑定到凭证上下文（id+name），防止密文交换攻击；明文>256字节先 zlib 压缩。
- v0 格式（旧数据）：无 AAD，自动兼容解密；首次轮换时自动升级到 v1。
- 凭证明文使用后主动清零。
"""

from __future__ import annotations

import os
import time
import zlib
import ctypes
import hashlib
import hmac as _hmac
from dataclasses import dataclass
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


MASTER_KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12

_V0 = 0x00
_V1 = 0x01

_COMPRESS_THRESHOLD = 256


def _zero(buf: bytearray) -> None:
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
    salt: bytes
    time_cost: int
    memory_cost: int
    parallelism: int

    def to_dict(self) -> dict:
        return {
            "salt": self.salt.hex(),
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "version": 1,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Argon2Params":
        return cls(
            salt=bytes.fromhex(d["salt"]),
            time_cost=int(d.get("time_cost", 3)),
            memory_cost=int(d.get("memory_cost", 65536)),
            parallelism=int(d.get("parallelism", 4)),
        )


def _mix_pepper(master_key: bytes, pepper: str) -> bytes:
    """用 HKDF-SHA256 将 pepper 混入主密钥，生成最终加密密钥。

    pepper 来自服务端 KEYHUB_SECRET_KEY，作为第二层防护：
    即使数据库泄露且主密码被猜解，没有 pepper 也无法解密。
    """
    if not pepper:
        return master_key
    pepper_bytes = pepper.encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=MASTER_KEY_LEN,
        salt=None,
        info=b"keyhub-pepper-v1",
    )
    return hkdf.derive(master_key + pepper_bytes)


class CryptoVault:
    def __init__(self, params: Argon2Params, master_key: bytes, pepper: str = ""):
        if len(master_key) != MASTER_KEY_LEN:
            raise ValueError(f"master_key must be {MASTER_KEY_LEN} bytes")
        self._params = params
        self._key = bytearray(_mix_pepper(master_key, pepper))
        self._aes = AESGCM(bytes(self._key))
        self._pepper = pepper

    @property
    def params(self) -> Argon2Params:
        return self._params

    def encrypt(self, plaintext: str | bytes, aad: bytes | None = None) -> bytes:
        """加密为 bytes = version(1) || nonce(12) || ciphertext。

        v1 格式：使用 AAD 绑定上下文（凭证 id/name），大明文先压缩。
        v0 格式（aad=None 时）：旧格式，向后兼容。
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        compressed = False
        if aad is not None and len(plaintext) > _COMPRESS_THRESHOLD:
            compressed_data = zlib.compress(plaintext, level=6)
            if len(compressed_data) < len(plaintext):
                plaintext = compressed_data
                compressed = True

        if aad is not None:
            flag = 0x01 if compressed else 0x00
            v1_aad = b"keyhub-v1|" + aad + b"|" + bytes([flag])
            nonce = os.urandom(NONCE_LEN)
            ct = self._aes.encrypt(nonce, plaintext, associated_data=v1_aad)
            return bytes([_V1]) + bytes([flag]) + nonce + ct
        else:
            nonce = os.urandom(NONCE_LEN)
            ct = self._aes.encrypt(nonce, plaintext, associated_data=None)
            return nonce + ct

    def decrypt(self, blob: bytes, aad: bytes | None = None) -> str:
        pt = self.decrypt_bytes(blob, aad)
        return pt.decode("utf-8")

    def decrypt_bytes(self, blob: bytes, aad: bytes | None = None) -> bytes:
        if len(blob) < NONCE_LEN + 16:
            raise ValueError("ciphertext too short")

        if blob[0] == _V1:
            if len(blob) < 2 + NONCE_LEN + 16:
                raise ValueError("v1 ciphertext too short")
            flag = blob[1]
            compressed = bool(flag & 0x01)
            nonce, ct = blob[2:2 + NONCE_LEN], blob[2 + NONCE_LEN:]
            if aad is None:
                aad = b""
            v1_aad = b"keyhub-v1|" + aad + b"|" + bytes([flag])
            pt = self._aes.decrypt(nonce, ct, associated_data=v1_aad)
            if compressed:
                pt = zlib.decompress(pt)
            return pt
        else:
            nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
            pt = self._aes.decrypt(nonce, ct, associated_data=None)
            return pt

    def zero(self) -> None:
        _zero(self._key)
        self._aes = None  # type: ignore[assignment]


def derive_master_key(
    master_password: str,
    params: Argon2Params,
) -> bytes:
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
    memory_cost: int = 131072,
    parallelism: int = 4,
) -> Argon2Params:
    """生成新的 Argon2 参数。默认 128MB 内存，比 OWASP 2025 推荐的 64MB 更安全。"""
    return Argon2Params(
        salt=os.urandom(SALT_LEN),
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
    )


_pw_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=131072,
    parallelism=4,
)


def hash_master_password(password: str) -> str:
    return _pw_hasher.hash(password)


def verify_master_password(password: str, phc_hash: str) -> bool:
    try:
        return _pw_hasher.verify(phc_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def needs_rehash(phc_hash: str) -> bool:
    return _pw_hasher.check_needs_rehash(phc_hash)


def secure_zero_string(s: str) -> None:
    del s


def generate_password(
    length: int = 20,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_similar: bool = False,
) -> str:
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
        issues.append("长度过短（建议至少 12 位）")
    if len(password) < 12:
        issues.append("建议至少 12 位以抵抗暴力破解")
    if not has_lower:
        issues.append("缺少小写字母")
    if not has_upper:
        issues.append("缺少大写字母")
    if not has_digit:
        issues.append("缺少数字")
    if not has_symbol:
        issues.append("缺少特殊符号")
    common = ["123456", "password", "qwerty", "abc123", "111111", "000000",
              "12345678", "password1", "123456789"]
    if password.lower() in common:
        issues.append("常见弱密码")
        entropy = min(entropy, 10)
    if password.isdigit():
        issues.append("纯数字密码")
        entropy = min(entropy, len(password) * math.log2(10))
    if entropy < 28:
        score, label = 0, "极弱"
    elif entropy < 40:
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
    import base64 as _b64
    s = secret.upper().replace(" ", "").rstrip("=")
    pad = (8 - len(s) % 8) % 8
    s = s + "=" * pad
    return _b64.b32decode(s)

def _hotp(secret_bytes: bytes, counter: int) -> str:
    import struct
    msg = struct.pack(">Q", counter)
    digest = _hmac.new(secret_bytes, msg, hashlib.sha1).digest()
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
    import base64 as _b64
    return _b64.b32encode(os.urandom(32)).decode("ascii")

def generate_totp_uri(secret: str, account: str, issuer: str = "KeyHub") -> str:
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
