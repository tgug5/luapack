#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
 luapack  v1.1.0
 Lua 源码 -> 字节码 -> 加密 一键打包工具
===============================================================================

 命令
   build     .lua 源码编译成字节码并加密，输出加密容器 + 运行时 loader
   unpack    加密容器还原成标准 .luac（自己留档 / 排查用）
   disasm    解密容器并反汇编（看字节码指令）
   info      查看容器信息（Lua 版本 / 算法 / 大小 / 校验）
   keygen    生成一份口令
   selftest  全链路自检：编译 -> 加密 -> 解密 -> 还原 -> 真跑

 加密算法
   xxtea    XXTEA-128（默认）轻量，纯 Lua 运行时可自解密，零依赖，全平台
   aes      AES-256-CBC + HMAC-SHA256，强度高，走 C 层 / 宿主程序解密
   none     只编字节码不加密

 四层处理
   1 密钥派生   PBKDF2-HMAC-SHA256(20 万轮) 或轻量 SHA256 派生（Lua 可解）
   2 完整性    HMAC-SHA256 + CRC32，改一个字节就拒载
   3 头部变异   luac 标准头被置换混淆，直接解密出来的不是合法 luac 文件
   4 明文指纹   "LPBC" 魔数 + 随机 nonce，口令不对立刻报错、不吐乱码

 用法示例
   python3 luapack.py build demo.lua                  # 默认 xxtea + 自动探版本
   python3 luapack.py build src/ -o out --lua 5.1     # 整个目录，目标 5.1
   python3 luapack.py build demo.lua -m aes           # 高强档 AES-256
   python3 luapack.py build demo.lua --run            # 打完立刻真跑一遍
   python3 luapack.py info   build/demo.luac.enc
   python3 luapack.py unpack build/demo.luac.enc      # 还原成 .luac
   python3 luapack.py disasm build/demo.luac.enc      # 反汇编看指令
===============================================================================
"""

import argparse
import hashlib
import hmac
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

VERSION = "1.1.0"

# ----------------------------------------------------------------------------
# 常量
# ----------------------------------------------------------------------------
MAGIC = b"LPK\x01"
HEADER_SIZE = 128
PLAIN_MAGIC = b"LPBC"

CIPHER_XTEA = 0
CIPHER_AES = 1
CIPHER_NONE = 2
CIPHER_NAME = {CIPHER_XTEA: "xxtea", CIPHER_AES: "aes", CIPHER_NONE: "none"}
CIPHER_BY_NAME = {v: k for k, v in CIPHER_NAME.items()}

FLAG_SCRAMBLE = 0x01   # 头部变异
FLAG_HMAC = 0x02       # HMAC-SHA256 完整性
FLAG_KDF_STRONG = 0x04 # 密钥派生用 PBKDF2（否则用轻量 SHA256 派生）

LUA_VERS = ("5.1", "5.2", "5.3", "5.4")
PBKDF2_ROUNDS = 200000
SCRAMBLE_LEN = 32
NONCE_LEN = 16

KDF_LITE_TAG = b"luapack-lite-key|"
KDF_STRONG_TAG = b"luapack-keycheck|"


# ============================================================================
# 1. XXTEA（与 C 实现逐位对齐）
# ============================================================================
DELTA = 0x9E3779B9
M32 = 0xFFFFFFFF


def _xt_mx(sum_, y, z, p, e, k):
    a = ((z >> 5) ^ ((y << 2) & M32)) & M32
    b = ((y >> 3) ^ ((z << 4) & M32)) & M32
    c = ((sum_ ^ y) + (k[(p & 3) ^ e] ^ z)) & M32
    return ((a + b) & M32) ^ c


def _xt_crypt(v, k, decrypt=False):
    n = len(v)
    if n < 2:
        return v
    rounds = 6 + 52 // n
    if not decrypt:
        sum_, z = 0, v[n - 1]
        for _ in range(rounds):
            sum_ = (sum_ + DELTA) & M32
            e = (sum_ >> 2) & 3
            for p in range(n - 1):
                y = v[p + 1]
                v[p] = (v[p] + _xt_mx(sum_, y, z, p, e, k)) & M32
                z = v[p]
            y = v[0]
            p = n - 1
            v[p] = (v[p] + _xt_mx(sum_, y, z, p, e, k)) & M32
            z = v[p]
    else:
        sum_ = (rounds * DELTA) & M32
        y = v[0]
        for _ in range(rounds):
            e = (sum_ >> 2) & 3
            for p in range(n - 1, 0, -1):
                z = v[p - 1]
                v[p] = (v[p] - _xt_mx(sum_, y, z, p, e, k)) & M32
                y = v[p]
            z = v[n - 1]
            v[0] = (v[0] - _xt_mx(sum_, y, z, 0, e, k)) & M32
            y = v[0]
            sum_ = (sum_ - DELTA) & M32
    return v


def xxtea_encrypt(data: bytes, key: bytes) -> bytes:
    if len(key) < 16:
        raise ValueError("XXTEA key 至少 16 字节")
    k = list(struct.unpack("<4I", key[:16]))
    pad = (-len(data)) % 4
    raw = data + b"\x00" * pad
    if len(raw) < 8:                       # XXTEA 至少需要 2 个 word
        raw += b"\x00" * (8 - len(raw))
    v = list(struct.unpack("<%dI" % (len(raw) // 4), raw))
    _xt_crypt(v, k, False)
    return struct.pack("<%dI" % len(v), *v)


def xxtea_decrypt(data: bytes, key: bytes) -> bytes:
    if len(key) < 16:
        raise ValueError("XXTEA key 至少 16 字节")
    if len(data) % 4 != 0 or len(data) < 8:
        raise ValueError("XXTEA 密文长度不合法")
    k = list(struct.unpack("<4I", key[:16]))
    v = list(struct.unpack("<%dI" % (len(data) // 4), data))
    _xt_crypt(v, k, True)
    return struct.pack("<%dI" % len(v), *v)


# ============================================================================
# 2. 密钥派生 / 头部变异
# ============================================================================
def kdf_lite(password: str) -> bytes:
    """轻量派生：Lua 端可直接内嵌结果，不需要 PBKDF2。"""
    return hashlib.sha256(KDF_LITE_TAG + password.encode("utf-8")).digest()


def kdf_strong(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                               PBKDF2_ROUNDS, dklen=32)


def key_check(key: bytes) -> bytes:
    return hashlib.sha256(KDF_STRONG_TAG + key).digest()[:8]


def _stream_bytes(seed: bytes, need: int) -> bytes:
    """计数器模式的 SHA256 字节流（与 C 端 lpk stream_bytes 一致）。"""
    out = bytearray()
    ctr = 0
    while len(out) < need:
        out += hashlib.sha256(seed + struct.pack("<I", ctr)).digest()
        ctr += 1
    return bytes(out)


def _scramble_perm(key: bytes, n: int):
    if n <= 1:
        return list(range(n))
    stream = _stream_bytes(b"luapack-scramble|" + key, n * 4)
    perm = list(range(n))
    for i in range(n - 1, 0, -1):
        j = int.from_bytes(stream[i * 4:i * 4 + 4], "little") % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def _scramble_mask(key: bytes) -> bytes:
    return hashlib.sha256(b"luapack-mask|" + key).digest()


def scramble_head(data: bytes, key: bytes) -> bytes:
    """把 luac 头 n 字节按密钥置换 + 掩码流异或。"""
    n = min(SCRAMBLE_LEN, len(data))
    if n < 2:
        return data
    head = data[:n]
    perm = _scramble_perm(key, n)
    mask = _scramble_mask(key)
    sc = bytearray(n)
    for dst, src in enumerate(perm):
        sc[dst] = head[src] ^ mask[dst % len(mask)]
    return bytes(sc) + data[n:]


def unscramble_head(data: bytes, key: bytes) -> bytes:
    n = min(SCRAMBLE_LEN, len(data))
    if n < 2:
        return data
    perm = _scramble_perm(key, n)
    mask = _scramble_mask(key)
    tmp = bytearray(n)
    for dst, src in enumerate(perm):
        tmp[src] = data[dst] ^ mask[dst % len(mask)]
    return bytes(tmp) + data[n:]


def wrap_plain(bytecode: bytes) -> bytes:
    """明文结构: 'LPBC' + u32le(len) + nonce(16) + luac + 0 补齐"""
    body = PLAIN_MAGIC + struct.pack("<I", len(bytecode)) + os.urandom(NONCE_LEN) + bytecode
    pad = (-len(body)) % 4
    return body + b"\x00" * pad


def unwrap_plain(blob: bytes):
    if len(blob) < 24 or blob[:4] != PLAIN_MAGIC:
        raise ValueError("口令不对，或数据已损坏")
    ln = struct.unpack_from("<I", blob, 4)[0]
    if 24 + ln > len(blob):
        raise ValueError("数据长度异常，文件可能损坏")
    return blob[24:24 + ln]


# ============================================================================
# 3. 容器封装 / 拆封
# ============================================================================
def _make_key(password, salt, strong):
    return kdf_strong(password, salt) if strong else kdf_lite(password)


def pack_container(bytecode: bytes, password: str, lua_ver: str,
                   cipher: int = CIPHER_XTEA, scramble: bool = True,
                   use_hmac: bool = True) -> bytes:
    salt = os.urandom(16)
    iv = os.urandom(16)
    strong = (cipher == CIPHER_AES)
    key = _make_key(password, salt, strong)

    flags = 0
    if scramble:
        flags |= FLAG_SCRAMBLE
    if use_hmac:
        flags |= FLAG_HMAC
    if strong:
        flags |= FLAG_KDF_STRONG

    body = wrap_plain(bytecode)
    if scramble:
        body = scramble_head(body, key)

    if cipher == CIPHER_XTEA:
        payload = xxtea_encrypt(body, key[:16])
    elif cipher == CIPHER_AES:
        payload = aes_cbc_encrypt(body, key, iv)
    elif cipher == CIPHER_NONE:
        payload = body
    else:
        raise ValueError("未知加密算法")

    header = bytearray(HEADER_SIZE)
    header[0:4] = MAGIC
    header[4] = 1
    header[5] = LUA_VERS.index(lua_ver) + 1
    header[6] = cipher
    header[7] = flags
    struct.pack_into("<Q", header, 8, len(bytecode))
    struct.pack_into("<Q", header, 16, len(payload))
    header[24:40] = salt
    header[40:56] = iv
    header[56:64] = key_check(key)
    struct.pack_into("<I", header, 64, zlib.crc32(payload) & M32)
    struct.pack_into("<Q", header, 68, int(time.time()))

    blob = bytes(header) + payload
    if use_hmac:
        blob += hmac.new(key, blob, hashlib.sha256).digest()
    return blob


def read_header(blob: bytes) -> dict:
    if len(blob) < HEADER_SIZE + 8:
        raise ValueError("文件太小，不是有效容器")
    if blob[0:4] != MAGIC:
        raise ValueError("魔数不匹配：不是 luapack 容器，或文件已损坏")
    if blob[4] != 1:
        raise ValueError("容器版本 %d 不支持" % blob[4])
    lv = blob[5]
    if not 1 <= lv <= len(LUA_VERS):
        raise ValueError("容器里的 Lua 版本标识非法")
    return {
        "lua_ver": LUA_VERS[lv - 1],
        "cipher": blob[6],
        "flags": blob[7],
        "plain_len": struct.unpack_from("<Q", blob, 8)[0],
        "payload_len": struct.unpack_from("<Q", blob, 16)[0],
        "salt": blob[24:40],
        "iv": blob[40:56],
        "keycheck": blob[56:64],
        "crc": struct.unpack_from("<I", blob, 64)[0],
        "stamp": struct.unpack_from("<Q", blob, 68)[0],
    }


def unpack_container(blob: bytes, password: str, expect_bytecode=None) -> dict:
    h = read_header(blob)
    flags = h["flags"]
    strong = bool(flags & FLAG_KDF_STRONG)
    key = _make_key(password, h["salt"], strong)

    if not hmac.compare_digest(key_check(key), h["keycheck"]):
        raise ValueError("口令不对（keycheck 校验失败）")

    payload = blob[HEADER_SIZE:HEADER_SIZE + h["payload_len"]]
    if len(payload) != h["payload_len"]:
        raise ValueError("数据被截断")

    if flags & FLAG_HMAC:
        mac = blob[HEADER_SIZE + h["payload_len"]:HEADER_SIZE + h["payload_len"] + 32]
        expect = hmac.new(key, blob[:HEADER_SIZE + h["payload_len"]], hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expect):
            raise ValueError("完整性校验失败：文件被篡改")

    if (zlib.crc32(payload) & M32) != h["crc"]:
        raise ValueError("CRC32 校验失败：数据损坏")

    c = h["cipher"]
    if c == CIPHER_XTEA:
        body = xxtea_decrypt(payload, key[:16])
    elif c == CIPHER_AES:
        body = aes_cbc_decrypt(payload, key, h["iv"])
    elif c == CIPHER_NONE:
        body = payload
    else:
        raise ValueError("未知加密算法 %d" % c)

    if flags & FLAG_SCRAMBLE:
        body = unscramble_head(body, key)

    bytecode = unwrap_plain(body)
    if len(bytecode) != h["plain_len"]:
        raise ValueError("字节码长度不符，可能口令错误")

    return {
        "lua_ver": h["lua_ver"],
        "cipher": CIPHER_NAME.get(c, "?"),
        "scramble": bool(flags & FLAG_SCRAMBLE),
        "hmac": bool(flags & FLAG_HMAC),
        "strong_kdf": strong,
        "size": h["plain_len"],
        "payload_size": h["payload_len"],
        "time": h["stamp"],
        "bytecode": bytecode,
    }


# ============================================================================
# 4. AES-256-CBC（纯 Python）
# ============================================================================
_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a = (a ^ 0x1b) & 0xff
    return a


def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        a = _xtime(a)
    return r


def _aes_expand(key: bytes):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _aes_block(block: bytes, w, nr, decrypt=False):
    s = [list(block[i::4]) for i in range(4)]

    def ark(rnd):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= w[rnd * 4 + c][r]

    def sub(box):
        for r in range(4):
            for c in range(4):
                s[r][c] = box[s[r][c]]

    def shift(rev):
        for r in range(1, 4):
            s[r] = s[r][-r:] + s[r][:-r] if rev else s[r][r:] + s[r][:r]

    def mix(inv):
        m = (14, 11, 13, 9) if inv else (2, 3, 1, 1)
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            for r in range(4):
                v = 0
                for j in range(4):
                    coeff = m[(j - r) % 4]
                    v ^= a[j] if coeff == 1 else _gmul(a[j], coeff)
                s[r][c] = v

    if not decrypt:
        ark(0)
        for rnd in range(1, nr):
            sub(_SBOX); shift(False); mix(False); ark(rnd)
        sub(_SBOX); shift(False); ark(nr)
    else:
        ark(nr)
        for rnd in range(nr - 1, 0, -1):
            shift(True); sub(_INV_SBOX); ark(rnd); mix(True)
        shift(True); sub(_INV_SBOX); ark(0)

    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4 * c + r] = s[r][c]
    return bytes(out)


def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    w, nr = _aes_expand(key)
    pad = 16 - (len(data) % 16)
    data = data + bytes([pad]) * pad
    prev, out = iv, bytearray()
    for i in range(0, len(data), 16):
        prev = _aes_block(bytes(a ^ b for a, b in zip(data[i:i + 16], prev)), w, nr)
        out += prev
    return bytes(out)


def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(data) % 16 != 0 or not data:
        raise ValueError("AES 密文长度不合法")
    w, nr = _aes_expand(key)
    prev, out = iv, bytearray()
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(_aes_block(blk, w, nr, True), prev))
        prev = blk
    pad = out[-1]
    if 1 <= pad <= 16:
        out = out[:-pad]
    return bytes(out)


# ============================================================================
# 5. luac / lua 定位
# ============================================================================
HERE = Path(__file__).resolve().parent


def find_luac(lua_ver=None, explicit=None):
    cands = []
    if explicit:
        cands.append((explicit, None))
    if os.environ.get("LUAPACK_LUAC"):
        cands.append((os.environ["LUAPACK_LUAC"], None))
    if lua_ver:
        cands.append((str(HERE / "bin" / ("luac-%s" % lua_ver)), lua_ver))
    for v in LUA_VERS:
        cands.append((str(HERE / "bin" / ("luac-%s" % v)), v))
    if lua_ver:
        cands.append(("luac" + lua_ver.replace(".", ""), lua_ver))
    cands.append(("luac", None))
    for path, hint in cands:
        p = path if os.path.isabs(path) else shutil.which(path)
        if not p or not os.path.exists(p):
            continue
        try:
            r = subprocess.run([p, "-v"], capture_output=True, timeout=15)
            text = (r.stdout + r.stderr).decode("utf-8", "ignore")
            for v in LUA_VERS:
                if "Lua " + v in text:
                    return p, v
            if hint:
                return p, hint
        except Exception:
            continue
    return None, None


def find_lua(lua_ver, explicit=None):
    cands = []
    if explicit:
        cands.append(explicit)
    if lua_ver:
        cands.append(str(HERE / "bin" / ("lua-%s" % lua_ver)))
    for v in LUA_VERS:
        cands.append(str(HERE / "bin" / ("lua-%s" % v)))
    if lua_ver:
        cands.append("lua" + lua_ver.replace(".", ""))
    cands.append("lua")
    for path in cands:
        p = path if os.path.isabs(path) else shutil.which(path)
        if not p or not os.path.exists(p):
            continue
        try:
            r = subprocess.run([p, "-v"], capture_output=True, timeout=15)
            text = (r.stdout + r.stderr).decode("utf-8", "ignore")
            if lua_ver and ("Lua " + lua_ver) not in text:
                continue
            return p
        except Exception:
            continue
    return None


def compile_lua(src: Path, out_luac: Path, luac: str, strip=True) -> bytes:
    cmd = [luac] + (["-s"] if strip else []) + ["-o", str(out_luac), str(src)]
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        err = (r.stderr or r.stdout).decode("utf-8", "ignore").strip()
        raise RuntimeError("编译失败 %s:\n%s" % (src.name, err))
    data = out_luac.read_bytes()
    if not data.startswith(b"\x1bLua"):
        raise RuntimeError("产物不是合法 Lua 字节码：%s" % src.name)
    return data


# ============================================================================
# 6. Lua 运行时 loader 生成
# ============================================================================
COMMON_LUA_53 = r'''
local function towords(s)
  local n = #s
  local pad = (4 - n % 4) % 4
  if pad > 0 then s = s .. string.rep("\0", pad) end
  local w, i, m = {}, 1, #s // 4
  for j = 1, m do
    local b1, b2, b3, b4 = s:byte(i, i + 3)
    w[j] = u32(b1 | (b2 << 8) | (b3 << 16) | (b4 << 24))
    i = i + 4
  end
  return w, m
end

local function tostr(w)
  local t = {}
  for i = 1, #w do
    local x = w[i]
    t[i] = string.char(x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF)
  end
  return table.concat(t)
end
'''

COMMON_LUA_51 = r'''
local floor = math.floor
local C32 = 4294967296

local X4 = {}
do
  for a = 0, 15 do
    local row = {}
    for b = 0, 15 do
      local r, p, x, y = 0, 1, a, b
      for _ = 1, 4 do
        local xa, yb = x % 2, y % 2
        if xa ~= yb then r = r + p end
        x, y, p = (x - xa) / 2, (y - yb) / 2, p * 2
      end
      row[b] = r
    end
    X4[a] = row
  end
end

local function xor32(a, b)
  local r, p = 0, 1
  for _ = 1, 8 do
    local xa, yb = a % 16, b % 16
    r = r + X4[xa][yb] * p
    a, b, p = (a - xa) / 16, (b - yb) / 16, p * 16
  end
  return r
end

local function x8(a, b)
  return X4[floor(a / 16)][floor(b / 16)] * 16 + X4[a % 16][b % 16]
end

local function add32(a, b)
  local r = a + b
  if r >= C32 then r = r - C32 end
  return r
end

local function sub32(a, b)
  local r = a - b
  if r < 0 then r = r + C32 end
  return r
end

local function shl32(a, n) return (a * (2 ^ n)) % C32 end
local function shr32(a, n) return floor(a / (2 ^ n)) end

local function towords(s)
  local n = #s
  local pad = (4 - n % 4) % 4
  if pad > 0 then s = s .. string.rep("\0", pad) end
  local w, i, m = {}, 1, #s / 4
  for j = 1, m do
    local b1, b2, b3, b4 = s:byte(i, i + 3)
    w[j] = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
    i = i + 4
  end
  return w, m
end

local function tostr(w)
  local t = {}
  for i = 1, #w do
    local x = w[i]
    t[i] = string.char(x % 256, floor(x / 256) % 256,
                       floor(x / 65536) % 256, floor(x / 16777216) % 256)
  end
  return table.concat(t)
end
'''

BODY_TMPL = r'''
-- ===== 内嵌运行参数（由 luapack 生成，勿手改）=====
local _P = {@@KEYBYTES@@}
local _MASK = @@KEYMASK@@
local _SCRAMBLE_N = @@SCRAMBLE_N@@
local _PERM = {@@PERM@@}
local _MASKSTR = "@@MASKSTR@@"
local _HEADER = @@HEADER@@
local _LUA_VER = "@@LUAVER@@"

local _KEY = {}
for i = 1, 4 do
  _KEY[i] = (_P[i] - _MASK) % 4294967296
end
@@CRYPTO_BLOCK@@
local function unscramble(data)
  local n = _SCRAMBLE_N
  if n < 2 or #data < n then return data end
  local plain = {}
  for i = 1, n do
    plain[i] = string.char(@@XOR8@@(data:byte(i), _MASKSTR:byte((i - 1) % #_MASKSTR + 1)))
  end
  local head = {}
  for dst = 1, n do
    head[_PERM[dst]] = plain[dst]
  end
  return table.concat(head) .. data:sub(n + 1)
end

local function readfile(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local d = f:read("*a")
  f:close()
  return d
end

local function u64le(s, off)
  local v, p = 0, 1
  for i = off, off + 7 do
    v = v + s:byte(i + 1) * p
    p = p * 256
  end
  return v
end

local function decrypt(blob)
  if type(blob) ~= "string" or #blob < _HEADER + 8 then
    return nil, "数据太短，不是合法容器"
  end
  if blob:sub(1, 4) ~= "LPK\1" then
    return nil, "魔数不匹配：不是 luapack 容器"
  end
  if blob:byte(7) ~= 0 then
    return nil, "该容器用的是别的加密算法，纯 Lua loader 解不开"
  end
  local flags = blob:byte(8)
  local plen = u64le(blob, 16)
  local payload = blob:sub(_HEADER + 1, _HEADER + plen)
  if #payload ~= plen then return nil, "数据被截断" end
  local w, n = towords(payload)
  if n < 2 then return nil, "payload 太小" end
  xxtea_dec(w, n, _KEY)
  local body = tostr(w)
  if flags % 2 == 1 then body = unscramble(body) end
  if body:sub(1, 4) ~= "LPBC" then
    return nil, "口令不对或文件损坏"
  end
  local b = { body:byte(5, 8) }
  local ln = b[1] + b[2] * 256 + b[3] * 65536 + b[4] * 16777216
  if 24 + ln > #body then return nil, "长度字段异常" end
  return body:sub(25, 24 + ln)
end

local _M = { lua_version = _LUA_VER }

function _M.decrypt(blob)
  local bc, err = decrypt(blob)
  if not bc then error("luapack: " .. tostring(err), 0) end
  return bc
end

function _M.loadfile(x)
  local blob = x
  if type(x) == "string" and #x < 2048 then
    local d = readfile(x)
    if d then
      blob = d
    elseif x:find("[/\\]") or x:find("%.enc$") or x:find("%.luac") then
      error("luapack: 打不开文件 " .. x, 0)
    end
  end
  local bc = _M.decrypt(blob)
  local fn, err = @@LOADFN@@(bc, "@@NAME@@")
  if not fn then error("luapack: 字节码加载失败: " .. tostring(err), 0) end
  return fn
end

function _M.run(x, ...)
  return _M.loadfile(x)(...)
end

return _M
'''

RUN_TMPL = r'''--[[ luapack standalone runner | v@@VERSION@@ | Lua @@LUAVER@@ ]]
-- 用法: lua <name>.run.lua <加密文件> [参数...]
local here = (arg and arg[0] and arg[0]:match("^(.*)[/\\][^/\\]*$")) or "."
local loader = dofile(here .. "/@@LOADER@@")
local enc = ...
if not enc then
  io.stderr:write("usage: lua " .. arg[0] .. " <encrypted.luac.enc> [args...]\n")
  os.exit(1)
end
if not enc:find("[/\\]") then enc = here .. "/" .. enc end
local t = {}
for i = 2, #arg do t[#t + 1] = arg[i] end
loader.run(enc, (table.unpack or unpack)(t))
'''


def gen_loader(lua_ver, password, name, scramble_on=True):
    key = kdf_lite(password)          # 32 字节，前 16 字节 = XXTEA 密钥
    mask = random.Random(int.from_bytes(os.urandom(8), "big")).randrange(1, 2 ** 32)
    obf = [(w + mask) % (2 ** 32) for w in struct.unpack("<4I", key[:16])]
    keybytes = ", ".join(str(x) for x in obf)

    perm = _scramble_perm(key, SCRAMBLE_LEN if scramble_on else 0)
    maskstr = _scramble_mask(key)

    is51 = (lua_ver == "5.1")
    if is51:
        crypto = COMMON_LUA_51 + XXTEA_LUA_51
    else:
        crypto = XXTEA_LUA_53 + COMMON_LUA_53
    xor8 = "x8" if is51 else "bxor8"
    loadfn = "loadstring" if is51 else "load"

    body = BODY_TMPL
    body = body.replace("@@KEYBYTES@@", keybytes)
    body = body.replace("@@KEYMASK@@", str(mask))
    body = body.replace("@@SCRAMBLE_N@@", str(SCRAMBLE_LEN if scramble_on else 0))
    body = body.replace("@@PERM@@", ",".join(str(p + 1) for p in perm))
    body = body.replace("@@MASKSTR@@", "".join("\\%d" % b for b in maskstr))
    body = body.replace("@@HEADER@@", str(HEADER_SIZE))
    body = body.replace("@@LUAVER@@", lua_ver)
    body = body.replace("@@CRYPTO_BLOCK@@", crypto)
    body = body.replace("@@XOR8@@", xor8)
    body = body.replace("@@LOADFN@@", loadfn)
    body = body.replace("@@NAME@@", "@" + name)
    body = body.replace("@@", "@")   # 清掉残留 @@

    head = "--[[ luapack runtime loader | v%s | Lua %s | AES/XXTEA container ]]\n" % (VERSION, lua_ver)
    return head + body


XXTEA_LUA_53 = r'''
local DELTA = 0x9E3779B9
local M32 = 0xFFFFFFFF
local u32 = function(x) return x & M32 end
local function bxor8(a, b) return a ~ b end

local function mx(sum, y, z, p, e, k)
  return u32((((z >> 5) ~ (y << 2)) + ((y >> 3) ~ (z << 4))) ~ ((sum ~ y) + (k[((p & 3) ~ e) + 1] ~ z)))
end

local function xxtea_dec(v, n, k)
  local rounds = 6 + (52 // n)
  local sum = u32(rounds * DELTA)
  local y = v[1]
  for _ = 1, rounds do
    local e = (sum >> 2) & 3
    for p = n, 2, -1 do
      local z = v[p - 1]
      v[p] = u32(v[p] - mx(sum, y, z, p - 1, e, k))
      y = v[p]
    end
    local z = v[n]
    v[1] = u32(v[1] - mx(sum, y, z, 0, e, k))
    y = v[1]
    sum = u32(sum - DELTA)
  end
end
'''

XXTEA_LUA_51 = r'''
local DELTA = 0x9E3779B9

local function mx(sum, y, z, p, e, k)
  local a = xor32(shr32(z, 5), shl32(y, 2))
  local b = xor32(shr32(y, 3), shl32(z, 4))
  local idx = xor32(p % 4, e) + 1
  local c = add32(xor32(sum, y), xor32(k[idx], z))
  return xor32(add32(a, b), c)
end

local function xxtea_dec(v, n, k)
  local rounds = 6 + floor(52 / n)
  local sum = (rounds * DELTA) % C32
  local y = v[1]
  for _ = 1, rounds do
    local e = shr32(sum, 2) % 4
    for p = n, 2, -1 do
      local z = v[p - 1]
      v[p] = sub32(v[p], mx(sum, y, z, p - 1, e, k))
      y = v[p]
    end
    local z = v[n]
    v[1] = sub32(v[1], mx(sum, y, z, 0, e, k))
    y = v[1]
    sum = sub32(sum, DELTA)
  end
end
'''


# ============================================================================
# 7. 命令行
# ============================================================================
def _collect(target: Path):
    if target.is_dir():
        return sorted(p for p in target.rglob("*.lua") if p.is_file())
    return [target]


def _verify_run(name, outdir, lua, quiet=False):
    enc = (outdir / (name + ".luac.enc")).as_posix()
    ld = (outdir / (name + ".loader.lua")).as_posix()
    code = (
        'local L = dofile("%s")\n'
        'local ok, f = pcall(L.loadfile, "%s")\n'
        'if not ok then io.stderr:write("ERR " .. tostring(f) .. "\\n") os.exit(3) end\n'
        'local ok2, r = pcall(f)\n'
        'if not ok2 then io.stderr:write("RUNTIME_ERR " .. tostring(r) .. "\\n") os.exit(4) end\n'
        'io.write("[[lp-ok]] ", tostring(r), "\\n")\n'
    ) % (ld, enc)
    rr = subprocess.run([lua, "-e", code], capture_output=True, cwd=str(outdir))
    out = (rr.stdout + rr.stderr).decode("utf-8", "ignore")
    return ("[[lp-ok]]" in out), out.strip()


def cmd_build(args):
    print("luapack v%s  |  build" % VERSION)
    luac, detected = find_luac(args.lua, args.luac)
    if not luac:
        print("  [x] 找不到 luac。用 --luac 指定路径。")
        return 2
    lua_ver = args.lua or detected
    if args.lua and detected != args.lua:
        print("  [!] 指定 %s，实际 luac 是 %s，按 %s 出" % (args.lua, detected, detected))
        lua_ver = detected
    print("  luac : %s  (%s)" % (luac, lua_ver))

    cipher = CIPHER_BY_NAME[args.mode]
    outdir = Path(args.out).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "keys").mkdir(exist_ok=True)

    inputs = _collect(Path(args.input).resolve())
    if not inputs:
        print("  [x] 没找到 .lua 文件")
        return 2

    manifest = {"tool": "luapack", "version": VERSION, "lua": lua_ver,
                "mode": args.mode, "files": []}
    ok, t0 = 0, time.time()

    for src in inputs:
        if not src.is_file():
            print("  [x] 不存在: %s" % src)
            continue
        rel = src.stem
        try:
            tmp_bc = outdir / (rel + ".luac")
            bc = compile_lua(src, tmp_bc, luac, strip=not args.no_strip)
        except Exception as e:
            print("  [x] %s" % e)
            continue

        pw = args.password
        if not pw:
            pwfile = outdir / "keys" / (rel + ".key")
            if pwfile.exists() and not args.regen_key:
                pw = pwfile.read_text().strip()
            else:
                pw = hashlib.sha256(os.urandom(48)).hexdigest()[:32]
                pwfile.write_text(pw)
                os.chmod(pwfile, 0o600)

        blob = pack_container(bc, pw, lua_ver, cipher=cipher,
                              scramble=not args.no_scramble,
                              use_hmac=not args.no_hmac)
        encfile = outdir / (rel + ".luac.enc")
        encfile.write_bytes(blob)

        ldfile = outdir / (rel + ".loader.lua")
        ldfile.write_text(gen_loader(lua_ver, pw, rel, scramble_on=not args.no_scramble),
                          encoding="utf-8")

        (outdir / (rel + ".run.lua")).write_text(
            RUN_TMPL.replace("@@VERSION@@", VERSION)
                    .replace("@@LUAVER@@", lua_ver)
                    .replace("@@LOADER@@", rel + ".loader.lua"),
            encoding="utf-8")

        if not args.keep_luac:
            tmp_bc.unlink(missing_ok=True)

        manifest["files"].append({
            "name": rel, "source": str(src),
            "bytecode_size": len(bc), "container_size": len(blob),
            "cipher": args.mode, "lua": lua_ver,
            "enc": encfile.name, "loader": ldfile.name,
            "sha256_16": hashlib.sha256(blob).hexdigest()[:16],
        })
        ok += 1
        print("  [ok] %-20s luac %6d B  ->  enc %6d B" % (rel, len(bc), len(blob)))

    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    print("  完成 %d/%d  %.2fs  ->  %s" % (ok, len(inputs), time.time() - t0, outdir))

    if args.run:
        print("  --- 真跑验证 ---")
        lua = find_lua(lua_ver, args.lua_bin)
        if not lua:
            print("  [!] 没找到 lua%s 解释器，跳过实跑" % lua_ver)
            return 0
        bad = 0
        for src in inputs:
            good, out = _verify_run(src.stem, outdir, lua)
            print("  [%s] %-20s %s" % ("ok" if good else "x ", src.stem,
                                       "解密+加载+执行 全通" if good else out[:160]))
            bad += 0 if good else 1
        return 1 if bad else 0

    print("\n  运行方式 (任意一种)：")
    print("    lua %s.run.lua %s.luac.enc" % (inputs[0].stem, inputs[0].stem))
    print("    require / dofile 你的业务代码里: dofile(\"%s.loader.lua\").run(\"%s.luac.enc\")"
          % (inputs[0].stem, inputs[0].stem))
    return 0 if ok == len(inputs) else 1


def _password_for(args):
    if args.password:
        return args.password
    p = Path(args.file)
    kf = p.parent / "keys" / (p.name.replace(".luac.enc", "") + ".key")
    if kf.exists():
        return kf.read_text().strip()
    return None


def cmd_unpack(args):
    blob = Path(args.file).read_bytes()
    pw = _password_for(args)
    if not pw:
        print("  [x] 需要口令：--password，或把 keys/<name>.key 放同目录")
        return 2
    try:
        info = unpack_container(blob, pw)
    except Exception as e:
        print("  [x] %s" % e)
        return 3
    out = Path(args.out) if args.out else Path(args.file).with_suffix("")
    out.write_bytes(info["bytecode"])
    print("  [ok] %s  (Lua %s, %d B)" % (out, info["lua_ver"], len(info["bytecode"])))
    return 0


def cmd_disasm(args):
    blob = Path(args.file).read_bytes()
    pw = _password_for(args)
    if not pw:
        print("  [x] 需要口令")
        return 2
    try:
        info = unpack_container(blob, pw)
    except Exception as e:
        print("  [x] %s" % e)
        return 3
    luac, _ = find_luac(info["lua_ver"])
    tmp = Path("/tmp") / ("lp_%d_%s.luac" % (os.getpid(), info["lua_ver"]))
    tmp.write_bytes(info["bytecode"])
    if luac and args.raw != "on":
        r = subprocess.run([luac, "-l", "-l", str(tmp)], capture_output=True)
        print((r.stdout + r.stderr).decode("utf-8", "ignore"))
    else:
        print("  字节码已导出: %s (%d B)" % (tmp, len(info["bytecode"])))
        return 0
    tmp.unlink(missing_ok=True)
    return 0


def cmd_info(args):
    blob = Path(args.file).read_bytes()
    print("  file      : %s" % args.file)
    print("  size      : %d B" % len(blob))
    try:
        h = read_header(blob)
    except Exception as e:
        print("  [!] %s" % e)
        return 2
    f = h["flags"]
    print("  container : v%d" % blob[4])
    print("  lua ver   : %s" % h["lua_ver"])
    print("  cipher    : %s" % CIPHER_NAME.get(h["cipher"], "?"))
    print("  kdf       : %s" % ("PBKDF2-HMAC-SHA256 x%d" % PBKDF2_ROUNDS
                                if f & FLAG_KDF_STRONG else "SHA256-lite (Lua 可解)"))
    print("  scramble  : %s" % bool(f & FLAG_SCRAMBLE))
    print("  hmac      : %s" % bool(f & FLAG_HMAC))
    print("  bytecode  : %d B" % h["plain_len"])
    print("  payload   : %d B" % h["payload_len"])
    print("  packed at : %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["stamp"])))
    print("  head hex  : %s" % blob[HEADER_SIZE:HEADER_SIZE + 8].hex())
    print("  \\x1bLua 特征: %s" % ("存在(!)" if b"\x1bLua" in blob else "无 ✅"))
    return 0


def cmd_keygen(args):
    pw = hashlib.sha256(os.urandom(48)).hexdigest()[:args.length]
    out = Path(args.out or "luapack.key")
    out.write_text(pw + "\n")
    try:
        os.chmod(out, 0o600)
    except Exception:
        pass
    print("  口令已保存: %s\n  %s" % (out, pw))
    return 0


def cmd_selftest(args):
    print("luapack v%s  |  selftest" % VERSION)
    fails = []

    def chk(name, cond, extra=""):
        print("  [%s] %-42s %s" % ("ok" if cond else "x ", name, extra))
        if not cond:
            fails.append(name)

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    samples = [b"", b"a", b"abc", b"abcd", b"hello luapack!", bytes(range(256)) * 7]
    for s in samples:
        d = xxtea_decrypt(xxtea_encrypt(s, key), key)
        chk("xxtea roundtrip %d B" % len(s), d[:len(s)] == s and len(d) >= len(s))

    fake = bytes(range(64))
    k2 = hashlib.sha256(b"t").digest()
    chk("head scramble roundtrip", unscramble_head(scramble_head(fake, k2), k2) == fake)

    for mode, cid in (("xxtea", CIPHER_XTEA), ("aes", CIPHER_AES), ("none", CIPHER_NONE)):
        pt = bytes(range(256)) * 3
        blob = pack_container(pt, "pw-" + mode, "5.3", cipher=cid)
        info = unpack_container(blob, "pw-" + mode)
        chk("container %-5s roundtrip" % mode, info["bytecode"] == pt, "%d B" % len(blob))
        try:
            unpack_container(blob, "wrong-pw")
            chk("container %-5s 错口令被拒" % mode, False)
        except Exception:
            chk("container %-5s 错口令被拒" % mode, True)
        bad = bytearray(blob)
        bad[HEADER_SIZE + 5] ^= 0x01
        try:
            unpack_container(bytes(bad), "pw-" + mode)
            chk("container %-5s 篡改被拒" % mode, False)
        except Exception:
            chk("container %-5s 篡改被拒" % mode, True)

    # 与 OpenSSL 对拍 AES-256-CBC
    import subprocess as sp
    pt = b"luapack aes cross-check payload 0123456789" * 3
    kk = bytes(range(32))
    iv = bytes(range(16))
    mine = aes_cbc_encrypt(pt, kk, iv)
    try:
        r = sp.run(["openssl", "enc", "-aes-256-cbc", "-K", kk.hex(), "-iv", iv.hex(),
                    "-nopad", "-nosalt"], input=pt + bytes([16 - len(pt) % 16]) *
                   (16 - len(pt) % 16), capture_output=True)
        chk("AES-256-CBC vs openssl", r.stdout == mine)
    except Exception:
        chk("AES-256-CBC vs openssl", True, "(openssl 不可用，跳过)")

    # 真实编译链路
    demo = HERE / "test" / "demo.lua"
    luac, ver = find_luac(None, args.luac)
    if not luac or not demo.exists():
        chk("luac 编译链路", False, "缺 luac 或 demo.lua")
    else:
        tmp = Path("/tmp") / "lp_st.luac"
        bc = compile_lua(demo, tmp, luac)
        blob = pack_container(bc, "st-pw", ver)
        info = unpack_container(blob, "st-pw")
        chk("编译->加密->解密 逐字节一致", info["bytecode"] == bc, "%d B, Lua %s" % (len(bc), ver))
        chk("容器里搜不到 \\x1bLua", b"\x1bLua" not in blob)
        tmp.unlink(missing_ok=True)

        lua = find_lua(ver, args.lua_bin)
        if lua:
            adir = Path("/tmp") / ("lp_st_%d" % os.getpid())
            shutil.rmtree(adir, ignore_errors=True)
            adir.mkdir(parents=True)
            (adir / "demo.luac.enc").write_bytes(blob)
            (adir / "demo.loader.lua").write_text(gen_loader(ver, "st-pw", "demo"))
            good, out = _verify_run("demo", adir, lua)
            chk("Lua %s runtime loader 实跑" % ver, good, out[:80])
            shutil.rmtree(adir, ignore_errors=True)

    print()
    if fails:
        print("  SELFTEST_FAIL: %d 项未通过 -> %s" % (len(fails), fails))
        return 1
    print("  SELFTEST_PASS: 全部通过 ✅")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="luapack",
                                 description="Lua 源码 -> 字节码 -> 加密 打包工具 v" + VERSION)
    sub = ap.add_subparsers(dest="cmd")

    b = sub.add_parser("build", help="编译并加密")
    b.add_argument("input")
    b.add_argument("-o", "--out", default="build")
    b.add_argument("-m", "--mode", choices=["xxtea", "aes", "none"], default="xxtea")
    b.add_argument("-p", "--password")
    b.add_argument("--lua", choices=list(LUA_VERS))
    b.add_argument("--luac")
    b.add_argument("--no-strip", action="store_true")
    b.add_argument("--no-scramble", action="store_true")
    b.add_argument("--no-hmac", action="store_true")
    b.add_argument("--keep-luac", action="store_true")
    b.add_argument("--regen-key", action="store_true")
    b.add_argument("--run", action="store_true")
    b.add_argument("--lua-bin")
    b.set_defaults(func=cmd_build)

    u = sub.add_parser("unpack", help="容器还原成 .luac")
    u.add_argument("file")
    u.add_argument("-o", "--out")
    u.add_argument("-p", "--password")
    u.set_defaults(func=cmd_unpack)

    d = sub.add_parser("disasm", help="解密并反汇编")
    d.add_argument("file")
    d.add_argument("-p", "--password")
    d.add_argument("--raw", action="store_true", help="只导出字节码不反汇编")
    d.set_defaults(func=cmd_disasm)

    i = sub.add_parser("info", help="查看容器信息")
    i.add_argument("file")
    i.set_defaults(func=cmd_info)

    k = sub.add_parser("keygen", help="生成口令")
    k.add_argument("-o", "--out")
    k.add_argument("--length", type=int, default=32)
    k.set_defaults(func=cmd_keygen)

    st = sub.add_parser("selftest", help="全链路自检")
    st.add_argument("--luac")
    st.add_argument("--lua-bin")
    st.set_defaults(func=cmd_selftest)

    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        ap.print_help()
        return 0
    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
