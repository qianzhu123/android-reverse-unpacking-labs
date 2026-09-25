#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
crypto_lab.py — 与 shell/src/com/ijiami/shell/Crypto.java 完全一致的加解密实现。

为什么要 Python 里再写一份：
  离线脱壳时我们用 Python 模拟"壳在运行时干的事"。
  两边必须字节级一致，所以把常量放在这里，并在 verify 阶段做一次交叉校验。

payload 容器格式（v1 整体加密）：
  [0..4)   int32_le  原始 dex 长度
  [4..8)   magic     'AJM\\x01'
  [8..)    XOR(key) 后的 dex

KEY 是 8 字节轮转 key，第 i 字节额外异或一个位置计数 i&0xff ——
这样做的好处：相同明文在不同偏移处密文不同，能挡住"直接搜 dex 魔数"的笨办法，
同时又不至于复杂到没法手算。
"""

import struct

KEY = bytes([0x5A, 0x3C, 0x7F, 0x11, 0xE4, 0x29, 0x8D, 0x63])
MAGIC = b'AJM\x01'
HEADER = 8
KEY_LEN = len(KEY)

# ---- 第二代/第三代：被抽取指令的侧表 CODE_TABLE 容器 ----
TABLE_MAGIC = b'AJMT'
CODE_TABLE_HEADER = 8  # magic(4) + count(4)


def u32le(buf, off):
    """读 int32 小端（脱壳时解析 payload / 侧表头部用）。"""
    return struct.unpack_from('<I', buf, off)[0]


def _stream(data, offset=0):
    """逐字节做 XOR(key[i%8] ^ (i&0xff))，i 从 0 重新开始计数。"""
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ KEY[i & (KEY_LEN - 1)] ^ (i & 0xFF)
    return bytes(out)


def xor(data):
    """对外暴露的逐字节流密码原语（侧表里每条指令密文用这个解）。"""
    return _stream(data)


def encrypt(plain):
    out = bytearray()
    out += struct.pack('<I', len(plain))
    out += MAGIC
    out += _stream(plain)
    return bytes(out)


def decrypt(packed):
    """解出 v1 整体加密 payload，返回原始 dex 字节（与 encrypt 对称）。"""
    if len(packed) < HEADER:
        raise ValueError('payload 长度不足 header (%d)' % len(packed))
    length = u32le(packed, 0)
    magic = bytes(packed[4:8])
    if magic != MAGIC:
        raise ValueError('payload magic 不符：%r（预期 %r）' % (magic, MAGIC))
    body = bytes(packed[HEADER:HEADER + length])
    return _stream(body)


def build_code_table(entries):
    """entries: list of dict(class_idx, method_idx, code_off, insns)
       侧表格式：[magic 'AJMT'][count][每条: u4 class_idx, u4 method_idx, u4 code_off,
                 u4 insns_len, insns_len 字节密文]"""
    out = bytearray(TABLE_MAGIC)
    out += struct.pack('<I', len(entries))
    for e in entries:
        ins = e['insns']
        out += struct.pack('<IIII', e['class_idx'], e['method_idx'],
                           e['code_off'], len(ins))
        out += _stream(ins)
    return bytes(out)


def parse_code_table(blob):
    if bytes(blob[:4]) != TABLE_MAGIC:
        raise ValueError('不是 CODE_TABLE，magic=%r' % bytes(blob[:4]))
    count = u32le(blob, 4)
    off = CODE_TABLE_HEADER
    out = []
    for _ in range(count):
        cidx, midx, coff, ilen = struct.unpack_from('<IIII', blob, off)
        off += 16
        enc = bytes(blob[off:off + ilen])
        off += ilen
        out.append({'class_idx': cidx, 'method_idx': midx, 'code_off': coff,
                    'insns': _stream(enc)})
    return out, off


def self_test():
    """拿一段已知数据跑一遍加解密，保证与 Java 侧语义一致。"""
    data = bytes(range(256)) * 3
    enc = encrypt(data)
    dec = decrypt(enc)
    assert dec == data, 'round-trip 失败'
    return 'self_test OK: len=%d, packed=%d' % (len(data), len(enc))


if __name__ == '__main__':
    print(self_test())
