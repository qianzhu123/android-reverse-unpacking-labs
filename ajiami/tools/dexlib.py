#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
dexlib.py — 本工程自建的最小 dex 解析 / 改写库。

为什么自己写而不用现成库：
  本工程的目的是「把 dex 结构讲清楚」，判定和脱壳都要落到具体字节偏移上，
  所以这里全部按 dex_format spec 手写，每一步都能对应到十六进制编辑器里的位置。

覆盖范围：
  header / map_list / string_ids / type_ids / proto_ids / field_ids /
  method_ids / class_defs / class_data / code_item
  + 改写后重算 adler32 checksum 与 sha1 signature

字节布局备忘（小端）：
  DexHeader       0x00 - 0x70
    magic[8]      0x00   "dex\\n037\\0"
    checksum      0x08   adler32(data[12:])
    signature[20] 0x0c   sha1(data[32:])
    file_size     0x20
    header_size   0x24   恒为 0x70
    endian_tag    0x28   恒为 0x12345678
    map_off       0x34
    string_ids    0x38(size) 0x3c(off)
    type_ids      0x40 / 0x44
    proto_ids     0x48 / 0x4c
    field_ids     0x50 / 0x54
    method_ids    0x58 / 0x5c
    class_defs    0x60 / 0x64
    data          0x68 / 0x6c
"""

import hashlib
import struct
import zlib

HEADER_SIZE = 0x70
CODE_ITEM_HEADER = 16  # registers/ins/outs/tries(u2 x4) + debug_info_off(u4) + insns_size(u4)


# ---------------------------------------------------------------- 基础读取
def _u2(b, o):
    return struct.unpack_from('<H', b, o)[0]


def _u4(b, o):
    return struct.unpack_from('<I', b, o)[0]


def read_uleb128(buf, off):
    """返回 (value, new_off)。dex 里所有 size / index diff 都是 uleb128。"""
    result = 0
    shift = 0
    while True:
        byte = buf[off]
        result |= (byte & 0x7F) << shift
        off += 1
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, off


def encode_uleb128(value):
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def mutf8_decode(raw):
    """MUTF-8 → str。dex 的字符串不是标准 UTF-8（0xC0 0x80 表示 U+0000）。"""
    out = []
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c < 0x80:
            out.append(chr(c))
            i += 1
        elif c & 0xE0 == 0xC0 and i + 1 < n:
            out.append(chr(((c & 0x1F) << 6) | (raw[i + 1] & 0x3F)))
            i += 2
        elif c & 0xF0 == 0xE0 and i + 2 < n:
            out.append(chr(((c & 0x0F) << 12) | ((raw[i + 1] & 0x3F) << 6)
                           | (raw[i + 2] & 0x3F)))
            i += 3
        else:
            out.append('?')
            i += 1
    return ''.join(out)


# ---------------------------------------------------------------- Dex
class Dex(object):
    def __init__(self, data):
        self.data = bytearray(data)
        if bytes(self.data[:8])[:4] != b'dex\n':
            raise ValueError('不是 dex 文件，magic=%r' % bytes(self.data[:8]))
        d = self.data
        self.magic = bytes(d[0:8]).decode('latin1')
        self.checksum = _u4(d, 0x08)
        self.signature = bytes(d[0x0C:0x20])
        self.file_size = _u4(d, 0x20)
        self.header_size = _u4(d, 0x24)
        self.endian_tag = _u4(d, 0x28)
        self.map_off = _u4(d, 0x34)
        self.string_ids_size = _u4(d, 0x38)
        self.string_ids_off = _u4(d, 0x3C)
        self.type_ids_size = _u4(d, 0x40)
        self.type_ids_off = _u4(d, 0x44)
        self.proto_ids_size = _u4(d, 0x48)
        self.proto_ids_off = _u4(d, 0x4C)
        self.field_ids_size = _u4(d, 0x50)
        self.field_ids_off = _u4(d, 0x54)
        self.method_ids_size = _u4(d, 0x58)
        self.method_ids_off = _u4(d, 0x5C)
        self.class_defs_size = _u4(d, 0x60)
        self.class_defs_off = _u4(d, 0x64)
        self.data_size = _u4(d, 0x68)
        self.data_off = _u4(d, 0x6C)
        self._str_cache = {}

    # --------------------------- header 校验
    def check(self):
        """返回 (checksum_ok, signature_ok, size_ok, endian_ok)"""
        b = bytes(self.data)
        return (
            zlib.adler32(b[12:]) & 0xFFFFFFFF == self.checksum,
            hashlib.sha1(b[32:]).digest() == self.signature,
            len(b) == self.file_size,
            self.endian_tag == 0x12345678,
        )

    def finalize(self):
        """改写 dex 后必须调用：重算 checksum + signature，返回 bytes。

        顺序不能反！spec 是：
            signature = sha1(data[32:])
            checksum  = adler32(data[12:])      ← 覆盖的是含 signature 的区域
        如果先算 checksum 再改 signature，checksum 就对应了旧的 license ... 详见 README §7.3：
        本机第一次实现就是这个顺序错误，导致还原出的 dex 在 dexdump 下报 Bad checksum。
        """
        if len(self.data) != self.file_size:
            struct.pack_into('<I', self.data, 0x20, len(self.data))  # file_size
        self.signature = hashlib.sha1(bytes(self.data[32:])).digest()
        self.data[0x0C:0x20] = self.signature
        self.checksum = zlib.adler32(bytes(self.data[12:])) & 0xFFFFFFFF
        struct.pack_into('<I', self.data, 0x08, self.checksum)
        return bytes(self.data)

    # --------------------------- 字符串表
    def string_at(self, idx):
        """通过 string_ids 索引取字符串"""
        if idx == 0xFFFFFFFF:
            return '<none>'
        if idx in self._str_cache:
            return self._str_cache[idx]
        if idx >= self.string_ids_size:
            raise IndexError('string_idx %d 越界 (size=%d)' % (idx, self.string_ids_size))
        off = _u4(self.data, self.string_ids_off + idx * 4)
        size, p = read_uleb128(self.data, off)
        end = self.data.index(b'\x00', p)
        s = mutf8_decode(bytes(self.data[p:end]))
        self._str_cache[idx] = s
        return s

    def all_strings(self):
        for i in range(self.string_ids_size):
            yield i, self.string_at(i)

    def find_strings(self, needle):
        return [(i, s) for i, s in self.all_strings() if needle in s]

    # --------------------------- 类型 / 原型 / 成员
    def type_at(self, idx):
        if idx == 0xFFFFFFFF:
            return '<none>'
        return self.string_at(_u4(self.data, self.type_ids_off + idx * 4))

    def proto_at(self, idx):
        off = self.proto_ids_off + idx * 12
        shorty = _u4(self.data, off)
        ret = _u4(self.data, off + 4)
        params = _u4(self.data, off + 8)
        return self.string_at(shorty), self.type_at(ret), params

    def field_at(self, idx):
        off = self.field_ids_off + idx * 8
        clazz = _u2(self.data, off)
        typ = _u2(self.data, off + 2)
        name = _u4(self.data, off + 4)
        return self.type_at(clazz), self.type_at(typ), self.string_at(name)

    def method_at(self, idx):
        off = self.method_ids_off + idx * 8
        clazz = _u2(self.data, off)
        proto = _u2(self.data, off + 2)
        name = _u4(self.data, off + 4)
        return self.type_at(clazz), idx, proto, self.string_at(name)

    # --------------------------- map_list
    def map_items(self):
        items = []
        if self.map_off == 0:
            return items
        n = _u4(self.data, self.map_off)
        off = self.map_off + 4
        for _ in range(n):
            items.append((_u2(self.data, off), _u4(self.data, off + 4)))
            off += 12
        return items

    # --------------------------- class_def
    def class_def(self, i):
        off = self.class_defs_off + i * 32
        d = self.data
        return {
            'index': i,
            'class_off': off,
            'class_idx': _u4(d, off),
            'access_flags': _u4(d, off + 4),
            'superclass_idx': _u4(d, off + 8),
            'interfaces_off': _u4(d, off + 12),
            'source_file_idx': _u4(d, off + 16),
            'annotations_off': _u4(d, off + 20),
            'class_data_off': _u4(d, off + 24),
            'static_values_off': _u4(d, off + 28),
        }

    def class_defs(self):
        for i in range(self.class_defs_size):
            yield self.class_def(i)

    def class_name(self, cd):
        return self.type_at(cd['class_idx'])

    # --------------------------- class_data
    def class_data(self, off):
        """解析 class_data_item → {'virtual':[...], 'direct':[...]}"""
        if off == 0:
            return {'static_fields': 0, 'instance_fields': 0, 'direct': [], 'virtual': []}
        p = off
        sfs, p = read_uleb128(self.data, p)
        ifs, p = read_uleb128(self.data, p)
        dms, p = read_uleb128(self.data, p)
        vms, p = read_uleb128(self.data, p)

        fields_idx = 0
        for _ in range(sfs):
            diff, p = read_uleb128(self.data, p)
            acc, p = read_uleb128(self.data, p)
            fields_idx += diff
        fields_idx = 0
        for _ in range(ifs):
            diff, p = read_uleb128(self.data, p)
            acc, p = read_uleb128(self.data, p)
            fields_idx += diff

        # direct/virtual 两组 encoded_method 各自独立累加 method_idx_diff
        direct = []
        midx = 0
        for _ in range(dms):
            diff, p = read_uleb128(self.data, p)
            acc, p = read_uleb128(self.data, p)
            code_off, p = read_uleb128(self.data, p)
            midx += diff
            direct.append({'method_idx': midx, 'access_flags': acc,
                           'code_off': code_off, 'entry_off': None})
        virtual = []
        midx = 0
        for _ in range(vms):
            diff, p = read_uleb128(self.data, p)
            acc, p = read_uleb128(self.data, p)
            code_off, p = read_uleb128(self.data, p)
            midx += diff
            virtual.append({'method_idx': midx, 'access_flags': acc,
                            'code_off': code_off, 'entry_off': None})
        return {'static_fields': sfs, 'instance_fields': ifs,
                'direct': direct, 'virtual': virtual}

    # --------------------------- code_item
    def code_item(self, off):
        if off == 0:
            return None
        d = self.data
        reg, ins, outs, tries = struct.unpack_from('<HHHH', d, off)
        dbg, insns_size = struct.unpack_from('<II', d, off + 8)
        insns_off = off + CODE_ITEM_HEADER
        return {
            'off': off,
            'registers_size': reg,
            'ins_size': ins,
            'outs_size': outs,
            'tries_size': tries,
            'debug_info_off': dbg,
            'insns_size': insns_size,              # 单位是 u2 code unit
            'insns_off': insns_off,
            'insns_bytes': insns_size * 2,
            'insns': bytes(d[insns_off:insns_off + insns_size * 2]),
        }

    def read_insns(self, off):
        ci = self.code_item(off)
        return ci['insns'] if ci else b''

    def write_insns(self, off, blob):
        """把字节写回 code_item 的 insns 区（长度必须一致），返回是否成功。"""
        ci = self.code_item(off)
        if ci is None:
            return False
        if len(blob) != ci['insns_bytes']:
            raise ValueError('insns 长度不符：期望 %d，实际 %d'
                             % (ci['insns_bytes'], len(blob)))
        self.data[ci['insns_off']:ci['insns_off'] + ci['insns_bytes']] = blob
        return True

    # --------------------------- 遍历
    def iter_methods(self):
        """产出 (class_name, method 描述 dict)。method dict 含 code_off / access_flags。"""
        for cd in self.class_defs():
            cname = self.class_name(cd)
            data = self.class_data(cd['class_data_off'])
            for kind in ('direct', 'virtual'):
                for m in data[kind]:
                    yield cname, kind, m

    def method_signature(self, m):
        clazz, midx, proto, name = self.method_at(m['method_idx'])
        shorty, ret, _ = self.proto_at(proto)
        return '%s->%s%s' % (clazz, name, shorty)

    # --------------------------- 统计
    def method_code_stats(self):
        """统计有多少方法「有 code_item 但 insns 是全 0」。
           —— 这是识别二代类抽取最关键的量化指标。"""
        total = 0
        with_code = 0
        empty = 0
        per_class = {}
        for cname, kind, m in self.iter_methods():
            total += 1
            if m['code_off'] == 0:
                continue
            with_code += 1
            ci = self.code_item(m['code_off'])
            is_empty = (ci['insns'].count(0) == len(ci['insns'])) and ci['insns_size'] > 0
            if is_empty:
                empty += 1
            st = per_class.setdefault(cname, {'total': 0, 'empty': 0})
            st['total'] += 1
            if is_empty:
                st['empty'] += 1
        return {'total': total, 'with_code': with_code, 'empty': empty,
                'empty_ratio': (empty / with_code) if with_code else 0.0,
                'per_class': per_class}


def load(path):
    with open(path, 'rb') as f:
        return Dex(f.read())


if __name__ == '__main__':
    import sys
    dx = load(sys.argv[1])
    print('magic       :', repr(dx.magic))
    print('file_size   :', dx.file_size, '(实际', len(dx.data), ')')
    print('class_defs  :', dx.class_defs_size)
    print('hands check :', dx.check())
    st = dx.method_code_stats()
    print('methods     : total=%d with_code=%d empty=%d ratio=%.2f%%'
          % (st['total'], st['with_code'], st['empty'], st['empty_ratio'] * 100))
    print('--- classes ---')
    for cd in dx.class_defs():
        print('  %-40s (class_data_off=0x%x)' % (dx.class_name(cd), cd['class_data_off']))
