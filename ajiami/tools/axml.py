#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
axml.py — 最小 AndroidManifest 二进制 XML (AXML) 解析器。

为什么不直接用 aapt2 dump xmltree：
  本机 aapt2 37.0.0 的 dump xmltree 改了接口（要先 --file 抽出的文件，还报错缺 apk），
  不同 build-tools 版本输出格式还不一样。为了让判定工具"只依赖结构、不依赖某个外部工具"，
  这里手写解析：读 StringPool + ResourceMap + 元素/属性树，精确拿到
  <application android:name> 和四大组件的类名。

输出：parse(blob) -> {'application': str|None, 'components': {tag:[class...]}, 'elements': [...]}
"""

import struct

TYPE_STRING = 0x03

ATTR_NAME_RESID = 0x01010003  # android:name 的资源 id（标准固定值）

CHUNK_XML = 0x0003
CHUNK_STRING_POOL = 0x0001
CHUNK_RESOURCE_MAP = 0x0180
CHUNK_START_NS = 0x0100
CHUNK_START_ELEMENT = 0x0102


def _u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def _u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def _read_string_pool(blob, off, size):
    """返回字符串列表（UTF-8 或 UTF-16，按 flags 自动）。"""
    str_count = _u32(blob, off + 8)
    _style_count = _u32(blob, off + 12)
    flags = _u32(blob, off + 16)
    strings_start = _u32(blob, off + 20)
    header_size = _u16(blob, off + 2)
    is_utf8 = bool(flags & 0x100)
    data_base = off + strings_start
    # 偏移表在 chunk 头之后（off + header_size），表项值相对 data_base
    table_base = off + header_size
    offsets = [_u32(blob, table_base + i * 4) for i in range(str_count)]
    out = []
    for o in offsets:
        p = data_base + o
        if is_utf8:
            # u8 length, u8 转义, 然后 UTF-8 字节, 然后 0x00
            n = blob[p]; p += 1
            if n & 0x80:
                n = ((n & 0x7F) << 8) | blob[p]; p += 1
            # 跳过 16 位长度
            _ = blob[p]; p += 1
            if _ & 0x80:
                p += 1
            end = blob.index(0, p)
            out.append(blob[p:end].decode('utf-8', 'replace'))
        else:
            n = _u16(blob, p); p += 2
            end = p + n * 2
            raw = blob[p:end]
            out.append(raw.decode('utf-16-le', 'replace'))
    return out


def _read_resource_map(blob, off, size):
    """返回 {res_id: 对应 string pool 下标}。"""
    header_size = _u16(blob, off + 2)
    count = (size - header_size) // 4
    m = {}
    for i in range(count):
        rid = _u32(blob, off + header_size + i * 4)
        m[rid] = i
    return m


def parse(blob):
    if blob[:4] != b'\x03\x00\x08\x00':  # RES_XML_TYPE 的魔数小端
        # 有的 aapt2 头是 03 00 08 00，这里做个容错
        pass
    strings = []
    resmap = {}          # res_id -> string pool index
    elements = []        # (tag_name, {attr_name: attr_value})
    # aapt2 把所有子 chunk 嵌在根 XML chunk 内部，从偏移 8（根头之后）开始
    pos = 8
    # 第一遍：先把 StringPool 和 ResourceMap 读完
    while pos + 8 <= len(blob):
        ctype = _u16(blob, pos)
        csize = _u32(blob, pos + 4)
        if ctype == CHUNK_STRING_POOL:
            strings = _read_string_pool(blob, pos, csize)
        elif ctype == CHUNK_RESOURCE_MAP:
            resmap = _read_resource_map(blob, pos, csize)
        if csize <= 0:
            break
        pos += csize

    # 第二遍：扫元素树
    pos = 8
    stack = []
    while pos + 8 <= len(blob):
        ctype = _u16(blob, pos)
        csize = _u32(blob, pos + 4)
        if ctype == CHUNK_START_ELEMENT:
            line = _u32(blob, pos + 8)
            name_idx = _u32(blob, pos + 16)  # node.name：aapt2 下为 string pool 下标
            if 0 <= name_idx < len(strings):
                tag = strings[name_idx]
            else:
                tag = '<id 0x%08x>' % name_idx
            # 属性区
            attr_start = _u16(blob, pos + 20)
            attr_size = _u16(blob, pos + 22)
            attr_count = _u16(blob, pos + 24)
            attrs = {}
            ap = pos + attr_start
            for _ in range(attr_count):
                a_ns = _u32(blob, ap)
                a_name = _u32(blob, ap + 4)     # aapt2 下为资源 id
                a_raw = _u32(blob, ap + 8)      # 字面量（字符串下标）
                a_type = blob[ap + 15]          # Res_value.type
                a_data = _u32(blob, ap + 12)
                aname = resmap.get(a_name)
                if aname is not None and 0 <= aname < len(strings):
                    key = strings[aname]
                else:
                    key = '<res 0x%08x>' % a_name
                if a_type == TYPE_STRING:
                    val = strings[a_data] if 0 <= a_data < len(strings) else None
                else:
                    val = a_data
                attrs[key] = val
                ap += attr_size
            elements.append((tag, attrs))
            stack.append(tag)
        elif ctype == 0x0103:  # END_ELEMENT
            if stack:
                stack.pop()
        if csize <= 0:
            break
        pos += csize

    # 组装结果
    components = {}
    application = None
    for tag, attrs in elements:
        if tag == 'application':
            application = attrs.get('name')
        elif tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
            n = attrs.get('name')
            if n:
                components.setdefault(tag, []).append(n)
    return {'application': application, 'components': components, 'elements': elements}


if __name__ == '__main__':
    import sys, zipfile
    z = zipfile.ZipFile(sys.argv[1])
    print(parse(z.read('AndroidManifest.xml')))
