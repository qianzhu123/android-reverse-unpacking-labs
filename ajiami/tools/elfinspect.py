#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
elfinspect.py — 极简 ELF 解析（纯 Python，零依赖）

为什么要有它：
    SO 加壳 / 自定义 Linker 的信号**全部写在 ELF 结构里**，不解析 ELF 就只能靠文件名和熵猜。
    之前 detect.py 对 lib/*.so 只算了个文件级熵，等于没看 Native 层。

工程量原则：只解析够用的部分（ELF 头 / Program Header / Section Header / 粗略符号），
不实现重定位、指令解码。目标是**发现异常结构**，不是替代 readelf。

-exported API:
    inspect(blob, name=None) -> dict
"""

import struct

ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
SHT_NOBITS = 8
PF_X = 0x1

# 正常 Android .so 里几乎必然出现的标准节名
EXPECTED_SECTIONS = ('.text', '.rodata', '.data', '.bss', '.dynsym', '.dynstr',
                     '.hash', '.gnu.hash', '.got', '.plt', '.rela.dyn',
                     '.rela.plt', '.dynamic', '.comment', '.note')


def shannon_entropy(b):
    try:
        import apkutil
        return apkutil.shannon_entropy(b)
    except Exception:
        import math
        if not b:
            return 0.0
        freq = [0] * 256
        for x in b:
            freq[x] += 1
        n = float(len(b))
        return -sum((c / n) * math.log(c / n, 2) for c in freq if c)


def _hent_end(blob):
    """返回机器字长是否为 64 位。"""
    return blob[4] == 2


def inspect(blob, name=None):
    out = {'name': name or '', 'size': len(blob), 'error': None,
           'anomalies': [], 'notes': []}
    if len(blob) < 64 or blob[:4] != b'\x7fELF':
        out['error'] = '不是 ELF 文件'
        return out

    ei_class = blob[4]
    ei_data = blob[5]
    if ei_data != 1:                       # 只处理 little-endian（Android 都是）
        out['error'] = '非 little-endian，暂不支持'
        return out
    is64 = (ei_class == 2)
    out['class'] = 'ELF%d' % (64 if is64 else 32)

    try:
        if is64:
            (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff,
             _flags, _ehsize, e_phentsize, e_phnum, e_shentsize,
             e_shnum, e_shstrndx) = struct.unpack_from('<HHIQQQIHHHHHH', blob, 16)
        else:
            (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff,
             _flags, _ehsize, e_phentsize, e_phnum, e_shentsize,
             e_shnum, e_shstrndx) = struct.unpack_from('<HHIIIIIHHHHHH', blob, 16)
    except Exception as e:
        out['error'] = 'ELF 头解析失败：%s' % e
        return out

    out['type'] = 'ET_DYN(共享对象)' if e_type == ET_DYN else ('e_type=%d' % e_type)
    out['machine'] = '0x%X' % e_machine
    out['entry'] = e_entry

    # ---- Program Headers
    phs = []
    if e_phoff and e_phnum:
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            try:
                # 字段位置必须按各自 Elf*_Phdr 布局逐项取，不能靠顺序解包
                #   Elf64_Phdr: type,flags,offset,vaddr,paddr,filesz,memsz,align
                #   Elf32_Phdr: type,offset,vaddr,paddr,filesz,memsz,flags,align
                p_type = struct.unpack_from('<I', blob, off)[0]
                if is64:
                    p_flags = struct.unpack_from('<I', blob, off + 4)[0]
                    p_filesz = struct.unpack_from('<Q', blob, off + 32)[0]
                    p_memsz = struct.unpack_from('<Q', blob, off + 40)[0]
                else:
                    p_filesz = struct.unpack_from('<I', blob, off + 16)[0]
                    p_memsz = struct.unpack_from('<I', blob, off + 20)[0]
                    p_flags = struct.unpack_from('<I', blob, off + 24)[0]
            except Exception:
                break
            phs.append({'type': p_type, 'filesz': p_filesz,
                        'memsz': p_memsz, 'flags': p_flags})
    out['ph_count'] = len(phs)
    out['exec_load'] = len([p for p in phs if p['type'] == PT_LOAD and p['flags'] & PF_X])

    # ---- Section Headers
    secs = []
    if e_shoff and e_shnum and e_shstrndx < e_shnum:
        try:
            if is64:
                _n, _t, _f, _a, _o, sh_size, sh_link, _info, _al, sh_entsize = \
                    struct.unpack_from('<II', blob, e_shoff) + (0,) * 8
                shstr_off = struct.unpack_from('<Q', blob,
                                               e_shoff + e_shstrndx * e_shentsize + 24)[0]
            else:
                shstr_off = struct.unpack_from('<I', blob,
                                               e_shoff + e_shstrndx * e_shentsize + 16)[0]
            shstr_size = struct.unpack_from(
                '<Q' if is64 else '<I', blob,
                e_shoff + e_shstrndx * e_shentsize + (32 if is64 else 20))[0]
            strtab = blob[shstr_off:shstr_off + shstr_size]
        except Exception:
            strtab = b''

        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            try:
                if is64:
                    (sh_name, sh_type, _fl, _ad, sh_offset,
                     sh_size, _lk, _in, _al, _es) = struct.unpack_from('<IIQQQQIIQQ', blob, off)
                else:
                    (sh_name, sh_type, _fl, _ad, sh_offset,
                     sh_size, _lk, _in, _al, _es) = struct.unpack_from('<IIIIIIIIII', blob, off)
            except Exception:
                break
            nm = ''
            if strtab and sh_name < len(strtab):
                end = strtab.find(b'\x00', sh_name)
                nm = strtab[sh_name:end if end >= 0 else len(strtab)].decode('latin1')
            secs.append({'name': nm, 'type': sh_type, 'offset': sh_offset, 'size': sh_size})

    out['sh_count'] = len(secs)
    out['sections'] = [s['name'] for s in secs if s['name']]

    # ---- 每个节求熵（只对有内容的节）
    ent = []
    for s in secs:
        if s['type'] == SHT_NOBITS or s['size'] == 0 or not s['name']:
            continue
        blob_seg = blob[s['offset']:s['offset'] + min(s['size'], 1 << 20)]
        if not blob_seg:
            continue
        # 大节抽样，避免把内存喂爆
        step = max(1, len(blob_seg) // (1 << 18))
        sample = blob_seg[::step]
        ent.append({'name': s['name'], 'entropy': round(shannon_entropy(sample), 4),
                    'size': s['size'], 'offset': s['offset']})
    ent.sort(key=lambda x: -x['entropy'])
    out['section_entropy'] = ent[:8]

    text = [e for e in ent if e['name'] == '.text']
    out['text_entropy'] = text[0]['entropy'] if text else None

    out['has_dynsym'] = '.dynsym' in out['sections']
    out['has_dynstr'] = '.dynstr' in out['sections']
    # JNI 入口江湖位的粗查：导出符号名里有没有 JNI_OnLoad
    out['has_jni_onload'] = b'JNI_OnLoad' in blob

    # ---------------------- 异常判定
    A = out['anomalies']
    if e_type == ET_DYN and out['sh_count'] == 0 and out['exec_load']:
        A.append('no_section_headers：共享对象却完全没有节头表 —— 自定义 Linker 的典型形态（自己按 Program Header 装载）')
    if not out['has_dynsym'] and out['exec_load']:
        A.append('no_dynsym：没有动态符号表，无法被标准 dlopen 解析，疑似自实现符号解析')
    if not out['has_dynstr']:
        A.append('no_dynstr：没有动态字符串表')
    if out['text_entropy'] is not None and out['text_entropy'] > 7.0:
        A.append('high_text_entropy：.text 节熵 %.3f > 7.0 —— 代码段被加密/压缩' % out['text_entropy'])
    std = [n for n in out['sections'] if n in EXPECTED_SECTIONS]
    if out['sh_count'] and len(std) <= 1:
        A.append('few_standard_sections：标准节只剩 %d 个（%s），节表被裁剪/混淆' % (len(std), ', '.join(std[:5])))

    # 注意：SO VMP 无法靠这些静态特征确认 —— 解释器也可能是普通大函数。
    if A:
        out['notes'].append('以上为 SO【加壳/自实现 Linker】的结构性信号；'
                            'SO VMP 静态不可确认，需动态/对比 trace 才能定性。')
    return out
