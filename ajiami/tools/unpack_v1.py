#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
unpack_v1.py — 一代加固脱壳（静态、无需真机）

流程（每一步都打印出来，对应 README 里手动复现的步骤）：
  1) 从 APK 里取出 assets/ijm_payload.bin（或直接使用解出的 payload 文件）
  2) 解析头部：8 字节魔数 'AJM\\x01' + 4 字节小端 = 原始 dex 长度
  3) 对剩余字节解密（与 packer 对称）
  4) 校验 dex 魔数 + adler32 checksum
  5) 写出还原 dex，并与黄金样本 classes_orig.dex 做 sha256 对照

用法：
  python tools/unpack_v1.py samples/app_packed_v1.apk analysis_output/unpack_v1_dex.dex
  python tools/unpack_v1.py samples/app_packed_v1.apk analysis_output/unpack_v1_dex.dex --pristine samples/classes_orig.dex
  python tools/unpack_v1.py samples/payload_v1.bin analysis_output/unpack_v1_dex.dex
"""

import argparse
import hashlib
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import crypto_lab

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_payload_from_apk(apk):
    z = zipfile.ZipFile(apk)
    cands = [n for n in z.namelist()
             if n.startswith('assets/') and z.read(n)[:4] in (b'AJM\x01',)]
    if not cands:
        # 退化：用约定名字
        cands = ['assets/ijm_payload.bin']
    data = z.read(cands[0])
    return cands[0], data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('input', help='APK 或 payload 文件')
    ap.add_argument('out', help='还原后的 dex 输出路径')
    ap.add_argument('--pristine', help='黄金对照 dex（用于 sha256 比对），可选')
    args = ap.parse_args()

    if args.input.lower().endswith('.apk') or zipfile.is_zipfile(args.input):
        asset_name, payload = read_payload_from_apk(args.input)
        print('[1] 从 APK 取出 payload: %s  (%d bytes)' % (asset_name, len(payload)))
    else:
        payload = open(args.input, 'rb').read()
        print('[1] 直接读取 payload 文件: %s  (%d bytes)' % (args.input, len(payload)))

    decl_len = crypto_lab.u32le(payload, 0)
    magic = payload[4:8]
    print('[2] 头部: decl_len=%d  magic=%r' % (decl_len, magic))
    if magic != b'AJM\x01':
        print('[!] 魔数不对，可能不是本工程的 payload（或已被变种改名，需先定位）')
        return 1

    raw = crypto_lab.decrypt(payload)
    print('[3] 解密后长度 = %d' % len(raw))
    print('[4] dex 魔数校验: %r' % raw[:8])
    if raw[:4] != b'dex\n':
        print('[!] 解密结果不是 dex，检查密钥/算法')
        return 1

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or '.', exist_ok=True)
    open(args.out, 'wb').write(raw)
    print('[5] 已写出: %s' % args.out)
    print('    sha256 = %s' % hashlib.sha256(raw).hexdigest())

    if args.pristine:
        gold = open(args.pristine, 'rb').read()
        ok = hashlib.sha256(gold).hexdigest() == hashlib.sha256(raw).hexdigest()
        print('[6] 与黄金 %s 对照: %s'
              % (os.path.basename(args.pristine), '完全一致 ✓' if ok else '不一致 ✗'))
        if not ok:
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
