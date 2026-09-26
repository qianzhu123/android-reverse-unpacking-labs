#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
make_icon.py — 生成 unpacker 的应用图标（产物 unpacker/app_icon.ico）。

设计（纯 Pillow 绘制，无外部素材）：
  · 盾形（加固 / 防护主题）+ 内部亮色核心（被保护的内容）
  · 右下角一块「脱离的碎片」——脱壳后内容与壳分离的视觉隐喻
  · 绘制在 4× 超采样画布上再缩到各尺寸，小图标也平滑
  · 扁平高对比，16px 下仍可辨识

产出：app_icon.ico（16/24/32/48/64/128/256 多尺寸，Windows 各场景各取所需）
"""

import os

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'app_icon.ico')
SS = 4          # 超采样倍数
BASE = 256      # 逻辑画布尺寸

SHELL = (86, 106, 132, 255)        # 外壳：灰蓝
SHELL_EDGE = (60, 76, 98, 255)     # 外壳描边
CORE = (38, 198, 162, 255)         # 内芯：亮青绿
CORE_EDGE = (26, 150, 122, 255)
SHARD = (140, 235, 210, 255)       # 碎片：更亮，强调"已脱出"
HILITE = (255, 255, 255, 70)


def polygon(d, pts, **kw):
    d.polygon(pts, **kw)


def shield_points(cx, cy, w, h):
    """盾形顶点（顶边平直、两侧下收、底部收尖），归一化后按 w/h 缩放。"""
    shape = [
        (-0.50, -0.50), (0.00, -0.50), (0.50, -0.50),   # 顶边
        (0.50, -0.06),                                   # 右上
        (0.42, 0.24), (0.20, 0.44), (0.00, 0.50),        # 右侧收向底尖
        (-0.20, 0.44), (-0.42, 0.24),                    # 左侧收向底尖
        (-0.50, -0.06),
    ]
    return [(cx + x * w, cy + y * h) for x, y in shape]


def draw_icon(size):
    """返回 size×size 的 RGBA 图标。"""
    s = BASE * SS
    img = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    cx, cy = s / 2, s * 0.50
    W, H = s * 0.60, s * 0.82

    # ---- 外壳（整盾，灰蓝 + 描边）----
    outer = shield_points(cx, cy, W, H)
    polygon(d, outer, fill=SHELL, outline=SHELL_EDGE, width=int(s * 0.022))

    # ---- 内芯（缩小 0.64 的同形盾，亮青）；右下部留一道"开口"给碎片让位 ----
    inner_all = shield_points(cx, cy, W * 0.64, H * 0.64)
    # 挖掉右下角一小块，表达"内容从此处脱出"
    inner = [p for p in inner_all
             if not (p[0] - cx > W * 0.12 and p[1] - cy > H * 0.10)]
    if len(inner) >= 3:
        polygon(d, inner, fill=CORE, outline=CORE_EDGE)

    # ---- 碎片：脱离出的小三角，位于开口外侧，略向下 ----
    shard = [
        (cx + W * 0.30, cy + H * 0.24),
        (cx + W * 0.46, cy + H * 0.18),
        (cx + W * 0.40, cy + H * 0.40),
    ]
    polygon(d, shard, fill=SHARD, outline=CORE_EDGE)

    # ---- 顶部高光（提升立体感，小尺寸下自然淡出）----
    d.line([(cx - W * 0.30, cy - H * 0.40),
            (cx, cy - H * 0.445),
            (cx + W * 0.30, cy - H * 0.40)],
           fill=HILITE, width=int(s * 0.030), joint='curve')

    img = img.resize((size, size), Image.LANCZOS)
    return img


def main():
    sizes = [16, 24, 32, 48, 64, 128, 256]
    imgs = [draw_icon(x) for x in sizes]
    imgs[0].save(OUT, format='ICO', append_images=imgs[1:],
                 sizes=[(x, x) for x in sizes])
    print('[+] 图标已生成: unpacker/app_icon.ico (%d bytes, 尺寸 %s)'
          % (os.path.getsize(OUT), sizes))
    prev = os.path.join(HERE, 'app_icon_preview.png')
    imgs[-1].save(prev)
    print('    预览: unpacker/app_icon_preview.png')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
