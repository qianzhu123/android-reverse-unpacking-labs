#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
gui.py — unpacker 的图形界面（tkinter + tkinterdnd2 真拖放）。

窗口布局：
  ┌────────────────────────────────────────────┐
  │  拖入 APK / dex / so（或点击选择文件）      │  ← 拖放区，全窗口接受文件
  │  [判定]  [解固]  [选黄金样本…]  [回归矩阵]   │  ← 按钮区
  │  ┌──────────────────────────────────────┐  │
  │  │ 输出区（[!]/[*]/[+] 原样显示）        │  │  ← 结果文本，可复制
  │  └──────────────────────────────────────┘  │
  └────────────────────────────────────────────┘

行为约定（与 CLI 完全一致，只是把 stdout 引到文本区）：
  · 判定 = analyzer.analyze（只读体检），结果带认知边界提示
  · 解固 = unpack.main_with_repo（判定→路由→两级验证）；
    黄金样本可选，不选则明确提示 anchor-only 级验证
  · 回归矩阵 = regression.main_with_repo（19 样本双向断言）
  · 产物固定写在被解固文件旁边的 unpacker_output/（不在 GUI 里另选目录，保持简单；
    CLI 用户仍可用 unpack -o）

长任务在后台线程跑，界面不冻结；运行中按钮禁用 + 状态栏提示。
"""

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, ttk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _HAS_DND = True
except ImportError:  # 无 tkinterdnd2 时退化为纯点击选择（exe 内置了它，一般不会走到）
    _HAS_DND = False

HERE = os.path.dirname(os.path.abspath(__file__))


# ------------------------------------------------ stdout 重定向到队列（线程安全）
class _QueueWriter:
    def __init__(self, q, tag):
        self.q, self.tag = q, tag

    def write(self, s):
        if s.strip('\r\n'):          # 空行直接吞掉，避免队列爆炸
            self.q.put((self.tag, s.rstrip('\n')))
        return len(s)

    def flush(self):
        pass


class Gui:
    def __init__(self, repo_root):
        self.repo = repo_root
        self.q = queue.Queue()
        self.worker = None

        tk_cls = TkinterDnD.Tk if _HAS_DND else tk.Tk
        self.root = tk_cls()
        self.root.title('unpacker · Android 解固工具（判定 / 解固 / 回归）')
        self.root.geometry('880x620')

        self._build()
        if _HAS_DND:
            # 全窗口接受文件拖放
            for w in (self.root, self.drop_lbl, self.out):
                w.drop_target_register(DND_FILES)
                w.dnd_bind('<<Drop>>', self._on_drop)
        self.root.after(80, self._drain_queue)

    # ---------------------------------------------------------------- UI
    def _build(self):
        pad = {'padx': 8, 'pady': 4}

        top = ttk.Frame(self.root)
        top.pack(fill='x', **pad)
        self.drop_lbl = tk.Label(
            top, text='⬇ 把 APK / dex / so 拖到这里（也支持全窗口拖放）',
            relief='groove', padx=16, pady=18, bg='#f0f4f8')
        self.drop_lbl.pack(fill='x', pady=(0, 6))
        self.drop_lbl.bind('<Button-1>', lambda e: self._pick_file())

        row = ttk.Frame(top)
        row.pack(fill='x', pady=2)
        self.file_var = tk.StringVar(value='（未选择文件）')
        ttk.Label(row, text='目标:').pack(side='left')
        ttk.Label(row, textvariable=self.file_var, foreground='#0a58ca').pack(side='left')

        btns = ttk.Frame(self.root)
        btns.pack(fill='x', **pad)
        self.btn_analyze = ttk.Button(btns, text='① 判定（只读体检）', command=self._do_analyze)
        self.btn_analyze.pack(side='left', padx=4)
        self.btn_unpack = ttk.Button(btns, text='② 解固（判定→路由→验证）', command=self._do_unpack)
        self.btn_unpack.pack(side='left', padx=4)
        ttk.Button(btns, text='选黄金样本（可选）', command=self._pick_pristine).pack(side='left', padx=4)
        self.pristine_var = tk.StringVar(value='')
        ttk.Label(btns, textvariable=self.pristine_var, foreground='#6c757d').pack(side='left', padx=2)
        self.btn_reg = ttk.Button(btns, text='③ 回归矩阵', command=self._do_regression)
        self.btn_reg.pack(side='right', padx=4)

        body = ttk.Frame(self.root)
        body.pack(fill='both', expand=True, **pad)
        self.out = tk.Text(body, wrap='char', font=('Consolas', 9), state='disabled')
        self.out.pack(fill='both', expand=True)
        sb = ttk.Scrollbar(body, command=self.out.yview)
        sb.pack(side='right', fill='y')
        self.out.configure(yscrollcommand=sb.set)
        # [!]=失败红 [*]=步骤灰 [+]=成功绿，与 CLI 语义一致
        for tag, color in (('[!]', '#c0392b'), ('[*]', '#6c757d'), ('[+]', '#1e8449')):
            self.out.tag_configure(tag, foreground=color)

        self.status = tk.StringVar(value='就绪')
        ttk.Label(self.root, textvariable=self.status, relief='sunken', anchor='w').pack(
            fill='x', side='bottom')

        self.file_path = None

    # -------------------------------------------------------- 输出区
    def _say(self, line):
        self.out.configure(state='normal')
        tag = None
        for t in ('[!]', '[*]', '[+]'):
            if line.lstrip().startswith(t):
                tag = t
                break
        self.out.insert('end', line + '\n', tag or ())
        self.out.see('end')
        self.out.configure(state='disabled')

    def _drain_queue(self):
        try:
            while True:
                tag, line = self.q.get_nowait()
                if tag == '__done__':      # 哨兵：任务结束，主线程解锁按钮
                    self._task_done()
                    continue
                self._say(line)
        except queue.Empty:
            pass
        self.root.after(80, self._drain_queue)

    # -------------------------------------------------------- 拖放/选择
    def _accept_path(self, p):
        p = p.strip('{}')            # 路径带空数时 tkinterdnd2 会加 {}
        if not os.path.isfile(p):
            self._say('[!] 不是文件: %s' % p)
            return
        self.file_path = os.path.abspath(p)
        self.file_var.set(self.file_path)
        self._say('[*] 已选目标: %s' % self.file_path)

    def _on_drop(self, event):
        for p in event.data.split():    # 多文件只取第一个（多文件判定用 CLI）
            self._accept_path(p)
            break

    def _pick_file(self):
        p = filedialog.askopenfilename(
            title='选择 APK / dex / so 文件',
            filetypes=[('支持格式', '*.apk *.dex *.so *.xapk'), ('所有文件', '*.*')])
        if p:
            self._accept_path(p)

    def _pick_pristine(self):
        p = filedialog.askopenfilename(
            title='选择黄金对照样本（用于 byte-exact 验证，可选）',
            filetypes=[('支持格式', '*.apk *.dex *.so'), ('所有文件', '*.*')])
        if p:
            self.pristine_var.set(os.path.basename(p))
            self._pristine = os.path.abspath(p)
            self._say('[*] 黄金样本: %s' % self._pristine)
        else:
            self._pristine = None

    # -------------------------------------------------------- 任务执行
    def _run_task(self, name, fn):
        if self.worker and self.worker.is_alive():
            self._say('[!] 有任务正在运行，请等它结束。')
            return
        for b in (self.btn_analyze, self.btn_unpack, self.btn_reg):
            b.state(['disabled'])
        self.status.set('运行中: %s …' % name)

        def run():
            old_out, old_err = sys.stdout, sys.stderr
            sys.stdout = _QueueWriter(self.q, '')
            sys.stderr = _QueueWriter(self.q, '[!]')
            try:
                fn()
            except Exception as e:
                self.q.put(('[!]', '[!] 内部错误: %r' % e))
            finally:
                sys.stdout, sys.stderr = old_out, old_err
                # 不在 worker 线程碰 tkinter（after 也不行——RuntimeError）；
                # 埋一个哨兵，主循环的 _drain_queue 看到后自己解锁按钮。
                self.q.put(('__done__', '[*] —— %s 结束 ——' % name))

        self.worker = threading.Thread(target=run, daemon=True)
        self.worker.start()

    def _task_done(self):
        for b in (self.btn_analyze, self.btn_unpack, self.btn_reg):
            b.state(['!disabled'])
        self.status.set('就绪')

    def _require_file(self):
        if not self.file_path or not os.path.exists(self.file_path):
            self._say('[!] 请先拖入或选择一个文件。')
            return None
        return self.file_path

    # -------------------------------------------------------- 三个按钮
    def _do_analyze(self):
        p = self._require_file()
        if not p:
            return

        def fn():
            import analyzer
            analyzer.main_with_repo([p], self.repo)
        self._say('=' * 60)
        self._run_task('判定', fn)

    def _do_unpack(self):
        p = self._require_file()
        if not p:
            return
        argv = [p]
        if getattr(self, '_pristine', None):
            argv += ['--pristine', self._pristine]
        else:
            self._say('[*] 未选黄金样本——解固将只做 anchor-only 级验证（选黄金样本可得 byte-exact）')

        def fn():
            import unpack as _unpack
            _unpack.main_with_repo(argv, self.repo)
        self._say('=' * 60)
        self._run_task('解固', fn)

    def _do_regression(self):
        def fn():
            import regression
            regression.main_with_repo([], self.repo)
        self._say('=' * 60)
        self._run_task('回归矩阵', fn)

    def run(self):
        self._say('[*] unpacker GUI 就绪。仓库根: %s' % self.repo)
        self._say('[*] 用法：拖入文件 → ① 判定 → （可选：选黄金样本）→ ② 解固；③ 回归矩阵不依赖文件。')
        self.root.mainloop()


def launch(repo_root):
    Gui(repo_root).run()
