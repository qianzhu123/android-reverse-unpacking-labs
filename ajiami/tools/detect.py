#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
detect.py — 加固判定（禁止偷懒版）

核心要求：结论必须来自「可量化的结构/统计特征」，而不是文件名或某个字符串。
本脚本会同时给出两套判据的结果，好让你亲眼看到朴素判据是怎么失效的：

  判据 A（朴素/易错）  只看家族字符串 "ijiami" / "ProxyApplication"
                       —— 变种样本上必然漏报
  判据 B（结构/统计）   dex 空方法率 + 高熵 asset + Application 是否为代理 + 业务类缺失

用法：
  python tools/detect.py samples/apks/app_orig.apk
  python tools/detect.py samples/apks/app_packed_v2.apk
  python tools/detect.py samples/apks/app_packed_v2_variant.apk
  python tools/detect.py samples/dex/extracted_v2.dex --json
  python tools/detect.py samples/apks/*.apk            # 一次对比多个
"""

import json
import os
import re
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import apkutil
import dexlib
import elfinspect
import envload

# 从 build/env.sh 读取 AJ_AAPT2 等配置，无需先 source（PowerShell 也能跑）
envload.ensure_env()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FAMILY_STRINGS = ['ijiami', 'ProxyApplication', 'ijiami_shell_version',
                  'ijiami_real_application', 'ijm_payload', 'ijm_codes']
LOADER_STRINGS = ['DexClassLoader', 'InMemoryDexClassLoader', 'PathClassLoader',
                  'loadClass', 'System.loadLibrary']
SUSPECT_SO = ['libijiami', 'libExec', 'libexec', 'libDexHelper', 'libjiagu',
              'libprotectClass', 'libshell']
APP_BASE = 'Landroid/app/Application;'

ACC_NATIVE = 0x0100

# invoke-* 操作码（含 /range 变体）：35c 与 3rc 的 BBBB 位置相同，都在 u2[1]
INVOKE_OPS = frozenset([0x6e, 0x6f, 0x70, 0x71, 0x72,      # kind
                        0x74, 0x75, 0x76, 0x77])            # kind/range

# 只收录「正常 App 几乎不会自然出现」的高特异性串，避免制造新的误报源。
# 反例教训：'META-INF/' 看着像签名校验，实际任何处理 zip/apk 的代码都会出现，
#          在真实 App 上直接误报 —— 已被实测剔除。'checkSha1' / '/data/local/tmp'
#          / '/proc/self/maps' 同理偏泛，一并剔除。
ANTI_ANALYSIS_STRINGS = {
    '反调试': ['TracerPid', '/proc/self/status', 'isDebuggerConnected',
               'waitForDebugger', 'gdbserver', 'android_server', 'PTRACE_TRACEME'],
    '反Hook/注入': ['XposedBridge', 'de.robv.android.xposed',
                    'fridaserver', 'libfrida', 'com.saurik.substrate'],
    '完整性/签名校验': ['getSigningInfo', 'CERT.RSA', 'hasAppSignatureChanged'],
}

# 库/框架包的常见前缀。声明在 manifest 里的组件若属于这些包属【正常现象】：
# 它们既不能算"App 自身业务类"，也不能因为被分到次级 dex 就判成壳。
LIB_PREFIXES = ('android.', 'androidx.', 'java.', 'javax.', 'kotlin.', 'kotlinx.',
                'dalvik.', 'org.jetbrains.', 'com.google.', 'com.android.',
                'com.facebook.', 'com.squareup.', 'io.reactivex.')

# 认知边界声明：明确告诉使用者本工具【不】覆盖哪些方案，
# 避免把"没看到已知特征"当成"没有加固"（这是最危险的误判方向）。
COVERAGE_NOTICE = (
    '认知边界：本工具自动覆盖 DEX 三代（整体加密 / 抽取 / 选择性抽取）、已知厂商 SO 名单(B8)、\n'
    '          VMP 汇聚形态(B11)、Java2CPP native 占比(B12)、反分析能力痕迹(B10)、\n'
    '          SO 加壳/自实现 Linker 的 ELF 结构异常(B13)。\n'
    '          仍需人工复核的场景：① SO VMP —— 即便 B13 看到正常 ELF，VMP 解释器仍是普通大函数，\n'
    '          静态不可定性，须动态 trace 确认；② 不走"汇聚调用"形态的自定义 VMP；\n'
    '          ③ 精巧的字符串加密。\n'
    '          故"未见已知特征"绝不等于"未加固"。'
)


def _norm(class_descriptor):
    """'Lcom/demo/target/MainActivity;' -> 'com.demo.target.MainActivity'"""
    return class_descriptor.strip(';').lstrip('L').replace('/', '.')


# ------------------------------------------------------------ 二进制 manifest 取串
def manifest_strings(blob):
    """从 aapt2 编译后的二进制 XML 里抠出可读字符串（UTF-16LE 与 ASCII 都捞一遍）。"""
    outs = []
    # UTF-16LE：连续 [ascii,0x00] 成对出现
    chunks = re.findall(rb'(?:[\x20-\x7e]\x00){4,}', blob)
    for c in chunks:
        outs.append(c.decode('utf-16-le'))
    # ASCII
    for c in re.findall(rb'[\x20-\x7e]{5,}', blob):
        outs.append(c.decode('latin1'))
    # 去重保序
    seen = set()
    out = []
    for s in outs:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


_AAPT2_WARNED = False


def _find_aapt2():
    """定位 aapt2。

    解析顺序：
      1) 环境变量 AJ_AAPT2（显式配置，来自 build/env.sh；文件不存在则忽略）
      2) 系统 PATH（shutil.which，Windows 下会按 PATHEXT 找到 aapt2.exe）

    不硬编码任何机器绝对路径 —— 换机器 / 换 SDK 版本都不会失效。
    找不到返回 None，调用方退化到字符串启发式。
    """
    import shutil
    cand = os.environ.get('AJ_AAPT2')
    if cand and os.path.exists(cand):
        return cand
    return shutil.which('aapt2')


def aapt2_xmltree(apk_path):
    """用 aapt2 dump xmltree 精确解析二进制 AndroidManifest.xml。

    返回 {'application': 类名 or None, 'components': {tag: [类名...]}, 'raw': 文本}
    aapt2 不可用时返回 None —— 那时退化到字符串启发式（见 fallback）。
    """
    import subprocess
    aapt2 = _find_aapt2()
    if not aapt2:
        global _AAPT2_WARNED
        if not _AAPT2_WARNED:
            sys.stderr.write('[warn] 未找到 aapt2（PATH 里没有，且 AJ_AAPT2 未设置/不存在）'
                             ' —— Manifest 精确解析不可用，判据 B7 会退化\n')
            _AAPT2_WARNED = True
        return None
    try:
        out = subprocess.run([aapt2, 'dump', 'xmltree', '--file',
                              'AndroidManifest.xml', apk_path],
                             capture_output=True, timeout=60)
        text = out.stdout.decode('utf-8', 'replace')
    except Exception:
        return None
    if 'application' not in text:
        return None

    comps = {}
    app_name = None
    pkg = None
    stack = []
    for line in text.splitlines():
        s = line.rstrip()
        indent = len(s) - len(s.lstrip())
        level = indent // 2
        body = s.strip()
        stack = stack[:level]
        if body.startswith('E: '):
            stack.append(body[3:].split(' ')[0])
        elif body.startswith('A: ') and stack:
            tag = stack[-1]
            # manifest 上的 package：<manifest package="com.xxx">
            if tag == 'manifest' and pkg is None:
                pm = re.search(r'\bpackage="([^"]*)"', body)
                if pm:
                    pkg = pm.group(1)
            # 形如  A: ...:name(0x01010003)="com.xxx.Y" (Raw: "com.xxx.Y")
            m = re.search(r'name\([^)]*\)="([^"]*)"', body)
            if m:
                val = m.group(1)
                # 【修正 5】Manifest 允许写相对类名 ".MainActivity"，
                # 它会隐式展开为 package + name。直接拿原始串去和 dex 类名比对
                # 会永远不相等 —— 这是比多 dex 更普遍的 B7 误报源。
                if pkg and (val.startswith('.') or '.' not in val):
                    val = pkg + ('' if val.startswith('.') else '.') + val
                if tag == 'application':
                    app_name = val
                elif tag in ('activity', 'activity-alias', 'service',
                             'receiver', 'provider'):
                    comps.setdefault(tag, []).append(val)
                elif tag == 'meta-data':
                    comps.setdefault('meta-data', []).append(val)
    return {'application': app_name, 'components': comps, 'raw': text,
            'package': pkg}


def extract_class_names(strings):
    """从 manifest 字符串里抽取"看起来像类名"的点分标识符。

    注意：二进制 XML 的 UTF-16LE 串前面经常带一个字节的长度前缀，
    直接整体匹配会拿到 '!com.ijiami.shell.ProxyApplication' 这种脏串，
    所以这里用 finds-in-string 而不是 fullmatch。
    """
    pat = re.compile(r'(?:[A-Za-z][A-Za-z0-9_$]*\.){2,}[A-Za-z][A-Za-z0-9_$]*')
    out = []
    seen = set()
    for s in strings:
        for m in pat.findall(s):
            if m.startswith('android.') or m.startswith('http'):
                continue
            if m not in seen:
                seen.add(m)
                out.append(m)
    return out


def find_application_name(strings):
    return extract_class_names(strings)


def _invoke_targets(insns):
    """粗扫 insns 里的 invoke-* 目标 method_idx。

    注意：这是**不严谨**的线性扫描（未按指令边界逐条走），多 code unit 指令的
    载荷字节有可能被误读成伪 invoke。但 VMP 判据要求「≥3 个不同方法汇聚到同一个
    目标」，噪声几乎不可能凑出稳定的汇聚点，所以够用；结论也只标"疑似"。
    """
    out = []
    for i in range(0, len(insns) - 3, 2):
        if insns[i] in INVOKE_OPS:
            out.append(struct.unpack_from('<H', insns, i + 2)[0])
    return out


def _tiny_call_hubs(dx, max_units=16, min_callers=2, min_hub_units=30):
    """找出「多个极短方法 <> 汇聚到一个大方法」的结构 —— DEX VMP 的典型形状。

    实测数据（samples/apks/app_vmp.apk）：
        被保护的业务方法  com.demo.vmapp.VmBusiness.mix/twist   units=11，各 1 个 invoke
        解释器            com.ijiami.vmp.Vmp.run                units=196（大，含调度循环）
    据此定了三条硬约束，缺一条都会在普通 App 上误报：
      (a) 目标不能属于库/框架包（否则 `java.lang.Object.<init>` 会被每个构造函数
          汇聚命中 —— app_orig 上实测 5 个 caller，任何 App 都会触发）
      (b) 排除 `<init>` / `<clinit>`（同上，构造链是天然的伪汇聚）
      (c) 目标自身必须是「大方法」（>= min_hub_units code unit）——
          解释器才有这个体积；普通工具类的转发桩很小。
    """
    size_of = {}
    for cname, kind, m in dx.iter_methods():
        if m['code_off']:
            ci = dx.code_item(m['code_off'])
            if ci:
                size_of[m['method_idx']] = ci['insns_size']

    callers = {}
    for cname, kind, m in dx.iter_methods():
        if m['code_off'] == 0:
            continue
        ci = dx.code_item(m['code_off'])
        if not ci or not ci['insns_size'] or ci['insns_size'] > max_units:
            continue
        tg = _invoke_targets(ci['insns'])
        if len(tg) != 1:
            continue
        callers.setdefault(tg[0], set()).add((cname, m['method_idx']))

    hubs = []
    for tgt, who in callers.items():
        if len(who) < min_callers or size_of.get(tgt, 0) < min_hub_units:
            continue
        try:
            clazz, _, _, name = dx.method_at(tgt)
        except Exception:
            continue
        sname = _norm(clazz)
        if name in ('<init>', '<clinit>') or sname.startswith(LIB_PREFIXES):
            continue
        hubs.append({'target': '%s->%s' % (sname, name),
                     'callers': len(who), 'hub_units': size_of[tgt]})
    hubs.sort(key=lambda h: -h['callers'])
    return hubs[:5]


# ------------------------------------------------------------ dex 侧特征
def dex_features(blob, label='classes.dex'):
    try:
        dx = dexlib.Dex(blob)
    except Exception as e:
        return {'label': label, 'error': str(e)}

    st = dx.method_code_stats()
    strings = [s for _, s in dx.all_strings()]

    family_hits = sorted({t for t in FAMILY_STRINGS if any(t in s for s in strings)})
    loader_hits = sorted({t for t in LOADER_STRINGS if any(t in s for s in strings)})

    # Application 是否是"代理"：继承 Application 但自身方法极少（典型壳 < 10）
    app_classes = []
    for cd in dx.class_defs():
        cname = dx.class_name(cd)
        super_name = dx.type_at(cd['superclass_idx'])
        if super_name == APP_BASE:
            data = dx.class_data(cd['class_data_off'])
            n = len(data['direct']) + len(data['virtual'])
            app_classes.append({'class': cname, 'methods': n})

    # 每个类的空方法占比（v3 的关键判据）
    hot_classes = []
    for cname, s in st['per_class'].items():
        if s['total'] and s['empty']:
            hot_classes.append({
                'class': cname, 'empty': s['empty'], 'total': s['total'],
                'ratio': round(s['empty'] / s['total'], 3)})
    hot_classes.sort(key=lambda x: -x['ratio'])

    # native 方法占比：Java2CPP / 重度 native 化的信号（业务被搬进 SO 时，
    # DEX 侧只剩下 native 声明桩，空方法率不会升高，B3 会失效）
    native_cnt = 0
    for cname, kind, m in dx.iter_methods():
        if m['access_flags'] & ACC_NATIVE:
            native_cnt += 1
    native_ratio = round(native_cnt / float(st['total'] or 1), 4)

    # DEX VMP：方法体退化成一句解释器调用，并大量汇聚到同一目标
    vmp_hubs = _tiny_call_hubs(dx)

    # 反分析能力痕迹（反调试 / 反 Hook / 完整性校验）
    threat_hits = {}
    for cate, pats in ANTI_ANALYSIS_STRINGS.items():
        hits = sorted({p for p in pats if any(p in s for s in strings)})
        if hits:
            threat_hits[cate] = hits

    all_classes = [_norm(dx.class_name(cd)) for cd in dx.class_defs()]

    return {
        'label': label,
        'size': len(blob),
        'entropy': round(apkutil.shannon_entropy(blob), 4),
        'magic': dx.magic.replace('\n', '\\n'),
        'class_defs': dx.class_defs_size,
        'methods_total': st['total'],
        'methods_with_code': st['with_code'],
        'methods_empty': st['empty'],
        'empty_ratio': round(st['empty_ratio'], 4),
        'checksum_ok': dx.check()[0],
        'family_string_hits': family_hits,
        'loader_string_hits': loader_hits,
        'application_classes': app_classes,
        'hot_classes': hot_classes[:8],
        'classes': all_classes,
        'sample_classes': all_classes[:20],
        'native_count': native_cnt,
        'native_ratio': native_ratio,
        'vmp_hubs': vmp_hubs,
        'threat_string_hits': threat_hits,
    }


# ------------------------------------------------------------ APK 侧特征
def apk_features(path):
    f = {'path': os.path.basename(path), 'size': os.path.getsize(path)}
    if not zipfile.is_zipfile(path):
        f['type'] = 'raw'
        return f
    f['type'] = 'apk'
    z = zipfile.ZipFile(path)
    entries = []
    so_report = []
    for i in z.infolist():
        blob = z.read(i.filename)
        entries.append({'name': i.filename, 'size': i.file_size,
                        'entropy': round(apkutil.shannon_entropy(blob), 4)})
        # lib/*.so：真正进入 ELF 结构（以前只算了个文件级熵，等于没看 Native 层）
        if i.filename.startswith('lib/') and i.filename.endswith('.so'):
            try:
                so_report.append(elfinspect.inspect(blob, i.filename))
            except Exception as e:
                so_report.append({'name': i.filename, 'error': str(e), 'anomalies': []})
    f['entries'] = entries
    f['so'] = so_report

    manifest = z.read('AndroidManifest.xml') if 'AndroidManifest.xml' in z.namelist() else b''
    strings = manifest_strings(manifest)
    f['manifest_strings'] = strings
    f['manifest_application_candidates'] = find_application_name(strings)

    tree = aapt2_xmltree(path)
    if tree:
        f['manifest_application'] = tree['application']
        f['manifest_components'] = tree['components']
        f['manifest_parsed'] = True
    else:
        # 退化：用字符串启发式凑一个 application 名
        cands = find_application_name(strings)
        f['manifest_application'] = cands[0] if cands else None
        f['manifest_components'] = {}
        f['manifest_parsed'] = False

    f['assets'] = [e for e in entries if e['name'].startswith('assets/')]
    f['libs'] = [e for e in entries if e['name'].startswith('lib/')]
    dexes = []
    for name in z.namelist():
        if name.endswith('.dex'):
            dexes.append(dex_features(z.read(name), name))
    f['dexes'] = dexes
    return f


def dex_file_features(path):
    blob = open(path, 'rb').read()
    return {'path': os.path.basename(path), 'type': 'dex',
            'dexes': [dex_features(blob, os.path.basename(path))]}


# ------------------------------------------------------------ 判定逻辑
def verdict(f):
    """返回 (结论, [触发的规则], [朴素规则结果], [对照提示], [需人工复核项])"""
    rules = []
    notes = []          # 不足以定性、但需要人工复核的信号（不参与结论 ladder）
    dxs = f.get('dexes') or []
    main = dxs[0] if dxs else {}
    assets = f.get('assets') or []
    libs = f.get('libs') or []
    sos = f.get('so') or []
    manifest_cands = f.get('manifest_application_candidates') or []
    app_name = f.get('manifest_application')
    comps = f.get('manifest_components') or {}

    # 声明在 manifest 里的类 = application + 四大组件（不含 meta-data 的 value）
    declared = set()
    if app_name:
        declared.add(app_name)
    for tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
        declared.update(comps.get(tag, []))

    # 【修正 1】多 dex（multidex）是现代 App 常态：AndroidX 组件类常被分到
    # classes2/3/4.dex。原先所有判据只读主 dex(dxs[0])，会把正常 App 判成壳。
    # 凡是"某类是否存在"的判断，一律改用【所有 dex 的并集】。
    all_dex_classes = set()
    merged_family = set()
    merged_loader = set()
    merged_app_classes = []
    merged_native = 0
    merged_methods = 0
    merged_vmp = []
    merged_threat = {}
    for d in dxs:
        if d.get('error'):
            continue
        all_dex_classes.update(d.get('classes') or [])
        merged_family.update(d.get('family_string_hits') or [])
        merged_loader.update(d.get('loader_string_hits') or [])
        merged_app_classes.extend(d.get('application_classes') or [])
        merged_native += d.get('native_count', 0)
        merged_methods += d.get('methods_total', 0)
        merged_vmp.extend(d.get('vmp_hubs') or [])
        for _k, _v in (d.get('threat_string_hits') or {}).items():
            merged_threat.setdefault(_k, set()).update(_v)

    # 【修正 2】App 自身包名从 manifest 组件推导，并剔除库/框架包。
    # 两个坑必须同时避开：
    #   (a) 原先写死 'com/demo'，那只对本工程样本成立；对任意真实 App 恒为空，
    #       于是"只要存在任何高熵 asset 就误报成一代"。
    #   (b) 但不能反过来把 declared 全算上：加固 App 的 Application 就是壳的
    #       代理类（如 com.ijiami.shell.ProxyApplication），它必然存在于 dex 中，
    #       把它的包当成"App 自身包"会让 biz 恒不为空、B6 永远不命中。
    # 所以只取四大组件，显式排除 application 类本身。
    _comps = set()
    for tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
        _comps.update(comps.get(tag, []))
    app_pkgs = sorted({c.rsplit('.', 1)[0] for c in _comps
                       if not c.startswith(LIB_PREFIXES)})

    empty_ratio = main.get('empty_ratio', 0.0) if not main.get('error') else None
    class_defs = main.get('class_defs', 0)
    family_hits = sorted(merged_family) if merged_family else []
    loader_hits = sorted(merged_loader) if merged_loader else []
    app_classes = merged_app_classes or []

    # ---- 判据 A：朴素字符串规则（记录它的结论，然后证明它会错）
    naive = ('命中家族字符串 %s' % family_hits) if family_hits else '未命中任何家族字符串'

    # ---- 判据 B：结构 / 统计
    high_entropy_assets = [a for a in assets if a['entropy'] > 7.5 and a['size'] > 1024]
    if high_entropy_assets:
        rules.append('B1 高熵 asset(%s, %.3f bit/byte) —— 存在加密 payload'
                     % (high_entropy_assets[0]['name'], high_entropy_assets[0]['entropy']))

    # B2：(错误示范，保留在报告里做对照) 只看 dex 里类数量就下结论
    #      —— 在本工程 app_orig.apk 上会误报，详见 README §5.2
    naive2_hint = ('类数=%d（<=8 会被朴素规则误判为壳）' % class_defs) if class_defs else ''

    # B3：空方法率
    if empty_ratio is not None:
        if empty_ratio > 0.4:
            rules.append('B3 全类空方法率 %.1f%% > 40%% —— 类抽取（二代）' % (empty_ratio * 100))
        elif empty_ratio > 0.02:
            rules.append('B3* 整体空方法率仅 %.1f%%，但存在局部空方法类 —— 需下钻到单类\n'
                         '      → %s' % (empty_ratio * 100,
                                         '; '.join('%s %d/%d' % (h['class'], h['empty'], h['total'])
                                                  for h in (main.get('hot_classes') or [])[:3])))

    # B4：代理 Application（精确匹配 manifest 声明的 application 名）+ 动态加载能力
    proxy = None
    for a in app_classes:
        if a['methods'] <= 8 and app_name and _norm(a['class']) == app_name:
            proxy = a
            break
    if proxy and loader_hits:
        rules.append('B4 manifest 声明的 Application=%s 在 dex 里是个"小 Application"(%d 方法)'
                     ' 且 dex 引用了动态加载类 %s —— Application 被代理'
                     % (app_name, proxy['methods'], loader_hits[:2]))
    elif 'DexClassLoader' in loader_hits or 'InMemoryDexClassLoader' in loader_hits:
        rules.append('B4 dex 直接引用动态加载类 %s' % loader_hits[:2])

    # B5：未用到（B4 已经把代理 Application 的精确身份说清楚了），保留占位以便扩展 flat)

    # B6：没有业务类 + 有高熵 payload => 一代
    #     业务类不能写死包名判断（'com/demo' 只对本工程样本成立，对真实 App 恒为空，
    #     会导致"只要存在任何高熵 asset 就误报为一代"）。改为 App 自身包名判断。
    #     若推不出包名（例如四大组件全是库里的），宁可不判，避免瞎下结论。
    biz = [c for c in all_dex_classes if any(c.startswith(p + '.') for p in app_pkgs)]
    if high_entropy_assets and app_pkgs and not biz:
        rules.append('B6 所有 dex 的并集中都没有 App 自身包(%s)的业务类，且存在高熵 asset'
                     ' —— 真 dex 只能藏在 asset 里，判定为一代整体加密'
                     % ', '.join(app_pkgs[:3]))

    allmanifest = set(declared)
    # 【修正 3】必须比对"所有 dex 的并集"，不能只比主 dex。
    # 真实 multidex App 的 AndroidX 组件常在 classes2/3/4.dex，
    # 只比主 dex 会把它们误算成"缺失" —— 这正是把普通 App 判成壳的根因。
    missing = sorted(allmanifest - all_dex_classes)
    if missing:
        rules.append('B7 AndroidManifest 声明了 %d 个类，其中 %d 个在所有 classes*.dex 的并集中都不存在'
                     ' —— 需由运行期动态加载提供（强证据，但定性为一代还需配合 B1/B6 的载荷证据）\n'
                     '      缺失：%s' % (len(allmanifest), len(missing), ', '.join(missing[:5])))

    # ---- 原先被声明为"不覆盖"、但其实静态可检的几类（本次补强）
    # 反分析能力只进 notes，不进 rules：对抗能力 ≠ 加壳，
    # 让它翻结论会重新制造第二类误报（真实 App 里这类串常来自第三方SDK）。
    threat_hits = {k: sorted(v) for k, v in sorted(merged_threat.items())}
    if threat_hits:
        notes.append('检出反分析能力痕迹：%s —— 属对抗能力，'
                     '不代表被加壳，需人工确认来源（可能是第三方 SDK 自带）'
                     % '; '.join('%s(%s)' % (k, ', '.join(v)) for k, v in threat_hits.items()))
    if merged_vmp:
        top = merged_vmp[0]
        rules.append('B11 %d 个极短方法体汇聚调用同一个大方法 %s（目标 %d code unit）'
                     ' —— 业务方法已退化为解释器调用，疑似 DEX VMP'
                     '（此形态下 insns 非零，B3 空方法率必然失效）'
                     % (top['callers'], top['target'], top['hub_units']))
    native_ratio = (merged_native / float(merged_methods)) if merged_methods else 0.0
    if native_ratio >= 0.30 and merged_native >= 5:
        rules.append('B12 native 方法占比 %.1f%%（%d/%d）≥ 30%% 阈值'
                     ' —— 疑似 Java2CPP / 重度 native 化，业务逻辑可能已迁入 SO'
                     % (native_ratio * 100, merged_native, merged_methods))

    # ---- Native 侧：f['libs'] 原先采了却不判定，SUSPECT_SO 更是死代码
    suspect_so = []
    for e in libs:
        base = os.path.basename(e['name'])
        if any(s.lower() in base.lower() for s in SUSPECT_SO):
            suspect_so.append(base)
    if suspect_so:
        rules.append('B8 存在已知壳/加固厂商特征的 SO：%s'
                     ' —— Native 侧加固信号，需进 ELF 层确认'
                     % ', '.join(sorted(set(suspect_so))))

    # 熵异常的 SO 只作为"需人工复核"的提示，不让其单独翻结论（避免新的误报源）
    packed_so = [e for e in libs if e['size'] > 20000 and e['entropy'] > 7.5]
    if packed_so:
        notes.append('SO 文件级熵异常（>7.5）%s —— 可能被加壳/加密，需结合下面 ELF 结构判断'
                     % ', '.join('%s(%.3f)' % (os.path.basename(e['name']), e['entropy'])
                                 for e in packed_so[:3]))

    # ELF 结构级信号（这才是 SO 加壳真正留下痕迹的地方）
    so_bad = [s for s in sos if s.get('anomalies')]
    if so_bad:
        top = so_bad[0]
        rules.append('B13 %s 的 ELF 结构异常：%s'
                     ' —— 疑似 SO 加壳 / 自实现 Linker，需人工进 ELF 层确认'
                     % (os.path.basename(top['name']), '；'.join(top['anomalies'][:3])))
    if sos and not so_bad:
        notes.append('%d 个 SO 已做 ELF 结构检查，未见加壳/自定义 Linker 信号；'
                     '注意 SO VMP 静态无法确认，仍需动态 trace（SCRIPT.md §2 / §3.6：SO · B13）' % len(sos))

    # ---- 结论 ladder
    has_b3 = any(r.startswith(('B3 ', 'B3*')) for r in rules)
    has_b6 = any(r.startswith('B6') for r in rules)
    has_b7 = any(r.startswith('B7') for r in rules)
    has_b8 = any(r.startswith('B8') for r in rules)
    has_b13 = any(r.startswith('B13') for r in rules)
    has_b11 = any(r.startswith('B11') for r in rules)
    has_b12 = any(r.startswith('B12') for r in rules)
    has_payload = bool(high_entropy_assets)

    if has_b3:
        concl = '已加固：类抽取型（二代及以上）'
    elif has_b6 and has_b7:
        concl = '已加固：DEX 整体加密型（一代）'
    elif has_b11:
        concl = '疑似 DEX VMP（业务方法退化为解释器调用，B3 空方法率在此失效）—— 需人工确认'
    elif has_b12:
        concl = '疑似 Java2CPP / 重度 native 化（DEX 侧只剩 native 桩）—— 需人工确认'
    elif has_b8:
        concl = '疑似 Native 侧加固（发现已知壳厂商 SO），需 ELF 层确认'
    elif has_b13:
        concl = '疑似 SO 加壳 / 自实现 Linker（ELF 结构异常），需 ELF 层确认'
    elif has_b7 and has_payload:
        concl = '疑似 DEX 动态加载（有缺失组件类 + 有高熵载荷），证据不足以下代次结论'
    elif rules and any(not r.startswith('B1') for r in rules):
        concl = '疑似加固（证据不足以下代次结论）'
    else:
        # B1 单独不足以翻结论：真实 App 里压缩资源 / ML 模型 / 加密库都可能是高熵的，
        # 单凭"有一个高熵文件"就判可疑，等于把半个应用商店都标成可疑。
        concl = '未见已知加固特征（不等于未加固，见下方认知边界）'
    hints = ['朴素阈值类数<=8：%s' % naive2_hint] if naive2_hint else []
    return concl, rules, naive, hints, notes


# ------------------------------------------------------------ 输出
def report(f, as_json=False):
    concl, rules, naive, hints, notes = verdict(f)
    if as_json:
        print(json.dumps({'features': f, 'verdict': concl, 'rules': rules,
                          'naive_string_rule': naive, 'hints': hints,
                          'notes_need_manual': notes},
                         ensure_ascii=False, indent=2))
        return
    print('=' * 72)
    print('样本：%s   (%s, %d bytes)' % (f['path'], f['type'], f['size']))
    print('=' * 72)
    if f['type'] == 'apk':
        print('--- ZIP 条目 ---')
        for e in f['entries']:
            print('  %-42s %8d  %s' % (e['name'], e['size'], e['entropy']))
        print('--- AndroidManifest（aapt2 xmltree 精确解析）---')
        _app = f.get('manifest_application')
        if _app:
            _app_disp = _app
        elif f.get('manifest_parsed'):
            _app_disp = '(无 application 声明)'
        else:
            _app_disp = '(解析失败)'
        print('  application = %s' % _app_disp)
        comps = f.get('manifest_components') or {}
        for k in ('activity', 'service', 'receiver', 'provider'):
            if comps.get(k):
                print('  %-10s : %s' % (k + 's', ', '.join(comps[k])))
    print('--- dex 特征 ---')
    for d in f['dexes']:
        if d.get('error'):
            print('  %s : %s' % (d['label'], d['error']))
            continue
        print('  [%s] %d bytes, magic=%s, entropy=%.4f'
              % (d['label'], d['size'], d['magic'], d['entropy']))
        print('       class_defs=%d  methods=%d(with code %d, empty %d)  空方法率=%.2f%%'
              % (d['class_defs'], d['methods_total'], d['methods_with_code'],
                 d['methods_empty'], d['empty_ratio'] * 100))
        print('       checksum_ok=%s' % d['checksum_ok'])
        print('       家族字符串命中: %s' % (d['family_string_hits'] or '无'))
        print('       动态加载字符串: %s' % (d['loader_string_hits'] or '无'))
        print('       Application 类: %s' % (d['application_classes'] or '无'))
        if d['hot_classes']:
            print('       含空方法的类(按空率排序):')
            for h in d['hot_classes']:
                print('          %-46s %2d/%2d  %.0f%%'
                      % (h['class'], h['empty'], h['total'], h['ratio'] * 100))
    if f.get('libs'):
        print('--- Native 侧 (lib/) ---')
        for e in f['libs']:
            print('  %-42s %8d  %s' % (e['name'], e['size'], e['entropy']))
    print('--- 判定 ---')
    print('  【判据 A · 朴素字符串】%s' % naive)
    for r in rules:
        print('  【判据 B · 结构】%s' % r)
    print('  >> 结论：%s' % concl)
    for h in hints:
        print('  （对照）%s' % h)
    if notes:
        print('  【需人工复核】')
        for n in notes:
            print('     - %s' % n)
    print('  ' + COVERAGE_NOTICE)
    print()


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    as_json = '--json' in sys.argv
    if not args:
        print(__doc__)
        return 1
    for p in args:
        p = p if os.path.isabs(p) else os.path.join(ROOT, p)
        if not os.path.exists(p):
            print('不存在: %s' % p)
            continue
        f = apk_features(p) if (p.lower().endswith('.apk') or zipfile.is_zipfile(p)) \
            else dex_file_features(p)
        report(f, as_json)
    return 0


if __name__ == '__main__':
    sys.exit(main())
