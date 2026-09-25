#!/usr/bin/env python
# detect_packer.py — 基于"结构特征"判断加壳 / 是否 UPX / 是否变种
# 不使用文件名、不依赖 UPX 字符串，全部靠 ELF 结构与统计特征判定。
#
# 用法:
#   python tools/detect_packer.py <file>            # 详细判定（含教学解释）
#   python tools/detect_packer.py <file> --brief    # 只看结论
#   python tools/detect_packer.py <file> --verify   # 实证确认被篡改的魔数（需 upx）
#   python tools/detect_packer.py <file> --verify --upx <upx 路径>
#
# 【可复用】不依赖任何具体项目：upx 通过 PATH / 环境变量 UPX / --upx 定位。
import sys, os, struct, math, collections, subprocess, shutil, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _disp(p):
    """产物/日志里不落绝对路径：工程内路径显示成相对路径，工程外只显示文件名。"""
    try:
        rp = os.path.relpath(os.path.abspath(p), ROOT)
        if not rp.startswith('..'):
            return rp.replace('\\', '/')
    except Exception:
        pass
    return os.path.basename(p)


def _upx_from_path():
    """在 PATH 里找 upx。
    注意: Windows 下 shutil.which() 会优先搜索"当前目录"，会让项目自带的 upx.exe
    意外盖掉系统 upx，所以这里手动遍历 PATH 并跳过当前目录。
    """
    cwd = os.path.abspath(os.getcwd())
    names = ("upx.exe", "upx") if os.name == "nt" else ("upx",)
    for d in (os.environ.get("PATH") or "").split(os.pathsep):
        d = d.strip().strip('"')
        if not d: continue
        try:
            if os.path.abspath(d) == cwd: continue
        except Exception:
            continue
        for n in names:
            p = os.path.join(d, n)
            if os.path.isfile(p): return p
    return None

def find_upx(explicit=None):
    """定位 UPX 可执行文件（与具体项目无关）。

    优先级: --upx 显式指定 > 环境变量 UPX > 项目根目录下的 upx.exe / upx
            > PATH 中的 upx / upx.exe > tools/upx396.exe（仅兜底）
    项目内优先于 PATH：本 lab 的实测数值基于项目自带版本，换版本可能复现不出同样样本；
    要换版本请显式 --upx / UPX=，不要靠 PATH 偷偷切。
    """
    if explicit: return explicit
    env = os.environ.get("UPX")
    if env and os.path.exists(env): return env
    for c in (os.path.join(ROOT, "upx.exe"), os.path.join(ROOT, "upx")):
        if ROOT and os.path.exists(c): return c
    w = _upx_from_path()
    if w: return w
    c = os.path.join(ROOT, "tools", "upx396.exe")
    if ROOT and os.path.exists(c): return c
    return None

# 认知边界：明确告诉使用者本工具【不】覆盖哪些方案，
# 避免把"没看到已知特征"当成"没有加固"（这是最危险的误判方向）。
COVERAGE_NOTICE = (
    "本工具覆盖 UPX 类壳（魔数/结构特征）与 SO 加壳/自实现 Linker 的 ELF 结构异常"
    "（节头剥离 B13）。\n"
    "  仍需人工复核的场景：① SO VMP —— 即便 ELF 结构正常，VMP 解释器仍是普通大函数，"
    "静态不可定性，须动态 trace 确认；② 不走'汇聚调用'形态的自定义 VMP；"
    "③ 精巧的字符串加密。\n"
    "  故'未见已知特征'绝不等于'未加固'。"
)

# ---------- 基础工具 ----------
def entropy(b):
    if not b: return 0.0
    c=collections.Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def parse_elf(d):
    if d[:4]!=b"\x7fELF": return None
    is64 = d[4]==2
    en="<"
    if is64:
        e_type,e_machine = struct.unpack_from(en+"HH",d,16)
        e_entry,e_phoff,e_shoff = struct.unpack_from(en+"QQQ",d,24)
        e_phentsize,e_phnum,e_shentsize,e_shnum = struct.unpack_from(en+"HHHH",d,54)
    else:
        e_type,e_machine = struct.unpack_from(en+"HH",d,16)
        e_entry,e_phoff,e_shoff = struct.unpack_from(en+"III",d,24)
        e_phentsize,e_phnum,e_shentsize,e_shnum = struct.unpack_from(en+"HHHH",d,42)
    loads=[]
    for i in range(e_phnum):
        o=e_phoff+i*e_phentsize
        if is64:
            t,fl,off,va,pa,fsz,msz,al = struct.unpack_from(en+"IIQQQQQQ",d,o)
        else:
            t,off,va,pa,fsz,msz,fl,al = struct.unpack_from(en+"IIIIIIII",d,o)
        if t==1:
            loads.append(dict(i=i,off=off,vaddr=va,filesz=fsz,memsz=msz,flags=fl))
    sect=[]
    if e_shoff and e_shnum:
        for i in range(e_shnum):
            o=e_shoff+i*e_shentsize
            if is64:
                nm,ty,fl,ad,of,sz = struct.unpack_from(en+"IIQQQQ",d,o)
            else:
                nm,ty,fl,ad,of,sz = struct.unpack_from(en+"IIIIII",d,o)
            sect.append(dict(i=i,type=ty,addr=ad,off=of,size=sz))
    return dict(is64=is64,e_type=e_type,e_machine=e_machine,e_entry=e_entry,
                e_shnum=e_shnum,loads=loads,sect=sect)

def magic_candidates(d, tail=96, lo=2, hi=16):
    """被篡改的 UPX 魔数候选。
    放宽会误判（如 00000000 这种填充出现几百次），所以设三重约束：
      1) 出现次数在 [2,16] 之间（真魔数通常只出现几次）
      2) 不是 4 字节全相同的填充值（如 00 00 00 00）
      3) 至少有一次出现在文件尾部（UPX 的 l_info 在尾部）
    """
    cnt=collections.Counter()
    for i in range(len(d)-3):
        g=d[i:i+4]
        if g!=b"UPX!": cnt[g]+=1
    tailb=d[max(0,len(d)-tail):]
    cands=[]
    for g,c in cnt.items():
        if not (lo<=c<=hi): continue                      # ① 次数筛选
        # ② 只排除 0x00/0xFF 这类纯填充；不能排除"4字节全同"，
        #    否则 XXXX 这种真实占位魔数会被误杀
        if g[0]==g[1]==g[2]==g[3] and g[0] in (0x00,0xFF): continue
        if g not in tailb: continue                       # ③ 必须出现在尾部
        offs=[]; i=-1
        while True:
            i=d.find(g,i+1)
            if i<0: break
            offs.append(i)
        cands.append((g,offs))
    # 可打印 ASCII 的更可疑（人手工替换时常留可读占位符），其次按出现次数升序
    cands.sort(key=lambda x:(0 if all(32<=b<127 for b in x[0]) else 1, len(x[1])))
    return cands[:5]

# ---------- 特征判定 ----------
def detect(path, brief=False, verify=False, upx=None):
    d=open(path,"rb").read()
    e=parse_elf(d)
    if not e:
        print("[!] 不是 ELF 文件:", path); return
    H=entropy(d)
    total_memsz=sum(s["memsz"] for s in e["loads"])
    ratio_mem = total_memsz/len(d) if d else 0
    upx_bang = d.count(b"UPX!")

    print("="*70)
    print("目标:", path, "  (%d bytes)"%len(d))
    print("  架构: %s  e_type=%d  e_entry=0x%X"%(
          ("64-bit" if e["is64"] else "32-bit"), e["e_type"], e["e_entry"]))
    print("-"*70)
    print("逐项特征判定（不依赖文件名/不依赖 UPX 字符串）:\n")

    score=0
    feats=[]
    cands = magic_candidates(d)

    # F1 节区表
    f1 = (e["e_shnum"]==0)
    # F2 熵
    f2 = H>7.0
    # F3 解压缓冲段：要求 memsz>=32KB，否则普通 .bss 会被误判
    big=[s for s in e["loads"]
         if s["filesz"]>0 and s["memsz"]/max(1,s["filesz"])>=4 and s["memsz"]>=0x8000]
    f3 = len(big)>0
    # F4 入口在 stub 段
    stub=None
    for s in e["loads"]:
        if s["vaddr"]<=e["e_entry"]<s["vaddr"]+s["memsz"]:
            stub=s; break
    f4 = bool(stub is not None and e["loads"] and stub is not e["loads"][0])
    # F5 内存/文件体积比
    f5 = ratio_mem>=3.0
    # F6 UPX 魔数
    f6 = upx_bang>0
    # F7 尾部 sz_unc
    tail4 = struct.unpack_from("<I", d, len(d)-12)[0]
    f7 = (1000 < tail4 < 64*1024*1024) and (tail4 > len(d))
    # F8 只在"已有>=2项加壳特征"时才启用，避免干净文件被误判为变种
    packed_ev = sum([f1,f2,f3,f4,f5])
    f8 = (not f6) and packed_ev>=2 and len(cands)>0

    # ---- B13：SO 加壳 / 自实现 Linker 的 ELF 结构异常（独立于 UPX 打分）----
    # 正常 NDK .so 永远带完整节头（e_shnum>0）；节头被剥离的自实现 Linker 才会 e_shnum=0。
    # 这是干净、可靠、不会误伤的强信号——UPX 类壳不改 e_shnum，故与上面 F1~F8 不冲突。
    exec_load = any((s.get("flags", 0) & 1) for s in e["loads"])
    b13 = (e["e_type"] == 3 and e["e_shnum"] == 0 and exec_load)

    feats.append(("F1 节区头数量", "e_shnum=%d"%e["e_shnum"],
        "加壳样本常被剥离节区表(e_shnum=0)，IDA 里看不到 .text/.rodata", f1, 2))
    feats.append(("F2 整文件熵", "%.3f bits/byte"%H,
        "正常代码/数据约 4~6.5；>7.0 说明主体是压缩或加密数据", f2, 2))
    desc = ("PT_LOAD[%d] filesz=0x%X -> memsz=0x%X (%.1fx)"%(
            big[0]["i"],big[0]["filesz"],big[0]["memsz"],
            big[0]["memsz"]/max(1,big[0]["filesz"]))) if f3 else "无"
    feats.append(("F3 大解压缓冲段", desc,
        "UPX 的 UPX0：文件里几乎为空、内存中却很大(解压目标区)；要求 memsz>=32KB 以排除普通 .bss", f3, 3))
    feats.append(("F4 入口位置",
        ("e_entry=0x%X 落在 PT_LOAD[%d] (vaddr=0x%X, size=0x%X)"%(
            e["e_entry"], stub["i"], stub["vaddr"], stub["memsz"])) if stub else "未落在任何 PT_LOAD",
        "入口不在首个段、而在一段较小的 stub 里 => 先执行解压代码", f4, 2))
    feats.append(("F5 内存/文件体积比", "%.2fx (memsz=0x%X)"%(ratio_mem,total_memsz),
        "运行时占用远大于文件体积 => 运行时会解压出更多内容", f5, 2))
    feats.append(("F6 'UPX!' 魔数", "出现 %d 次"%upx_bang,
        "标准 UPX 特征；变种会把它们替换掉", f6, 3))
    feats.append(("F7 尾部 sz_unc 字段", "0x%X = %d"%(tail4,tail4),
        "UPX 在尾部结构里记录解压后大小；远大于当前文件 => 被压缩过", f7, 2))
    feats.append(("F8 疑似被篡改魔数",
        ("候选 %r 出现 %d 次 @ %s"%(cands[0][0], len(cands[0][1]),
          [hex(x) for x in cands[0][1]])) if (f8 and cands) else "无",
        "无 UPX!，但有'重复(2~16次)且出现在尾部'的 4 字节 token => 特征被替换过", f8, 3))

    for name,val,why,hit,pts in feats:
        mark = "命中" if hit else "  - "
        if hit: score += pts
        print("  [%s] %-16s %s"%(mark,name,val))
        if not brief:
            print("        判据: %s   (+%d)"%(why,pts if hit else 0))

    # ---- B13 提示（独立于 UPX 打分）----
    if b13:
        print("\n[B13 · SO 加壳 / 自实现 Linker] e_type=ET_DYN 但 e_shnum=0（节头表被剥离）："
              "自定义 Linker 通常自己按 Program Header 装载，不写标准节头。"
              "这是可靠的强信号——正常 NDK .so 永远带完整节头，不会误伤。")
    print("-"*70)
    print("综合得分: %d"%score)

    # 结论
    packed = False
    if f6 and score>=6:
        verdict="标准 UPX 壳（特征完整）"
        action="直接 upx -t 验证，然后 upx -d 解包，不必手脱"
        packed = True
    elif f8 and score>=6:
        verdict="★ 变种 UPX 壳（UPX 特征被抹掉，但结构仍在）"
        action="走解法 A：把候选 token 还原成 'UPX!'（必须全部还原）后 upx -d；失败则走解法 B 内存 dump"
        packed = True
    elif score>=4:
        verdict="疑似加壳（非 UPX 或深度魔改）"
        action="无法用 upx 处理 -> 走解法 B：动态运行 + 内存 dump + ELF Fix"
        packed = True
    else:
        verdict="未见已知加固特征（≠未加壳）"
        action=("无 UPX 特征、结构正常，可直接 IDA 分析；"
                "注意自实现 Linker / SO VMP 静态不可确认，需动态 trace")
        # B13 优先：即便其它特征没命中，节头被剥离也要单独标出来
        if b13:
            verdict="疑似 SO 加壳 / 自实现 Linker（ELF 节头被剥离）— 需人工进 ELF 层确认"
            action="无 UPX 特征但节头被剥离 => 自实现 Linker 概率高，走解法 B 内存 dump + ELF Fix"
            packed = True

    print("判定结果: %s"%verdict)
    print("建议动作: %s"%action)
    print("-"*70)
    print("认知边界（本工具不覆盖的方案，绝不等于'没有加固'）:")
    print("  "+COVERAGE_NOTICE)

    if f8 and cands:
        print("\n[魔数候选] 可用十六进制编辑器自行把这些偏移改回 'UPX!':")
        for g,offs in cands:
            print("   token %r  x%d  偏移: %s"%(g,len(offs),[hex(x) for x in offs]))
        print("   注意: 必须把所有出现位置都改回，UPX 校验和覆盖全部内嵌魔数，只改一处仍会失败。")
        print("   提示: 上面是静态启发式候选，可能有巧合项；用 --verify 可实证确认哪一个是真魔数。")
        if verify:
            UPX=find_upx(upx)
            if not UPX:
                print("\n[实证验证] 未找到 upx，跳过实证。解决方式任选其一："
                      "把 upx 加入 PATH / 设置环境变量 UPX / --upx <路径>")
            else:
                print("\n[实证验证] 逐个候选打补丁后用 upx -t 检验:  (upx = %s)" % _disp(UPX))
                tmp=os.path.join(tempfile.gettempdir(),"_detect_probe.so")
                for g,offs in cands:
                    try:
                        open(tmp,"wb").write(d.replace(g, b"UPX!"))
                        r=subprocess.run([UPX,"-t",tmp],capture_output=True,text=True,timeout=60)
                        ok=(r.returncode==0)
                    except Exception:
                        ok=False
                    finally:
                        if os.path.exists(tmp): os.remove(tmp)
                    print("   %r x%-3d -> upx -t %s"%(g,len(offs),
                          "OK   <= 这就是被篡改的真魔数" if ok else "FAIL"))
    res = dict(b13=b13, verdict=verdict, score=score,
               e_type=e["e_type"], e_shnum=e["e_shnum"],
               is_packed=packed)
    print("="*70+"\n")
    return res

if __name__=="__main__":
    argv=sys.argv[1:]
    args=[a for a in argv if not a.startswith("--")]
    brief="--brief" in argv
    verify="--verify" in argv
    upx=None
    if "--upx" in argv and argv.index("--upx")+1 < len(argv):
        upx=argv[argv.index("--upx")+1]
    if not args:
        print("用法: python tools/detect_packer.py <file> [--brief] [--verify] [--upx <path>]")
        sys.exit(1)
    for p in args: detect(p, brief, verify, upx)
