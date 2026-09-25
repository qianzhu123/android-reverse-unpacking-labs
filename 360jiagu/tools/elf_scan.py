#!/usr/bin/env python
# elf_scan.py — 极简 ELF 解析器（无第三方依赖）
# 对应文档第二步"确定 ELF 基本信息"与第三步"不要只依赖 UPX 特征"。
# 输出：ELF 头 / Program Header / Section Header / 动态段(DT_*) / UPX 指纹检测。
import sys, struct

PT_LOAD=1; PT_DYNAMIC=2; PT_INTERP=3; PT_NOTE=4
DT_NULL=0; DT_NEEDED=1; DT_SYMTAB=6; DT_STRTAB=5; DT_SONAME=14
DT_INIT=12; DT_FINI=13; DT_INIT_ARRAY=25; DT_INIT_ARRAYSZ=27
DT_FINI_ARRAY=26; DT_SYMENT=11; DT_STRSZ=10
SHT_PROGBITS=1; SHT_STRTAB=3; SHT_NOBITS=8

def u(data, off, fmt):
    return struct.unpack_from(fmt, data, off)[0]

def vaddr_to_off(phdrs, vaddr):
    for p in phdrs:
        if p['type']==PT_LOAD and p['vaddr']<=vaddr<p['vaddr']+p['filesz']:
            return vaddr-p['vaddr']+p['offset']
    return None

def cstr(data, off):
    end=data.index(b'\x00', off)
    return data[off:end].decode('latin1')

def parse(path):
    data=open(path,'rb').read()
    if data[:4]!=b'\x7fELF': return None
    ei_class=data[4]; ei_data=data[5]
    is64 = (ei_class==2)
    le = (ei_data==1)
    en='<' if le else '>'
    e_type=u(data,16,en+'H'); e_machine=u(data,18,en+'H')
    if is64:
        e_entry=u(data,24,en+'Q'); e_phoff=u(data,32,en+'Q'); e_shoff=u(data,40,en+'Q')
        e_phentsize=u(data,54,en+'H'); e_phnum=u(data,56,en+'H')
        e_shentsize=u(data,58,en+'H'); e_shnum=u(data,60,en+'H'); e_shstrndx=u(data,62,en+'H')
    else:
        e_entry=u(data,24,en+'I'); e_phoff=u(data,28,en+'I'); e_shoff=u(data,32,en+'I')
        e_phentsize=u(data,42,en+'H'); e_phnum=u(data,44,en+'H')
        e_shentsize=u(data,46,en+'H'); e_shnum=u(data,48,en+'H'); e_shstrndx=u(data,50,en+'H')
    # program headers
    phdrs=[]
    for i in range(e_phnum):
        o=e_phoff+i*e_phentsize
        if is64:
            p={'type':u(data,o,en+'I'),'flags':u(data,o+4,en+'I'),
               'offset':u(data,o+8,en+'Q'),'vaddr':u(data,o+16,en+'Q'),
               'filesz':u(data,o+32,en+'Q'),'memsz':u(data,o+40,en+'Q')}
        else:
            p={'type':u(data,o,en+'I'),'offset':u(data,o+4,en+'I'),
               'vaddr':u(data,o+8,en+'I'),'filesz':u(data,o+16,en+'I'),
               'memsz':u(data,o+20,en+'I'),'flags':u(data,o+24,en+'I')}
        phdrs.append(p)
    # section headers + names
    shdrs=[]; shnames=[]
    if e_shoff:
        for i in range(e_shnum):
            o=e_shoff+i*e_shentsize
            if is64:
                sh={'name':u(data,o,en+'I'),'type':u(data,o+4,en+'I'),
                    'flags':u(data,o+8,en+'Q'),'addr':u(data,o+16,en+'Q'),
                    'offset':u(data,o+24,en+'Q'),'size':u(data,o+32,en+'Q')}
            else:
                sh={'name':u(data,o,en+'I'),'type':u(data,o+4,en+'I'),
                    'flags':u(data,o+8,en+'I'),'addr':u(data,o+12,en+'I'),
                    'offset':u(data,o+16,en+'I'),'size':u(data,o+20,en+'I')}
            shdrs.append(sh)
        shstr_off=shdrs[e_shstrndx]['offset'] if e_shstrndx<len(shdrs) else 0
        for sh in shdrs:
            shnames.append(cstr(data, shstr_off+sh['name']))
    # dynamic section
    dyn=None
    for p in phdrs:
        if p['type']==PT_DYNAMIC:
            dyn={'off':p['offset'],'sz':p['filesz']}
    dyninfo={}
    if dyn:
        entsize=16 if is64 else 8
        strtab_off=None; needed=[]
        i=0
        tags=[]
        while i+entsize<=dyn['off']+dyn['sz']:
            o=dyn['off']+i
            if is64:
                tag=u(data,o,en+'q'); val=u(data,o+8,en+'Q')
            else:
                tag=u(data,o,en+'i'); val=u(data,o+4,en+'I')
            tags.append((tag,val))
            i+=entsize
            if tag==DT_NULL: break
        for tag,val in tags:
            if tag==DT_STRTAB:
                strtab_off=vaddr_to_off(phdrs,val)
            if tag in (DT_INIT,DT_FINI,DT_INIT_ARRAY,DT_FINI_ARRAY):
                dyninfo.setdefault({DT_INIT:'DT_INIT',DT_FINI:'DT_FINI',
                    DT_INIT_ARRAY:'DT_INIT_ARRAY',DT_FINI_ARRAY:'DT_FINI_ARRAY'}[tag], hex(val))
            if tag==DT_INIT_ARRAYSZ: dyninfo['DT_INIT_ARRAYSZ']=val
        for tag,val in tags:
            if tag==DT_NEEDED and strtab_off is not None:
                needed.append(cstr(data, strtab_off+val))
        dyninfo['DT_NEEDED']=needed
    # UPX fingerprint
    upx_bang=data.count(b'UPX!')
    upx_sec=[n for n in shnames if n.startswith('UPX')]
    sec_renamed=[n for n in shnames if n.startswith('SEC')]
    return {'data':data,'is64':is64,'le':le,'e_type':e_type,'e_machine':e_machine,
            'e_entry':e_entry,'phdrs':phdrs,'shdrs':shdrs,'shnames':shnames,
            'dyninfo':dyninfo,'upx_bang':upx_bang,'upx_sec':upx_sec,'sec_renamed':sec_renamed}

ET={0:'ET_NONE',1:'ET_REL',2:'ET_EXEC',3:'ET_DYN',4:'ET_CORE'}
MACH={0x03:'X86',0x28:'ARM',0x08:'MIPS',0xB7:'AARCH64',0x3E:'X86_64'}

def report(p, path):
    print("="*64)
    print("FILE:", path, "(%d bytes)"%len(p['data']))
    print("  e_type   : %d (%s)"%(p['e_type'], ET.get(p['e_type'],'?')))
    print("  e_machine: 0x%X (%s)"%(p['e_machine'], MACH.get(p['e_machine'],'?')))
    print("  e_entry  : 0x%X"%p['e_entry'])
    print("  class    : %d-bit, %s"%(64 if p['is64'] else 32, 'LE' if p['le'] else 'BE'))
    print("-- Program Headers --")
    for i,ph in enumerate(p['phdrs']):
        tname={1:'PT_LOAD',2:'PT_DYNAMIC',3:'PT_INTERP',4:'PT_NOTE'}.get(ph['type'],'0x%X'%ph['type'])
        print("  [%2d] %-12s off=0x%X vaddr=0x%X filesz=0x%X memsz=0x%X flags=%d"%(
            i,tname,ph['offset'],ph['vaddr'],ph['filesz'],ph['memsz'],ph['flags']))
    print("-- Section Headers (%d) --"%len(p['shdrs']))
    for i,sh in enumerate(p['shdrs']):
        nm=p['shnames'][i] if i<len(p['shnames']) else ''
        print("  [%2d] %-16s type=0x%X addr=0x%X off=0x%X size=0x%X"%(
            i,nm,sh['type'],sh['addr'],sh['offset'],sh['size']))
    print("-- Dynamic (DT_*) --")
    di=p['dyninfo']
    if di:
        for k,v in di.items():
            print("  %s = %s"%(k,v))
    else:
        print("  (no PT_DYNAMIC)")
    print("-- UPX 指纹检测 --")
    print("  'UPX!' 出现次数 : %d"%p['upx_bang'])
    print("  段名含 UPX*    : %s"%(p['upx_sec'] if p['upx_sec'] else '无'))
    print("  段名含 SEC*    : %s"%(p['sec_renamed'] if p['sec_renamed'] else '无'))
    if p['upx_bang']>0 or p['upx_sec']:
        print("  => 命中明显 UPX 特征（疑似标准/弱变种 UPX）")
    elif p['e_type'] in (2,3) and any(s['type']==PT_DYNAMIC for s in p['phdrs']):
        print("  => 无明显 UPX 字符串，但仍是动态库：需结合运行时内存判断（变种可能）")
    print("="*64+"\n")

if __name__=='__main__':
    for path in sys.argv[1:]:
        p=parse(path)
        if p: report(p, path)
        else: print("[!] not an ELF:", path)
