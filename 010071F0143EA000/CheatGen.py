# This Script is Programmed by Eiffel2018
# Works in IDA PRO v7.5 up 
# Requirement: Python 3.9.x (with idapyswitch) and Keystone 
# Operate with a clean NSO (or main.elf) or GDB connected with segment defined by markRegions64.py

isDebug = True

import idc, ida_bytes, ida_search, ida_struct, idautils, sys, ida_kernwin, ida_funcs, idaapi, ida_segment, math
from inspect import currentframe, getframeinfo
from ida_idaapi import BADADDR
from keystone import *

TM='E'
gdb = ida_segment.get_segm_by_name('main') != None
Base=main= ida_segment.get_segm_by_name('main').start_ea if gdb else ida_segment.get_segm_by_name('.text').start_ea
CodeStart = Base+0x30
CodeEnd = ida_segment.get_segm_by_name('main').end_ea if gdb else ida_segment.get_segm_by_name('.rodata').start_ea
DataStart = ida_segment.get_segm_by_name('main_data').start_ea if gdb else ida_segment.get_segm_by_name('.rodata').start_ea
DataEnd = ida_segment.get_segm_by_name('main_data').end_ea if gdb else ida_segment.get_segm_by_name('.init_array').end_ea

def p(x): # output String or HEX number
    print(hex(x) if isinstance(x, int) and x>1 else x)
def cls():
    ida_kernwin.activate_widget(ida_kernwin.find_widget("Output window"), True);
    ida_kernwin.process_ui_action("msglist:Clear");
def s(): # get current address, used for GBD environment
    return get_screen_ea()
def a(): # print current address as [main+??????] used for GBD environment
    msg('main+')
    p(s()-Base)
def r():
    addr=get_next_func(get_screen_ea())-4
    while get_wide_dword(addr) in (0,0xD503201F,0xE7FFDEFE): addr-=4
    makeFunc(addr)
def g(name):
    jumpto(get_name_ea(CodeStart,name))
def halt(text):
    print(text)
    raise error(0)
def debug(text):
    if isDebug: print(text)
def show(text):
    ida_kernwin.replace_wait_box(text)
    time.sleep(0.00000001)
def isCode(targetAddr):
    return is_code(get_full_flags(targetAddr))
def isFunc(targetAddr):
    return ida_bytes.is_func(get_full_flags(targetAddr))
def isPointer(targetAddr):
    # return is_off(get_full_flags(targetAddr),OPND_ALL)
    addr=get_qword(targetAddr);
    return addr>CodeStart and addr<DataEnd
def isFound(targetAddr):
    return targetAddr != BADADDR
def notFound(targetAddr):
    return targetAddr == BADADDR
def Addr2DWord(opAddr):
    return "{:08X}".format(opAddr & 0xFFFFFFFF)
def Value2DWord(value):
    if type(value) is str: value=int(value.replace(' ',''), 16)
    return "{:08X}".format(value & 0xFFFFFFFF)
def Value2QWord(value):
    if type(value) is str: value=int(value.replace(' ',''), 16)
    return "{:08X} {:08X}".format(value // 0x100000000, value & 0xFFFFFFFF)
def Float2DWord(f):
    return struct.unpack('<I', struct.pack('<f', f))[0]
def GetBytes(length,opAddr):
    return {1:ida_bytes.get_original_byte(opAddr), 2:ida_bytes.get_original_word(opAddr), 4:ida_bytes.get_original_dword(opAddr), 8:ida_bytes.get_original_dword(opAddr)}[length]
def makeFunc(addr):
    if not(CodeEnd>addr>CodeStart): return
    addr=addr//4*4
    while idaapi.get_func(addr)==None or not(isCode(addr)):
        funcStart=get_func_attr(get_prev_func(addr),FUNCATTR_END)
        while get_wide_dword(funcStart) in (0,0xD503201F,0xE7FFDEFE): funcStart+=4
        print('Making Function at %X'%(funcStart))
        del_items(funcStart)
        if not(ida_funcs.add_func(funcStart)):
            funcEnd=find_func_end(funcStart)
            if notFound(funcEnd) or funcEnd<funcStart:
                funcEnd=funcStart+4
                while print_insn_mnem(funcEnd) not in ('RET','B','BR') and funcEnd<CodeEnd and not(get_wide_dword(funcEnd) in (0,0xD503201F,0xE7FFDEFE)): funcEnd+=4
                if print_insn_mnem(funcEnd) in ('RET','B','BR'): funcEnd+=4
                ida_funcs.add_func(funcStart,funcEnd)
                auto_wait()
def getFuncStart(targetAddr):
    makeFunc(targetAddr)
    return get_func_attr(targetAddr,FUNCATTR_START)
def getFuncEnd(targetAddr):
    makeFunc(targetAddr)
    return get_func_attr(targetAddr,FUNCATTR_END)
def AOB(pattern,searchStart=CodeStart,searchEnd=CodeEnd):
    return ida_search.find_binary(searchStart, searchEnd, pattern, 0, SEARCH_DOWN|SEARCH_NEXT)
def AOB2(pattern,offset,pattern2):
    opAddr=AOB(pattern)
    return AOB(pattern2,get_operand_value(opAddr+offset,0)) if isFound(opAddr) else BADADDR
def AOB3(pattern,pattern2):
    opAddr=AOB(pattern)
    return AOB(pattern2,opAddr) if isFound(opAddr) else BADADDR
def allOccur(pattern):
    result=[]
    CheatAddr=AOB(pattern)
    while isFound(CheatAddr):
        result.append(CheatAddr)
        CheatAddr=AOB(pattern,CheatAddr+4)
    return result
def checkUnique(pattern):
    CheatAddr=AOB(pattern)
    return not(isFound(AOB(pattern,CheatAddr))) if isFound(CheatAddr) else None
def getBytesPattern(opAddr):
    return ' '.join('{:02X}'.format(x) for x in ida_bytes.get_bytes(opAddr, 4))
def anaysis(opAddr):
    cmd=print_insn_mnem(opAddr)
    if cmd == 'BL' or cmd == 'B':
        return '? ? ? {:02X}'.format(ida_bytes.get_original_byte(opAddr+3))
    elif cmd == 'ADRP' or cmd == 'ADRL':
        return '? ? ? ?'
    elif cmd == '' and print_insn_mnem(opAddr-4)=='ADRL':
        return "? ? ? {:02X}".format(ida_bytes.get_original_byte(opAddr+3))
    elif 'PAGEOFF' in print_operand(opAddr,1):
        return "{:02X} ? ? {:02X}".format(ida_bytes.get_original_byte(opAddr),ida_bytes.get_original_byte(opAddr+3))
    else:
        return getBytesPattern(opAddr)
def getAOB(opAddr=BADADDR):
    if opAddr==BADADDR: opAddr=get_screen_ea()
    pattern=space=''
    result=False
    funcEnd=getFuncEnd(opAddr)
    while opAddr<funcEnd and result==False:
        pattern+=space+anaysis(opAddr)
        space=' '
        opAddr+=4
        result=checkUnique(pattern)
    print('Not Unqiue! \n'+pattern if result==None else pattern)
def searchNextASM(addr,command,operand=None):
    funcEnd=getFuncEnd(addr)
    while addr<funcEnd:
        if operand==None:
            if print_insn_mnem(addr)==command: break
        else:
            if print_insn_mnem(addr)==command and operand==print_operand(addr,0): break
        addr+=4
    return addr if addr<funcEnd else BADADDR
def searchPrevASM(addr,command,operand=None):
    funcStart=getFuncStart(addr)
    while addr>=funcStart:
        if operand==None:
            if print_insn_mnem(addr)==command: break
        else:
            if print_insn_mnem(addr)==command and operand==print_operand(addr,0): break
        addr-=4
    return addr if addr>=funcStart else BADADDR
def PatchBytes(length,opAddr,value):
    if type(value) is str: value=int(value.replace(' ',''), 16)
    if (length==1):
        ida_bytes.patch_byte(opAddr,value)
    elif (length==2):
        ida_bytes.patch_word(opAddr,value)
    elif (length==4):
        ida_bytes.patch_dword(opAddr,value)
    elif (length==8):
        ida_bytes.patch_qword(opAddr,value)
    else:
        print('Error in PatchBytes(%X,%X,%X)'%(length,opAddr,value))
def CheatCode(length,opAddr,value):
    return '0{}0E0000 {} {}'.format(length,Addr2DWord(opAddr),Value2DWord(value) if length<=4 else Value2QWord(value))
def RestoreCode(length,opAddr):
    return CheatCode(length,opAddr,GetBytes(length,opAddr) if length<=4 else get_qword(opAddr))
def PointerCode(offsets, length, value): # offsets use tuples/list with at least 2 element
    if len(offsets)<2: return 'Error with PointerCode'
    code = '580F0000 {:08X}'.format(offsets[0])
    for offset in offsets[1:-1]: 
        code += '\n580F1000 {:08X}'.format(offset)
    code += '\n780F0000 {:08X}'.format(offsets[-1])
    code += '\n6{:1X}0F0000 {}'.format(length, Value2QWord(value))
    return code
def ptr(offsets,length=0): # return the address/value of pointer expression, e.g. [[main+123456]+1234]+32 , type ptr((123456,0x1234,0x32)) or ptr((123456,0x1234,0x32),4)
    if len(offsets)<2: return 'Error with NOEXES expression'
    addr=Base if offsets[0]<0x10000000 else 0
    for offset in offsets[:-1]: 
        addr = get_qword(addr+offset)
    addr += offsets[-1]
    # jumpto(addr)
    return addr if length==0 else GetBytes(length,addr)
def ButtonCode(key,code):
    keymap={'a':0x1,'b':0x2,'x':0x4,'y':0x8,'l3':0x10,'r3':0x20,'l':0x40,'r':0x80,'zl':0x100,'zr':0x200,'plus':0x400,'minus':0x800,'left':0x1000,'up':0x2000,'right':0x4000,'down':0x8000,'l3left':0x10000,'l3up':0x20000,'l3right':0x40000,'l3down':0x80000,'r3left':0x100000,'r3up':0x200000,'r3right':0x400000,'r3down':0x800000,'sl':0x1000000,'sr':0x2000000}
    if isinstance(key, str) and key.lower() in keymap: key=keymap[key.lower()] 
    return '8{:07X}\n{}\n20000000'.format(key,code)
def ConditionCode(length,opAddr,value,commands,otherwise=None):
    result = '1%d050000 %s %s\n%s\n'%(length,Addr2DWord(opAddr),Value2DWord(value) if length<=4 else Value2QWord(value),commands)
    if otherwise != None: result += '21000000\n%s\n'%(otherwise)
    result += '20000000'
    return result
def ToggleCode(button,length,opAddr,code):
    return ButtonCode(button,ConditionCode(length,opAddr,code,RestoreCode(length,opAddr),CheatCode(length,opAddr,code)))
def ASM(asm_code):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    try:
        bytecode, cnt = ks.asm(asm_code, as_bytes=True)
    except:
        warning("Error in code: %s"%asm_code)
        bytecode=b'FFFFFFFF'
    return ''.join(map('{:02X}'.format, reversed(bytecode)))
def applyPatch(code):# use 3 """ to quote the multiline codes
    lines=code.split('\n')
    for line in lines:
        if len(line)<26 or line[0]!='0': continue
        type,addr,value=(int(x.replace(' ',''),16) for x in line.split(' ',2))
        size=(type&0x0F000000)//0x1000000
        PatchBytes(size,Base+addr,value)
        del_items(addr+Base)
        create_insn(addr+Base)
def Hack(length,CheatAddr,Code):
    global DelayOutput
    if notFound(CheatAddr): 
        print(CheatName+': AOB broken!')
    else:
        print(RestoreCode(length,CheatAddr))
        DelayOutput += '\n' + CheatCode(length,CheatAddr,Code)
def HackAll(length,AOB,Code):
    global DelayOutput
    CheatAddrs=allOccur(AOB)
    if len(CheatAddrs)<1: 
        print(CheatName+': AOB broken!')
    else:
        for CheatAddr in CheatAddrs:
            print(RestoreCode(length,CheatAddr))
            DelayOutput += '\n' + CheatCode(length,CheatAddr,Code)
def CodeCave(CheatAddr,Codes):
    global CodeK, DelayOutput
    if notFound(CheatAddr): 
        print(CheatName+': AOB broken!')
    else:
        for instruction in reversed(Codes):
            CodeK-=4
            DelayOutput += '\n' + CheatCode(4,CodeK,ASM(instruction))
        DelayOutput += '\n' + CheatCode(4,CheatAddr,ASM('BL '+hex(CodeK-CheatAddr)))
        print(RestoreCode(4,CheatAddr))
def RegData(assignValue,isCommon=True):
    global CodeK, DelayOutput
    CodeK-=4
    if isCommon:
        print(CheatCode(4,CodeK,assignValue))
    else:
        DelayOutput += '\n' + CheatCode(4,CodeK,assignValue)
    return CodeK
def CodeFunc(Codes):
    global CodeK
    ResultCode=''
    for instruction in reversed(Codes):
        CodeK-=4
        ResultCode += '\n' + CheatCode(4,CodeK,ASM(instruction))
    return ResultCode
def Either(aob1,aob2):
    return aob1 if isFound(aob1) else aob2

    
# How to code the following section?
# First you need to load the above functions (Run once or Copy and Paste in the Python output windows)
# then type getAOB(0xAddressOfCheat) and you will get the AOB pattern
# You may check how many results can be get from binary search and choose one of the following method 
# AOB(pattern) return the first search result
# allOccur(pattern) return all the search results found
# AOB2(pattern1,offset,pattern2) return the result of second search, inside the BL/B function found by pattern1 + offset
# AOB3(pattern1,pattern2) return the nearest result of second search from the first search
# After the cheat codes were generated, you may paste it on the GDB with the applyPatch('''XXXXX''') function

if not(gdb):
    CodeK=CodeEnd
    cls()
    print('applyPatch(\'\'\'')
    CheatCnt=0
    DelayOutput = ''
################################ START ######################################

    # print("[Fire Emblem Warriors, Three Hopes Demo v1.00 (v0)  TID=01006E6017792000  BID=5BCDD361F58B7FFD]")
    print("[Fire Emblem Warriors, Three Hopes (US) v1.0.0(v0)  TID=010071F0143EA000  BID=8A25CB320BEDF519]")

# actorID= ptr((ActorObject,0,4))
#      or P1 actorID= ptr((0x24AFCB8,0x4B0,0x3950+0x2F4),1)
#      or P2 actorID= ptr((0x24AFCB8,0x4B8,0x3950+0x2F4),1)

# ActorObject
#       ptr((0x24AFCB8,0x358,0,0x10,0x4AA8,0x18,8*actorID)) 
#   Alternative method
#       P1 =ptr((0x24AFCB8,0x4B0,0x1E0,0x5E8))
#       P2 =ptr((0x24AFCB8,0x4B8,0x1E0,0x5E8))

# 敵我    ptr((ActorObject,0x2C))  0=敵方 1=我方

# Ability能力值 ptr((ActorObject,0x2B0))
#   Moving Speed     +0x4 / +0x84
#   Max HP  +0x20
#   HP     +0x24
#  無雙槽 WarriorsGauge   +0x38 / +0x34
#  力量 STR    +0x44
#  魔力 MAG    +0x46
#  技巧 DEX    +0x48
#  速度 SPD    +0x4A
#  幸運 LUK    +0x4C
#  防守 DEF    +0x4E
#  魔防 RES    +0x50
#  魅力 CHA    +0x52

# 技能/魔法1  ptr((ActorObject,0x2E8,0x8))
# 技能/魔法2 ptr((ActorObject,0x2E8,0x10))
#   Might       +0xF4
#   Durability  +0xF8
#   CoolDown    +0x1C

# 武器 ptr((ActorObject,0x338))
#   Hold X  CoolDown +0x14

# Adjutant ATK  副官追擊條 ptr((0x24AFCB8,0xB290,0x8,0,0x10,0x10+0x398)) 
# Adjutant DEF  副官守衞條 ptr((0x24AFCB8,0xB290,0x8,0,0x10,0x10+0x39C)) 


# Actor in City 
#     ptr((0x24AFC90,0x18,0x18,0xAC * actorID))  normally actorID = 0

# Max LV ptr((0x24AFC90,0x18,0x48,0x5BC)) float32 default 15, may change to 255
# LV        ptr((0x24AFCA8,0x18,0x8*(0x85+OrderID),0x17E)) OrderID = 0 to 3
# EXP        ptr((0x24AFCA8,0x18,0x8*(0x85+OrderID),0x168))

# 訓練點  Training =  ptr((0x24AFCA8,0x18,0x18,0x188 / Max 0x18B))
# 交流點  Activity =  ptr((0x24AFCA8,0x18,0x18,0x60 / Max ))
# 金錢  Gold =  ptr((0x24AFCA8,0x18,0x20,0x38))  heap+8325428
# 名聲  Renown =  ptr((0x24AFCA8,0x18,0x20,0x40))
# 作戰資源數 Strategy Resource =  ptr((0x24AFCA8,0x18,0x20,0x128)) heap+8325518  

# 瞬移次數  Shadow Slide = ptr((0x24AFCA8,0x18,0x10,0x234))  heap+82AE184
 
# 武器/物品 ptr((0x24AFC90,0x18,0x88,0x58*itemID))   price offset=0xC




    print('\n{Restore Code 還原碼}')
    
    Multiplier=1.5 
    CheatName = 'Speed Up 移動速度 (%.1fx)'%Multiplier
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4, AOB3('40 05 40 BD 08 10 2E 1E','42 85 40 BD'), ASM('FMOV S2, #%.2f'%Multiplier)) # LDR S2, [X10,#0x84]
    Hack(4, AOB('64 85 40 BD 63 05 40 BD'), ASM('FMOV S4, #%.2f'%Multiplier)) # LDR S4, [X11,#0x84]
    Hack(4, AOB('C1 86 40 BD 03 08 21 1E'), ASM('FMOV S1, #%.2f'%Multiplier)) # LDR S1, [X22,#0x84]
    Hack(4, AOB3('40 09 40 BD 08 10 2E 1E','42 85 40 BD'), ASM('FMOV S2, #%.2f'%Multiplier)) # LDR S2, [X10,#0x84]
            
    CheatName = 'Invincible HP不減'
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    CodeCave(AOB2('E8 08 00 B4 01 01 44 2D',0x10,'02 25 00 BD'),(  # STR S2, [X8,#0x24]\
            'LDRH W9,[X26,#0x2C]',\
            'TBZ W9, 0, .+8',\
            'FMOV S2, S3',\
            'STR S2, [X8,#0x24]',\
            'RET'))

    Multiplier=2.5
    CheatName = 'Damage Multiplier 傷害倍率 (%.1fx)'%Multiplier
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    CodeCave(AOB2('E8 08 00 B4 01 01 44 2D',0x10,'21 01 22 1E'),(  # SCVTF S1, W9
            'SCVTF S1, W9',\
            'LDRH W9,[X26,#0x2C]',\
            'TBNZ W9, 0, .+12',\
            'FMOV S3, #%.2f'%Multiplier,\
            'FMUL S1, S1, S3',\
            'RET'))

    CheatName = 'Unlimited Class Action 任意使用兵種動作 (Hold X)'
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4,AOB3('01 4D 41 BC 21 28 20 1E','01 01 00 BD'),ASM('STR S3, [X8]'))  # STR S1, [X8]

    CheatName = 'Unlimited CombatArts/Magic 任意使用技能/魔法 (R + X/Y)'
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4,AOB('00 15 40 BD ? ? ? 14 00 15 40 BD'),ASM('nop'))  # STR S0, [X8,#0x1C]
    Hack(4,AOB('28 61 01 B9'),ASM('nop'))  # STR W8, [X9,#0x160]

    CheatName = 'Max CombatArts/Magic LV and EXP 技能/魔法經驗等級最大'
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    CheatAddr=AOB('29 A1 46 79 4B 69 6B 38') # LDRH W9, [X9,#0x350]
    Hack(4,CheatAddr,ASM('LDRB W13, [X10,X13]'))
    Hack(4,CheatAddr+8,ASM('ADD W11, W13, W11'))
    Hack(4,CheatAddr+12,ASM('STRH W11, [X9,#0x350]'))
    Hack(4,CheatAddr+16,ASM('MOV W9, W11'))
    Hack(4,CheatAddr+20,ASM('MOV W12, #2'))

    CheatName = 'Free Warrior/Partner Special 任意使用無雙/連攜奧義 (A)'
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4,AOB('00 28 21 1E 41 01 27 1E 8A 3D 00 13'), ASM('SCVTF S0, W12'))  # FADD S0, S0, S1 增加無雙條
    Hack(4,AOB('00 28 21 1E 01 01 27 1E 60 3B 00 BD'), ASM('SCVTF S0, W9'))  # FADD S0, S0, S1 使出無雙奧義
    Hack(4,AOB3('48 5B 41 F9 C8 02 00 B4','00 28 21 1E'), ASM('SCVTF S0, W10'))  # FADD S0, S0, S1 使出連攜奧義
    
    CheatName = 'Unlimited Unique Action Ability 任意使出個人特技 (ZR) ** use after EP1'
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4,AOB('E0 03 14 AA F4 4F 44 A9 F6 57 43 A9 F9 0F 40 F9'), ASM('MOV X0, #0x1000000000000000'))  # MOV X0, X20 虛報有效
    Hack(4,AOB('08 5D 46 BD 09 59 46 BD'), ASM('FMOV S8, #31.0'))  # LDR S8, [X8,#0x65C] 個人特技條 顯示全滿

    CheatName = 'Max Awakening Gauge 覺醒值最大 (R + A)'
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4,AOB('61 0B 00 BD 88 ? ? F9 61 0E 40 B9'), ASM('STR S2, [X27,#8]'))  # STR S1, [X27,#8] 覺醒條增加
    Hack(4,AOB('20 38 20 1E 08 20 20 1E ? ? ? ? 00 01 00 BD'), ASM('FMOV S0, S1'))  # FSUB S0, S1, S0 覺醒條不減
    # Hack(4,AOB('00 CD 43 BD 08 59 A8 52'), ASM('FMOV S0, #1.0'))  # LDR S0, [X8,#0x3CC] 覺醒時扣減量改少
    Hack(4,AOB('7F 0B 00 B9 68 1B 00 B9'), ASM('NOP'))  # STR WZR, [X27,#8] 覺醒後使出無雙時不扣減
    HackAll(4, '68 0B 40 B9 7A 03 40 F9', ASM('MOV W8, #0x42C80000'))  # LDR W8, [X27,#8] 連攜奧義後覺醒條100
    
    CheatName = 'Max Adjutant Gauges 副官追擊條/守衞條最大'
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4,AOB3('21 99 43 BD','00 20 21 1E'), ASM('FMOV S0, S1'))  # FCMP S0, S1
    Hack(4,AOB3('21 9D 43 BD','00 20 21 1E'), ASM('FMOV S0, S1'))  # FCMP S0, S1

    CheatName = 'Unlimited Vulnerary 任意使用傷藥回復HP (R + B)'
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4,AOB('B4 72 52 39'), ASM('MOV W20, -1'))  # MOV W20, #0xFFFFFFFF 用藥次數0

    Multiplier=4
    CheatName = 'EXP Multiplier 經驗倍率 (%dx)'%(2**int(math.log(Multiplier,2)))
    CheatCnt+=1; DelayOutput += '\n\n[#%02da %s]'%(CheatCnt,CheatName)
    if isFound(AOB('29 01 01 0B 1F 01 09 6B')):
        Hack(4,AOB('29 01 01 0B 1F 01 09 6B'),ASM('ADD W9, W9, W1, LSL %d'%math.log(Multiplier,2)))  # ADD W9, W9, W1
    else:
        Hack(4,AOB('52 02 01 0B 5F 00 12 6B'),ASM('ADD W18, W18, W1, LSL %d'%math.log(Multiplier,2)))  # ADD W18, W18, W1

    Multiplier=16
    CheatName = 'EXP Multiplier 經驗倍率 (%dx)'%(2**int(math.log(Multiplier,2)))
    DelayOutput += '\n\n[#%02db %s]'%(CheatCnt,CheatName)
    if isFound(AOB('29 01 01 0B 1F 01 09 6B')):
        Hack(4,AOB('29 01 01 0B 1F 01 09 6B'),ASM('ADD W9, W9, W1, LSL %d'%math.log(Multiplier,2)))  # ADD W9, W9, W1
    else:
        Hack(4,AOB('52 02 01 0B 5F 00 12 6B'),ASM('ADD W18, W18, W1, LSL %d'%math.log(Multiplier,2)))  # ADD W18, W18, W1
 
    Multiplier=64
    CheatName = 'EXP Multiplier 經驗倍率 (%dx)'%(2**int(math.log(Multiplier,2)))
    DelayOutput += '\n\n[#%02dc %s]'%(CheatCnt,CheatName)
    if isFound(AOB('29 01 01 0B 1F 01 09 6B')):
        Hack(4,AOB('29 01 01 0B 1F 01 09 6B'),ASM('ADD W9, W9, W1, LSL %d'%math.log(Multiplier,2)))  # ADD W9, W9, W1
    else:
        Hack(4,AOB('52 02 01 0B 5F 00 12 6B'),ASM('ADD W18, W18, W1, LSL %d'%math.log(Multiplier,2)))  # ADD W18, W18, W1

    CheatName = 'Training Points 99 訓練次數' # heap+F442AF8 / heap+F56F948
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    CodeCave(AOB('02 23 46 39'), ('MOV W2, #99','STRB W2, [X24,#0x188]','STRB W2, [X24,#0x18B]','RET')) # LDRB W2, [X24,#0x188]

    CheatName = 'Activity Points 99 交流次數' # heap+831D760
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    CodeCave(AOB('02 83 41 39'), ('MOV W2, #99','STRB W2, [X24,#0x5F]','STRB W2, [X24,#0x60]','RET')) # LDRB W2, [X24,#0x60]
    # Hack(4,AOB('6B 31 8C 1A 0C 7D 41 39'), ASM('MOV W11, W12')) # CSEL W11, W11, W12, CC 交流次數不減, 暫用

    CheatName = 'Max Exp after training 訓練後兵種經驗最大' 
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4, AOB('4B 80 8B 1A'), ASM('MOV W2, W11')) # CSEL W11, W2, W11, HI
    
    CheatName = 'Max Support after training 訓練後支援度最大' 
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4, AOB('F5 03 02 2A F4 03 01 2A F3 03 00 2A'), ASM('MOV W21, #550')) # MOV W21, W2
    
    CheatName = 'Gold does not decrease 金錢不減' # heap+8325CA8
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4, AOB('0A 1D 00 F9 09 02 00 34'), ASM('NOP')) # STR X10, [X8,#0x38]
    Hack(4, AOB('09 1D 00 F9 08 82 8D 1A'), ASM('NOP')) # STR X9, [X8,#0x38]
    Hack(4, AOB('09 1D 00 F9 E0 C3 0A 91'), ASM('NOP')) # STR X9, [X8,#0x38]
    Hack(4, AOB('4B 1D 00 F9 00 31 40 F9'), ASM('NOP')) # STR X11, [X10,#0x38]
    Hack(4, AOB('28 1F 00 F9 20 01 00 54'), ASM('NOP')) # STR X8, [X25,#0x38] 重鑄
    HackAll(4, '2B 1D 00 F9 20 01 00 54', ASM('NOP')) # STR X11, [X9,#0x38] 鍛造
    HackAll(4, '09 1D 00 F9 00 01 00 54', ASM('NOP')) # STR X9, [X8,#0x38] 解鎖
    Hack(4, AOB('6C 1D 00 F9 CC 0A 95 52'), ASM('NOP')) # STR X12, [X11,#0x38]

    CheatName = 'Items Stock does not decrease 存量不減' 
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4, Either(AOB('2A 69 2D 38'), AOB('6C 69 2E 38')), ASM('NOP')) # STRB W10, [X9,X13] / STRB W12, [X11,X14]
    Hack(4, AOB('2A 69 2C 38 BF E6 03 71'), ASM('NOP')) # STRB W10, [X9,X12]

    CheatName = 'Item Max after bought 道具購買後最大' 
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    if isFound(AOB('4A 01 08 0B 2A 69 2C 78')):
        Hack(4, AOB('4A 01 08 0B 2A 69 2C 78'), ASM('MOV W10, #999')) # ADD W10, W10, W8
    else:
        Hack(4, AOB('8C 01 08 0B 6C 69 2D 78'), ASM('MOV W12, #999')) # ADD W12, W12, W8
    Hack(4, AOB('4A 01 0C 0B 2A 01 00 79'), ASM('MOV W10, #99')) # ADD W10, W10, W12

    CheatName = 'Materials does not reduce 打鐵舖材料不減' 
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    HackAll(4, '2B 69 2D 78 89 05 00 71', ASM('NOP')) # STRH W11, [X9,X13] 鍛造
    Hack(4, AOB('0A 69 29 78 40 17 40 F9'), ASM('NOP')) # STRH W10, [X8,X9] 重鑄
    Hack(4, AOB('0A 69 29 78 E0 C3 0A 91'), ASM('NOP')) # STRH W10, [X8,X9] 解鎖
    Hack(4, AOB('0A 69 29 78 E0 03 15 2A'), ASM('NOP')) # STRH W10, [X8,X9] 解鎖?
    Hack(4, AOB('6E 69 2C 78'), ASM('NOP')) # STRH W14, [X11,X12]
    Hack(4, AOB('E8 01 00 79'), ASM('NOP')) # STRH W8, [X15] 解鎖

    CheatName = 'Show All Shop Items 商店貨品全開' 
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4, AOB('23 05 00 54 ? ? ? F9'), ASM('NOP')) # B.CC loc_2E77FC / B.CC loc_2E6688
    Hack(4, AOB('03 0B 00 54 ? ? ? F9'), ASM('NOP')) # B.CC loc_2E7BEC / B.CC loc_2E69AC
    Hack(4, AOB3('1F 49 00 71 EA 27 9F 1A','40 01 08 0A'), ASM('MOV W0, #1')) # AND W0, W10, W8
    Hack(4, AOB('7F 01 02 6B 29 01 00 54'), ASM('CMP WZR, W2')) # CMP W11, W2 ; B.LS loc_2E6C48
    Hack(4, AOB('80 05 00 54 2B 41 41 39'), ASM('NOP')) # B.EQ loc_2E6688

    CheatName = 'Not for sale available 可購非賣品 (Take care 小心)' 
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4, AOB('80 05 00 54 ? 41 41 39'), ASM('NOP')) # B.EQ loc_2E77FC / B.EQ loc_2E6688
    Hack(4, AOB('60 0B 00 54 ? 41 5F 38'), ASM('NOP')) # B.EQ loc_2E7BEC / B.EQ loc_2E69AC
    Hack(4, Either(AOB('88 06 00 54 40 01 5D BC'),AOB('88 06 00 54 60 01 5D BC')) , ASM('NOP')) # B.HI loc_2E7BEC
    Hack(4, AOB3('EC 6B 9B 52','E0 03 1F 2A'), ASM('MOV W0, #1')) # MOV W0, WZR
    Hack(4, AOB('C0 FE FF 54 2A ? ? F9 4A 0D 40 F9'), ASM('NOP')) # B.EQ loc_2E638C 裝備

    CheatName = 'Max Renown 名聲值最大'  # heap+8325CB0
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    PAGEOFF=AOB('? ? ? ? 08 ? ? F9 08 ? ? F9 08 ? ? F9 01 ? ? B9 E0 03 00 91 ? ? ? 94 05 00 80 12 E2 03 00 91 E0 03 14 AA')
    if notFound(PAGEOFF):
        print(CheatName+': AOB broken!')
    else: 
        PointerBase=get_operand_value(PAGEOFF,1)+get_operand_value(PAGEOFF+4,1)
        DelayOutput += '\n' + PointerCode((PointerBase,get_operand_value(PAGEOFF+8,1),get_operand_value(PAGEOFF+12,1),get_operand_value(PAGEOFF+16,1)), 4, 99999)

    CheatName = 'Max Strategy Resource 作戰資源值最大'  # heap+8325CB0
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4, AOB('2A 29 01 B9 0A F5 98 52'), ASM('STR W11, [X9,#0x128]')) # STR W10, [X9,#0x128]
    Hack(4, AOB('A0 01 0A 0B'), ASM('MOV W0, #200')) # ADD W0, W13, W10

    CheatName = 'Inf Shadow Slide 無限瞬移'  # heap+8325CB0
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4, AOB('09 D1 08 39 ? ? ? 94'), ASM('NOP'))  # STRB W9, [X8,#0x234]
    
    Multiplier=5
    CheatName = 'K.O. Multiplier 擊殺倍率 (%dx)'%Multiplier
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    Hack(4, AOB('21 00 80 52 F4 4F 43 A9 F7 0B 40 F9'), ASM('MOV W1, #%d'%Multiplier))  # MOV W1, #1
    CheatAddr=AOB3('3F 1D 00 F1 09 07 80 52 29 81 9F 9A 08 69 69 F8','C0 03 5F D6') # RET
    if isFound(CheatAddr):
        DelayOutput += CodeFunc(('ADD W0, W0, W0, LSL#2','RET'))
        Hack(4, CheatAddr, ASM('B '+hex(CodeK-CheatAddr)))  

    CheatName = 'Max LV limited to 255 等級上限'  # ptr((0x24AFC90,0x18,0x48,0x5BC))
    CheatCnt+=1; DelayOutput += '\n\n[#%02d. %s]'%(CheatCnt,CheatName)
    PAGEOFF=AOB('? ? ? ? 28 ? ? F9 09 ? ? F9 2B ? ? F9')
    if notFound(PAGEOFF):
        RegData(Float2DWord(255),False)
        CodeCave(AOB('60 01 40 BD CC FA 45 39'), # LDR S0, [X11]
            ('LDR S0, .+12', 'STR S0, [X11]', 'RET'))
    else: 
        PointerBase=get_operand_value(PAGEOFF,1)+get_operand_value(PAGEOFF+4,1)
        OFFSET=AOB3('? ? ? ? 28 ? ? F9 09 ? ? F9 2B ? ? F9','2F 25 40 F9') # LDR X15, [X9,#0x48]
        DelayOutput += '\n' + PointerCode((PointerBase,get_operand_value(PAGEOFF+8,1),get_operand_value(OFFSET,1),get_operand_value(OFFSET+4,1)), 4, Float2DWord(255))



    # DelayOutput += '\n\n[#### Pause 暫停 (ZL及+鍵)]'
    # DelayOutput += '\n80000500 FF000000 20000000'
    # DelayOutput += '\n[#### Resume 恢復 (ZL及-鍵)]'
    # DelayOutput += '\n80000900 FF100000 20000000'

    print(DelayOutput)
    print('\n[Created by Eiffel2018, enjoy!]')

################################# END #######################################
    print('\'\'\')')

""" Remarks
    
"""
