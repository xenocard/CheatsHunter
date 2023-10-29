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
codestart = Base+0x30
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
def h(): # print current address as [heap+??????] used for GBD environment
    msg('heap+')
    p(s()-ida_segment.get_segm_by_name('heap').start_ea)
def r():
    addr=get_next_func(get_screen_ea())-4
    while get_wide_dword(addr) in (0,0xD503201F,0xE7FFDEFE): addr-=4
    makeFunc(addr)
def g(name):
    jumpto(get_name_ea(codestart,name))
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
    return addr>codestart and addr<DataEnd
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
    if not(CodeEnd>addr>codestart): return
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
def AOB(pattern,searchStart=codestart,searchEnd=CodeEnd):
    return ida_search.find_binary(searchStart, searchEnd, pattern, 0, SEARCH_DOWN|SEARCH_NEXT) if not(gdb) else BADADDR
def AOB2(pattern,offset,pattern2):
    opAddr=AOB(pattern)
    return AOB(pattern2,get_operand_value(opAddr+offset,0)) if isFound(opAddr) else BADADDR
def AOB3(pattern,pattern2):
    opAddr=AOB(pattern)
    return AOB(pattern2,opAddr) if isFound(opAddr) else BADADDR
def allOccur(pattern):
    result=[]
    cheatAddr=AOB(pattern)
    while isFound(cheatAddr):
        result.append(cheatAddr)
        cheatAddr=AOB(pattern,cheatAddr+4)
    return result
def checkUnique(pattern):
    cheatAddr=AOB(pattern)
    return not(isFound(AOB(pattern,cheatAddr))) if isFound(cheatAddr) else None
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
def HackJump(cheatAddr):
    global delayOutput
    if notFound(cheatAddr): 
        print(cheatName+': AOB broken!')
    else:
        print(RestoreCode(4,cheatAddr))
        delayOutput += '\n' + CheatCode(4,cheatAddr,ASM('B '+hex(get_operand_value(cheatAddr,0)-cheatAddr)))
def Hack(cheatAddr,codes,showRestoreCode=True):
    global delayOutput
    if notFound(cheatAddr): 
        print(cheatName+': AOB broken!')
    else:
        if type(codes)==str: codes=[codes]
        for code in codes:
            if showRestoreCode: print(RestoreCode(4,cheatAddr))
            delayOutput += '\n' + CheatCode(4,cheatAddr, ASM(code))
            cheatAddr+=4
def HackAll(AOB,codes):
    global delayOutput
    cheatAddrs=allOccur(AOB)
    if len(cheatAddrs)<1: 
        print(cheatName+': AOB broken!')
    else:
        for cheatAddr in cheatAddrs:
            Hack(cheatAddr,codes)
def CodeFunc(codes):
    global codeK
    ResultCode=''
    for instruction in reversed(codes):
        codeK-=4
        ResultCode += '\n' + CheatCode(4,codeK,ASM(instruction))
    return ResultCode
def CodeCave(cheatAddr,codes):
    global codeK, delayOutput
    if notFound(cheatAddr): 
        print(cheatName+': AOB broken!')
    else:
        delayOutput += CodeFunc(codes)
        Hack(cheatAddr, 'BL '+hex(codeK-cheatAddr))
def RegData(assignValue):
    global codeK
    codeK-=4
    return CheatCode(4,codeK,assignValue)
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
    codeK=CodeEnd
    cls()
    print('applyPatch(\'\'\'')
    cheatCnt=0
    delayOutput = ''
################################ START ######################################


    print("[F.I.S.T., Forged In Shadow Torch (US) v1.0.2(v131072)  TID=01009F8017F48000  BID=2BA022399C02FE4A]")


    print('\n[Restore Code 還原碼]')

    cheatName = 'Invincible 無敵'
    cheatCnt+=1; delayOutput += '\n\n[#%02d. %s]'%(cheatCnt,cheatName)
    Hack(AOB('FD 7B BE A9 F3 0B 00 F9 FD 03 00 91 E8 8E 99 52 68 45 A6 72 01 1C A0 4E'), 'RET')

    cheatName = 'One Hit Kill 秒殺'
    cheatCnt+=1; delayOutput += '\n\n[#%02d. %s]'%(cheatCnt,cheatName)
    Hack(AOB('20 38 20 1E E1 03 27 1E 08 20 20 1E 20 9C 20 1E 00 60 05 BD'), 'FSUB S0, S1, S1')

    cheatName = 'Inf Stamina 精力不減 (UP/DOWN+X)' 
    cheatCnt+=1; delayOutput += '\n\n[#%02d. %s]'%(cheatCnt,cheatName)
    Hack(AOB('69 EE 00 B9 69 12 44 39'), 'NOP') # STR W9, [X19,#0xEC]

    cheatName = 'Inf Drinks 胡蘿蔔汁不減 (ZR)'  
    cheatCnt+=1; delayOutput += '\n\n[#%02d. %s]'%(cheatCnt,cheatName)
    Hack(AOB('A8 EE 01 B9 E0 03 14 AA'), 'NOP') # STR W8, [X21,#0x1EC]
    Hack(AOB('68 EE 01 B9 7F 02 08 39'), 'NOP') # STR W8, [X19,#0x1EC]
    Hack(AOB('C8 EE 01 B9 68 42 42 39'), 'NOP') # STR W8, [X22,#0x1EC]
    Hack(AOB('C8 EE 01 B9 E0 03 14 AA'), 'NOP') # STR W8, [X22,#0x1EC]

    cheatName = 'Inf Money 金錢不減'
    cheatCnt+=1; delayOutput += '\n\n[#%02d. %s]'%(cheatCnt,cheatName)
    Hack(AOB('08 01 01 6B AA 00 00 54 E0 03 1F 2A FD 7B 41 A9 FF 83 00 91'), 'SUBS W8, W8, WZR') # SUBS W8, W8, W1

    Multiplier=4
    cheatName = 'Money Multiplier 金錢倍率 (%dx)'%(2 ** int(math.log(Multiplier,2)))
    cheatCnt+=1; delayOutput += '\n\n[#%02d. %s]'%(cheatCnt,cheatName)
    Hack(AOB('08 01 01 0B 08 B0 00 B9'), 'ADD W8, W8, W1, LSL#%d'%math.log(Multiplier,2))

    cheatName = 'Inf Data Disk 數據磁盤不減'
    cheatCnt+=1; delayOutput += '\n\n[#%02d. %s]'%(cheatCnt,cheatName)
    Hack(AOB('08 01 01 6B AA 00 00 54 E0 03 1F 2A FD 7B 41 A9 FF 83 00 91 C0 03 5F D6 08 CC 00 B9'), 'SUBS W8, W8, WZR') # SUBS W8, W8, W1
    Hack(AOB3('08 CC 40 B9 1F 01 01 6B','E0 B7 9F 1A'), 'MOV W0, #1') # CSET W0, GE

    cheatName = 'Stay on Wall 停在墻上'
    cheatCnt+=1; delayOutput += '\n\n[#%02d. %s]'%(cheatCnt,cheatName)
    cheatAddr=AOB('60 3E 4C BD EC 03 27 1E')
    if isFound(cheatAddr):
        Hack(cheatAddr, 'FMOV S0, WZR') # LDR S0, [X19,#0xC3C]
        delayOutput += '\n' + ButtonCode('l3down',RestoreCode(4,cheatAddr))

    cheatName = 'Non-stop Dash 一直滑行 (Hold R)'
    cheatCnt+=1; delayOutput += '\n\n[#%02d. %s]'%(cheatCnt,cheatName)
    cheatAddr1=AOB('02 A8 4B BD') # LDR S2, [X0,#0xBA8]
    cheatAddr2=AOB('61 AA 4B BD') # LDR S1, [X19,#0xBA8]
    if isFound(cheatAddr1) and isFound(cheatAddr2): 
        delayOutput += '\n' + RestoreCode(4,cheatAddr1) + '\n' + RestoreCode(4,cheatAddr2)
        delayOutput += '\n' + ButtonCode('R', CheatCode(4, cheatAddr1, ASM('FMOV S2, #31')) + '\n' + CheatCode(4, cheatAddr2, ASM('FMOV S1, #31')))

    cheatName = 'Moon Jump 登月跳'
    cheatCnt+=1; delayOutput += '\n\n[#%02d. %s]'%(cheatCnt,cheatName)
    Hack(AOB('00 40 43 BD C0 03 5F D6 08 A0 4C 39'),'FMOV S0, #31.0') # LDR S0, [X0,#0x340]

    cheatName = 'Inf Jump 無限跳躍'
    cheatCnt+=1; delayOutput += '\n\n[#%02d. %s]'%(cheatCnt,cheatName)
    HackAll('68 4A 03 B9 68 02 40 F9 08 41 44 F9 E0 03 13 AA 00 01 3F D6 E0 03 13 AA','STR WZR, [X19,#0x348]') # STR W8, [X19,#0x348]

    cheatName = 'Accelerate Movement/Swimming 加速移動/游泳'
    cheatCnt+=1; delayOutput += '\n\n[#%02d. %s]'%(cheatCnt,cheatName)
    HackAll('08 1D 42 F9 00 01 3F D6 ? ? ? ? 18 ? ? F9',('FMOV S0, #30.0','FMUL S0, S0, S0')) # LDR X8, [X8,#0x438];BLR X8

    # delayOutput += '\n\n[#### Pause 暫停 (ZL)]'
    # delayOutput += '\n'+ ButtonCode('ZL','FF000000')
    # delayOutput += '\n[#### Resume 恢復 (ZR)]'
    # delayOutput += '\n'+ ButtonCode('ZR','FF100000')

    print(delayOutput)
    print('\n[Created by Eiffel2018, enjoy!]')

################################# END #######################################
    print('\'\'\')')

""" Remarks
    
"""
