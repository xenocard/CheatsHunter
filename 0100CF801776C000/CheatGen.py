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
    # auto_wait()
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
def Double2QWord(d):
    return struct.unpack('<Q', struct.pack('<d', d))[0]
def Float2DWord(f):
    return struct.unpack('<I', struct.pack('<f', f))[0]
def GetBytes(length,opAddr):
    return {1:ida_bytes.get_original_byte(opAddr), 2:ida_bytes.get_original_word(opAddr), 4:ida_bytes.get_original_dword(opAddr), 8:ida_bytes.get_original_dword(opAddr)}[length]
def makeFunc(addr):
    if not(codeEnd>addr>codeStart): return
    addr=addr//4*4
    while get_wide_dword(addr) in (0,0xD503201F,0xE7FFDEFE): addr+=4
    if ida_funcs.is_func_tail(ida_funcs.get_fchunk(addr)):
        ida_funcs.remove_func_tail(ida_funcs.get_func(addr),ida_funcs.get_fchunk(addr).start_ea)
        addFunc(addr)
    while idaapi.get_func(addr)==None or not(isCode(addr)):
        funcStart=get_func_attr(get_prev_fchunk(addr),FUNCATTR_END)
        while get_wide_dword(funcStart) in (0,0xD503201F,0xE7FFDEFE): funcStart+=4
        del_items(funcStart)
        addFunc(funcStart)
    auto_wait()
def addFunc(funcStart):
    if not(ida_funcs.add_func(funcStart)):
        funcEnd=find_func_end(funcStart)
        if notFound(funcEnd) or funcEnd<funcStart:
            funcEnd=funcStart+4
            while print_insn_mnem(funcEnd) not in ('RET','B','BR') and funcEnd<codeEnd and not(get_wide_dword(funcEnd) in (0,0xD503201F,0xE7FFDEFE)): funcEnd+=4
            if print_insn_mnem(funcEnd) in ('RET','B','BR'): funcEnd+=4
            ida_funcs.add_func(funcStart,funcEnd)
            auto_wait()
def getFuncStart(targetAddr):
    func=ida_funcs.get_fchunk(targetAddr)
    if func==None: makeFunc(targetAddr);func=ida_funcs.get_fchunk(targetAddr)
    targetAddr=ida_funcs.get_fchunk(targetAddr).start_ea
    if ida_funcs.is_func_tail(ida_funcs.get_fchunk(targetAddr)):
        ida_funcs.remove_func_tail(ida_funcs.get_func(targetAddr),ida_funcs.get_fchunk(targetAddr).start_ea)
        addFunc(targetAddr)
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
    return '0{}0E0000 {} {}\n'.format(length,Addr2DWord(opAddr),Value2DWord(value) if length<=4 else Value2QWord(value))
def RestoreCode(length,opAddr):
    return CheatCode(length,opAddr,GetBytes(length,opAddr) if length<=4 else get_qword(opAddr))
def PointerCodeHeader(offsets): # offsets use tuples/list with at least 2 element
    if len(offsets)<2: return 'Error with PointerCode'
    code = '580F0000 {:08X}\n'.format(offsets[0])
    for offset in offsets[1:]: 
        code += '580F1000 {:08X}\n'.format(offset)
    return code
def PointerCodeBody(offset, length, value): 
    code = '480D0000 00000000 {:08X}\n'.format(offset)
    code += '6{:1X}0F01D0 {}\n'.format(length, Value2QWord(value))
    return code
def PointerCode(offsets, length, value, extras=None):
    code = PointerCodeHeader(offsets[0:-1])
    code += PointerCodeBody(offsets[-1], length, value)
    if extra!=None:
        for extra in extras:
            code += PointerCodeBody(extra[0], length, extra[1])
    return code
def ptr(offsets,length=0): # return the address/value of pointer expression, e.g. [[main+123456]+1234]+32 , type ptr((123456,0x1234,0x32)) or ptr((123456,0x1234,0x32),4)
    if type(offsets) not in (tuple, list): return 'Error with NOEXES expression'
    addr=Base if offsets[0]<0x10000000 else 0
    for offset in offsets[:-1]: 
        addr = get_qword(addr+offset)
    addr += offsets[-1]
    return addr if length==0 else GetBytes(length,addr)
def ButtonCode(key,code=None):
    keymap={'a':0x1,'b':0x2,'x':0x4,'y':0x8,'l3':0x10,'r3':0x20,'l':0x40,'r':0x80,'zl':0x100,'zr':0x200,'plus':0x400,'minus':0x800,'left':0x1000,'up':0x2000,'right':0x4000,'down':0x8000,'l3left':0x10000,'l3up':0x20000,'l3right':0x40000,'l3down':0x80000,'r3left':0x100000,'r3up':0x200000,'r3right':0x400000,'r3down':0x800000,'sl':0x1000000,'sr':0x2000000}
    if isinstance(key, str) and key.lower() in keymap: key=keymap[key.lower()]
    if code[-1]!='\n': code+='\n'
    return '8{:07X}\n{}20000000\n'.format(key,code) if code != None else '8%s'%key
def ConditionCode(length,opAddr,value,commands,otherwise=None):
    result = '1%d050000 %s %s\n%s\n'%(length,Addr2DWord(opAddr),Value2DWord(value) if length<=4 else Value2QWord(value),commands)
    if otherwise != None: result += '21000000\n%s\n'%(otherwise)
    result += '20000000\n'
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
def HackJump(cheatAddr,showRestoreCode=True,useButton=None):  # hack something like "B.NE 0x12345678" become "B 0x12345678" 
    global delayOutput
    if type(cheatAddr) is str: cheatAddr=AOB(cheatAddr)
    if notFound(cheatAddr): 
        print(cheatName+': AOB broken!')
    else:
        codes=ASM('B '+hex(get_operand_value(cheatAddr,0)-cheatAddr))
        Hack(cheatAddr,codes,showRestoreCode,useButton)
def Hack(cheatAddr,codes,showRestoreCode=True,useButton=None):
    global delayOutput, restoreCode, masterCode
    output=''
    if type(cheatAddr) is str: cheatAddr=AOB(cheatAddr)
    if notFound(cheatAddr): 
        print(cheatName+': AOB broken!')
    else:
        if type(codes)==str: codes=[codes]
        for instruction in codes:
            if showRestoreCode=='MasterCode': masterCode += RestoreCode(4,cheatAddr)
            elif showRestoreCode: restoreCode += RestoreCode(4,cheatAddr)
            output += CheatCode(4,cheatAddr, ASM(instruction) if re.match(r"^[0-9a-fA-F]{8}$", instruction[0:8]) is None else instruction)
            cheatAddr += 4
        if useButton != None: output=ButtonCode(useButton,output)
        delayOutput += output
def HackAll(cheatAddrList,codes,showRestoreCode=True,useButton=None):
    global delayOutput
    cheatAddrs=allOccur(cheatAddrList)
    if len(cheatAddrs)<1: 
        print(cheatName+': AOB broken!')
    else:
        if useButton != None: delayOutput += ButtonCode(useButton)
        for cheatAddr in cheatAddrs:
            Hack(cheatAddr,codes,showRestoreCode)
        if useButton != None: delayOutput += '20000000\n'
def CodeFunc(codes):
    global codeK
    ResultCode=lastInstruction=''
    end=codeK
    for instruction in reversed(codes):
        codeK-=4
        instruction=instruction.replace('{here}',hex(codeK)).replace('{end}',hex(end-codeK))
        if re.match(r"^[0-9a-fA-F]{8}$", instruction[0:8]) is None: instruction=ASM(instruction) 
        if lastInstruction=='':
            lastInstruction = instruction
        else:
            ResultCode += CheatCode(8,codeK,(lastInstruction)+(instruction))
            lastInstruction = ''
    if (lastInstruction != ''): ResultCode += CheatCode(4,codeK,(lastInstruction))
    return ResultCode
def CodeCave(cheatAddr,codes, showRestoreCode=True, use_BL=True):
    global codeK, delayOutput
    if type(cheatAddr) is str: cheatAddr=AOB(cheatAddr)
    if notFound(cheatAddr): 
        print(cheatName+': AOB broken!')
    else:
        delayOutput += CodeFunc(codes)
        Hack(cheatAddr, ('BL ' if use_BL else 'B ')+hex(codeK-cheatAddr), showRestoreCode)
def RegData(assignValue,size=4):
    global codeK
    codeK-=size
    return CheatCode(size,codeK,assignValue)
def Either(aob1,aob2):
    if type(aob1) is str: aob1=AOB(aob1)
    if type(aob2) is str: aob2=AOB(aob2)
    return aob1 if isFound(aob1) else aob2
def getADRP(addr):
    return get_operand_value(addr,1)+get_operand_value(addr+4,1)

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
    # print('applyPatch(\'\'\'')
    cheatCnt=0
    delayOutput = ''
    masterCode='{Master Code 關鍵碼}\n'
    restoreCode='[Restore Code 還原碼]\n'

################################ START ######################################

    print("[LIVE A LIVE (v0) TID=0100CF801776C000 BID=6E1059ADB083B99F]")

    cheatName = 'Inf HP 無限生命'
    cheatCnt+=1; show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    CodeCave('A8 3E 03 B9 BF FF 3C A9', ('LDRB W9, [X21,#0x328]','CBZ W9, .+8','STR W8, [X21,#0x33C]','RET')) 

    cheatName = 'One Hit Kill 秒殺'
    cheatCnt+=1; delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    CodeCave(AOB('A9 3E 43 B9 28 01 08 4B AA 42 52 39'), ('LDRB W9, [X21,#0x328]','CBZ W9, .+8','LDR W8, [X21,#0x33C]','LDR W9, [X21,#0x33C]','RET')) 

    cheatName = 'EXP Multiplier 經驗倍率 (%dx)'
    cheatAddr = AOB3('28 6D 1C 33 68 02 00 B9','F4 4F 45 A9')
    if isFound(cheatAddr):
        cheatCnt+=1;idx=ord('a')-1;temp=codeK; show('%d. %s'%(cheatCnt,cheatName))
        idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%2)
        CodeCave(cheatAddr, ('LDR W8, [X19]','ADD W8, W8, W8','STR W8, [X19]','LDR W8, [X20]','ADD W8, W8, W8','STR W8, [X20]','LDP X20, X19, [SP,#0x50]','RET'), showRestoreCode=False);codeK=temp
        idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%3)
        CodeCave(cheatAddr, ('LDR W8, [X19]','ADD W8, W8, W8, LSL#1','STR W8, [X19]','LDR W8, [X20]','ADD W8, W8, W8, LSL#1','STR W8, [X20]','LDP X20, X19, [SP,#0x50]','RET'), showRestoreCode=False);codeK=temp
        idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%4)
        CodeCave(cheatAddr, ('LDR W8, [X19]','LSL W8, W8, #2','STR W8, [X19]','LDR W8, [X20]','LSL W8, W8, #2','STR W8, [X20]','LDP X20, X19, [SP,#0x50]','RET'), showRestoreCode=False);codeK=temp
        idx+=1;delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%5)
        CodeCave(cheatAddr, ('LDR W8, [X19]','ADD W8, W8, W8, LSL#2','STR W8, [X19]','LDR W8, [X20]','ADD W8, W8, W8, LSL#2','STR W8, [X20]','LDP X20, X19, [SP,#0x50]','RET'))
        cheatName = 'Level Up After Every Battle 每戰升級'
        idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack('F3 03 02 2A F4 03 01 AA 16 FD 60 D3', 'MOV W19, #100')

    cheatName = 'Lv Up Abilities Multiplier 升級能力倍率 (%dx)'
    cheatCnt+=1;idx=ord('a')-1; show('%d. %s'%(cheatCnt,cheatName))
    idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%2)
    HackAll('01 00 19 0B E0 03 14 AA ? ? ? 97', 'ADD W1, W25, W0, LSL #1') # ADD W1, W0, W25
    HackAll('01 00 15 0B E0 03 14 AA ? ? ? 97', 'ADD W1, W21, W0, LSL #1') # ADD W1, W0, W21
    idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%4)
    HackAll('01 00 19 0B E0 03 14 AA ? ? ? 97', 'ADD W1, W25, W0, LSL #2', showRestoreCode=False) # ADD W1, W0, W25
    HackAll('01 00 15 0B E0 03 14 AA ? ? ? 97', 'ADD W1, W21, W0, LSL #2', showRestoreCode=False) # ADD W1, W0, W21
    idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%8)
    HackAll('01 00 19 0B E0 03 14 AA ? ? ? 97', 'ADD W1, W25, W0, LSL #3', showRestoreCode=False) # ADD W1, W0, W25
    HackAll('01 00 15 0B E0 03 14 AA ? ? ? 97', 'ADD W1, W21, W0, LSL #3', showRestoreCode=False) # ADD W1, W0, W21

    cheatName = 'Movement Speed 移動倍率 (%sx) Hold ZR'
    cheatCnt+=1;idx=ord('a')-1; show('%d. %s'%(cheatCnt,cheatName))
    idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%'1.5')
    Hack('6C 8E 42 BD', 'FMOV S12, #1.5',useButton='ZR', showRestoreCode='MasterCode') # LDR S12, [X19,#0x28C]
    idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%'2.0')
    Hack('6C 8E 42 BD', 'FMOV S12, #2.0',useButton='ZR', showRestoreCode=False) # LDR S12, [X19,#0x28C]
    idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%'2.5')
    Hack('6C 8E 42 BD', 'FMOV S12, #2.5',useButton='ZR', showRestoreCode=False) # LDR S12, [X19,#0x28C]

    cheatName = 'Custom Battle Settings'
    addr=AOB('F8 03 00 AA ? ? ? 94 08 8C 40 F9')
    if isFound(addr):
        secondOffset=get_operand_value(addr+8,1)
        URICBattleConstantSettingsLoader=get_operand_value(addr+4,0)
        URICBattleConstantSettingsPtr=getADRP(AOB('? ? ? ? 00 ? ? F9',URICBattleConstantSettingsLoader))
        masterCode += PointerCodeHeader((URICBattleConstantSettingsPtr,secondOffset))
        
        cheatName = 'Character Accuracy Value 擊中機率 100%'
        cheatCnt+=1; show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
        restoreCode += PointerCodeBody(0x50, 4, 76)
        delayOutput += PointerCodeBody(0x50, 4, 100)
        
        cheatName = 'Damage UpperLimit 傷害上限 99999'
        cheatCnt+=1; show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
        restoreCode += PointerCodeBody(0x58, 4, 999)
        delayOutput += PointerCodeBody(0x58, 4, 99999)

        cheatName = 'HP UpperLimit 生命上限 19999'
        cheatCnt+=1; show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
        restoreCode += PointerCodeBody(0x190, 4, 999)
        delayOutput += PointerCodeBody(0x190, 4, 19999)

        cheatName = 'Abilities UpperLimit 屬性上限 9999'
        cheatCnt+=1; show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
        restoreCode += PointerCodeBody(0x178, 4, 99)
        delayOutput += PointerCodeBody(0x178, 4, 9999)
        restoreCode += PointerCodeBody(0x180, 4, 150)
        delayOutput += PointerCodeBody(0x180, 4, 9999)
        restoreCode += PointerCodeBody(0x1A0, 4, 99)
        delayOutput += PointerCodeBody(0x1A0, 4, 9999)
        restoreCode += PointerCodeBody(0x1A8, 4, 99)
        delayOutput += PointerCodeBody(0x1A8, 4, 9999)

    cheatName = 'Damage Multiplier 攻擊傷害倍率 (%dx)'
    cheatCnt+=1;idx=ord('a')-1;temp=codeK; show('%d. %s'%(cheatCnt,cheatName))
    cheatAddr = AOB('09 00 30 1E 1F 01 09 6B 28 C1 88 1A')
    if isFound(cheatAddr):
        idx+=1;delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%2.5)
        CodeCave(cheatAddr, ('LDR X9, [X20,#0x1F0]','LDRB W9, [X9,#0x328]','CBNZ W9, .+12','FMOV S1, #2.5','FMUL S0, S0, S1','FCVTMS W9, S0','RET'), showRestoreCode=False);codeK=temp
        idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%5)
        CodeCave(cheatAddr, ('LDR X9, [X20,#0x1F0]','LDRB W9, [X9,#0x328]','CBNZ W9, .+12','FMOV S1, #5.0','FMUL S0, S0, S1','FCVTMS W9, S0','RET'), showRestoreCode=False);codeK=temp
        idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%10)
        CodeCave(cheatAddr, ('LDR X9, [X20,#0x1F0]','LDRB W9, [X9,#0x328]','CBNZ W9, .+12','FMOV S1, #10','FMUL S0, S0, S1','FCVTMS W9, S0','RET'), showRestoreCode=False);codeK=temp
        idx+=1; delayOutput += '\n[#%02d(%s) %s]\n'%(cheatCnt,chr(idx),cheatName%30)
        CodeCave(cheatAddr, ('LDR X9, [X20,#0x1F0]','LDRB W9, [X9,#0x328]','CBNZ W9, .+12','FMOV S1, #30','FMUL S0, S0, S1','FCVTMS W9, S0','RET'))


################################# END #######################################

    if masterCode !='{Master Code 關鍵碼]\n': print(masterCode)
    if restoreCode != '[Restore Code 還原碼]\n': print(restoreCode)
    print(delayOutput)
    print('[Created by Eiffel2018, enjoy!]\n')

    # print('\'\'\')')

""" Remarks
     +28       Float	WeaknessValue
     +2C       Float	ResistValue
     +30       Float	SkillSubTypeAbsorbRate
     +34      Struct	DamageLvTerm_BaseClampingRange
     +3C      Struct	DamageRandomTerm_RandomRange
     +44      Struct	HealingRandomTerm_RandomRange
     +4C         Int	MinAccuracyValue
     +50         Int	CharacterAccuracyValue
     +54       Float	MaxCharacterAccuracyFactor
     +58         Int	DamageUpperLimit
     +5C       Float	TargetRotateHitJudgmentRate
     +60       Float	TargetGoBackHitJudgmentRate
     +64      Struct	AdditionalEffectRelatedStatusRatioRange
     +6C         Int	MaxStatusConditionReceiveCount
     +70         Int	MaxBehaviorConditionReceiveCount
     +74         Int	MaxStatusModificationReceiveCount
     +78       Float	StatusConditionResistCoefficient
     +7C       Float	BehaviorConditionResistCoefficient
     +80       Float	StatusModificationResistCoefficient
     +84       Float	StatusConditionMakeStaggeredRate
     +88         Int	StatusConditionPoisonDamage
     +8C         Int	NumberActionToAdvanceTimeOfAdditionalEffectOfAlly
     +90         Int	ActionPointThreshold
     +94         Int	MaxEnemyNumToGetTimeCoefficient
     +98      Struct	AllyTimeCoefficientByOtherAllyMove
     +A0      Struct	EnemyTimeCoefficientByAllyMove
     +A8 StructArray	EnemyHateCoefficientByAllyMove
     +B8      Struct	AllyTimeCoefficientByOtherAllyPass
     +C0      Struct	EnemyTimeCoefficientByAllyPass
     +C8      Struct	AllyTimeCoefficientByOtherAllyAttack
     +D0      Struct	EnemyTimeCoefficientByAllyAttack
     +D8 StructArray	EnemyHateCoefficientByAllyAttack
     +E8 StructArray	EnemyHateCoefficientByNoAllyAttack
     +F8      Struct	AllyTimeCoefficientByEnemyAction
    +100      Struct	EnemyTimeCoefficientByOtherEnemyAction
    +108         Int	EnemyRemainActionPointByItMove
    +10C      Struct	PawnTimeCoefficientAgilityRange
    +114      Struct	TimeCoefficientAgilityDifferenceRange
    +11C         Int	ChapterGenshiZakiEventDamageCount
    +120         Int	ChapterGenshiZakiEventHpRate
    +124         Int	ChapterKunfuGrowthParamPhysicalAttack
    +128         Int	ChapterKunfuGrowthParamPhysicalDefense
    +12C         Int	ChapterKunfuGrowthParamAgility
    +130       Float	ChapterLastSinOdioMiddlePhaseConditionHpRate
    +134       Float	ChapterLastSinOdioLastPhaseConditionHpRate
    +138       Float	ChapterLastSinOdioMiddlePhaseHealHpRate
    +13C         Int	FieldConditionWaterDamage
    +140         Int	FieldConditionPoisonDamage
    +144         Int	FieldConditionFireDamage
    +148         Int	FieldConditionElectricDamage
    +14C       Float	FieldConditionVanishRate
    +150         Int	EncounterJudgementSpan
    +154        Name	AllyAILogicActionId
    +15C        Name	AllyAILogicMovementId
    +164        Name	AllyAILogicReactionId
    +16C      Struct	MaxParameterRange_Status
    +174      Struct	MaxParameterRange_StatusAtLevelup
    +17C      Struct	MaxParameterRange_StatusAtEquipment
    +184      Struct	MaxParameterRange_Level
    +18C      Struct	MaxParameterRange_HP
    +194      Struct	MaxParameterRange_HPAtDisplayed
    +19C      Struct	MaxParameterRange_Attack
    +1A4      Struct	MaxParameterRange_Defense
"""
