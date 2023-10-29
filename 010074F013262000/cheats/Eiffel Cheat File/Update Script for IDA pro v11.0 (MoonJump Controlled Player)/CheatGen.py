'''
    This is a idaPython script used for helping NS atmosphere cheat code production

    This Script is Programmed by Eiffel2018
    Works in IDA PRO v7.5 up 
    Requirement: Python 3.9.x (with idapyswitch) and Keystone 
    Operate with a clean NSO (or main.elf) 
'''

import idc, ida_bytes, ida_search, ida_struct, idautils, sys, ida_kernwin, ida_funcs, idaapi, ida_segment, math
from inspect import currentframe, getframeinfo
from ida_idaapi import BADADDR
from keystone import *

TM='E'
gdb = ida_segment.get_segm_by_name('.rodata') is None

if gdb and ida_kernwin.ask_yn(False, 'HIDECANCEL\nMark Regions?'):
    print('----- Script created by Eiffel2018 -----')
    info = send_dbg_command('get info')
    infoheader, dummy, infobody = info.partition('\nLayout:\n')
    layout, dummy, modules = infobody.partition('\nModules:\n')
    regions = ida_idd.meminfo_vec_t()
    for region in layout.splitlines():
        name, start, end = re.split('[:|-]',region.replace(' ', ''))
        if (name=='Alias' or name=='Heap' or name=='Stack'): 
            print(name, start, hex(int(end,16)+1))
            info = ida_idd.memory_info_t()
            info.name = name.lower()
            info.start_ea = int(start,16)
            info.end_ea = int(end,16)+1
            info.sclass = 'DATA'
            info.sbase = 0
            info.bitness = 2
            info.perm = 6
            regions.push_back(info)
    lastend=0
    lastbase=0
    lastname=''
    for region in modules.splitlines():
        start, end, name = region.strip().replace(' - ', ' ').split(' ');
        name, dummy, ext = name.partition('.');
        if (ext=='nss'): 
            name='main'
        if (ext=='nrs.elf'): 
            name='nro'
        if (lastend>0):
            info = ida_idd.memory_info_t()
            info.name = lastname + '-data'
            info.start_ea = lastend
            info.end_ea = int(start,16)
            info.sclass = 'DATA'
            # info.sbase = lastbase
            info.sbase = 0
            info.bitness = 2
            info.perm = 6
            regions.push_back(info)
            print(lastname + '-data', hex(lastend), start)
            lastend=0
        if (name=='saltysd_core' or name=='saltysd_core-data'):
            continue
        if (name=='' or name=='-data'):
            continue
        # if (name=='nnSdk'):
            # continue
        print(name, start, hex(int(end,16)+1))
        info = ida_idd.memory_info_t()
        info.name = name
        info.start_ea = int(start,16)
        info.end_ea = int(end,16)+1
        info.sclass = 'CODE'
        info.sbase = 0
        if (name=='main'):
            Base=int(start[:-1],16)
            info.sbase = Base
        info.bitness = 2
        info.perm = 5
        regions.push_back(info)
        lastend=info.end_ea
        lastbase=info.sbase
        lastname=info.name
        if (ext=='nrs.elf'): 
            mapping = send_dbg_command('get mapping '+hex(int(end,16)+1))
            start, end, dummy, nextName, dummy = mapping.replace(' - ', ' ').split(' ', 4);
            if (nextName=='AliasCode'):
                name='nro-static'
                print(name, start, hex(int(end,16)+1))
                info = ida_idd.memory_info_t()
                info.name = name
                info.start_ea = int(start,16)
                info.end_ea = int(end,16)+1
                info.sclass = 'DATA'
                info.sbase = 0
                info.bitness = 2
                info.perm = 4
                regions.push_back(info)
                lastend=info.end_ea
                lastbase=info.sbase
                lastname=info.name
                mapping = send_dbg_command('get mapping '+hex(int(end,16)+1))
                start, end, dummy, nextName, dummy = mapping.replace(' - ', ' ').split(' ', 4);
            if (nextName=='AliasCodeData'):
                name='nro-data'
                mapping = send_dbg_command('get mapping '+hex(int(end,16)+1))
                start2, end2, dummy, nextName2, dummy = mapping.replace(' - ', ' ').split(' ', 4);
                if (nextName2=='AliasCodeData'):
                    end = end2
                    mapping = send_dbg_command('get mapping '+hex(int(end,16)+1))
                    start2, end2, dummy, nextName2, dummy = mapping.replace(' - ', ' ').split(' ', 4);
                    if (nextName2=='AliasCodeData'):
                        end = end2
                print(name, start, hex(int(end,16)+1))
                info = ida_idd.memory_info_t()
                info.name = name
                info.start_ea = int(start,16)
                info.end_ea = int(end,16)+1
                info.sclass = 'DATA'
                info.sbase = 0
                info.bitness = 2
                info.perm = 6
                regions.push_back(info)
                lastend=info.end_ea
                lastbase=info.sbase
                lastname=info.name
                mapping = send_dbg_command('get mapping '+hex(int(end,16)+1))
                start, end, dummy, nextName, dummy = mapping.replace(' - ', ' ').split(' ', 4);
                lastend=0
    ida_dbg.set_manual_regions(regions)
    ida_dbg.enable_manual_regions(0)
    ida_dbg.refresh_debugger_memory()
    ida_dbg.enable_manual_regions(1)
    ida_dbg.refresh_debugger_memory()
    ida_dbg.edit_manual_regions()
    ida_kernwin.refresh_idaview_anyway()
    
Base=main= ida_segment.get_segm_by_name('main').start_ea if gdb else ida_segment.get_segm_by_name('.text').start_ea
codeStart = Base+0x30
codeEnd = ida_segment.get_segm_by_name('main').end_ea if gdb else ida_segment.get_segm_by_name('.rodata').start_ea
dataStart = ida_segment.get_segm_by_name('main_data').start_ea if gdb else ida_segment.get_segm_by_name('.rodata').start_ea
dataEnd = ida_segment.get_segm_by_name('main_data').end_ea if gdb else ida_segment.get_segm_by_name('.init_array').end_ea

dataAddr = BADADDR if gdb else ida_segment.get_segm_by_name('.bss').end_ea


def p(x): # output String or HEX number
    print(hex(x) if isinstance(x, int) and x>1 else x)
def cls():
    ida_kernwin.activate_widget(ida_kernwin.find_widget("Output window"), True);
    ida_kernwin.process_ui_action("msglist:Clear");
def s(): # get current address, used for GBD environment
    return get_screen_ea()
def a(): # print current address as [main+??????] used for GBD environment
    if not gdb: return
    Heap=ida_segment.get_segm_by_name('heap').start_ea
    if s()>Heap and Heap>Base or s()<Base:
        print('heap+%X'%(s()-Heap))
    else:
        print('main+%X'%(s()-Base))
def r():
    addr=get_next_func(get_screen_ea())-4
    while get_wide_dword(addr) in (0,0xD503201F,0xE7FFDEFE): addr-=4
    makeFunc(addr)
def halt(text):
    warning(text)
    raise error(0)
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
    return addr>codeStart and addr<dataEnd
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
    # auto_wait()
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
def AOB(pattern,searchStart=codeStart,searchEnd=codeEnd):
    return ida_search.find_binary(searchStart, searchEnd, pattern, 0, SEARCH_DOWN|SEARCH_NEXT) if not(gdb) else BADADDR
def AOB2(pattern,offset,pattern2=None): # funcion inside
    opAddr=AOB(pattern) if type(pattern) is str else pattern
    if notFound(opAddr): return BADADDR
    return get_operand_value(opAddr+offset,0) if pattern2 is None else AOB(pattern2,get_operand_value(opAddr+offset,0)) 
def AOB3(pattern,pattern2):
    opAddr=AOB(pattern) if type(pattern) is str else pattern
    if notFound(opAddr): return BADADDR
    return AOB(pattern2,opAddr) if type(pattern2) is str else opAddr+pattern2
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
    if type(value) not in (list,tuple):
        if type(value) is str and re.match(r"^[0-9a-fA-F]{8}$", value[0:8]) is None: value=ASM(value) 
        if type(value) is int: value=Value2DWord(value)
        return '0{}0E0000 {} {}\n'.format(length,Addr2DWord(opAddr),Value2DWord(value) if length<=4 else Value2QWord(value))
    lastInstruction = ResultCode = ''
    opAddr-=4
    for instruction in value:
        if type(instruction) is str and re.match(r"^[0-9a-fA-F]{8}$", instruction[0:8]) is None: instruction=ASM(instruction) 
        if type(instruction) is int: instruction=Value2DWord(instruction)
        if lastInstruction=='':
            lastInstruction = instruction
        else:
            ResultCode += CheatCode(8,opAddr,instruction+lastInstruction)
            lastInstruction = ''
        opAddr+=4
    if (lastInstruction != ''): ResultCode += CheatCode(4,opAddr,lastInstruction)
    return ResultCode
def RestoreCode(length,opAddr):
    if length>=8: return CheatCode(length,opAddr,[ get_wide_dword(opAddr+i) for i in range(0,length,4) ])
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
def PointerCodeStoreRegister(addr, length=8): 
    return 'A{:1X}F00400 {:08X}\n'.format(length, addr)
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
    if type(value) is str and re.match(r"^[0-9a-fA-F]{8}$", value[0:8]) is None: value=ASM(value) 
    result = '1%d050000 %s %s\n%s'%(length,Addr2DWord(opAddr),Value2DWord(value) if length<=4 else Value2QWord(value),commands)
    if otherwise != None: result += '21000000\n%s'%(otherwise)
    result += '20000000\n'
    return result
def ToggleCode(button,length,opAddr,code):
    # firstCode=code if length==4 else (code[0] if type(code) in (list,tuple) else (code[9:] if type(code) is str else (Value2QWord(code)&FFFFFFFF)))
    return ButtonCode(button,ConditionCode(length,opAddr,code,RestoreCode(length,opAddr),CheatCode(length,opAddr,code)))
def ASM(asm_code):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    try:
        bytecode, cnt = ks.asm(asm_code, as_bytes=True)
    except:
        warning("Error in code: %s"%asm_code)
        bytecode=b'FFFFFFFF'
    return ''.join(map('{:02X}'.format, reversed(bytecode)))
def ApplyPatch(code):# use 3 """ to quote the multiline codes
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
        warning(cheatName+': AOB broken!')
    else:
        codes=ASM('B '+hex(get_operand_value(cheatAddr,0)-cheatAddr))
        Hack(cheatAddr,codes,showRestoreCode,useButton)
def Hack(pattern,codes,showRestoreCode=True,useButton=None):
    global delayOutput, restoreCode, masterCode
    output=''
    cheatAddr=AOB(pattern) if type(pattern) is str else pattern
    if notFound(cheatAddr): 
        warning(cheatName+': AOB broken!\n%s'%(pattern if type(pattern) is str else hex(pattern)))
    else:
        if type(codes) is str or type(codes) is int: codes=[codes]
        length = len(codes)*4
        if showRestoreCode=='masterCode': masterCode += RestoreCode(length,cheatAddr)
        elif showRestoreCode: restoreCode += RestoreCode(length,cheatAddr)
        output += CheatCode(length, cheatAddr, codes)
        if useButton != None: output=ButtonCode(useButton,output)
        delayOutput += output
def HackAll(cheatAddrList,codes,showRestoreCode=True,useButton=None):
    global delayOutput
    cheatAddrs=allOccur(cheatAddrList)
    if len(cheatAddrs)<1: 
        warning(cheatName+': AOB broken!')
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
        warning(cheatName+': AOB broken!')
    else:
        delayOutput += CodeFunc(codes)
        Hack(cheatAddr, ('BL ' if use_BL else 'B ')+hex(codeK-cheatAddr), showRestoreCode)
def RegData(assignValue,size=4):
    global codeK
    codeK-=size
    return CheatCode(size,codeK,assignValue)
def DefineWriteableAddress(size=4):
    global dataAddr
    dataAddr-=size
    return dataAddr
def Either(aob1,aob2):
    if type(aob1) is str: aob1=AOB(aob1)
    if type(aob2) is str: aob2=AOB(aob2)
    return aob1 if isFound(aob1) else aob2
def getADRP(addr):
    return get_operand_value(addr,1)+get_operand_value(addr+4,1)

# How to code the following section?
# First you need to load the above functions (Run once or Copy and Paste in the Python output windows)
# then move the cursor type getAOB() and you will get the AOB pattern there
# AOB(pattern) return the first search result
# allOccur(pattern) return all the search results found
# AOB2(pattern1,offset) return the address of a BL/B function inside [pattern1 + offset]
# AOB2(pattern1,offset,pattern2) return the result of second search, inside the BL/B function found by pattern1 + offset (pattern11 may be an address or pattern)
# AOB3(pattern1,pattern2) return the nearest result of second search from the first search. pattern2 may be an offset or pattern
# After the cheat codes were generated, you may paste it onto F2 window of the GDB with the ApplyPatch('''XXXXX''') function

if not(gdb):
    codeK=codeEnd
    cls()
    # print('ApplyPatch(\'\'\'')
    cheatCnt=0
    delayOutput = masterCode = restoreCode=''

    english = True
################################ START ######################################

    print("[Xenoblade Chronicles 3 (US) v1.0.0(v0) TID=010074F013262000 BID=60887A25B6652991]")

    cheatCnt+=1;idx=ord('a');temp=codeK
    cheatAddr=AOB('08 14 40 B9 68 12 00 B9') # LDR W8, [X0,#0x14]
    cheatName = '50% Damage to Players' if english else '對玩家傷害減半' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('LDRB W8, [X0,#0x1E]','CBZ W8, .+16','LDUR W8, [X22,#0x5A]','TBNZ W8, #0, .+8','LSR W20,W20,#1','LDR W8, [X0,#0x14]','RET'))

    idx+=1;codeK=temp
    cheatName = '25% Damage to Players' if english else '對玩家傷害降至 1/4' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('LDRB W8, [X0,#0x1E]','CBZ W8, .+16','LDUR W8, [X22,#0x5A]','TBNZ W8, #0, .+8','LSR W20,W20,#2','LDR W8, [X0,#0x14]','RET'),False)

    idx+=1;codeK=temp
    cheatName = '12.5% Damage to Players' if english else '對玩家傷害降至 1/8' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('LDRB W8, [X0,#0x1E]','CBZ W8, .+16','LDUR W8, [X22,#0x5A]','TBNZ W8, #0, .+8','LSR W20,W20,#3','LDR W8, [X0,#0x14]','RET'),False)

    idx+=1;codeK=temp
    cheatName = '1/16 Damage to Players ★' if english else '對玩家傷害降至 1/16 ★' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('LDRB W8, [X0,#0x1E]','CBZ W8, .+16','LDUR W8, [X22,#0x5A]','TBNZ W8, #0, .+8','LSR W20,W20,#4','LDR W8, [X0,#0x14]','RET'),False)
        
    idx+=1;codeK=temp
    cheatName = 'Only -10 HP of Damage to Players' if english else '對玩家的傷害固定 -10 HP' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('LDRB W8, [X0,#0x1E]','CBZ W8, .+16','LDUR W8, [X22,#0x5A]','TBNZ W8, #0, .+8','MOV W20,#10','LDR W8, [X0,#0x14]','RET'),False)


    cheatCnt+=1;idx=ord('a');temp=codeK
    cheatAddr=AOB('68 12 00 B9 C9 BE 40 79')
    cheatName = 'Damage Multiplier (2x)' if english else '敵人傷害倍率 (2x)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('STR W8, [X19,#0x10]','LDRB W8, [X0,#0x1E]','CBNZ W8, .+16','LDUR W8, [X22,#0x5A]','TBNZ W8, #0, .+8','LSL W20,W20,#1','RET'))

    idx+=1;codeK=temp
    cheatName = 'Damage Multiplier (5x) ★' if english else '敵人傷害倍率 (5x) ★' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('STR W8, [X19,#0x10]','LDRB W8, [X0,#0x1E]','CBNZ W8, .+16','LDUR W8, [X22,#0x5A]','TBNZ W8, #0, .+8','ADD W20,W20,W20,LSL#2','RET'),False)

    idx+=1;codeK=temp
    cheatName = 'Damage Multiplier (13x)' if english else '敵人傷害倍率 (13x)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('STR W8, [X19,#0x10]','LDRB W8, [X0,#0x1E]','CBNZ W8, .+16','LDUR W8, [X22,#0x5A]','TBNZ W8, #0, .+8','MOV W8, #13','MUL W20,W20,W8','RET'),False)

    idx+=1;codeK=temp
    cheatName = 'Damage Multiplier (34x)' if english else '敵人傷害倍率 (34x)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('STR W8, [X19,#0x10]','LDRB W8, [X0,#0x1E]','CBNZ W8, .+16','LDUR W8, [X22,#0x5A]','TBNZ W8, #0, .+8','MOV W8, #34','MUL W20,W20,W8','RET'),False)

    idx+=1;codeK=temp
    cheatName = '9999999 Damage to Enemies' if english else '秒殺敵人' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('STR W8, [X19,#0x10]','LDRB W8, [X0,#0x1E]','CBNZ W8, .+20','LDUR W8, [X22,#0x5A]','TBNZ W8, #0, .+12','MOV W20, 0xC9FF','MOVK W20, 0x3B9A, LSL#16','RET'),False)


    masterCode += RegData(0);XPmultiplier=codeK
    masterCode += RegData(0);CMRmultiplier=codeK
    masterCode += RegData(0);CERmultiplier=codeK
    cheatAddr=AOB('36 00 40 B9 F3 03 00 AA F5 1F 9C 52') # LDR W22, [X1] side quest for add xp
    if isFound(cheatAddr): 
        masterCode += CodeFunc(('LDR W22, [X1]','LDR W19,%d-{here}'%XPmultiplier,'CBZ W19, .+8','MUL W22,W22,W19','RET'))
        masterCode += CheatCode(4,cheatAddr,'BL '+hex(codeK-cheatAddr))
    cheatAddr = AOB('93 03 08 8B B4 43 1D 38')
    if isFound(cheatAddr):
        masterCode += CodeFunc(('ADD X19, X28, X8',
            'LDR W26,%d-{here}'%XPmultiplier,'CBZ W26, .+20','LDR S0,[X19]','UCVTF S8, W26','FMUL S0, S0, S8','STR S0,[X19]',
            'LDR W26,%d-{here}'%CMRmultiplier,'CBZ W26, .+20','LDR S0,[X19,#4]','UCVTF S8, W26','FMUL S0, S0, S8','STR S0,[X19,#4]',
            'LDR W26,%d-{here}'%CERmultiplier,'CBZ W26, .+20','LDR S0,[X19,#8]','UCVTF S8, W26','FMUL S0, S0, S8','STR S0,[X19,#8]',
            'RET'))
        masterCode += CheatCode(4,cheatAddr,'BL '+hex(codeK-cheatAddr))

        cheatCnt+=1;idx=ord('a')
        cheatName = 'XP Multiplier (2x)' if english else '經驗倍率 (2x)' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(XPmultiplier, 2, False)
        
        idx+=1
        cheatName = 'XP Multiplier (3x)' if english else '經驗倍率 (3x)' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(XPmultiplier, 3, False)

        idx+=1
        cheatName = 'XP Multiplier (5x) ★' if english else '經驗倍率 (5x) ★' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(XPmultiplier, 5, False)

        idx+=1
        cheatName = 'XP Multiplier (9x)' if english else '經驗倍率 (9x)' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(XPmultiplier, 9, False)
        
        idx+=1
        cheatName = 'XP Multiplier (16x)' if english else '經驗倍率 (16x)' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(XPmultiplier, 16, False)


        cheatCnt+=1;idx=ord('a')
        cheatName = 'Class Mastery Rate (2x)' if english else '職業掌握度提昇倍率 (2x)' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(CMRmultiplier, 2, False)
        
        idx+=1
        cheatName = 'Class Mastery Rate (3x)' if english else '職業掌握度提昇倍率 (3x)' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(CMRmultiplier, 3, False)

        idx+=1
        cheatName = 'Class Mastery Rate (5x) ★' if english else '職業掌握度提昇倍率 (5x) ★' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(CMRmultiplier, 5, False)

        idx+=1
        cheatName = 'Class Mastery Rate (9x)' if english else '職業掌握度提昇倍率 (9x)' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(CMRmultiplier, 9, False)
        
        idx+=1
        cheatName = 'Class Mastery Rate (16x)' if english else '職業掌握度提昇倍率 (16x)' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(CMRmultiplier, 16, False)
        
        
        cheatCnt+=1;idx=ord('a')
        cheatName = 'Class Exploration Rate (2x)' if english else '職業探索度提昇倍率 (2x)' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(CERmultiplier, 2, False)
        
        idx+=1
        cheatName = 'Class Exploration Rate (3x)' if english else '職業探索度提昇倍率 (3x)' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(CERmultiplier, 3, False)

        idx+=1
        cheatName = 'Class Exploration Rate (5x) ★' if english else '職業探索度提昇倍率 (5x) ★' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(CERmultiplier, 5, False)

        idx+=1
        cheatName = 'Class Exploration Rate (9x)' if english else '職業探索度提昇倍率 (9x)' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(CERmultiplier, 9, False)
        
        idx+=1
        cheatName = 'Class Exploration Rate (16x)' if english else '職業探索度提昇倍率 (16x)' 
        show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
        Hack(CERmultiplier, 16, False)

    cheatCnt+=1
    cheatName = 'Class Awakening unlock (Break LV10 to LV20) ★' if english else '解鎖職業覺醒 (突破 LV10 到 LV20) ★' 
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    Hack('3B 01 88 1A 28 03 40 B9','MOV W27,#20') # CSEL W27, W9, W8, EQ
    Hack('49 01 80 52 08 61 40 39',('MOV W9, #1','STRB W9, [X8,#0x18]','TST W9, #1'))


    cheatCnt+=1;idx=ord('a')
    cheatAddr='A8 72 4A BD' #LDR S8, [X21,#0xA70]
    cheatName = 'Items Pick up Distance (3x)' if english else '物品撿拾距離 (3x)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'FMOV S8, #5.5') 
    
    idx+=1
    cheatName = 'Items Pick up Distance (7x)' if english else '物品撿拾距離 (7x)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'FMOV S8, #12', False) 

    idx+=1
    cheatName = 'Items Pick up Distance (15x)' if english else '物品撿拾距離 (15x)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'FMOV S8, #27', False) 

    idx+=1
    cheatName = 'Items Pick up Distance (28x) ★' if english else '物品撿拾距離 (28x) ★' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'LDR S8, [X21,#0xA54]', False) 

    idx+=1
    cheatName = 'Items Pick up Distance (∞)' if english else '物品撿拾距離 (∞)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'LDR S8, [X21,#0xA68]', False) 


    cheatCnt+=1;idx=ord('a')
    cheatAddr = AOB('20 20 22 1E 21 4C 22 1E 62 8E 47 2D 44 08 21 1E 61 08 24 1E 62 0E 41 BD 41 08 21 1E 21 08 28 1E') # FCMP S1, S2
    cheatName = 'Movement Speed (2x) hold Y' if english else '移動速度 (按Y鍵2x)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr,('FMOV S2, #2.0','FMUL S1, S1, S2'), useButton='Y')

    idx+=1
    cheatName = 'Movement Speed (3x hold Y)' if english else '移動速度 (按Y鍵3x)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr,('FMOV S2, #3.0','FMUL S1, S1, S2'), False, useButton='Y')

    idx+=1
    cheatName = 'Movement Speed (1.25x / 5x hold Y)' if english else '移動速度 (1.25x / 按Y鍵5x)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr,('FMOV S2, #1.25','FMUL S1, S1, S2'), False)
    Hack(cheatAddr,('FMOV S2, #5.0','FMUL S1, S1, S2'), False, useButton='Y')

    idx+=1
    cheatName = 'Movement Speed (1.5x / 8x hold Y) ★' if english else '移動速度 (1.5x / 按Y鍵8x) ★' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr,('FMOV S2, #1.5','FMUL S1, S1, S2'), False)
    Hack(cheatAddr,('FMOV S2, #8.0','FMUL S1, S1, S2'), False, useButton='Y')

    idx+=1
    cheatName = 'Movement Speed (2x / 13x hold Y)' if english else '移動速度 (2x / 按Y鍵13x)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr,('FMOV S2, #2.0','FMUL S1, S1, S2'), False)
    Hack(cheatAddr,('FMOV S2, #13.0','FMUL S1, S1, S2'), False, useButton='Y')


    cheatCnt+=1
    cheatName = 'Moon Jump (Hold B) ★' if english else '登月跳 (Hold B) ★' 
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    # cheatAddr = AOB('00 81 00 4D E8 26 40 F9')
    # delayOutput += RegData(0); ToggleAddr=codeK
    # delayOutput += CodeFunc(('FMOV S5, WZR','LDR S2, [SP,#0x34]','FCMP S2, S5','B.PL .+20','LDR S2, %d-{here}'%codeK,'FCMP S2, S5','B.EQ .+8','STR S2, [SP,#0x34]','ST1 {V0.S}[2], [X8]','RET'))
    # delayOutput += CheatCode(4,cheatAddr,'BL '+hex(codeK-cheatAddr))
    # delayOutput += ButtonCode('B',CheatCode(4,ToggleAddr,Float2DWord(0.35)))
    # delayOutput += ButtonCode('ZL',CheatCode(4,To
    cheatAddr = AOB('? ? ? ? 08 ? ? F9 08 41 00 91 08 00 00 F9 00 08 40 F9')
    if isFound(cheatAddr):
        memAddr = get_qword(getADRP(cheatAddr))+0x10
        delayOutput += RegData(0); ToggleAddr=codeK
        delayOutput += CodeFunc(('LDR X0,[X19,0x10]','LDR X0,[X0,0x10]','CBZ X0, #52','LDR X0,[X0]','AND X0,X0,0xFFF','CMP X0,%d'%(memAddr&0xFFF),'BNE .+36','FMOV S5, WZR','LDR S2, [SP,#0x34]','FCMP S2, S5','B.PL .+20','LDR S2, %d-{here}'%codeK,'FCMP S2, S5','B.EQ .+8','STR S2, [SP,#0x34]','ST1 {V0.S}[2], [X8]','RET'))
        cheatAddr = AOB('00 81 00 4D E8 26 40 F9')
        delayOutput += CheatCode(4,cheatAddr,'BL '+hex(codeK-cheatAddr))
        delayOutput += ButtonCode('B',CheatCode(4,ToggleAddr,Float2DWord(0.35)))
        delayOutput += ButtonCode('ZL',CheatCode(4,ToggleAddr,0))
    else:
        warning('AOB broken at #%d'%cheatCnt)

    
    cheatCnt+=1
    cheatName = 'Fall Damage -1 only ★' if english else '高空掉落傷害-1 ★' 
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    Hack('08 00 39 1E ? ? ? 14 09 28 41 A9','MOV W8,#1')


    cheatCnt+=1
    cheatName = 'No Cooldown Arts ★' if english else '戰技不用冷卻 ★' 
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    cheatAddr=AOB('? ? ? ? 08 ? ? F9 01 3C 00 F9 1F 48 00 F9')
    if isFound(cheatAddr):  
        memAddr=get_qword(getADRP(cheatAddr))+0x10
        CodeCave('68 12 00 BD F4 4F 42 A9 F5 0F 40 F9', ('LDR X20,[X19]','LDR X20,[X20,-0x28]','LDR X20,[X20]','AND x20,x20,0xFFF','CMP X20,%d'%(memAddr&0xFFF),'BEQ .+8','STR S8, [X19,#0x10]','RET'))


    cheatCnt+=1
    cheatName = 'Always Max Arts Gauge ★' if english else '戰技/天賦技能計量表常滿 ★'
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    CodeCave('00 13 40 BD 1F 01 09 6A', # LDR S0, [X24,#0x10]
        ('FMOV S0, 1.0','STR S0, [X24,#0x10]','RET'))


    cheatCnt+=1
    cheatName = 'Max Chain Attack Gauge ★' if english else '連鎖技能計量表常滿 ★'  # max=print(ptr((0x1777F80,0,0x120),4))
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    Hack('60 12 44 BD 08 29 20 1E', 'FMOV S0, S9') # LDR S0, [X19,#0x410]


    cheatCnt+=1 ; idx=ord('a')
    cheatName = 'Interlinking Heat keep Max' if english else '靈銜連結保持最熱' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack('08 24 40 BD','LDR S8, [X0,#0x28]') # LDR S8, [X0,#0x24]
    Hack('00 29 20 1E 69 2A 40 BD','FSUB S0, S8, S0') # FADD S0, S8, S0

    idx+=1
    cheatName = 'Interlinking Heat keep Min' if english else '靈銜連結保持最冷' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack('00 29 20 1E 69 2A 40 BD','FMOV S0, WZR',False) # FADD S0, S8, S0

    idx+=1
    cheatName = 'Interlinking no Over Heat ★' if english else '靈銜連結不過熱 ★' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave('69 2A 40 BD',('LDR S9, [X19,#0x28]','FCMP S0,S9','B.CC .+8','FMOV S0,S8','RET')) # LDR S9, [X19,#0x28]
    
    
    cheatCnt+=1 # heap+87E43614 / heap+1C867E030  
    cheatName = 'Money does not reduce' if english else '金錢不減' 
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    Hack('68 06 36 B9 E0 03 13 AA ? ? ? 97 68 D2 5E F9','NOP') # shop
    Hack(AOB2('60 06 40 F9 E2 03 1F AA',8,'F5 03 01 2A'),'MOV W21, WZR') # real
 
 
    cheatCnt+=1 ; idx=ord('a')
    cheatAddr = AOB('08 01 01 0B E9 E1 84 52')
    cheatName = 'Soul Point (SP) Multiplier (4x)' if english else 'SP增加倍率 (4x)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'ADD W8, W8, W1, LSL#2')
    
    idx+=1
    cheatName = 'Soul Point (SP) Multiplier (8x) ★' if english else 'SP增加倍率 (8x) ★' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'ADD W8, W8, W1, LSL#3',False)
    
    idx+=1
    cheatName = 'Soul Point (SP) Multiplier (16x)' if english else 'SP增加倍率 (16x)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'ADD W8, W8, W1, LSL#4',False)


    cheatCnt+=1 
    cheatName = 'Soul Point (SP) no reduction ★' if english else 'SP不減 ★' 
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    CodeCave(AOB3(cheatAddr,'08 00 00 B9'),('TBNZ W1, #0x1F,.+8','STR W8, [X0]','RET'),use_BL=False)
    
    
    cheatAddr = AOB('F4 03 02 2A F6 03 01 2A F3 03 00 AA ? ? ? 97 01 23 80 52') # MOV W20, W2  
    cheatCnt+=1 ; idx=ord('a')
    cheatName = 'Affinity Points Multiplier (3X)' if english else '羈伴點數增加倍率 (3X)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'ADD W20, W2, W2, LSL#1')
    
    idx+=1
    cheatName = 'Affinity Points Multiplier (5X) ★' if english else '羈伴點數增加倍率 (5X) ★' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'ADD W20, W2, W2, LSL#2',False)
    
    idx+=1
    cheatName = 'Affinity Points Multiplier (8X)' if english else '羈伴點數增加倍率 (8X)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'LSL W20, W2, #3',False)    
    
    
    cheatAddr = AOB('F3 03 02 2A F9 03 01 2A ? ? ? 94') # MOV W19, W2  without hack display
    cheatCnt+=1 ; idx=ord('a')
    cheatName = 'Items, Coins, Ether and Money multiplier (3X)' if english else '道具,硬幣,以太及錢增加倍率 (3X)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'ADD W19, W2, W2, LSL#1')
    
    idx+=1
    cheatName = 'Items, Coins, Ether and Money multiplier (5X) ★' if english else '道具,硬幣,以太及錢增加倍率 (5X) ★' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'ADD W19, W2, W2, LSL#2',False)
    
    idx+=1
    cheatName = 'Items, Coins, Ether and Money multiplier (8X)' if english else '道具,硬幣,以太及金錢增加倍率 (8X)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    Hack(cheatAddr, 'LSL W19, W2, #3',False)
    
    
    cheatAddr = AOB('20 01 23 1E 08 03 40 F9') # UCVTF S0, W9
    cheatCnt+=1 ; idx=ord('a');temp=codeK
    cheatName = 'Meal Effects Duration Multiplier (5X)' if english else '料理時效倍率 (3X)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('ADD W9, W9, W9, LSL#1','UCVTF S0, W9','RET'))
    
    idx+=1;codeK=temp
    cheatName = 'Meal Effects Duration Multiplier (5X) ★' if english else '料理時效倍率 (5X) ★' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('ADD W9, W9, W9, LSL#2','UCVTF S0, W9','RET'),False)
    
    idx+=1;codeK=temp
    cheatName = 'Meal Effects Duration Multiplier (8X)' if english else '料理時效倍率 (8X)' 
    show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    CodeCave(cheatAddr, ('LSL W9, W9, #3','UCVTF S0, W9','RET'),False)

    
    cheatCnt+=1
    cheatName = 'Gold/Silver Coins no redurction and display 999 ★' if english else '金/銀硬幣不減 & 虛報數量999 ★' 
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    Hack('? ? ? 97 ? ? ? 17 E2 03 01 2A','NOP')
    Hack('0A E1 5F 78 00 00 0A 0B ? ? ? 17 08 B9 81 52','MOV W10, #999')


    cheatCnt+=1
    cheatName = 'Ignore the LVs Difference (Act as the same LV) ★' if english else '無視等級差距 (職業探索的其中一個要求) ★' 
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    Hack('09 27 40 39 1F 01 09 6B','MOV W9, W8') # LDRB W9, [X24,#9]   cheat the result as the same level enemy


    cheatCnt+=1
    cheatName = 'Unlock all Classes (No Exploration Phase / Heroes to join)' if english else '全職業解鎖 (無須探索,無須英雄加入,直接使用)' 
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    Hack('08 59 40 39 F3 0B 40 F9','MOV W8, #1') # unlock without exploration LDRB W8, [X8,#0x16]
    Hack('00 3C 00 12 F4 4F 42 A9 F5 0B 40 F9','MOV W0, #0') # Exploration require exp = 1 # AND W0, W0, #0xFFFF
    Hack('E0 03 1F AA 15 04 00 34','MOV X0, #2') # Character Unlock # MOV X0, XZR

            
    cheatCnt+=1
    cheatName = 'Repairing unlocked class cannot explore after Cancelled' if english else '修復:"全職業解鎖"並還原後,無法探索的問題' 
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    Hack('29 FF FF 35 00 01 23 1E','NOP') 
    Hack('2B FF FF 35','NOP') 
    Hack('08 FF FF 35 E0 03 18 AA','NOP') 

            
    cheatCnt+=1
    cheatName = 'Items not required in Side Quest / Collectopaedia card ★' if english else '支線任務及手冊卡片,無視道具物品要求 ★' 
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    Hack('? ? ? 97 69 B6 48 F9 D6 06 00 91','NOP') 
    Hack('E0 33 88 1A','MOV W0, #99') 
    Hack('? ? ? 97 08 04 00 51 1F 00 00 71 E9 2F 40 F9','NOP')  # collection items

            
    cheatCnt+=1
    cheatName = 'Resting Camp can Drop LV ★' if english else '營火休息處可降級 (無須二周目) ★' 
    show('%d. %s'%(cheatCnt,cheatName)); delayOutput += '\n[#%02d. %s]\n'%(cheatCnt,cheatName)
    Hack('88 96 40 39 68 00 00 34','MOV W8,#1') 
    Hack('? ? ? 97 E0 F9 FF 34','MOV W0,#1') 


    # cheatCnt+=1;idx=ord('a');temp=codeK
    # cheatName = 'Ignore Class Exploration require that Class in Team)' if english else '無視職業探索要求(無須同隊有該職業仍可增加探索度)' 
    # show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    # CodeCave('A8 7A 76 B8', ('LDR W8, [SP,#0x180]','CMP W8,#14','LDR W8, [X21,X22,LSL#2]','BGE .+8','MOV W8,#100','RET'))
    # CodeCave('AA 7A 69 B8', ('LDR W10, [SP,#0x180]','CMP W10,#14','LDR W10, [X21,X9,LSL#2]','BGE .+8','MOV W10,#100','RET'))

    # idx+=1;codeK=temp
    # cheatName = '50% Exploration Rate instead of Zero ★' if english else '當同隊無該職業,探索度0改為50% ★' 
    # show('%d%s %s'%(cheatCnt,chr(idx),cheatName)); delayOutput += '\n[#%02d%s %s]\n'%(cheatCnt,chr(idx),cheatName)
    # CodeCave('A8 7A 76 B8', ('LDR W8, [SP,#0x180]','CMP W8,#14','LDR W8, [X21,X22,LSL#2]','BGE .+12','CBNZ W8,.+8','MOV W8,#100','RET'),False)
    # CodeCave('AA 7A 69 B8', ('LDR W10, [SP,#0x180]','CMP W10,#14','LDR W10, [X21,X9,LSL#2]','BGE .+12','CBNZ W10,.+8','MOV W10,#100','RET'),False)



################################# END #######################################

    if masterCode != '': msg(('\n{%s}\n'%('Master Code (includes share functions and restore code)' if english else '關鍵碼 (含共用函式及還原碼)'))+masterCode+restoreCode)
    elif restoreCode != '': msg(('\n{%s}\n'%('Restore Code (no share functions)' if english else '還原碼 (不含共用函式)'))+restoreCode)
    print(delayOutput)
    print('[This set of cheats is created by Eiffel2018, enjoy!]\n' if english else '[此套金手指由 Eiffel2018 制作, 免費提供, 歡迎轉載, 但請註明來源出處]')

    # print('\'\'\')')

""" Remarks
    Enmey Class = main+16F52B8
    Player Class = main+16F51F8
    offsets: 
        +00 Class
        +08 LV
        +0C EXP
        +10 ?
        +14 HP
        +1C player class type
        +1D enemy type
        +1E isPlayer
        +1F isEnemy ??
        +20 ??
        +28 STR 
        +2A 
        +2C
        +2E
"""
