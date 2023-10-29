# This Script is Programmed by Eiffel2018
# Works in IDA PRO v7.5 up 
# Requirement: Python 3.9.x (with idapyswitch) and Keystone 
# Operate with a clean NSO (or main.elf) or GDB connected with segment defined by markRegions64.py

import idc
import ida_search
from keystone import *

patch = False # set to True if you want to apply the cheat code to IDA memory
CodeStart = ida_segment.get_segm_by_name('.text').start_ea
CodeEnd = ida_segment.get_segm_by_name('.rodata').start_ea
DataStart = ida_segment.get_segm_by_name('.data').start_ea
DataEnd = ida_segment.get_segm_by_name('.prgend').start_ea

if patch:
    idc.set_name(CodeStart, 'CodeStart', idc.SN_AUTO)
    idc.set_name(CodeEnd, 'CodeEnd', idc.SN_AUTO)
    idc.set_name(DataStart, 'DataStart', idc.SN_AUTO)
    idc.set_name(DataEnd, 'DataEnd', idc.SN_AUTO)

def cls():
    ida_kernwin.activate_widget(ida_kernwin.find_widget("Output window"), True);
    ida_kernwin.process_ui_action("msglist:Clear");
def isFound(opAddr):
    return opAddr != BADADDR
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
        print('Error in PatchBytes({},{},{})',length,opAddr,value) 
def CheatCode(length,opAddr,value,isPatch=patch):
    if isPatch: PatchBytes(length,opAddr,value)
    return '0{}0E0000 {} {}'.format(length,Addr2DWord(opAddr),Value2DWord(value) if length<=4 else Value2QWord(value))
def RestoreCode(length,opAddr):
    return CheatCode(length,opAddr,GetBytes(length,opAddr),False)
def PointerCode(oppsets, length, value): # oppsets use tuples/list with at least 2 element
    if len(oppsets)<2: return 'Error with PointerCode'
    else:
        code = '580{}0000 {:08X}'.format(TM,oppsets[0])
        for offset in oppsets[1:-1]: 
            code += '\n580{}1000 {:08X}'.format(TM,offset)
        code += '\n780{}0000 {:08X}'.format(TM,oppsets[-1])
        code += '\n6{:1X}0{}0000 {}'.format(length, TM, Value2QWord(value))
        return code
def ButtonCode(key,code):
    return '8{:07X}\n{}\n20000000'.format(key,code)
def ASM(asm_code):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    bytecode, cnt = ks.asm(asm_code, as_bytes=True)
    return ''.join(map('{:02X}'.format, reversed(bytecode)))
def GrepAddr(opAddr):
    return idc.get_operand_value(opAddr,1)
def PraseADRP(base,target):
    return hex((target&0xFFFFF000)-(base&0xFFFFF000))
def AOB(pattern,searchStart=CodeStart):
    return ida_search.find_binary(searchStart, CodeEnd, pattern, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)
def AOB2(pattern,offset,pattern2):
    opAddr=AOB(pattern)
    return AOB(pattern2,idc.get_operand_value(opAddr+offset,0)) if isFound(opAddr) else BADADDR
def AOB3(pattern,pattern2):
    opAddr=AOB(pattern)
    return AOB(pattern2,opAddr+4) if isFound(opAddr) else BADADDR
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
    cmd=idc.print_insn_mnem(opAddr)
    if cmd == 'BL' or cmd == 'B':
        return '? ? ? {:02X}'.format(ida_bytes.get_original_byte(opAddr+3))
    elif cmd == 'ADRP' or cmd == 'ADRL':
        return '? ? ? ?'
    elif cmd == '' and idc.print_insn_mnem(opAddr-4)=='ADRL':
        return "? ? ? {:02X}".format(ida_bytes.get_original_byte(opAddr+3))
    elif 'PAGEOFF' in print_operand(opAddr,1):
        return "{:02X} ? ? {:02X}".format(ida_bytes.get_original_byte(opAddr),ida_bytes.get_original_byte(opAddr+3))
    else:
        return getBytesPattern(opAddr)
def getAOB(opAddr):
    pattern=space=''
    result=False
    funcEnd=idc.find_func_end(opAddr)
    while opAddr<funcEnd and result==False:
        pattern+=space+anaysis(opAddr)
        space=' '
        opAddr+=4
        result=checkUnique(pattern)
    print('Not Unqiue! \n'+pattern if result==None else pattern)

# How to code the following section?
# First you need to load the above functions (Run once or Copy and Paste in the Python output windows)
# then type getAOB(0xAddressOfCheat) and you will get the AOB pattern
# You may check how many results can be get from binary search and choose one of the following method 
# AOB(pattern) return the first search result
# allOccur(pattern) return all the search results found
# AOB2(pattern1,offset,pattern2) return the result of second search, inside the BL/B function found by pattern1 + offset
# AOB3(pattern1,pattern2) return the nearest result of second search from the first search

################################ START ######################################
cls()
print("[THE HOUSE OF THE DEAD, Remake (JP) v1.0.1(v65536)  TID=0100B3A017864000  BID=28663C90B7402063]")
print("[THE HOUSE OF THE DEAD, Remake (US) v1.0.1(v65536)  TID=010088401495E000  BID=CF5A2ADD49121042]")

DelayOutput = ''
print('\n{Restore Codes}')


CheatName = '#01. God Mode (Invincible+UnlockEverying+1HitKill)'
CheatAddr = AOB('88 02 40 F9 08 5D 40 F9 08 01 44 39 48 00 00 35')
if isFound(CheatAddr):
    CheatAddr+=0x1C
    DelayOutput += '\n\n[' + CheatName + ']'
    DelayOutput += '\n' + CheatCode(4,CheatAddr,ASM('MOV W0, 1'));
    print(RestoreCode(4,CheatAddr))
else:
    print(CheatName+': AOB broken!')

CheatName = '#02. Infinite Ammo'
CheatAddr = AOB('80 08 00 36 69 62 40 B9 1F 01 09 6B 6A 08 00 54')
CheatAddr2 = AOB('68 6A 00 B9 F4 4F 42 A9 F5 0B 40 F9 FD 7B C3 A8 C0 03 5F D6 ? ? ? 97')
if isFound(CheatAddr) and isFound(CheatAddr2):
    DelayOutput += '\n\n[' + CheatName + ']'
    DelayOutput += '\n' + CheatCode(4,CheatAddr,ASM('NOP'));
    DelayOutput += '\n' + CheatCode(4,CheatAddr2,ASM('NOP'));
    print(RestoreCode(4,CheatAddr))
    print(RestoreCode(4,CheatAddr2))
else:
    print(CheatName+': AOB broken!')
    
CheatName = '#03. Infinite Health'
CheatAddr = AOB2('82 36 40 B9 F4 4F 42 A9 F5 0B 40 F9 FD 7B C3 A8',0x10,'F3 03 02 2A F4 03 00 AA')
if isFound(CheatAddr):
    DelayOutput += '\n\n[' + CheatName + ']'
    DelayOutput += '\n' + CheatCode(4,CheatAddr,ASM('MOV W19, WZR'));
    print(RestoreCode(4,CheatAddr))
else:
    print(CheatName+': AOB broken!')


print(DelayOutput)
print('\n[Created by Eiffel2018, enjoy!]\n')

################################# END #######################################