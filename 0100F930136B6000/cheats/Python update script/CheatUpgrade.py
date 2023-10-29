import idc
import ida_search
from keystone import *

print("\n===== This Script is Programmed by Eiffel2018, enjoy ====")

CodeStart = ida_segment.get_segm_by_name(".text").start_ea
CodeEnd = ida_segment.get_segm_by_name(".rodata").start_ea

def isFound(opAddr):
    return opAddr != 0xFFFFFFFFFFFFFFFF
def AoB(pattern):
    result = ida_search.find_binary(CodeStart, CodeEnd, pattern, 0, idc.SEARCH_DOWN|idc.SEARCH_NEXT)
    if not(isFound(result)): print('Pattern "'+pattern+'" not fonud!')
    return result
def Addr2Hex(opAddr):
    return "{:08X}".format(opAddr & 0xFFFFFFFF)
def KeyStone(asm_code):
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    bytecode, cnt = ks.asm(asm_code, as_bytes=True)
    return "".join(map("{:02X}".format, reversed(bytecode)))
def Get1Byte(opAddr):
    return "000000{:02X}".format(idc.get_bytes(opAddr, 1)[0])
def Get2Byte(opAddr):
    return "0000"+"".join(map("{:02X}".format, reversed(idc.get_bytes(opAddr, 2))))
def Get4Byte(opAddr):
    return "".join(map("{:02X}".format, reversed(idc.get_bytes(opAddr, 4))))
def Get8Byte(opAddr):
    return Get4Byte(opAddr+4)+' '+Get4Byte(opAddr)
def GetBytes(opAddr,length):
    return { 1:Get1Byte(opAddr), 2:Get2Byte(opAddr), 4:Get4Byte(opAddr), 8:Get8Byte(opAddr)}[length]
def RestoreCode(opAddr,length):
    return '0'+str(length)+'0E0000 ' + Addr2Hex(opAddr) + ' ' + GetBytes(opAddr,length)

CodeK = CodeEnd-0x1000
#print("CodeK = "+hex(CodeK))

################################ START ######################################

AoB_Addr_01 = AoB("08 04 00 51 1F 00 00 71 E0 03 14 AA E9 17 9F 1A 01 C1 9F 1A 69 ? ? 39 ? ? ? 97 68 02 40 F9")
AoB_Addr_02 = AoB("08 1C A0 4E 00 80 44 BD 08 20 20 1E F3 03 00 AA ? ? 00 54")
AoB_Addr_03a = AoB("? ? ? 94 01 1C A0 4E E0 03 27 1E ? ? ? 94 08 1C A0 4E 60 ? ? BD 00 20 28 1E 00 02 00 54")
AoB_Addr_03b = AoB("? ? ? 94 01 1C A0 4E 00 1D A8 4E ? ? ? 94 08 1C A0 4E 60 ? ? BD 00 20 28 1E 00 02 00 54")
AoB_Addr_04a = AoB("08 B1 96 1A 01 7D A8 0A ? ? ? 97 94 C2 00 91 E0 03 14 AA ? ? ? 97 08 00 13 0B E0 03 14 AA")
AoB_Addr_04b = AoB("08 B1 95 1A 01 7D A8 0A ? ? ? 97 E0 03 00 32 FD ? ? A9 F4 ? ? A9 F5 ? ? F8 C0 03 5F D6")
AoB_Addr_04c = AoB("08 B0 88 1A 00 7D A8 0A FD ? ? A8 C0 03 5F D6 00 00 00 00 FD ? ? A9 FD 03 00 91 00 ? ? 91")
AoB_Addr_05a = AoB("08 B1 95 1A 01 7D A8 0A 68 ? ? F9 C0 22 37 9B ? ? ? 97 68 ? ? F9 C0 22 37 9B ? ? ? 97")
AoB_Addr_05b = AoB("08 B1 95 1A 01 7D A8 0A 68 ? ? F9 C0 22 37 9B ? ? ? 97 E0 03 00 32 ? FF FF 17 00 00 00 00")
AoB_Addr_05c = AoB("08 B1 95 1A 01 7D A8 0A 68 ? ? F9 C0 22 37 9B ? ? ? 97 E0 03 00 32 ? 00 00 14 E0 03 1F 2A")
AoB_Addr_05d = AoB("08 B0 88 1A 00 7D A8 0A FD ? ? A8 C0 03 5F D6 00 00 00 00 28 1C 00 12 C8 00 00 34 09 ? ? B9")
AoB_Addr_06 = AoB("FF 83 03 D1 F5 5B 00 F9 F4 4F 0C A9 FD 7B 0D A9 FD 43 03 91 F4 03 01 AA F3 03 00 AA BF 83 1E F8")

print("\n{Restore Code}")
if isFound(AoB_Addr_01): print(RestoreCode(AoB_Addr_01,4))
if isFound(AoB_Addr_02): print(RestoreCode(AoB_Addr_02,4))
if isFound(AoB_Addr_03a) and isFound(AoB_Addr_03b):
    print(RestoreCode(AoB_Addr_03a,4))
    print(RestoreCode(AoB_Addr_03b,4))
if isFound(AoB_Addr_04a) and isFound(AoB_Addr_04b) and isFound(AoB_Addr_04c):
    print(RestoreCode(AoB_Addr_04a,4))
    print(RestoreCode(AoB_Addr_04b,4))
    print(RestoreCode(AoB_Addr_04c,4))
if isFound(AoB_Addr_05a) and isFound(AoB_Addr_05b) and isFound(AoB_Addr_05c) and isFound(AoB_Addr_05d):
    print(RestoreCode(AoB_Addr_05a,4))
    print(RestoreCode(AoB_Addr_05b,4))
    print(RestoreCode(AoB_Addr_05c,4))
    print(RestoreCode(AoB_Addr_05d,4))
if isFound(AoB_Addr_06): print(RestoreCode(AoB_Addr_06,4))

if isFound(AoB_Addr_01):
    print("\n[#01. Infinite Lives]")
    print("040E0000", Addr2Hex(AoB_Addr_01), "52800128")
if isFound(AoB_Addr_02):
    print("\n[#02. Instant Beam Charge]")
    print("040E0000", Addr2Hex(AoB_Addr_02), "1E273008")
if isFound(AoB_Addr_03a) and isFound(AoB_Addr_03b):
    print("\n[#03. Infinite DOSE]")
    print("040E0000", Addr2Hex(AoB_Addr_03a), "D503201F")
    print("040E0000", Addr2Hex(AoB_Addr_03b), "D503201F")
if isFound(AoB_Addr_04a) and isFound(AoB_Addr_04b) and isFound(AoB_Addr_04c):
    print("\n[#04. Max R-coins]")
    print("040E0000", Addr2Hex(AoB_Addr_04a), "2A1603E8")
    print("040E0000", Addr2Hex(AoB_Addr_04b), "2A1503E8")
    print("040E0000", Addr2Hex(AoB_Addr_04c), "D503201F")
if isFound(AoB_Addr_05a) and isFound(AoB_Addr_05b) and isFound(AoB_Addr_05c) and isFound(AoB_Addr_05d):
    print("\n[#05. Max Resources]")
    print("040E0000", Addr2Hex(AoB_Addr_05a), "2A1503E8")
    print("040E0000", Addr2Hex(AoB_Addr_05b), "2A1503E8")
    print("040E0000", Addr2Hex(AoB_Addr_05c), "2A1503E8")
    print("040E0000", Addr2Hex(AoB_Addr_05d), "D503201F")
if isFound(AoB_Addr_06):
    print("\n[#06. Invincible]")
    print("040E0000", Addr2Hex(AoB_Addr_06), "D65F03C0")
print("\n[Created by Eiffel2018, enjoy!]\n")

################################# END #######################################