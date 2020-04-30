'''

This script used to convert ioctl codes for human-readable values while reverse engineering Windows Drivers.
You can also use this as a regular snippet in Ida Python.

Author: @Sv4r0g

'''


device = [None] * 94

device[1]  = "BEEP"
device[2]  = "CD_ROM"
device[3]  = "CD_ROM_FILE_SYSTEM"
device[4]  = "CONTROLLER"
device[5]  = "DATALINK"
device[6]  = "DFS"
device[7]  = "DISK"
device[8]  = "DISK_FILE_SYSTEM"
device[9]  = "FILE_SYSTEM"
device[10] = "INPORT_PORT"
device[11] = "KEYBOARD"
device[12] = "MAILSLOT"
device[13] = "MIDI_IN"
device[14] = "MIDI_OUT"
device[15] = "MOUSE"
device[16] = "MULTI_UNC_PROVIDER"
device[17] = "NAMED_PIPE"
device[18] = "NETWORK"
device[19] = "NETWORK_BROWSER"
device[20] = "NETWORK_FILE_SYSTEM"
device[21] = "NULL"
device[22] = "PARALLEL_PORT"
device[23] = "PHYSICAL_NETCARD"
device[24] = "PRINTER"
device[25] = "SCANNER"
device[26] = "SERIAL_MOUSE_PORT"
device[27] = "SERIAL_PORT"
device[28] = "SCREEN"
device[29] = "SOUND"
device[30] = "STREAMS"
device[31] = "TAPE"
device[32] = "TAPE_FILE_SYSTEM"
device[33] = "TRANSPORT"
device[34] = "UNKNOWN"
device[35] = "VIDEO"
device[36] = "VIRTUAL_DISK"
device[37] = "WAVE_IN"
device[38] = "WAVE_OUT"
device[39] = "8042_PORT"
device[40] = "NETWORK_REDIRECTOR"
device[41] = "BATTERY"
device[42] = "BUS_EXTENDER"
device[43] = "MODEM"
device[44] = "VDM"
device[45] = "MASS_STORAGE"
device[46] = "SMB"
device[47] = "KS"
device[48] = "CHANGER"
device[49] = "SMARTCARD"
device[50] = "ACPI"
device[51] = "DVD"
device[52] = "FULLSCREEN_VIDEO"
device[53] = "DFS_FILE_SYSTEM"
device[54] = "DFS_VOLUME"
device[55] = "SERENUM"
device[56] = "TERMSRV"
device[57] = "KSEC"
device[58] = "FIPS"
device[59] = "INFINIBAND"
device[62] = "VMBUS"
device[63] = "CRYPT_PROVIDER"
device[64] = "WDP"
device[65] = "BLUETOOTH"
device[66] = "MT_COMPOSITE"
device[67] = "MT_TRANSPORT"
device[68] = "BIOMETRIC"
device[69] = "PMI"
device[70] = "EHSTOR"
device[71] = "DEVAPI"
device[72] = "GPIO"
device[73] = "USBEX"
device[80] = "CONSOLE"
device[81] = "NFP"
device[82] = "SYSENV"
device[83] = "VIRTUAL_BLOCK"
device[84] = "POINT_OF_SERVICE"
device[85] = "STORAGE_REPLICATION"
device[86] = "TRUST_ENV"
device[87] = "UCM"
device[88] = "UCMTCPCI"
device[89] = "PERSISTENT_MEMORY"
device[90] = "NVDIMM"
device[91] = "HOLOGRAPHIC"
device[92] = "SDFXHCI"
device[93] = "UCMUCSI"  

access = [None] * 4

access[0] = "FILE_ANY_ACCESS"
access[1] = "FILE_READ_ACCESS"
access[2] = "FILE_WRITE_ACCESS"
access[3] = "Read and Write"

method = [None] * 4

method[0] = "METHOD_BUFFERED"
method[1] = "METHOD_IN_DIRECT"
method[2] = "METHOD_OUT_DIRECT"
method[3] = "METHOD_NEITHER"

# Function codes 0-2047 are reserved for Microsoft Corporation, and
# 2048-4095 are reserved for customers. We use MAX_FUNC_CODE macro to handle
# all possible function codes.

MAX_FUNC_CODE = 0xfff

ioctlcode = int('0x2222ce', 16)
deviceVal = (ioctlcode >> 16) & 0xfff
funcVal = (ioctlcode >> 2) & 0xfff
accessVal = (ioctlcode >> 14) & 3
methodVal = ioctlcode & 3

def PrintData():
    print "%s\n%s\n%s\n%s" % (PrintDeviceVal(),
                              PrintFuncVal() ,
                              PrintAccessVal(), 
                              PrintMethodVal())
    return 0

def IoctlDec():
    try:
        if (funcVal <= MAX_FUNC_CODE) & (deviceVal != 0):
            return PrintData()
    except IndexError:
            return "Error: device type out of range" 
                
def PrintDeviceVal():
    return "Device type: %s %s" % (device[deviceVal], hex(deviceVal))

def PrintFuncVal():
    return "Function value is: %s" % hex(funcVal) 

def PrintAccessVal():
    if (accessVal <= 4):
        return "Access: %s %s" % (access[accessVal], hex(accessVal))
    else:
        return 0

def PrintMethodVal():
    if (methodVal <= 4):
        return "Method: %s %s" % (method[methodVal], hex(methodVal))
    else:
        return 0
        
print IoctlDec()
