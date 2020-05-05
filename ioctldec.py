'''

This script used to convert ioctl codes for human-readable values while reverse engineering
Windows Drivers. You can also use this as a regular snippet in Ida Python.

Author: @Sv4r0g

'''

from sys import argv, exit #pylint: disable=redefined-builtin

DEVICE = [None] * 94

DEVICE[1] = "BEEP"
DEVICE[2] = "CD_ROM"
DEVICE[3] = "CD_ROM_FILE_SYSTEM"
DEVICE[4] = "CONTROLLER"
DEVICE[5] = "DATALINK"
DEVICE[6] = "DFS"
DEVICE[7] = "DISK"
DEVICE[8] = "DISK_FILE_SYSTEM"
DEVICE[9] = "FILE_SYSTEM"
DEVICE[10] = "INPORT_PORT"
DEVICE[11] = "KEYBOARD"
DEVICE[12] = "MAILSLOT"
DEVICE[13] = "MIDI_IN"
DEVICE[14] = "MIDI_OUT"
DEVICE[15] = "MOUSE"
DEVICE[16] = "MULTI_UNC_PROVIDER"
DEVICE[17] = "NAMED_PIPE"
DEVICE[18] = "NETWORK"
DEVICE[19] = "NETWORK_BROWSER"
DEVICE[20] = "NETWORK_FILE_SYSTEM"
DEVICE[21] = "NULL"
DEVICE[22] = "PARALLEL_PORT"
DEVICE[23] = "PHYSICAL_NETCARD"
DEVICE[24] = "PRINTER"
DEVICE[25] = "SCANNER"
DEVICE[26] = "SERIAL_MOUSE_PORT"
DEVICE[27] = "SERIAL_PORT"
DEVICE[28] = "SCREEN"
DEVICE[29] = "SOUND"
DEVICE[30] = "STREAMS"
DEVICE[31] = "TAPE"
DEVICE[32] = "TAPE_FILE_SYSTEM"
DEVICE[33] = "TRANSPORT"
DEVICE[34] = "UNKNOWN"
DEVICE[35] = "VIDEO"
DEVICE[36] = "VIRTUAL_DISK"
DEVICE[37] = "WAVE_IN"
DEVICE[38] = "WAVE_OUT"
DEVICE[39] = "8042_PORT"
DEVICE[40] = "NETWORK_REDIRECTOR"
DEVICE[41] = "BATTERY"
DEVICE[42] = "BUS_EXTENDER"
DEVICE[43] = "MODEM"
DEVICE[44] = "VDM"
DEVICE[45] = "MASS_STORAGE"
DEVICE[46] = "SMB"
DEVICE[47] = "KS"
DEVICE[48] = "CHANGER"
DEVICE[49] = "SMARTCARD"
DEVICE[50] = "ACPI"
DEVICE[51] = "DVD"
DEVICE[52] = "FULLSCREEN_VIDEO"
DEVICE[53] = "DFS_FILE_SYSTEM"
DEVICE[54] = "DFS_VOLUME"
DEVICE[55] = "SERENUM"
DEVICE[56] = "TERMSRV"
DEVICE[57] = "KSEC"
DEVICE[58] = "FIPS"
DEVICE[59] = "INFINIBAND"
DEVICE[62] = "VMBUS"
DEVICE[63] = "CRYPT_PROVIDER"
DEVICE[64] = "WDP"
DEVICE[65] = "BLUETOOTH"
DEVICE[66] = "MT_COMPOSITE"
DEVICE[67] = "MT_TRANSPORT"
DEVICE[68] = "BIOMETRIC"
DEVICE[69] = "PMI"
DEVICE[70] = "EHSTOR"
DEVICE[71] = "DEVAPI"
DEVICE[72] = "GPIO"
DEVICE[73] = "USBEX"
DEVICE[80] = "CONSOLE"
DEVICE[81] = "NFP"
DEVICE[82] = "SYSENV"
DEVICE[83] = "VIRTUAL_BLOCK"
DEVICE[84] = "POINT_OF_SERVICE"
DEVICE[85] = "STORAGE_REPLICATION"
DEVICE[86] = "TRUST_ENV"
DEVICE[87] = "UCM"
DEVICE[88] = "UCMTCPCI"
DEVICE[89] = "PERSISTENT_MEMORY"
DEVICE[90] = "NVDIMM"
DEVICE[91] = "HOLOGRAPHIC"
DEVICE[92] = "SDFXHCI"
DEVICE[93] = "UCMUCSI"

ACCESS = [None] * 4

ACCESS[0] = "FILE_ANY_ACCESS"
ACCESS[1] = "FILE_READ_ACCESS"
ACCESS[2] = "FILE_WRITE_ACCESS"
ACCESS[3] = "Read and Write"

METHOD = [None] * 4

METHOD[0] = "METHOD_BUFFERED"
METHOD[1] = "METHOD_IN_DIRECT"
METHOD[2] = "METHOD_OUT_DIRECT"
METHOD[3] = "METHOD_NEITHER"

# Function codes 0-2047 are reserved for Microsoft Corporation, and
# 2048-4095 are reserved for customers. We use MAX_FUNC_CODE constant to handle
# all possible function codes.

MAX_FUNC_CODE = 0xfff

IOCTL_CODE = int(argv[1], 16)
DEVICE_VAL = (IOCTL_CODE >> 16) & 0xfff
FUNC_VAL = (IOCTL_CODE >> 2) & 0xfff
ACCESS_VAL = (IOCTL_CODE >> 14) & 3
METHOD_VAL = IOCTL_CODE & 3

def main():
    """Check for argv len and print result"""
    if len(argv) != 2:
        exit("Usage: python ioctldec.py 0x2222ce")
    return ioctl_dec()

def print_data():
    """Print data as a format string"""
    print "%s\n%s\n%s\n%s" % (print_device_val(),
                              print_func_val(),
                              print_access_val(),
                              print_method_val())

def ioctl_dec():
    """Check for a valid ioctl code and print data"""
    try:
        if (FUNC_VAL <= MAX_FUNC_CODE) & (DEVICE_VAL != 0):
            return print_data()
    except IndexError:
        exit("Error: device type out of range")

def print_device_val():
    """Return a device type"""
    return "Device type: %s %s" % (DEVICE[DEVICE_VAL], hex(DEVICE_VAL))

def print_func_val():
    """Return a function value"""
    return "Function value: %s" % hex(FUNC_VAL)

def print_access_val():
    """Return an access value"""
    if ACCESS_VAL <= 4:
        return "Access: %s %s" % (ACCESS[ACCESS_VAL], hex(ACCESS_VAL))

def print_method_val():
    """Return method value"""
    if METHOD_VAL <= 4:
        return "Method: %s %s" % (METHOD[METHOD_VAL], hex(METHOD_VAL))

if __name__ == "__main__":
    main()
