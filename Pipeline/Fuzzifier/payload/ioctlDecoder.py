#! /usr/bin/env python3
import sys
from enum import Enum

class Device(Enum):
    BEEP = 1
    CD_ROM = 2
    CD_ROM_FILE_SYSTEM = 3
    CONTROLLER = 4
    DATALINK = 5
    DFS = 6
    DISK = 7
    DISK_FILE_SYSTEM = 8
    FILE_SYSTEM = 9
    INPORT_PORT = 10
    KEYBOARD = 11
    MAILSLOT = 12
    MIDI_IN = 13
    MIDI_OUT = 14
    MOUSE = 15
    MULTI_UNC_PROVIDER = 16
    NAMED_PIPE = 17
    NETWORK = 18
    NETWORK_BROWSER = 19
    NETWORK_FILE_SYSTEM = 20
    NULL = 21
    PARALLEL_PORT = 22
    PHYSICAL_NETCARD = 23
    PRINTER = 24
    SCANNER = 25
    SERIAL_MOUSE_PORT = 26
    SERIAL_PORT = 27
    SCREEN = 28
    SOUND = 29
    STREAMS = 30
    TAPE = 31
    TAPE_FILE_SYSTEM = 32
    TRANSPORT = 33
    UNKNOWN = 34
    VIDEO = 35
    VIRTUAL_DISK = 36
    WAVE_IN = 37
    WAVE_OUT = 38
    _8042_PORT = 39
    NETWORK_REDIRECTOR = 40
    BATTERY = 41
    BUS_EXTENDER = 42
    MODEM = 43
    VDM = 44
    MASS_STORAGE = 45
    SMB = 46
    KS = 47
    CHANGER = 48
    SMARTCARD = 49
    ACPI = 50
    DVD = 51
    FULLSCREEN_VIDEO = 52
    DFS_FILE_SYSTEM = 53
    DFS_VOLUME = 54

class Access(Enum):
    FILE_ANY_ACCESS = 0
    FILE_READ_ACCESS = 1
    FILE_WRITE_ACCESS = 2
    READ_WRITE_ACCESS = 3

class Method(Enum):
    METHOD_BUFFERED = 0
    METHOD_IN_DIRECT = 1
    METHOD_OUT_DIRECT = 2
    METHOD_NEITHER = 3

def decodeIt(ioctl_code):
    if isinstance(ioctl_code, str):
        input_val = int(ioctl_code, 16)
    else:
        input_val = ioctl_code

    if input_val == 0 or input_val > 0xFFFFFFFF:
        return None

    device_val = (input_val >> 16) & 0xFFF
    func_val = (input_val >> 2) & 0xFFF

    device_str = ""
    if 0 < device_val <= 54:
        device_str = f"{Device(device_val).name} (0x{device_val:03X})"
    else:
        device_str = f"0x{device_val:03X}"

    access = (input_val >> 14) & 3
    method = input_val & 3

    return {
        "Device": device_str,
        "Function": f"0x{func_val:03X}",
        "Access": Access(access),
        "Method": Method(method),
        "Common Bit": input_val >> 31
    }

def printDecoded(decoded_ioctl):
    if decoded_ioctl is None:
        print("Invalid IOCTL code")
    else:
        print("Device:", decoded_ioctl["Device"])
        print("Function:", decoded_ioctl["Function"])
        print("Access:", decoded_ioctl["Access"].name)
        print("Method:", decoded_ioctl["Method"].name)
        print("Common Bit:", decoded_ioctl["Common Bit"])

if __name__ == "__main__":
    if len(sys.argv) > 1:
        ioctl_code = sys.argv[1]
        decoded_ioctl = decodeIt(ioctl_code)
        printDecoded(decoded_ioctl)
    else:
        print("This is a IOCTL decoder; please provide a IOCTL code to decode as an argument")
        # Sample IOCTL code
        ioctl_code = "0x830020C3"
