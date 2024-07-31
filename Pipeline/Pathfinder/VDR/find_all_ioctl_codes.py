from idc import *
from idautils import *
import idaapi
from ida_hexrays import *
from ida_struct import *
import ida_typeinf, ida_pro, ida_auto, ida_loader, ida_idp, ida_kernwin
import ntpath, os, json
import re

RESULT_FILE = 'C:\\Windows\\Temp\\ida_ioctl_res.json'


def exit_without_change(status):

    print('-' * 50) # Differentiate the log

    # Not create/change idb
    process_config_line("ABANDON_DATABASE=YES")

    # Exit with the status code
    qexit(status)

# Ported from examples/hexrays/decompile_entry_points.py
def init_hexrays():
    
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "hexrays",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    
    if not decompiler:
        error("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
        return False
    
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "hexx64"
        else:
            decompiler += "64"
    
    if ida_loader.load_plugin(decompiler) and init_hexrays_plugin():
        return True
    else:
        error('Couldn\'t load or initialize decompiler: "%s"' % decompiler)
        return False

# heavily based on https://github.com/pwndbg/pwndbg/issues/844
def get_decompile_coord_by_ea(cfunc, addr):
    assert idaapi.IDA_SDK_VERSION >= 720, "You need an idea version >= 7.2"
    item = cfunc.body.find_closest_addr(addr)
    y_holder = idaapi.int_pointer()
    if not cfunc.find_item_coords(item, None, y_holder):
        return None
    return y_holder.value()

# used to return some context around the target function
def decompile_context(addr, context_lines=10):
    cfunc = decompile(addr)
    if cfunc is None:
        return None
    y = get_decompile_coord_by_ea(cfunc, addr)
    if y is None:
        return None
    lines = cfunc.get_pseudocode()
    retlines = []
    for lnnum in range(max(0, y - context_lines), min(len(lines), y + context_lines+1)):
        retlines.append(idaapi.tag_remove(lines[lnnum].line))
        if lnnum == y:
            retlines[-1] = '>' + retlines[-1][1:]
    return '\n'.join(retlines)

## getting the decompiled view, should have IoControlCode comparisions
def decompile_to_lines(addr):
    cfunc = decompile(addr)
    if cfunc is None:
        return None
    lines = cfunc.get_pseudocode()
    retlines = []
    for lnnum in range(0, len(lines)):
        retlines.append(idaapi.tag_remove(lines[lnnum].line))
    return retlines

def convert_to_int(str):
    """Converts the result of the 0[xX][0-9a-fA-F]+|-?\d* regex to an int"""
    # could be -1673502396, 0x222024 or 167502396
    # & & 0xFF..FF to make sure it's a 32 bit int
    if str.startswith("0x") or str.startswith("0X"):
        return int(str, 16) & 0xFFFF_FFFF
    else:
        return int(str) & 0xFFFF_FFFF

def check_direct_comparision(lines):
    found_comparisions = set()
    reg = r"IoControlCode[_a-zA-Z0-9]*\s([=><!]{2}|[<>]{1})\s(0[xX][0-9a-fA-F]+|-?\d*)"
    # TODO for some reason sometimes the name prop fails...
    for line in lines:
        match = re.search(reg, line)
        if match:
            if match.group(1) is not None and match.group(2) is not None:
                val = convert_to_int(match.group(2))
                if val < 16: # cases like ( _______IoControlCode == 4 )
                    continue
                found_comparisions.add((match.group(1), val, line.strip()))
    return found_comparisions

def check_switch_comparision(lines):
    found_comparisions = set()
    reg = r"case (0[xX][0-9a-fA-F]+|\d*)u?:"
    if any("switch" in line for line in lines):
        for line in lines:
            match = re.search(reg, line)
            if match:
                if match.group(1) is not None:
                    val = convert_to_int(match.group(1))
                    if val < 16: # case 1, case 4, case 2, ... are not IOCTL codes
                        continue
                    # all cases are an == operation
                    found_comparisions.add(("==", val, line.strip()))
        return found_comparisions
    else:
        return found_comparisions

def check_incremental_comparision(lines):
    """Whenever there is a calculation downwards which checks IoControlCode"""
    # IObitUnlocker.sys (509) is one such example
    #  __IoControlCode = _IoControlCode - 2236420;
    # if ( IoControlCode )
    # if ( IoControlCode != 0x4 )
    # ______IoControlCode = _____IoControlCode - 4;
    # if ( !______IoControlCode )
    found_comparisions = set()
    reg = r"IoControlCode\s*=.*IoControlCode\s*([-+]{1})\s*(0[xX][0-9a-fA-F]+|-?\d*)"
    last_set = None
    for line in lines:
        match = re.search(reg, line)
        if match:
            value = convert_to_int(match.group(2))
            operator = match.group(1)
            if value > 0xFF: # threshold of which never seen an incremental comparision
                last_set = value
            elif operator == '-' and last_set is not None: # its a modification of last
                last_set -= value
            elif operator == '+' and last_set is not None:
                last_set += value
            else:
                print(f'[I] Found IoControl Incremental with following operator {operator}')
            found_comparisions.add(('==', last_set, line.strip()))
    return found_comparisions

def search_all_comparisions(locations_to_check):
    """This will search all function decompilations of the given locations for IoControlCode comparisions"""
    comparisions = set()
    for loc in set(locations_to_check):
        if __debug__:
            print(f"[D] Finding IOCTL comparisionms in {loc:#x}")
        found = decompile_to_lines(loc)
        if found is None:
            if __debug__:
                print("Unable to decompile this location?")
            continue        
        comparisions = comparisions.union(check_direct_comparision(found))
        comparisions = comparisions.union(check_switch_comparision(found))
        comparisions = comparisions.union(check_incremental_comparision(found))
    return comparisions

def main():
    if ida_kernwin.cvar.batch: # batch mode execution
        # Wait until the initial auto analysis is finished
        ida_auto.auto_wait()

        # We need to load the decompiler manually
        if not init_hexrays():
            if ida_kernwin.cvar.batch:
                exit_without_change(-1)

    # To run after the ioctl propagate
    io_stack_locations = []
    ioctl_location = 0x000110D8

    # check the IOCTL handler if one is found & check the io stack locations
    # this will look at the full decompilation of the functions
    # where the decompiler shows the IoControlCode varname after the ioctl propg.
    locations_to_check = io_stack_locations + [ioctl_location]
    comparisions = search_all_comparisions(locations_to_check)

    print("Found comparisions:")
    for op, value, line in comparisions:
        print(f"{op} {value:#x} in {line}")
    

if __name__ == '__main__':
    main()
