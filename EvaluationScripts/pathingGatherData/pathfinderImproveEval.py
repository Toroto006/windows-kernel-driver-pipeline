import os
import json
import ctypes
import time
from functionsTree import *
import csv
import subprocess 
import time 
import shutil

TEST_ITERATIONS = 30

IDADIR = 'C:\\Program Files\\IDA Pro 8.4'

# The time multiplier for each instance, i.e. the first instance
# will have a timeout of 30 minutes, the second 1h, etc.
INTANCE_MULTIPLIER_TIMEOUT = 60 * 30

TEMP_FILE_PATH = 'C:\\Windows\\Temp\\IDA\\'
RESULT_FILE_PATH = f'{TEMP_FILE_PATH}{{}}_ida_ioctl_res.json'
LOG_PATH = f'{TEMP_FILE_PATH}{{}}_pathfinder.log'

ida_path = os.path.join(IDADIR, 'ida64.exe')
g_ida_ioctl_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'VDR', 'ida_ioctl_propagate.py')

ERR_DECOMPILE_FAILED = -1
ERR_UNKNOWN_WDF_VERSION = -2
ERR_NO_XREFTO_WDF_BIND_INFO = -3

def info(msg):
    print(f"INFO: {msg}")

def success(msg):
    print(f"SUCCESS: {msg}")
    
def error(msg):
    print(f"ERROR: {msg}")

def debug(msg):
    # set through -O to false
    if __debug__:
        print(f"DEBUG: {msg}")

evaluation_targets = [
    {'filename': 'd5e76d125d624f8025d534f49e3c4162.bin', 'id': 331, 'file': 357, 'size': 14376, 'type': 'WDM'},
    {'filename': 'Monitor.sys', 'id': 94, 'file': 101, 'size': 32520, 'type': 'WDM'},
    {'filename': 'aswArPot.sys', 'id': 3820, 'file': 12592, 'size': 229848, 'type': 'WDM'},
    {'filename': 'a216803d691d92acc44ac77d981aa767.bin', 'id': 1652, 'file': 1794, 'size': 13120, 'type': 'WDM'},
    {'filename': 'ahcache.sys', 'id': 2740, 'file': 3078, 'size': 292352, 'type': 'WDM'},
    {'filename': 'RamCaptureDriver64.sys', 'id': 2046, 'file': 2293, 'size': 34296, 'type': 'WDM'},
    {'filename': 'PixUsb.sys', 'id': 25993, 'file': 526239, 'size': 32832, 'type': 'WDM'},
    {'filename': '97580157f65612f765f39af594b86697.bin', 'id': 332, 'file': 359, 'size': 29688, 'type': 'WDM'},
    {'filename': '3ecd3ca61ffc54b0d93f8b19161b83da.bin', 'id': 676, 'file': 735, 'size': 14648, 'type': 'WDM'},
    {'filename': 'ZuluHm64.sys', 'id': 30105, 'file': 578676, 'size': 705664, 'type': 'WDM'},
    {'filename': 'a664904f69756834049e9e272abb6fea.bin', 'id': 284, 'file': 308, 'size': 27720, 'type': 'WDM'},
    {'filename': 'snpnio.sys', 'id': 4123, 'file': 12896, 'size': 100216, 'type': 'WDM'},
    {'filename': 'TSSysKit64.sys', 'id': 3964, 'file': 12736, 'size': 112784, 'type': 'WDM'},
    {'filename': 'fe937e1ed4c8f1d4eac12b065093ae63.bin', 'id': 1285, 'file': 1401, 'size': 7680, 'type': 'WDM'},
    {'filename': '3a7c69293fcd5688cc398691093ec06a.bin', 'id': 1405, 'file': 1527, 'size': 14376, 'type': 'WDM'},
    {'filename': 'atrk.sys', 'id': 3806, 'file': 12578, 'size': 70968, 'type': 'WDM'},
    {'filename': 'ab4656d1ec4d4cc83c76f639a5340e84.bin', 'id': 1537, 'file': 1672, 'size': 6144, 'type': 'WDM'},
    {'filename': 'a2be99e4904264baa5649c4d4cd13a17.bin', 'id': 635, 'file': 691, 'size': 29952, 'type': 'WDM'},
    {'filename': 'RDWM1231.SYS', 'id': 19868, 'file': 452938, 'size': 397312, 'type': 'WDM'},
    {'filename': '79f7e6f98a5d3ab6601622be4471027f.bin', 'id': 1062, 'file': 1160, 'size': 16240, 'type': 'WDM'},
    {'filename': 'RDWM1201.SYS', 'id': 19892, 'file': 454201, 'size': 393240, 'type': 'WDM'},
    {'filename': 'c04a5cdcb446dc708d9302be4e91e46d.bin', 'id': 1634, 'file': 1775, 'size': 16880, 'type': 'WDM'},
    {'filename': '697bbd86ee1d386ae1e99759b1e38919.bin', 'id': 1284, 'file': 1400, 'size': 15648, 'type': 'WDM'},
    {'filename': 'nokiaccxx64.sys', 'id': 15453, 'file': 320283, 'size': 38528, 'type': 'WDM'},
    {'filename': '1f3522c5db7b9dcdd7729148f105018e.bin', 'id': 745, 'file': 812, 'size': 31744, 'type': 'WDM'},
    {'filename': 'df5f8e118a97d1b38833fcdf7127ab29.bin', 'id': 1060, 'file': 1158, 'size': 29264, 'type': 'WDM'},
    {'filename': '6fb3d42a4f07d8115d59eb2ea6504de5.bin', 'id': 1371, 'file': 1491, 'size': 14648, 'type': 'WDM'},
    {'filename': 'HwRwDrv.sys', 'id': 82, 'file': 89, 'size': 14592, 'type': 'WDM'},
    {'filename': 'easeusmnt0.sys', 'id': 3700, 'file': 12471, 'size': 119512, 'type': 'WDM'},
    {'filename': 'pigeon.sys', 'id': 4054, 'file': 12827, 'size': 142592, 'type': 'WDM'},
    {'filename': 'gmer64.sys', 'id': 300, 'file': 324, 'size': 56592, 'type': 'WDM'},
    {'filename': '370a4ca29a7cf1d6bc0744afc12b236c.bin', 'id': 785, 'file': 855, 'size': 43920, 'type': 'WDM'},
    {'filename': 'RDWM1181.SYS', 'id': 19909, 'file': 455112, 'size': 391680, 'type': 'WDM'},
    {'filename': 'SRVKP.SYS', 'id': 35160, 'file': 656301, 'size': 24704, 'type': 'WDM'},
    {'filename': '8065a7659562005127673ac52898675f.bin', 'id': 1120, 'file': 1222, 'size': 14392, 'type': 'WDM'},
    {'filename': 'RDWM1197.SYS', 'id': 19902, 'file': 454777, 'size': 395784, 'type': 'WDM'},
    {'filename': 'SoftPerfectRAMDisk.sys', 'id': 4256, 'file': 13029, 'size': 251512, 'type': 'WDM'},
    {'filename': 'd104621c93213942b7b43d65b5d8d33e.bin', 'id': 368, 'file': 397, 'size': 24968, 'type': 'WDF'},
    {'filename': 'iomemory_vsl.sys', 'id': 6306, 'file': 99082, 'size': 907928, 'type': 'WDF'},
    {'filename': 'amdsfhkmdf.sys', 'id': 10850, 'file': 219480, 'size': 156392, 'type': 'WDF'},
]

def fetch_next_pathfinder_driver(instance):
    for driver in evaluation_targets:        
        for i in range(TEST_ITERATIONS):
            print(f"Running iteration {i+1}/{TEST_ITERATIONS} for {driver['filename']}")

            # instead of donwloading, just copy the driver to the correct location
            driver_location = f'{TEMP_FILE_PATH}ins_{instance}_{driver["filename"]}'
            src = f'./evalTargets/{driver["filename"]}'
            try:
                shutil.copyfile(src, driver_location)
            except Exception as e:
                print(e)
                exit(-1)

            yield driver_location, driver['id']
    
    print("No more drivers to fuzz.")
    exit(0)

def run_ida_script(target, timeout=0):
    # Make the command line for IDA
    # PYTHONOPTIMIZE=x to make python replace all debug prints with nop,
    # or run the pathfinder with -O
    log_path = LOG_PATH.format(os.path.basename(target))
    cmd = [ida_path, '-A', '-S{}'.format(g_ida_ioctl_path), '-L{}'.format(log_path), target]
    debug(' '.join(cmd))
    
    res_file = RESULT_FILE_PATH.format(os.path.basename(target))
    if os.path.isfile(res_file):
        os.remove(res_file)

    try:
        # Run the script
        print("Running IDA ...", end="")
        #proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #stdout, stderr = proc.communicate()
        #output = check_output(cmd, stderr=STDOUT, timeout=timeout)
        if timeout == 0:
            proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        print(" done")
    except subprocess.TimeoutExpired as e:
        error(f"IDA failed to run for {target} with Timeout: {e}")
        return None
    except Exception as e:
        error(f"IDA failed with Exception: {e}")

    ret_code = ctypes.c_int32(proc.returncode).value
    if __debug__:
        if ret_code == 200:
            info(f"{target} IOCTL found with some paths")
        elif ret_code == 100:
            info(f"{target} IOCTL found, but no paths")
        elif ret_code == 0:
            info(f"{target} no IOCTL handler found")
        elif ret_code == ERR_DECOMPILE_FAILED:
            error("DECOMPILATION FAILED")
        elif ret_code == ERR_UNKNOWN_WDF_VERSION:
            error("UNKNOWN WDF VERSION")
        elif ret_code == ERR_NO_XREFTO_WDF_BIND_INFO:
            error("NO XREFTO WDF BIND INFO")
        else:
            error(f"UNEXPECTED STATUS from IDA: {ret_code}")
    
    result = {}
    if ret_code > 0:
        if os.path.isfile(res_file):
            with open(res_file, "r") as f:
                result = json.loads(f.read())
        else:
            error(f"No result file found, but IDA returned {ret_code}?")
    
    # If something went wrong with IDA
    if "ret_code" not in result:
        result = {
            "ret_code": ret_code,
            "handler_type": 'unknown',
            "handler_addrs": [],
            "target_paths": [],
            "helper_paths": [],
            "wdf_functions": [],
            "comparisions": [],
        }
    
    if os.path.isfile(log_path):
        with open(log_path, 'r', encoding="utf8") as f:
            ida_log = f.read()
            result["ida_log"] = ida_log
            if __debug__:
                print("IDA LOG:")
                print(ida_log)
        os.remove(log_path)
    else:
        if __debug__:
            error("No ida log file??")
        result["ida_log"] = "FILE NOT FOUND"

    return result
 
def main():
    interesting_functions = {}
    with open('./interestingFunctions.csv', 'r') as f:
        reader = csv.reader(f)
        next(reader) # skip the header
        for row in reader:
            interesting_functions[row[0]] = int(row[1])
    print(f"Done loading {len(interesting_functions)} interesting functions.")

    # get the first argument, which says which instance this pathfinder is
    # this is used to create the result file to avoid conflicts
    instance = 1 # for the long ones we hopefully can do less later
    downloader = fetch_next_pathfinder_driver(instance)

    timing_data = {}

    while True:
        with open('timing_data.json', 'w') as f:
            json.dump(timing_data, f)

        driver_location, driver_id = next(downloader)
        if driver_location is not None:
            start_time = time.time()
            result = run_ida_script(driver_location, INTANCE_MULTIPLIER_TIMEOUT*instance)
            end_time = time.time()
            if result is None:
                print("IDA failed, skipping to next driver")
            else:
                took = end_time - start_time
                print(f"IDA took {took} seconds for {driver_id}")
                if driver_id not in timing_data:
                    timing_data[driver_id] = [took]
                else:
                    timing_data[driver_id].append(took)

            # clean up all files, even if IDA failed
            for f in os.listdir(TEMP_FILE_PATH):
                if f.startswith(f'ins_{instance}'):
                    os.remove(os.path.join(TEMP_FILE_PATH, f))
            
        else:
            time.sleep(30)


if __name__ == "__main__":
    main()