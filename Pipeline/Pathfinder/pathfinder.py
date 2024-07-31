import requests
import os
import json
import ctypes
import time
from functionsTree import *
import csv
import sys
import subprocess 


COORDINATOR_BASE_URL = 'http://COORDINATOR_IP:5000'
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

def download_file(file_id, driver_destination):
    url = f'{COORDINATOR_BASE_URL}/files/{file_id}'
    response = requests.get(url, verify=False)
    if response.status_code != 200:
        print(f"Failed to download the file {file_id}. Status code: {response.status_code}")
        return False
    # first check if file exists, if so error out
    if os.path.exists(driver_destination):
        print(f"File {driver_destination} already exists in temp folder. Exiting.")
        return False
    with open(driver_destination, 'wb') as f:
        f.write(response.content)
    
    return True


def fetch_next_pathfinder_driver(instance):
    doable_paths = [
        f'{COORDINATOR_BASE_URL}/todo-paths/ARM64',
        f'{COORDINATOR_BASE_URL}/todo-paths/AMD64',
    ]
    driver = None
    for url in doable_paths:
        # catch Max retries exceeded with url
        try:
            response = requests.get(url, verify=False)
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch the drivers for path checks.")
            time.sleep(30)
            continue
        
        if response.status_code != 200:
            print(f"Failed to fetch the drivers that require an IDA run. Status code: {response.status_code}")
        if len(response.json()['drivers']) >= 1+instance:
            driver = response.json()['drivers'][instance]
            break
        else:
            continue

    if driver is None:
        return None, None

    driver_location = f'{TEMP_FILE_PATH}ins_{instance}_{driver["filename"]}'
    if not download_file(driver['file'], driver_destination=driver_location):
        error(f"Could not download {driver['file']}")
        return None, None
    
    return driver_location, driver['id']

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
    instance = 0
    if len(sys.argv) >= 2:
        try:
            instance = int(sys.argv[1])
        except ValueError:
            print("Invalid instance number as argument.")
            exit(-1)

    while True:
        driver_location, driver_id = fetch_next_pathfinder_driver(instance)
        if driver_location is not None:
            result = run_ida_script(driver_location, INTANCE_MULTIPLIER_TIMEOUT*instance)

            if result is not None:
                # analyse the result
                for handler in result['handler_addrs']:
                    tree = makeFunctionTree(handler, result['target_paths'] + result['helper_paths'], result['handler_type'])
                    if __debug__:
                        print(tree)
                    result['function_tree'] = str(tree)
                    result['combined_sub_functions'] = len(combinedSubfunctions(tree))
                
                # make the return value change accoring to the found functions, i.e. the higher the value, the more interesting the found functions
                found_path_names = set([p['name'] for p in result['target_paths'] + result['helper_paths']])
                # use the interesting functions lookup table to calculate how "interesting" the total reachable functions
                for name in found_path_names:
                    if name in interesting_functions:
                        result['ret_code'] += interesting_functions[name]

            # clean up all files, even if IDA failed
            for f in os.listdir(TEMP_FILE_PATH):
                if f.startswith(f'ins_{instance}'):
                    os.remove(os.path.join(TEMP_FILE_PATH, f))
            
            if result is None:
                # If IDA timeouted, the only way to get None
                # then do not tell anything to the coordinator, as others will start it with hopefully more timeout
                continue
            
            # send the result to the coordinator
            url = f'{COORDINATOR_BASE_URL}/driver-paths/{driver_id}'
            
            # catch Max retries exceeded with url
            try:
                response = requests.post(url, json=result, verify=False)
            except requests.exceptions.RequestException as e:
                print(f"Failed to send result.")
                continue
            if response.status_code == 200:
                success(f"Sent result to coordinator for {driver_location} ({driver_id})")
            else:
                error(f"Failed to send result to coordinator. Status code: {response.status_code}")
        else:
            time.sleep(30)


if __name__ == "__main__":
    main()