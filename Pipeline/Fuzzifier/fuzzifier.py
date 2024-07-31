### Coordinator one, has DosDevice String, has IoCreateSymbolicLink, is otherwise interesting: has a phy string, has an mmapIo or any paths, lastly is recognized by IDA as a driver
import os
import time
import json
import signal
import requests
from subprocess import STDOUT, check_output, CalledProcessError, Popen, PIPE
from payload.fuzzingDecoder import decode_files_in_folder
import base64

COORDINATOR_BASE_URL = 'http://COORDINATOR_IP:5000'
FUZZING_HARNESS_VERSION = "0.1"

### Fuzzifier

def do_environment_check():
    # First check if all the necessary environment variables are set
    required_env_vars = ["KAFL_ROOT", "QEMU_ROOT", "LIBXDC_ROOT",
                        "CAPSTONE_ROOT", "RADAMSA_ROOT",
                        "EXAMPLES_ROOT", "KAFL_WORKSPACE", "KAFL_WORKDIR"]
    for env_var in required_env_vars:
        if env_var not in os.environ:
            print(f"Environment variable {env_var} is not set.")
            return False
    
    # Check we are in a virtual python environment under the KAFL_ROOT
    if not os.environ["VIRTUAL_ENV"] or not os.environ["VIRTUAL_ENV"].startswith(os.environ["KAFL_ROOT"]):
        print("Not in a virtual environment under KAFL_ROOT.")
        return False
    
    return os.getcwd().endswith('windows_x64')

def download_file(file_id, driver_destination):
    url = f'{COORDINATOR_BASE_URL}/files/{file_id}'
    response = requests.get(url, verify=False)
    if response.status_code != 200:
        print(f"Failed to download the file {file_id}. Status code: {response.status_code}")
        return False
    
    with open(driver_destination, 'wb') as f:
        f.write(response.content)
    
    return True

def download_next_fuzz_driver():
    # get next driver
    url = f'{COORDINATOR_BASE_URL}/todo-fuzzing/AMD64'
    response = requests.get(url)
    if response.status_code == 404 and 'No driver to fuzz' in response.text:
        raise Exception("no drivers to fuzz, waiting.")
    if response.status_code != 200:
        raise Exception(f"Failed to get next driver to fuzz: {response.status_code} - {response.text}")
    
    json_resp = response.json()
    driver = json_resp['driver']
    config = json_resp['configuration']

    fuzzing_id = json_resp['id']
    driver_id = driver['id']

    # check architecture against the current running architecture
    this_arch = check_output("uname -m", shell=True).decode('utf-8').strip()
    if this_arch == 'x86_64' and 'AMD64' not in driver['arch']:
        raise Exception(f"Driver {driver_id} is not for this architecture: {driver['arch']} vs {this_arch}")
    if this_arch == 'arm64' and 'ARM64' not in driver['arch']:
        raise Exception(f"Driver {driver_id} is not for this architecture: {driver['arch']} vs {this_arch}")

    # download the driver file to ./bin/driver/test_driver.sys
    driver_file = driver['file']
    if not download_file(driver_file, './bin/driver/test_driver.sys'):
        raise Exception(f"Failed to download {driver_file} for {driver_id}!")

    return fuzzing_id, driver, config

def get_fuzzing_stats():
    from kafl_fuzzer.common.config import settings
    from kafl_fuzzer.gui import GuiData
    settings.workdir_config = f"{settings.workdir}/config.yaml"
    gd = GuiData(settings.workdir)
    gd.aggregate()

    fuzzing_stats = {
        "runtime": gd.runtime(), # how long the fuzzer has been running
        "total_execs": gd.total_execs(), # number executions
        "execs_p_sec": gd.execs_p_sec_avg(), # how many executions per second

        "time_since_last_crash": gd.time_since("crash"), # how long since the last crash
        "time_since_last_kasan": gd.time_since("kasan"),
        "time_since_last_timeout": gd.time_since("timeout"),
        "time_since_last_regular": gd.time_since("regular"), # time since last regular new path
        
        "reload_p_sec": gd.reload_p_sec(), # how many reloads per second
        #'findings': {'regular': 1, 'crash': 0, 'kasan': 0, 'timeout': 0
        "total_regular": gd.stats['findings']['regular'],
        "total_crash": gd.stats['findings']['crash'],
        "total_kasan": gd.stats['findings']['kasan'],
        "total_timeout": gd.stats['findings']['timeout'],
        "total_reloads": gd.total_reloads(),
        "total_funky": gd.total_funky(), # how many funky itereations were done

        "paths_total": gd.paths_total(), # how many paths were explored
        "bb_covered": gd.bb_covered(), # how many basic blocks were covered
        "p_coll": gd.p_coll(), # probability of collision
        "bitmap_used": gd.bitmap_used(), # percent bitmap used
        "total_states": gd.normal_total(), # how many states/nodes there were
    }

    return fuzzing_stats

def setup_fuzzing(dos_string):
    setup_log = ""
    # sanity check the dos_string, i.e. not empty, does not contain \ at the end and no "
    if dos_string is None or len(dos_string) == 0 or \
        dos_string[-1] == '\\' or '"' in dos_string or "'" in dos_string:
        raise Exception(f"Invalid DOS device string: {dos_string}")

    vuln_test_template = ""
    with open("Fuzzifier/vuln_test.c.template", "r") as f:
        vuln_test_template = f.read()
    vuln_test_template = vuln_test_template.replace("DOS_DEVICE_STRING", dos_string)
    with open("./src/driver/vuln_test.c", "w") as f:
        f.write(vuln_test_template)

    # Compile test agent first
    build_agent_cmd = "x86_64-w64-mingw32-gcc ./src/driver/vuln_test.c -Wall -Werror -I ./ -o ./bin/driver/vuln_test.exe -Wall -lntdll -lpsapi"
    build_agent_output = ""
    try:
        build_agent_output = check_output(build_agent_cmd.split(' '), stderr=STDOUT, timeout=30).decode('utf-8')
    except CalledProcessError as e:
        raise Exception(f"Failed to compile agent: {e.output}")
    if len(build_agent_output) > 0:
        raise Exception(f"Failed to compile agent: {build_agent_output}")
    setup_log += build_agent_output
    
    # Then setup the Fuzzing VM
    # destroy it first to clean previous issues TODO figure out why this is necessary, should not be?
    vagrant_cmd = "vagrant destroy -f"
    try:
        vagrant_destroy_output = check_output(vagrant_cmd.split(' '), stderr=STDOUT, timeout=30).decode('utf-8')
        setup_log += vagrant_destroy_output
    except CalledProcessError as e:
        raise Exception(f"Failed to destroy existing VM: {e.output.decode('utf-8')}")
    
    time.sleep(10)

    vagrant_cmd = "vagrant up --no-provision"
    try:
        vagrant_up_output = check_output(vagrant_cmd.split(' '), stderr=STDOUT, timeout=120).decode('utf-8')
        setup_log += vagrant_up_output
    except CalledProcessError as e:
        raise Exception(f"Failed to start VM: {e.output.decode('utf-8')}")

    # Finally provision the VM with the current driver under test
    vagrant_cmd = "vagrant provision"
    try:
        vagrant_provision_output = check_output(vagrant_cmd.split(' '), stderr=STDOUT, timeout=260).decode('utf-8')
        setup_log += vagrant_provision_output
    except CalledProcessError as e:
        raise Exception(f"Failed to provision VM: {e.output.decode('utf-8')}")

    vagrant_cmd = "vagrant halt"
    try:
        vagrant_halt_output = check_output(vagrant_cmd.split(' '), stderr=STDOUT, timeout=120).decode('utf-8')
        setup_log += vagrant_halt_output
    except CalledProcessError as e:
        raise Exception(f"Failed to stop VM: {e.output.decode('utf-8')}")
    
    return setup_log

def send_fuzzing_log(log, driver_id, log_type):
    # Send the log to the backend
    if len(log) > 20000:
        log_name = f"{driver_id}_{log_type}_{time.time()}.log"
        with open(f"./Fuzzifier/logs/{log_name}", 'w') as f:
            f.write(log)
        log = f"Log too big, saved to file: {log_name}"
    
    url = f'{COORDINATOR_BASE_URL}/fuzzing-notes/{driver_id}/{log_type}'
    try:
        response = requests.post(url, data=log)
        if response.status_code != 200:
            print(f"Failed to send log to backend: {response.status_code}:\n{response.text}")
        else:
            print(f"Sending log to backend: {driver_id} - {log_type}")
    except Exception as e:
        print(f'Failed to send log: {e}')
        exit(-1)

stop_now = False
def signal_handler(sig, frame):
    print('You pressed Ctrl+C, will stop after next wakeup.')
    global stop_now
    if stop_now:
        print("You forced a stop!")
        exit(-1)
    stop_now = True
signal.signal(signal.SIGINT, signal_handler)

def run_fuzzing_loop(run_config):
    fuzzing_log = ""
    global stop_now
    stop_iteration = False
    start_time = time.time()
    # loop of single fuzzing 
    # TODO make more dynamic with ENV vars
    fuzz_cmd = f'source {os.environ["KAFL_ROOT"]}/env.sh; cd /home/user/kAFL/windows_x64; exec kafl fuzz -p 1 --purge --seed-dir ./seeds'
    print(f"Running {fuzz_cmd}")
    # bufsize = -1 means to get buffered out
    last_total_execs = 0
    with Popen(fuzz_cmd, stdout=PIPE, stderr=PIPE, bufsize=-1, universal_newlines=True, shell=True, preexec_fn=os.setsid) as p:
        print("Starting fuzzing loop")
        while time.time() - start_time < run_config['max_runtime'] and not stop_now and not stop_iteration:
            fuzzing_stats = get_fuzzing_stats()
            if time.time() - start_time > 60 * 5:
                # the first 5 minutes are not interesting really, as in those we can just run
                if fuzzing_stats['total_execs'] == last_total_execs:
                    # no new executions after that for every 10 seconds --> a problem
                    stop_iteration = True
                if run_config['max_last_crash'] is not None and fuzzing_stats['time_since_last_crash'] is not None and fuzzing_stats['time_since_last_crash'] > run_config['max_last_crash']:
                    stop_iteration = True
                if run_config['max_last_any'] is not None:
                    for ind in ['time_since_last_crash', 'time_since_last_kasan', 'time_since_last_timeout', 'time_since_last_regular']:
                        if fuzzing_stats[ind] is not None and fuzzing_stats[ind] > run_config['max_last_any']:
                            stop_iteration = True
            
            # clear screen first
            os.system('clear')
            print(f"Fuzzing stats for driver {driver_name} ({driver_id}), remaining time {int(run_config['max_runtime'] - (time.time()-start_time))}sec:")
            print(json.dumps(fuzzing_stats, indent=3))
            time.sleep(10)

        # First kill the process
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        # then read out the output
        try:
            out, err = p.communicate(timeout=30)
            fuzzing_log  = "========= Fuzzing starting =========\n"
            fuzzing_log += out
            fuzzing_log += "========= Fuzzing errors =========\n"
            fuzzing_log += err
            fuzzing_log += "========= Fuzzing end =========\n"
        except Exception as e:
            fuzzing_log += str(e)

        fuzzing_log += f"Total runtime: {time.time() - start_time} seconds\n"
        fuzzing_log += f"Retcode {p.returncode}"
        p.wait()
    
    return fuzzing_log

def send_fuzzing_results(fuzzing_id, driver_id):
    # Decode all crashes, payloads and timeouts
    corpus_dir = os.path.join(os.environ['KAFL_WORKDIR'], 'corpus')
    crashes = decode_files_in_folder(os.path.join(corpus_dir, 'crash'), visible=False)
    kasan = decode_files_in_folder(os.path.join(corpus_dir, 'kasan'), visible=False)
    timeout = decode_files_in_folder(os.path.join(corpus_dir, 'timeout'), visible=False)
    # We want to save the regular outputs for resume
    regular = decode_files_in_folder(os.path.join(corpus_dir, 'regular'), visible=False)
    fuzzing_stats = get_fuzzing_stats()

    # Send the results to the backend
    results = {
        "payloads": {
            "crash": crashes,
            "kasan": kasan,
            "timeout": timeout,
            "regular": regular,
        },
        "stats": fuzzing_stats,
        "fuzzing_id": fuzzing_id,
        "version": FUZZING_HARNESS_VERSION,
    }

    url = f"{COORDINATOR_BASE_URL}/driver-fuzzing/{driver_id}"
    response = requests.post(url, json=results)
    if response.status_code != 200:
        print(f"Failed to send results to backend: {response.status_code} - {response.text}")
    else:
        print(f"Sent results to backend: {driver_id}")

def update_fuzzing_state_running(fuzzing_id, state="running"):
    url = f"{COORDINATOR_BASE_URL}/driver-fuzzing/{fuzzing_id}"
    # put method sending the state
    response = requests.put(url, json={"state": state})
    if response.status_code != 200:
        print(f"Failed to update fuzzing state to running: {response.status_code} - {response.text}")
    else:
        print(f"Updated fuzzing state to {state} ({fuzzing_id})")

def save_seeds(seeds):
    """Seeds is a list of base64 encoded seeds."""
    # first clean out all old seeds
    for f in os.listdir('./seeds'):
        os.remove(os.path.join('./seeds', f))
    if len(seeds) == 0:
        return "No seeds provided for this fuzzing item?"
    # then save the decoded ones
    log = ""
    for i, seed in enumerate(seeds):
        seed_file = f"./seeds/seed_{i}.bin"
        with open(seed_file, 'wb') as f:
            f.write(base64.b64decode(seed))
        log += f"Saved seed {i} to {seed_file}\n"
    return log
    

if __name__ == "__main__":
    # Assert running in the correct environment
    if not do_environment_check():
        print("Start Fuzzifier under the kafl environment, in the expected 'windows_x64/Fuzzifier' folder!\nExiting now.")
        exit(1)
    
    while not stop_now:
        time.sleep(60) # slow to make stopping and co possible
        try:
            fuzzing_id, driver, config  = download_next_fuzz_driver()
            driver_id = driver['id']
            driver_name = driver['name']
            if driver_id is None:
                print(f"No new driver to fuzz, waiting!")
                time.sleep(30)
                continue
            print(f"Setting up fuzzing of driver {driver_name} ({driver_id})")
        except Exception as e:
            print(f"FAILED to run fuzzing: {e}")
            time.sleep(30)
            continue
        print(f"Downloaded, setting up now.")

        setup_log = None
        try:
            setup_log = setup_fuzzing(driver['dos_device_str'])
            send_fuzzing_log(setup_log, driver_id, "fuzzing-setup")
            if "Attempting graceful shutdown of VM" not in setup_log:
                print(f"Failed with setup, see log for {driver_id} - setup")
                time.sleep(60)
                continue

            setup_log += save_seeds(config['seeds'])
        except Exception as e:
            send_fuzzing_log(f"Failed to setup fuzzing: {e}", driver_id, "fuzzing-setup")
            # setup should never fail bc of driver, so don't error it out
            if setup_log is not None and 'but another process is already executing an action on the machine' in setup_log:
                time.sleep(120)
            else:
                update_fuzzing_state_running(fuzzing_id, state="errored")
            time.sleep(60)
            continue

        update_fuzzing_state_running(fuzzing_id, state="running")
        
        try:
            fuzzing_log = run_fuzzing_loop(config)       
            send_fuzzing_log(fuzzing_log, driver_id, "fuzzing")
            if 'FAIL' in fuzzing_log: # the harness adds FAIL for all types of failures
                update_fuzzing_state_running(fuzzing_id, state="errored")
            else:
                send_fuzzing_results(fuzzing_id, driver_id)
        except Exception as e:
            send_fuzzing_log(f"Failed to run fuzzing: {e}", driver_id, "fuzzing")
            update_fuzzing_state_running(fuzzing_id, state="errored") # if broken, we are still done
        
        if not stop_now:
            # Give time for vagrant vms to stop
            time.sleep(15)

    print("Fuzzifier stopped.")