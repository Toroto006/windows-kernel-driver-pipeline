# coding=utf8
import requests
import time
from urllib3.exceptions import InsecureRequestWarning
import os
from sigcheckParser import parse_sigcheck_output

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

COORDINATOR_BASE_URL = 'http://COORDINATOR_IP:5000'

# the work dir is the directory this file is in
WORKDIR = os.path.dirname(os.path.realpath(__file__))

def fetch_driver_signatures_todo(page=1):
    url = f'{COORDINATOR_BASE_URL}/todo-signatures'
    # catch Max retries exceeded with url
    try:
        response = requests.get(url, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch the drivers.")
        return []
    if response.status_code == 200:
        return response.json()['drivers']
    else:
        print(f"Failed to fetch the drivers that require signature checking. Status code: {response.status_code}")
        return []

def do_driver_certificat_checking(driver):
    # first download the file
    url = f'{COORDINATOR_BASE_URL}/files/{driver["file"]}'
    response = requests.get(url, verify=False)
    if response.status_code != 200:
        print(f"Failed to download the file {driver['file']}. Status code: {response.status_code}")
        return
    
    driver_filename = driver['filename']
    # first check if file exists, if so error out
    if os.path.exists(f'C:\\Windows\\Temp\\{driver_filename}'):
        print(f"File {driver['filename']} already exists in temp folder. Exiting.")
        return
    with open(f'C:\\Windows\\Temp\\{driver_filename}', 'wb') as f:
        f.write(response.content)
    
    temp_output = os.path.join(WORKDIR, "sigcheck.txt")
    # then run sigcheck over it
    sigcheck_cmd = os.path.join(WORKDIR, "sigcheck64.exe")
    sigcheck_cmd += f' -accepteula -h -i -e -w {temp_output}'
    sigcheck_cmd += f' "C:\\Windows\\Temp\\{driver_filename}"'
    sigcheck_cmd += " > nul 2>&1"

    os.system(sigcheck_cmd)
    time.sleep(1) # wait for output to be written
    
    # get results from sigcheck.txt
    sigcheck_output = ""
    with open(temp_output, 'r', encoding='UTF-16') as f:
        sigcheck_output = f.read()
    
    if len(sigcheck_output) == 0:
        print(f"Failed to get any output from sigcheck for {driver['filename']}")
        return
    
    try:
        output = parse_sigcheck_output(sigcheck_output)
    except Exception as e:
        print(f"Failed to parse the output from sigcheck for {driver['filename']}. Error: {e}")
        return

    # check sha256 is correct
    if output['SHA256'].lower() != driver['sha256'].lower():
        print(f"\nERROR: downloaded wrong file?!? ({driver['filename']} [{driver['id']}] with driver file sha256:{driver['sha256']} and sigcheck sha256:{output['SHA256']})")
        return

    # send the results to the coordinator
    url = f'{COORDINATOR_BASE_URL}/driver-signature/{driver["id"]}'
    response = requests.post(url, json=output, verify=False)
    if response.status_code != 200:
        print(f"Failed to send the results to the coordinator for {driver['filename']}. Status code: {response.status_code}")
        return
    
    # Cleanup
    os.remove(f'C:\\Windows\\Temp\\{driver_filename}')
    os.remove(temp_output)

# Main for if this is run within a container, or by hand
def main():
    while True:
        drivers = fetch_driver_signatures_todo()
        if len(drivers) == 0: # We are done with one full iteration
            time.sleep(30)
            continue
        
        for driver in drivers:
            print(f"Doing {driver['filename']} ({driver['id']}) ... ", end="")
            do_driver_certificat_checking(driver)
            print("done")
    
if __name__ == "__main__":
    main()