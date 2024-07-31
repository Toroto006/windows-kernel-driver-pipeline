import os
import requests
import time
import hashlib
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

COORDINATOR_BASE_URL = 'http://COORDINATOR_IP:5000'

def clean_filename(filename):
    # remove all things that might break pathing after download
    return filename.replace("/", "_").replace("\\", "_").replace(":", "_")\
                .replace(" ", "_").replace('"', "_").replace("'", "_")\
                .replace("?", "_").replace("*", "_").replace("<", "_")\
                .replace(">", "_").replace("|", "_")

def check_hashes(hashes):
    known_files = []
    new_hashes = []

    for hash in hashes:
        url = f'{COORDINATOR_BASE_URL}/driver-id/{hash}'
        #print(f"Fetching existing files info for page {page}...")
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            print(f"Hash {hash} already exists.")
            known_files.append(hash)
        elif response.status_code == 400:
            print(f"Hash {hash} is an invalid hash?")
        else:
            new_hashes.append(hash)
    
    return new_hashes, known_files

def download_file(hash, driver_destination):
    url = f'{COORDINATOR_BASE_URL}/driver-id/{hash}'
    response = requests.get(url, verify=False)
    if response.status_code != 200:
        print(f"Failed to get driver id for hash {hash}. Status code: {response.status_code}")
        return False
    driver_id = response.json()['driver_id']

    # get file_id from drivers endpoint
    url = f'{COORDINATOR_BASE_URL}/drivers/{driver_id}'
    response = requests.get(url, verify=False)
    if response.status_code != 200:
        print(f"Failed to get file id for hash {hash}. Status code: {response.status_code}")
        return False
    file_id = response.json()['driver']['file']

    # download the file
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

def calculate_sha256(full_path):
    with open(full_path, 'rb') as f:
        sha256 = hashlib.sha256()
        while True:
            data = f.read(65536) # lets read stuff in 64kb chunks!
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()

def upload_file(file_path, origin=None):
    sha256 = calculate_sha256(file_path)
    url = f'{COORDINATOR_BASE_URL}/ogfile/{sha256}'
    data = {'origin': origin} if origin else {}
    response = requests.post(url, data=data, verify=False)
    if response.status_code == 200:
        return True, None
    elif response.status_code == 400 and 'Invalid hash length' in response.text:
        return False, f"[E] Hash {sha256} of {file_path} is an invalid hash?"
    elif response.status_code == 404:
        # This file does not yet exist, lets upload it
        files = {'file': open(file_path, 'rb')}
        data = {'origin': origin} if origin else {}
        # Suppressing the InsecureRequestWarning
        response = requests.post(f"{COORDINATOR_BASE_URL}/ogfile", files=files, data=data, verify=False)
        if response.status_code == 409 and 'already exists' in response.text:
            return True, None
        elif response.status_code == 500 and 'database is locked' in response.text:
            # TODO change backend DB to not get (sqlite3.OperationalError) database is locked
            time.sleep(1)
            return upload_file(file_path, origin)
        elif response.status_code != 200:
            return False, f"Failed to upload file '{file_path}'. Status code: {response.status_code} and response: {response.text}"
        else:
            return True, None
    else:
        return False, f"Failed to get file id for {file_path} hash {sha256}. Status code: {response.status_code} and response: {response.text}"
