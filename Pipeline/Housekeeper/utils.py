import os
import requests
import time
import hashlib
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

COORDINATOR_BASE_URL = 'http://coordinator:5000'
#COORDINATOR_BASE_URL = 'http://COORDINATOR_IP:5000'

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
        if 'ogfile_id' not in response.json():
            return None, f"Success uploading file '{file_path}' but failed to get new_ogfile id for it"
        return response.json()['ogfile_id'], None
    elif response.status_code == 400 and 'Invalid hash length' in response.text:
        return None, f"[E] Hash {sha256} of {file_path} is an invalid hash?"
    elif response.status_code == 404:
        # This file does not yet exist, lets upload it
        files = {'file': open(file_path, 'rb')}
        data = {'origin': origin} if origin else {}
        # Suppressing the InsecureRequestWarning
        response = requests.post(f"{COORDINATOR_BASE_URL}/ogfile", files=files, data=data, verify=False)
        if response.status_code == 409 and 'already exists' in response.text:
            if 'ogfile_id' not in response.json():
                return None, f"File '{file_path}' already exists, but new_ogfile id for it not responded"
            return response.json()['ogfile_id'], None
        elif response.status_code == 500 and 'database is locked' in response.text:
            # TODO change backend DB to not get (sqlite3.OperationalError) database is locked
            time.sleep(1)
            return upload_file(file_path, origin)
        elif response.status_code != 200:
            return None, f"Failed to upload file '{file_path}'. Status code: {response.status_code} and response: {response.text}"
        else:
            if 'ogfile_id' not in response.json():
                return None, f"Success uploading file '{file_path}' but failed to get new_ogfile id for it"
            return response.json()['ogfile_id'], None
    elif response.status_code == 409 and 'already exists' in response.text:
        if 'ogfile_id' not in response.json():
            return None, f"File '{file_path}' already exists, but new_ogfile id for it not responded"
        return response.json()['ogfile_id'], None
    else:
        return None, f"Failed to get file id for {file_path} hash {sha256}. Status code: {response.status_code} and response: {response.text}"
