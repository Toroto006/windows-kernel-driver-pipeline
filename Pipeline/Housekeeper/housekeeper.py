import requests
import time
from urllib3.exceptions import InsecureRequestWarning
import re
import tempfile
import subprocess
import logging
from utils import upload_file
import os
import shutil

logging.basicConfig(level=logging.INFO)

if __debug__:
    logging.getLogger().setLevel(logging.DEBUG)

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

COORDINATOR_BASE_URL = 'http://coordinator:5000'
#COORDINATOR_BASE_URL = 'https://coordinator.pipeline.orb.local/'

def fetch_existing_files_info(page=1):
    url = f'{COORDINATOR_BASE_URL}/existing-files-info/{page}'
    logging.info(f"Fetching existing files info for page {page}...")
    response = requests.get(url, verify=False)
    if response.status_code == 200:
        return response.json()['files']
    else:
        logging.info(f"Failed to fetch existing files info. Status code: {response.status_code}")
        return []

to_delete_MIME_types = [
    'application/xml',
    'application/json',
    'text/plain',
    'text/xml',
]

def clean_plain_text(files_info):
    kept_files = []
    for file_info in files_info:
        delete_counter = 0
        for note in file_info['notes']:
            if 'content' in note and isinstance(note['content'], list):
                for line in note['content']:
                    if "file seems to be plain text" in line:
                        delete_counter += 1
                    elif "(.DS_STORE) Mac OS X folder information" in line:
                        delete_counter += 2
                        break
                    elif '100.0% (.CHM) Windows HELP File' in line:
                        delete_counter += 2
                        break
                    elif "Text - UTF-" in line:
                        match = re.match(r"(\d{1,3}\.\d{1,2})% \(\.TXT\) Text - UTF-\d", line)
                        if match:
                            if float(match.group(1)) > 66:
                                delete_counter += 2
                                break
                    
            if 'content' in note and isinstance(note['content'], object):
                if 'MIMEType' in note['content']:
                    if note['content']['MIMEType'].startswith('text/'):
                        delete_counter += 1
                    elif note['content']['MIMEType'] in to_delete_MIME_types:
                        delete_counter += 2
        if file_info['filename'].endswith(".inf"):
            # all inf files we wanna keep, as those might have SDDL strings in them for installation
            delete_counter -= 2
        if file_info['filename'].endswith(".sys") or file_info['filename'].endswith(".dll") or file_info['filename'].endswith(".exe"):
            # we want to keep these as well, as they might be drivers or executables
            delete_counter -= 2
        if delete_counter >= 2:
            assert not ".sys" in file_info['filename'], f"File {file_info['filename']} ({file_info['id']}) is a system file?"
            url = f'{COORDINATOR_BASE_URL}/files/{file_info["id"]}'
            response = requests.delete(url, verify=False)
            if response.status_code == 200:
                logging.info(f"File {file_info['filename']} ({file_info['id']}) deleted successfully.")
            else:
                logging.info(f"Failed to delete file {file_info['filename']} ({file_info['id']}). Status code: {response.status_code}")
        else:
            kept_files.append(file_info)
            
    return kept_files

def do_clean_files():
    page = 1
    while page < 200: # limit amount of time running through cleaning files
        files_info = fetch_existing_files_info(page)
        if len(files_info) == 0: # We are done with one full iteration
            print("No more files to fetch, waiting.")
            return
        
        # Do cleanup of text files
        logging.info(f"Cleaning plain text files for page {page}...")
        files_info = clean_plain_text(files_info)
        page += 1


def download_file(file_id, file_location):
    url = f'{COORDINATOR_BASE_URL}/files/{file_id}'
    response = requests.get(url, verify=False)
    if response.status_code != 200:
        logging.info(f"Failed to download the file {file_id}. Status code: {response.status_code}")
        return False
    
    # create folders if they do not exist
    os.makedirs(os.path.dirname(file_location), exist_ok=True)
    with open(file_location, 'wb') as f:
        f.write(response.content)
    
    return True

def extraction_file(file_type):
    iteration = 0
    while iteration < 10:
        try:
            response = requests.get(f'{COORDINATOR_BASE_URL}/ogfiles-to-extract/{file_type}/1', verify=False)
        except requests.exceptions.RequestException as e:
            logging.info(f"Failed to fetch the files for extraction.")
            time.sleep(30)
        
        if response.status_code != 200:
            logging.info(f"Failed to fetch the files for extraction. Status code: {response.status_code}")
            return
        
        if len(response.json()['ogfiles']) == 0:
            # all files extracted
            return
        
        ogfiles = response.json()['ogfiles']
        
        for ogfile in ogfiles:
            file_location = tempfile.mktemp(dir="/tmp")
            if not download_file(ogfile['file'], file_location=file_location):
                logging.info(f"[E] Could not download file {ogfile['file']} for ogfile {ogfile['id']}.")
                continue
            
            yield file_location, ogfile
        
        iteration += 1

def upload_extracted_files(temp_dir, ogfile, extracted_origin):
    if os.path.exists(temp_dir) and os.path.isdir(temp_dir) is False:
        return False
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file in ['.rdata', '.text', '.reloc', '.rsrc', '.data', '.idata', '.pdata', '.rdata', '.edata',]:
                # skip all files that are obvious 7z leftovers from "failed" extractions
                continue
            new_ogfile_id, error = upload_file(os.path.join(root, file), origin=extracted_origin)
            
            if new_ogfile_id is None:
                logging.error(f"Failed to upload extracted file {file}: {error}")
                return False

            response = requests.post(f'{COORDINATOR_BASE_URL}/extractions', json={
                'ogfile': ogfile['id'],
                'new_ogfile': new_ogfile_id
            }, verify=False)
            if response.status_code == 409:
                logging.info(f"Extraction already exists for ogfile {ogfile['id']} and new_ogfile {new_ogfile_id}.")
            elif response.status_code != 200:
                logging.error(f"Failed to save extraction to database. Status code: {response.status_code}")
                return False
    return True

def do_cab_extraction():
    for file_location, ogfile in extraction_file(file_type="Microsoft Cabinet archive data"):
        logging.info(f"Extracting file {ogfile['file']} to {file_location}...")
        temp_dir = tempfile.mkdtemp(dir="/tmp")
        try:
            subprocess.run(["cabextract", "-f", "-d", temp_dir, file_location])
            extracted_origin = f"{ogfile['origin']} - extraction" if "extraction" not in ogfile['origin'] else ogfile['origin']
            if not upload_extracted_files(temp_dir, ogfile, extracted_origin):
                # failed do not set it to extracted
                continue

            response = requests.patch(f'{COORDINATOR_BASE_URL}/ogfile/{ogfile["id"]}', json={
                'extracted': True
            }, verify=False)
            if response.status_code != 200:
                logging.error(f"Failed to mark ogfile as extracted. Status code: {response.status_code}")
                continue
            # delete the original file from disk
            response = requests.delete(f'{COORDINATOR_BASE_URL}/files/{ogfile["file"]}', verify=False)
            if response.status_code != 200:
                logging.error(f"Failed to delete original file {ogfile['file']} from disk after extraction. Status code: {response.status_code}")
                continue
            
        except Exception as e:
            logging.error(f"Failed to extract file {file_location}. Error: {e}")
        finally:
            if os.path.exists(file_location):
                os.remove(file_location)
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

def do_exe_extraction():
    non_sys_types = ["%PE32%executable%(GUI)%", "%PE32%executable%(console)%"]
    for file_type in non_sys_types:
        for file_location, ogfile in extraction_file(file_type=file_type):
            logging.info(f"Extracting file {ogfile['file']} to {file_location}...")
            temp_dir = tempfile.mkdtemp(dir="/tmp")
            try:
                # it should be possible to use 7zip for most types of installers? TODO source other than collaborator
                # very hacky way of doing this though, still some results more than just completely ignoring it for now
                subprocess.run(["7z", "x", "-o" + temp_dir, file_location], check=True)
                extracted_origin = f"{ogfile['origin']} - extraction 7z" if "extraction 7z" not in ogfile['origin'] else ogfile['origin']
                if not upload_extracted_files(temp_dir, ogfile, extracted_origin):
                    continue

                response = requests.patch(f'{COORDINATOR_BASE_URL}/ogfile/{ogfile["id"]}', json={
                    'extracted': True
                }, verify=False)
                if response.status_code != 200:
                    logging.error(f"Failed to mark ogfile as extracted. Status code: {response.status_code}")
                    continue
                # delete the original file from disk
                response = requests.delete(f'{COORDINATOR_BASE_URL}/files/{ogfile["file"]}', verify=False)
                if response.status_code != 200:
                    logging.error(f"Failed to delete original file {ogfile['file']} from disk after extraction. Status code: {response.status_code}")
                    continue
                
            except Exception as e:
                logging.error(f"Failed to extract file {file_location}. Error: {e}")
            finally:
                if os.path.exists(file_location):
                    os.remove(file_location)
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)

def do_extractions():
    do_exe_extraction()
    do_cab_extraction()
    # TODO maybe more

def main():
    logging.info("Starting housekeeper...")
    last_time_iteration = time.time()
    while True:
        if time.time() - last_time_iteration < 60:
            time.sleep(30)
            last_time_iteration = time.time()
        do_extractions()
        do_clean_files()

if __name__ == "__main__":
    time.sleep(10) # Wait for coordinator to start
    main()
