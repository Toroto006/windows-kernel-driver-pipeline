import xml.etree.ElementTree as ET
import csv
import re
import requests
import zipfile
import os
import json
import shutil

zip_file_url = 'https://aka.ms/VulnerableDriverBlockList'
zip_file_path = 'vulnerable_driver_blocklist.zip'
extracted_dir_path = 'windows_blocklist_extracted'

# Regular expression pattern for SHA256 hash
sha256_pattern = re.compile(r'^[a-fA-F0-9]{64}$')

def downloadWindowsBlockList():
    # Create a directory to store the extracted XML files
    os.makedirs(extracted_dir_path, exist_ok=True)

    # Download the ZIP file
    response = requests.get(zip_file_url)
    with open(zip_file_path, 'wb') as zip_file:
        zip_file.write(response.content)

    # Extract the contents of the ZIP file
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(extracted_dir_path)

    print("MS BlockList files downloaded and extracted successfully.")

# help from ChatGPT for parts of the parsing function
def parseWindowsBlockList(target, writer):
    # Parse the XML file
    tree = ET.parse(target)
    root = tree.getroot()

    # Define namespaces
    namespaces = {'ns': 'urn:schemas-microsoft-com:sipolicy'}

    # Iterate through each Deny element
    for node in root.findall('.//ns:Deny', namespaces) + root.findall('.//ns:FileAttrib', namespaces):
        filename = node.get('FileName')
        friendly_name = node.get('FriendlyName')

        # Extract SHA256 hash from the FriendlyName after '\', if there is one
        sha256 = ''
        if '\\' in friendly_name:
            sha256 = friendly_name.split('\\')[-1].split(' ')[0].strip()
            filename = friendly_name.split('\\')[0] if filename is None else filename
        
        # Check if the extracted string matches the pattern of a SHA256 hash
        if not sha256_pattern.match(sha256):
            sha256 = ''
        
        if (filename is None or len(filename) == 0) and len(sha256) == 0:
            # The filename is <filename> Hash of the friendly_name
            regex = r"(.*) Hash "
            matches = re.match(regex, friendly_name)
            if matches:
                filename = matches.group(1)

        if (filename is not None and len(filename) > 0) or (sha256 is not None and len(sha256) > 0):
            writer.writerow([filename, sha256.lower(), 'MS BlockList', f'Custom parser from XML BlockList {target}'])
        else:
            print(f"Skipping entry as filename and sha256 are empty? {ET.tostring(node)}")
    
    print(f"XML file '{target}' parsed successfully.")

def parseLoldriversList(writer):
    # get json from loldrivers api https://www.loldrivers.io/api/drivers.json

    response = requests.get('https://www.loldrivers.io/api/drivers.json')
    if response.status_code == 200:
        lol_drivers = response.json()

        for driver in lol_drivers:
            if 'KnownVulnerableSamples' not in driver or len(driver['KnownVulnerableSamples']) == 0:
                print(f"Skipping driver as it does not have KnownVulnerableSamples? {driver}")
                continue
            
            for knownSample in driver['KnownVulnerableSamples']:
                filename = ''
                if 'OriginalFilename' in knownSample:
                    filename = knownSample['OriginalFilename']
                if len(filename) == 0 and 'Filename' in knownSample:
                    filename = knownSample['Filename']
                
                if 'SHA256' in knownSample:
                    sha256 = knownSample['SHA256']
                if not sha256_pattern.match(sha256):
                    sha256 = ''

                description = ''
                if 'Commands' in driver and 'Description' in driver['Commands']:
                    description = driver['Commands']['Description']
                if len(description) == 0 and 'Description' in knownSample:
                    description = knownSample['Description']

                origin = 'LOL Drivers List'

                if (filename is not None and len(filename) > 0) or (sha256 is not None and len(sha256) > 0):
                    writer.writerow([filename, sha256.lower(), origin, description])
                else:
                    print(f"Skipping driver as filename or sha256 is empty? {json.dumps(driver, indent=4)}")

        print(f"LOL Drivers List ({len(lol_drivers)}) parsed successfully.")
    else:
        print(f"Failed to fetch LOL Drivers List. Status code: {response.status_code} and response: {response.text}")

def addVDRVulnerableDrivers(writer):
    # load the VDR.csv and add all of them
    with open('VDR.csv', 'r') as vdrfile:
        reader = csv.reader(vdrfile)
        next(reader) # skip header
        for row in reader:
            filename, sha256 = row
            writer.writerow([filename, sha256.lower(), 'VDR Vulnerable Drivers List', ''])
    print(f"VDR Vulnerable Drivers List added successfully.")

if __name__ == '__main__':

    # Open CSV file for writing
    with open('../knownVulnerableDrivers.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['filename', 'sha256', 'origin', 'blocked', 'description'])

        # Microsoft Windows Driver Block List
        downloadWindowsBlockList()
        for filename in os.listdir(extracted_dir_path):
            if filename.endswith('.xml'):
                parseWindowsBlockList(os.path.join(extracted_dir_path, filename), writer)

        # LOL Drivers List
        parseLoldriversList(writer)

        # VDR Vulnerable Drivers List
        addVDRVulnerableDrivers(writer)
    
        # Cleanup all files again
        os.remove(zip_file_path)
        shutil.rmtree(extracted_dir_path)