import os
import argparse
import requests
import time
import hashlib
from utils import upload_file

def upload_files_to_(folder_path, origin=None):
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            upload_file(file_path, origin)
        elif os.path.isdir(file_path):
           upload_files_to_(file_path, origin)

def main():
    parser = argparse.ArgumentParser(description="Upload files to /ogfile destination")
    parser.add_argument("folder_path", help="Path to the folder containing files to upload")
    parser.add_argument("--origin", help="Origin for the files (optional)")
    args = parser.parse_args()

    folder_path = args.folder_path
    origin = args.origin

    if os.path.exists(folder_path):
        upload_files_to_(folder_path, origin)
    else:
        print("Folder not found.")


if __name__ == "__main__":
    main()
