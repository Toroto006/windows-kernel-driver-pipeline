import os
import csv
import json
from sys import argv

from VTinterface import download_files_individually, get_VT_quotas, get_VT_usage
from utils import download_file, check_hashes


def get_hashes_MDE(csv_file_path):
    """Reads the MDE export csv file and returns a list of sha1 hashes for all found drivers."""
    hashes = set()

    with open(csv_file_path, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter=',', quotechar='"')
        next(reader)
        for sha1,Signer,EventCount in reader:
            assert len(sha1) == 40
            hashes.add(sha1)
    
    return list(hashes)

if __name__ == "__main__":
    if len(argv) != 2:
        print(f"Usage: {argv[0]} <path_to_MDE_export_csv>")
        exit(1)

    output_dir = 'downloaded_files'
    os.makedirs(output_dir, exist_ok=True)
    # check the output directory has no files
    if len(os.listdir(output_dir)) > 0:
        print(f"Output directory {output_dir} is not empty. Exiting.")
        exit(1)

    csv_file_path = argv[1]
    hashes = get_hashes_MDE(csv_file_path)
    print(f"Gotten {len(hashes)} files from {csv_file_path}...")

    # check which already exist
    hashes, known_files = check_hashes(hashes)

    remaining_quotas = get_VT_quotas()
    print(f"Remaining quotas: {json.dumps(remaining_quotas, indent=3)}")
    assert remaining_quotas['api']['daily'] - len(hashes) > 0, f"If you'd download you'd use up other quota."

    api_usage = get_VT_usage()
    print(f"This API key usage: {json.dumps(api_usage, indent=3)}")

    if input(f"Do you want to continue and download? Would cost {len(hashes)} api calls. (Yes/No) ") != 'Yes':
        print("Exiting...")
        exit(0)
    else:
        # download unknown from VT, if they exist
        print(f"Downloading {len(hashes)} files, bc they are new...")
        not_found = download_files_individually(hashes, output_dir) # Currently broken + still uses quota??
        # download those that are known from our coordinator
        for hash in known_files:
            file_path = os.path.join(output_dir, hash)
            if not download_file(hash=hash, driver_destination=file_path):
                print(f"Failed to download file {hash} from coordinator.")
        
        # write a csv file with the not found hashes, i.e. those we have to get through MDE
        if len(not_found) > 0:
            with open(os.path.join(output_dir, "not_found_hashes.csv"), "w") as f:
                for hash in not_found:
                    f.write(f"{hash}\n")
            print(f"Written {len(not_found)} hashes to not_found_hashes.csv.")
        else:
            print("All files downloaded successfully.")

        remaining_quotas = get_VT_quotas()
        print(f"Remaining quotas: {json.dumps(remaining_quotas, indent=3)}")