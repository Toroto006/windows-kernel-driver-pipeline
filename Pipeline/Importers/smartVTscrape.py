import os
import json
from VTinterface import get_VT_quotas, get_VT_usage, intelligence_search_file_iter, download_files_individually
import signal
import pickle
import hashlib
import time
from utils import download_file, check_hashes
from sys import argv

stop_now = False
def signal_handler(sig, frame):
    print('You pressed Ctrl+C, will stop after next wakeup.')
    global stop_now
    stop_now = True
signal.signal(signal.SIGINT, signal_handler)

def print_intelligence_quota_remaining():
    quotas = get_VT_quotas()
    print(f"Remaining intelligence quotas: down {quotas['intelligence_downloads']['group']}, search {quotas['intelligence_searches']['group']}, API daily: {quotas['api']['daily']}")

### Get list of drivers from VT

def do_current_query():
    # positive:1- means no detections --> most known vuln should be gone, e.g. elastic has lol drivers as checks
    # imports:IoCreateSymbolicLink is necessary for interaction from user space, TODO how do I want to do WdfDeviceCreateDeviceInterface?
    # imports:WdfVersionBind for pure WDF drivers?
    # tag:native Identifies Portable Executable linked using the Native subsystem, there is a high probability of these files being drivers
    # tag:64bit for now to get the full pipeline effect
    # tag:signed to get only signed drivers, got enough of those for now
    
    query = "tag:64bits tag:signed type:executable positives:1- tag:native imports:IoCreateSymbolicLink" # query_cursor_3d4b25fcaf92577cb44aad47781bdb6a.pickle

    files = []
    batch_size = 250
    try:
        # if there exists a cursor file, load it
        cursor = None
        cursor_name = f"query_cursor_{hashlib.md5(query.encode()).hexdigest()}.pickle"
        if os.path.exists(cursor_name):
            with open(cursor_name, "rb") as f:
                cursor = pickle.load(f)

        iterator, toClose = intelligence_search_file_iter(query, limit=10000, min_remain_api_quota=15, cursor=cursor, batch_size=batch_size)

        # Then iterate over all file results
        global stop_now
        counter = 0
        for file in iterator:
            f = {
                "meaningful_name": file.get("meaningful_name"),
                "sha1": file.get("sha1"),
                "sha256": file.sha256,
                "size": file.get("size"),
                #"signature_info": file.get("signature_info"),
                "names": file.get("names"),
                "downloadable": file.get("downloadable"),
            }
            files.append(f)
            counter += 1
            print(f"Got file: {f['meaningful_name']} ({f['sha256']})")
            if counter % batch_size == 0: # to at least finish the current batch
                print(f"Gotten {counter} hashes.")
                if stop_now:
                    break
                print_intelligence_quota_remaining()
        
        # Save for next run
        with open(cursor_name, "wb") as f:
            pickle.dump(iterator.cursor, f)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        toClose()

    results = {
        "query": query,
        "files": files,
    }
    result_name = f"VTresults/results_{hashlib.md5(query.encode()).hexdigest()}_{time.strftime('%Y%m%d-%H%M%S')}.json"
    os.makedirs("VTresults", exist_ok=True)
    with open(result_name, "w") as f:
        json.dump(results, f, indent=3)
    
    print(f"Saved {len(files)} results to {result_name}.")
    
    return results

### Get the actual drivers now

def get_hashes(result_file):
    hashes = set()

    with open(result_file, 'r') as f:
        data = json.load(f)
        print(f"Doing {result_file} of quert {data['query']} with {len(data['files'])} files.")
        for file in data['files']:
            hashes.add(file['sha256'])

    return list(hashes)

def get_sha256_name_mapping(result_file):
    sha256_name = {}

    with open(result_file, 'r') as f:
        data = json.load(f)
        for file in data['files']:
            name = file['meaningful_name']
            # if the name is a full path, be it Windows or Unix path,
            # search through the names instead to find one without
            # otherwise take the actual file of the path

            # TODO fix later

            sha256_name[file['sha256']] = name

    return sha256_name

def download_results():
    output_dir = 'downloaded_files'
    os.makedirs(output_dir, exist_ok=True)
    # check the output directory has no files
    if len(os.listdir(output_dir)) > 1:
        print(f"Output directory {output_dir} is not empty. Exiting.")
        exit(1)

    # Load a result from the VTresults
    all_files = os.listdir('VTresults')
    results = [f for f in all_files if f.endswith('.json') and f.startswith('results_5970d')]
    if len(results) == 0:
        print("No results found in VTresults. Run the query first/again!")
        exit(1)
    result_file = os.path.join('VTresults', results[0])


    hashes = get_hashes(result_file)
    print(f"Gotten {len(hashes)} files")
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
        # TODO manual download to use stop_now and save them with the nice name of VT
        # TODO add a size check if the download locally would even fit in disk
        not_found = download_files_individually(hashes, output_dir) # Currently broken + still uses quota??
        # download those that are known from our coordinator
        for hash in known_files:
            file_path = os.path.join(output_dir, hash)
            if not download_file(hash=hash, driver_destination=file_path):
                print(f"Failed to download file {hash} from coordinator.")
        
        # write a csv file with the not found hashes
        if len(not_found) > 0:
            print(f"We have {len(not_found)} hashes?? How did we get those from VT in the first place?")
            print("Writing them to a csv file.")
            with open(os.path.join(output_dir, 'not_found.csv'), 'w') as f:
                for hash in not_found:
                    f.write(f"{hash}\n")
        else:
            print("All files downloaded successfully.")
            
            # rename the results_file to preprend done_
            os.rename(result_file, result_file.replace('results_', 'done_results_'))

        remaining_quotas = get_VT_quotas()
        print(f"Remaining quotas: {json.dumps(remaining_quotas, indent=3)}")

if __name__ == "__main__":
    print_intelligence_quota_remaining()
    
    # first argument says to query VT or download hashes
    if len(argv) != 2:
        print(f"Usage: {argv[0]} <query|download>")
        exit(1)
    
    if argv[1] == 'query':
        do_current_query()
    elif argv[1] == 'download':
        download_results()
    else:
        print(f"Unknown argument {argv[1]}, current quota:")
        print_intelligence_quota_remaining()