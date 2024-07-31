from vt import Client, APIError
import os
import asyncio
import json
import time

API_KEY = "API_KEY_TO_ADD"

# Function to download files, given as hash list, from VirusTotal
# TODO fix for when file not found:
# Error downloading batch: ('NotFoundError', 'File "c0ce6844f275fe5aa75d38a1c9bc4bccad20617c" not found')
async def download_batch(client, hashes, zip_file_path, sleep_time=15):
    raise NotImplementedError("This function uses INTELLIGENCE DOWNLOADS QUOTA!")
    with open(zip_file_path, "wb") as zipfile:
        try:
            await client.download_zip_files_async(hashes, zipfile)

            # Extract the contents of the ZIP file
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)
                os.remove(zip_file_path)
        except APIError as e:
            if 'ForbiddenError' in str(e):
                print("ForbiddenError, did you check the API KEY?")
                exit(1)
            else:
                print(f"Error downloading batch: {e}")

# USES INTELLIGENCE DOWNLOADS QUOTA
def download_files(hashes, output_dir):
    raise NotImplementedError("This function uses INTELLIGENCE DOWNLOADS QUOTA!")
    with Client(API_KEY) as client:
        batch_size = 10
        downloadBatches = []
        for i, hash_batch in enumerate([hashes[i:i + batch_size] for i in range(0, len(hashes), batch_size)]):
            zip_file_path = os.path.join(output_dir, f'downloaded_files_{i}.zip')
            downloadBatches.append(download_batch(client, hash_batch, zip_file_path))
        loop = asyncio.get_event_loop()
        loop.run_until_complete(asyncio.gather(*downloadBatches))
        
        downloaded_files = os.listdir(output_dir)
        if len(downloaded_files) != len(hashes):
            print(f"Only {len(downloaded_files)} files were downloaded, but {len(hashes)} were expected.")
            print("Check the hashes of the files that were not downloaded.")
            print("Exiting...")
            exit(1)
            
    print("Files downloaded and extracted successfully.")

def get_VT_quotas():
    with Client(API_KEY) as client:
        req = f"https://www.virustotal.com/api/v3/users/{API_KEY}/overall_quotas"
        quotas_resp = client.get_json(req)

        if 'data' not in quotas_resp:
            print(f"Error getting quotas: {json.dumps(quotas_resp)}")
            exit(1)

        data = quotas_resp['data']
        if 'group' not in data['api_requests_monthly']:
            print(f"There is no group quotas for your key, you sure its correct?")
            exit(2)

        api_remaining = {}
        if data['api_requests_monthly']['user']['allowed'] > 0:
            api_remaining = {
                'monthly': data['api_requests_monthly']['user']['allowed'] - data['api_requests_monthly']['user']['used'],
                'daily': data['api_requests_daily']['user']['allowed'] - data['api_requests_daily']['user']['used'],
                'hourly': data['api_requests_hourly']['user']['allowed'] - data['api_requests_hourly']['user']['used'],
            }
        else:
            api_remaining = {
                'monthly': data['api_requests_monthly']['group']['allowed'] - data['api_requests_monthly']['group']['used'],
                'daily': data['api_requests_daily']['group']['allowed'] - data['api_requests_daily']['group']['used'],
                'hourly': data['api_requests_hourly']['group']['allowed'] - data['api_requests_hourly']['group']['used'],
            }

        intelligence_downloads_remaining = {
            'group': data['intelligence_downloads_monthly']['group']['allowed'] - data['intelligence_downloads_monthly']['group']['used'],
            'user': data['intelligence_downloads_monthly']['user']['allowed'] - data['intelligence_downloads_monthly']['user']['used'],
        }

        intelligence_searches_remaining = {
            'group': data['intelligence_searches_monthly']['group']['allowed'] - data['intelligence_searches_monthly']['group']['used'],
            'user': data['intelligence_searches_monthly']['user']['allowed'] - data['intelligence_searches_monthly']['user']['used'],
        }

        remaining_quotas = {
            'api': api_remaining,
            'intelligence_downloads': intelligence_downloads_remaining,
            'intelligence_searches': intelligence_searches_remaining,
        }

        return remaining_quotas

def get_VT_usage():
    with Client(API_KEY) as client:
        req = f"https://www.virustotal.com/api/v3/users/{API_KEY}/api_usage"
        quotas_resp = client.get_json(req)

        if 'data' not in quotas_resp or 'total' not in quotas_resp['data'] or 'daily' not in quotas_resp['data']:
            print(f"Error getting api usage: {json.dumps(quotas_resp)}")
            exit(1)

        data = quotas_resp['data']
        todays_date = time.strftime("%Y-%m-%d")
        if todays_date not in data['daily']:
            print(f"Error getting todays ({todays_date}) usage: {json.dumps(data)}")
            exit(1)

        api_usage = {
            'today-downloads': data['daily'][todays_date]['/api/v3/(file_download)'] if '/api/v3/(file_download)' in data['daily'][todays_date] else 0,
            'total-downloads': data['total']['/api/v3/(file_download)'] if '/api/v3/(file_download)' in data['total'] else 0,
        }
        return api_usage

# Function to download files, given as hash list, from VirusTotal
# every file is downloaded individually, which COSTS QUOTA
def download_files_individually(hashes, output_dir):
    not_found = []
    with Client(API_KEY) as client:
        for hash in hashes:
            file_path = os.path.join(output_dir, hash)
            with open(file_path, "wb") as f:
                try:
                    client.download_file(hash, f)
                except APIError as e:
                    if 'TooManyRequestsError' in str(e):
                        print("Too many requests, sleeping for 60 seconds...")
                        time.sleep(60)
                        hashes.append(hash) # TODO Does this work to try again?
                    elif 'ForbiddenError' in str(e):
                        print("ForbiddenError, did you check the API KEY?")
                        exit(1)
                    elif 'NotFoundError' in str(e):
                        print(f"File {hash} not found.")
                        not_found.append(hash)
                    else:
                        print(f"Error downloading file {hash}: {e}")

        for hash in not_found:
            file_path = os.path.join(output_dir, hash)
            if os.path.exists(file_path) and os.path.getsize(file_path) == 0:
                os.remove(file_path)
            else:
                print(f"File {hash} was not found, but it is not 0B big?")

    downloaded_files = os.listdir(output_dir)
    if len(downloaded_files) != len(hashes) - len(not_found):
        print(f"Only {len(downloaded_files)} files were downloaded, but {len(hashes) - len(not_found)} were expected, while {len(not_found)} were not found.")
        print("Check the hashes of the files that were not downloaded.")
    else:
        print("Files downloaded and extracted successfully.")
    return not_found

def check_usage_okay(min_remain_api_quota=200):
    quotas = get_VT_quotas()
    if quotas['api']['daily'] <= min_remain_api_quota:
        raise Exception(f"Remaining API quota is too low: {quotas['api']['daily']} <= {min_remain_api_quota}")

def intelligence_search_file_iter(query, cursor=None, limit=5000, min_remain_api_quota=200, batch_size=25):
    check_usage_okay(min_remain_api_quota)
    client = Client(API_KEY)
    files = client.iterator(
        "/intelligence/search", params={
            "query": query,
            # "descriptors_only": "true", # Uses the same amount of 
        }, limit=limit, cursor=cursor, batch_size=batch_size) # batch_size=10 is the default?
    
    def toClose():
        client.close()

    return files, toClose