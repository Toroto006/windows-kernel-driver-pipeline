from get_microsoft_updates import find_updates
from utils import upload_file, clean_filename
import tempfile
import requests
import os
import logging
import time
import random as rand

logging.basicConfig(level=logging.INFO)

if __debug__:
    logging.getLogger().setLevel(logging.info)

producers = [
    "dell",
    "razer",
    "asus",
    "msi",
    "intel",
    "gigabyte",
    "nvidia",
    "hp",
    "lenovo",
    "acer",
    "ASUS",
    "toshiba",
    "amd",
    "alienware",
    "samsung",
    "lg",
    "huawei",
    "amazon",
    "qualcomm",
    "realtek",
    "broadcom",
    "marvell",
    "sandisk",
    "kingston",
    "seagate",
    "western digital",
    "hitachi",
    "sony",
    "panasonic",
    "sharp",
    "nec",
    "mitsubishi",
    "fujitsu",
    "ibm",
    "linksys",
    "netgear",
    "tp-link",
    "d-link",
    "cisco",
    "mediatek",
    "Philips",
    "Siemens",
    "Ralink",
    "zebris",
    "lsi", # some more semiconductor producers
    "asmedia",
    "sis",
    "ati",
    "rockchip",
    "spreadtrum",
    "unisonic",
    "fresco logic",
    "nuvoton",
    "canaan",
    "ingenic",
    "gxworks",
    "semiconductor",
    "cavium",
    "xilinx",
    "imagination technologies",
    "cadence design systems",
    "synopsys",
    "arm",
    "HyperX",
    "SteelSeries",
    "Corsair",
    "Turtle Beach",
    "ROCCAT",
    "Scuf",
    "ASTRO",
    "Mad Catz",
    "Victrix by PDP",
    "PowerA",
    "Hori",
    "Nacon",
    "Thrustmaster",
    "Fanatec",
    "BenQ",
    "Acer",
    "MSI",
    "Racer",
    "Blue",
    "Sennheiser",
    "EPOS",
    "Creative Labs",
    "SteelSeries",
    "NZXT",
    "CORSAIR",
    "Health", # any generic terms
    "Medical",
    "Media",
]

compound_words = [
    "Windows 11",
    "Windows 10",
    "Gaming",
    "bios",
    "mouse",
    "disk",
    "driver",
    "audio",
    "USB",
    "cam",
    "biometric",
    "eye",
    "scanner",
    "finger",
    "recorder",
    "display",
    "monitor",
    "keyboard",
    "printer",
    "scanner",
    "camera",
    "speaker",
    "headset",
    "microphone",
    "modem",
    "router",
    "switch",
    "hub",
    "firewall",
    "access point",
    "repeater",
    "extender",
    "adapter",
    "dock",
    "modem",
    "ports",
]

too_many_results = [] # list of vendorIDs that showed more than 1000 results

def load_vendorIDs():
    # will either load known good vendor IDs from a file
    # or bruteforce
    list_vendorIDs = set()
    if os.path.exists("vendorIDs.txt"):
        with open("vendorIDs.txt", "r") as f:
            for line in f:
                list_vendorIDs.add(line.strip())
    if len(list_vendorIDs) < 500:
        # some examples, only interested in vid_XXXX and ven_XXXX
        # usb\vid_066f&pid_3600
        # usb\vid_04f3&pid_0c98
        # pci\ven_1004&dev_0308&subsys_03081004&rev_00
        for brute in range(0, 0xffff):
            list_vendorIDs.add(f"vid_{brute:04x}")
            list_vendorIDs.add(f"ven_{brute:04x}")
    # for all those that showed more than 1000 lets brute also the product or device id
    for elem in too_many_results:
        if elem not in list_vendorIDs:
            continue
        prefix = 'pid' if elem.startswith('vid') else 'dev'
        for brute in range(0, 0xffff):
            list_vendorIDs.add(f"{elem}&{prefix}_{brute:04x}")
    logging.info(f"Done creating vendorIDs list of len: {len(list_vendorIDs)}")
    return sorted(list(list_vendorIDs))

list_found_vendorIDs = set()
def save_vendorIDs():
    global list_found_vendorIDs
    with open("vendorIDs.txt", "r") as f:
        for line in f:
            list_found_vendorIDs.add(line.strip())
    with open("vendorIDs.txt", "w") as f:
        for vendor_id in list(set(list_found_vendorIDs)):
            f.write(f"{vendor_id}\n")
    logging.info(f"Saved vendorIDs {len(list_found_vendorIDs)}")

def next_search_combinations():
    for i, vendor_id in enumerate(load_vendorIDs()):
        # be nice to the server, sleep between 0.2 and 3 seconds
        time.sleep(rand.uniform(0.2, 3))
        if i % 50 == 0 and i > 0:
            save_vendorIDs()
        yield vendor_id

    for producer in producers:
        yield producer
    
    for producer in producers:
        for compound_word in compound_words:
            yield f"{producer} {compound_word}"
    
    for compound_word in compound_words:
        yield compound_word
    

def main():
    logging.info(f"Running update cataloger")
    while True:
        for search_combination in next_search_combinations():
            try:
                for update in find_updates(search_combination, all_updates=True):
                    logging.info(f"Found {update} {update.id} which has:")
                    if "vid_" in search_combination or "ven_" in search_combination:
                        list_found_vendorIDs.add(search_combination)
                    if update.exists_in_cache:
                        logging.info(f"Found {update} {update.id} in cache, not doing again.")
                        continue
                    
                    for download_infos in update.get_download_urls():
                        # download the file to local temp
                        download_url = download_infos.url
                        download_destination = tempfile.mktemp(dir="/tmp", prefix=clean_filename(f"MU_{update.title}_{update.id}_"))
                        try:
                            with open(download_destination, "wb") as f:
                                req = requests.get(download_url, stream=True)
                                for chunk in req.iter_content(chunk_size=1024):
                                    if chunk:
                                        f.write(chunk)
                            logging.info(f"Downloaded {download_url} to {download_destination}")
                            # upload the file to coordinator for further processing
                            origin = f"Microsoft Update ({search_combination})"
                            worked, error = upload_file(download_destination, origin=origin)
                            if not worked:
                                print(f"Error while uploading {download_destination}: {error}")
                                continue
                            update.done()
                            logging.info(f"Uploaded {download_destination} to {origin}")
                        except Exception as e:
                            print(f"Error while downloading {download_url}: {e}")
                        finally:    
                            if os.path.exists(download_destination):                                                
                                os.remove(download_destination)

            except Exception as e:
                print(f"Error while searching for {search_combination}: {e}")
        # next run 12 hours
        time.sleep(60 * 60 * 12)
        
if __name__ == "__main__":
    main()