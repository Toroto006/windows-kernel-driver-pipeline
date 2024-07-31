#!/usr/bin/env python3
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.legend import Legend
Line2D._us_dashSeq    = property(lambda self: self._dash_pattern[1])
Line2D._us_dashOffset = property(lambda self: self._dash_pattern[0])
Legend._ncol = property(lambda self: self._ncols)
from dbConnection import run_query, close_connection

import random
import requests
import json
import numpy as np
from scipy.stats import mannwhitneyu, kstest

COORDINATOR_BASE_URL = 'http://COORDINATOR_IP:5000'

def download_file(file_id, driver_destination):
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


evaluation_targets = [
    {'filename': 'd5e76d125d624f8025d534f49e3c4162.bin', 'id': 331, 'file': 357, 'size': 14376, 'type': 'WDM'},
    {'filename': 'Monitor.sys', 'id': 94, 'file': 101, 'size': 32520, 'type': 'WDM'},
    {'filename': 'aswArPot.sys', 'id': 3820, 'file': 12592, 'size': 229848, 'type': 'WDM'},
    {'filename': 'a216803d691d92acc44ac77d981aa767.bin', 'id': 1652, 'file': 1794, 'size': 13120, 'type': 'WDM'},
    {'filename': 'ahcache.sys', 'id': 2740, 'file': 3078, 'size': 292352, 'type': 'WDM'},
    {'filename': 'RamCaptureDriver64.sys', 'id': 2046, 'file': 2293, 'size': 34296, 'type': 'WDM'},
    {'filename': 'PixUsb.sys', 'id': 25993, 'file': 526239, 'size': 32832, 'type': 'WDM'},
    {'filename': '97580157f65612f765f39af594b86697.bin', 'id': 332, 'file': 359, 'size': 29688, 'type': 'WDM'},
    {'filename': '3ecd3ca61ffc54b0d93f8b19161b83da.bin', 'id': 676, 'file': 735, 'size': 14648, 'type': 'WDM'},
    {'filename': 'ZuluHm64.sys', 'id': 30105, 'file': 578676, 'size': 705664, 'type': 'WDM'},
    {'filename': 'a664904f69756834049e9e272abb6fea.bin', 'id': 284, 'file': 308, 'size': 27720, 'type': 'WDM'},
    {'filename': 'snpnio.sys', 'id': 4123, 'file': 12896, 'size': 100216, 'type': 'WDM'},
    {'filename': 'TSSysKit64.sys', 'id': 3964, 'file': 12736, 'size': 112784, 'type': 'WDM'},
    {'filename': 'fe937e1ed4c8f1d4eac12b065093ae63.bin', 'id': 1285, 'file': 1401, 'size': 7680, 'type': 'WDM'},
    {'filename': '3a7c69293fcd5688cc398691093ec06a.bin', 'id': 1405, 'file': 1527, 'size': 14376, 'type': 'WDM'},
    {'filename': 'atrk.sys', 'id': 3806, 'file': 12578, 'size': 70968, 'type': 'WDM'},
    {'filename': 'ab4656d1ec4d4cc83c76f639a5340e84.bin', 'id': 1537, 'file': 1672, 'size': 6144, 'type': 'WDM'},
    {'filename': 'a2be99e4904264baa5649c4d4cd13a17.bin', 'id': 635, 'file': 691, 'size': 29952, 'type': 'WDM'},
    {'filename': 'RDWM1231.SYS', 'id': 19868, 'file': 452938, 'size': 397312, 'type': 'WDM'},
    {'filename': '79f7e6f98a5d3ab6601622be4471027f.bin', 'id': 1062, 'file': 1160, 'size': 16240, 'type': 'WDM'},
    {'filename': 'RDWM1201.SYS', 'id': 19892, 'file': 454201, 'size': 393240, 'type': 'WDM'},
    {'filename': 'c04a5cdcb446dc708d9302be4e91e46d.bin', 'id': 1634, 'file': 1775, 'size': 16880, 'type': 'WDM'},
    {'filename': '697bbd86ee1d386ae1e99759b1e38919.bin', 'id': 1284, 'file': 1400, 'size': 15648, 'type': 'WDM'},
    {'filename': 'nokiaccxx64.sys', 'id': 15453, 'file': 320283, 'size': 38528, 'type': 'WDM'},
    {'filename': '1f3522c5db7b9dcdd7729148f105018e.bin', 'id': 745, 'file': 812, 'size': 31744, 'type': 'WDM'},
    {'filename': 'df5f8e118a97d1b38833fcdf7127ab29.bin', 'id': 1060, 'file': 1158, 'size': 29264, 'type': 'WDM'},
    {'filename': '6fb3d42a4f07d8115d59eb2ea6504de5.bin', 'id': 1371, 'file': 1491, 'size': 14648, 'type': 'WDM'},
    {'filename': 'HwRwDrv.sys', 'id': 82, 'file': 89, 'size': 14592, 'type': 'WDM'},
    {'filename': 'easeusmnt0.sys', 'id': 3700, 'file': 12471, 'size': 119512, 'type': 'WDM'},
    {'filename': 'pigeon.sys', 'id': 4054, 'file': 12827, 'size': 142592, 'type': 'WDM'},
    {'filename': 'gmer64.sys', 'id': 300, 'file': 324, 'size': 56592, 'type': 'WDM'},
    {'filename': '370a4ca29a7cf1d6bc0744afc12b236c.bin', 'id': 785, 'file': 855, 'size': 43920, 'type': 'WDM'},
    {'filename': 'RDWM1181.SYS', 'id': 19909, 'file': 455112, 'size': 391680, 'type': 'WDM'},
    {'filename': 'SRVKP.SYS', 'id': 35160, 'file': 656301, 'size': 24704, 'type': 'WDM'},
    {'filename': '8065a7659562005127673ac52898675f.bin', 'id': 1120, 'file': 1222, 'size': 14392, 'type': 'WDM'},
    {'filename': 'RDWM1197.SYS', 'id': 19902, 'file': 454777, 'size': 395784, 'type': 'WDM'},
    {'filename': 'SoftPerfectRAMDisk.sys', 'id': 4256, 'file': 13029, 'size': 251512, 'type': 'WDM'},
    {'filename': 'd104621c93213942b7b43d65b5d8d33e.bin', 'id': 368, 'file': 397, 'size': 24968, 'type': 'WDF'},
    {'filename': 'iomemory_vsl.sys', 'id': 6306, 'file': 99082, 'size': 907928, 'type': 'WDF'},
    {'filename': 'amdsfhkmdf.sys', 'id': 10850, 'file': 219480, 'size': 156392, 'type': 'WDF'}
]

def createEvaluationTargetList():
    query = """WITH unique_filenames AS (
                SELECT DISTINCT ON (filename) drivers.id AS id, files.id AS file, filename, type, size
                FROM drivers
                JOIN files ON drivers.file = files.id
                JOIN public."pathResults" ON drivers.path_results = public."pathResults".id
                WHERE ret_code > 200 AND architecture = 'AMD64'
                ORDER BY filename
            )
            SELECT *
            FROM unique_filenames
            ORDER BY RANDOM()
            LIMIT 100;"""
    result = run_query(query)
    evaluation_targets = []
    for target in result:
        evaluation_targets.append({
            'filename': target[2],
            'id': target[0],
            'file': target[1],
            'size': target[4],
            'type': target[3]
        })
    
    print(f"Created evaluation target list with {len(evaluation_targets)}:\n{evaluation_targets}")
    print(f"There are {len(list(filter(lambda x: x['type'] == 'WDM', evaluation_targets)))} WDM drivers and {len(list(filter(lambda x: x['type'] == 'WDF', evaluation_targets)))} WDF drivers.")

    res = input("You want me to download them?")
    if res == "Y":
        for target in evaluation_targets:
            download_file(target['file'], f"./pathingGatherData/evalTargets/{target['filename']}")
        print("Downloaded all files.")

def pathingResults(save_tex=False):
    print(f"Pathing statistics")

    ### general statistics for the featuers
    # total drivers with pathing results
    query = """SELECT COUNT(*)
                FROM drivers
                JOIN public."pathResults" ON drivers.path_results = public."pathResults".id;"""
    total_drivers = run_query(query)[0][0]
    print(f"Total drivers with pathing results: {total_drivers}")

    # total ARM64 drivers
    query = """SELECT COUNT(*)
                FROM drivers
                JOIN files ON drivers.file = files.id
                WHERE architecture = 'ARM64' OR architecture = 'ARM16';"""
    total_arm = run_query(query)[0][0]    
    query = """SELECT COUNT(*)
                FROM drivers
                JOIN public."pathResults" ON drivers.path_results = public."pathResults".id
                JOIN files ON drivers.file = files.id
                WHERE architecture = 'ARM64';"""
    total_arm64 = run_query(query)[0][0]

    percent_arm = total_arm / total_drivers * 100
    percent_arm64 = total_arm64 / total_arm * 100

    # how many ARM64 drivers have ret_code > 200
    query = """SELECT COUNT(*)
                FROM drivers
                JOIN files ON drivers.file = files.id
                JOIN public."pathResults" ON drivers.path_results = public."pathResults".id
                WHERE ret_code > 200 AND architecture = 'ARM64';"""
    deemed_likely_arm = run_query(query)[0][0]
    print(f"Out of {total_arm64} ARM64 drivers ({percent_arm:.1f}% of all drivers and {percent_arm64:.1f}% of all ARM drivers) deemed likely vulnerable: {deemed_likely_arm}")

    # loop detection for ARM
    query = """SELECT COUNT(DISTINCT drivers.id)
                FROM drivers
                JOIN notes ON notes.isfor = drivers.file
                WHERE notes.content LIKE '%loop%';"""
    loop_detection_arm = run_query(query)[0][0]
    percent_loop = loop_detection_arm / total_drivers * 100
    print(f"{loop_detection_arm} ({percent_loop:.1f}% of all ARM64/AMD64 drivers) were found using the loop detection.")

    # memset detection 
    query = """SELECT COUNT(DISTINCT drivers.id)
                FROM drivers
                JOIN notes ON notes.isfor = drivers.file
                WHERE notes.content LIKE '%memset64%';"""
    memset_detection = run_query(query)[0][0]
    percent_memset = memset_detection / total_drivers * 100
    print(f"{memset_detection} ({percent_memset:.1f}% of all ARM64/AMD64 drivers) were found using the memset64 detection.")

    # WDF includes probably
    query = """SELECT COUNT(DISTINCT functions.name) as distinct_fct, COUNT(functions.name) as total_fct, COUNT(DISTINCT drivers.id) as in_drivers
                FROM drivers
                JOIN public."staticResults" ON drivers.static_results = public."staticResults".id
                JOIN public."functions_staticResults" ON public."functions_staticResults"."staticResults_id" = public."staticResults".id
                JOIN functions ON public."functions_staticResults"."functions_id" = functions.id
                WHERE functions.name LIKE 'Wdf%' 
                AND functions.name NOT IN ('WdfVersionBind', 'WdfVersionBindClass', 'WdfVersionUnbind', 'WdfVersionUnbindClass');"""
    result = run_query(query)
    distinct_wdf_functions_found = result[0][0]
    total_wdf_functions_found = result[0][1]
    in_drivers = result[0][2]
    print(f"Found {distinct_wdf_functions_found} distinct WDF functions with {total_wdf_functions_found} total functions in {in_drivers} drivers.")
    # most intersting functions, i.e. only WdfDeviceCreateSymbolicLink, WdfDeviceCreateDeviceInterface and WdfMemoryGetBuffer
    query = """SELECT COUNT(functions.name) as total_fct, COUNT(DISTINCT drivers.id) as in_drivers
                FROM drivers
                JOIN public."staticResults" ON drivers.static_results = public."staticResults".id
                JOIN public."functions_staticResults" ON public."functions_staticResults"."staticResults_id" = public."staticResults".id
                JOIN functions ON public."functions_staticResults"."functions_id" = functions.id
                WHERE functions.name IN ('WdfDeviceCreateSymbolicLink', 'WdfDeviceCreateDeviceInterface');"""
    result = run_query(query)
    total_wdf_functions_found = result[0][0]
    in_drivers = result[0][1]
    print(f"Found {total_wdf_functions_found} total functions in {in_drivers} drivers for WdfDeviceCreateSymbolicLink WdfDeviceCreateDeviceInterface.")

    ### speed improvements
    global evaluation_targets
    evaluation_targets = {f'{elem["id"]}': elem for elem in evaluation_targets}

    original_speeds = None
    with open('pathingGatherData/timing_data_without_imp.json', 'r') as f:
    #with open('pathingGatherData/timing_data_with_imp.json', 'r') as f:
        original_speeds = json.load(f)
        
    speed_improvements = None
    with open('pathingGatherData/timing_data_with_imp.json', 'r') as f:
        speed_improvements = json.load(f)
        #min_len = min(map(len, speed_improvements.values()))
        #speed_improvements = {k: v[:30] for k,v in speed_improvements.items()}
    
    # same subset of drivers
    speed_improvements = {k: v for k,v in speed_improvements.items() if k in original_speeds}
    #original_speeds = {k: [vm + np.mean(v) for vm in v] for k,v in speed_improvements.items() if k in original_speeds}

    # calculate mean and std for each
    #mean_std = {k: (np.mean(v), np.median(v), np.std(v)) for k,v in speed_improvements.items()}
    # for k,v in mean_std.items():
    #     print(f"{k}: {v[0]:.2f} {v[1]:.2f} {v[2]:.2f}")

    # do normality test on speed improvements
    # alp = 0.05
    # normal = []
    # for k,v in speed_improvements.items():
    #     stat, p = normaltest(v)
    #     #print(f"Speed improvements for {k} {len(v)} has p-value {p:.4f}. {'Not' if p < alp else ''} Normally distributed.")
    #     normal.append(p < alp)
    #print(f"Speed improvements {'not ' if not all(normal) else ''}normally distributed ({len(list(filter(lambda x: x, normal)))/len(normal)*100:.1f}% are normal).")

    WDFs = list(filter(lambda x: evaluation_targets[x]['type'] == 'WDF', speed_improvements.keys()))
    WDMs = list(filter(lambda x: evaluation_targets[x]['type'] == 'WDM', speed_improvements.keys()))
    print(f"Out of {len(speed_improvements)} {len(WDMs)} WDM drivers and {len(WDFs)} WDF drivers were in test.")

    # calculate the median time saving for all WDM drivers
    median_without = [np.median(original_speeds[k]) for k in WDMs]
    median_with = [np.median(speed_improvements[k]) for k in WDMs]
    median_time_saving = [m1 - m2 for m1,m2 in zip(median_without, median_with)]
    print(f"Median time saving for WDM drivers: {np.mean(median_time_saving):.2f} with std {np.std(median_time_saving):.2f}.")

    # calculate the median time saving for all WDF drivers
    median_without = [np.median(original_speeds[k]) for k in WDFs]
    median_with = [np.median(speed_improvements[k]) for k in WDFs]
    median_time_saving = [m1 - m2 for m1,m2 in zip(median_without, median_with)]
    print(f"Median time saving for WDF drivers: {np.mean(median_time_saving):.2f} with std {np.std(median_time_saving):.2f}.")

    # do Wilcoxon-Mann-Whitney U test on speed improvements compared to original
    alp = 0.05
    mwu = []
    sig_imp = []
    for k,v in speed_improvements.items():
        # X defined as X - med(X)
        X = np.array(original_speeds[k])
        Y = np.array(v)
        X_m = X - np.median(X)
        Y_m = Y - np.median(Y)
        stat, p = kstest(X_m, Y_m, alternative='two-sided')
        #print(f"Speed improvements for {k} {len(v)} has p-value {p:.4f}. {'Not' if p < alp else ''} significant.")
        if p < alp and (len(v) < 30 or len(original_speeds[k]) < 30):
            # H_0 is rejected
            print(f"Speed improvements for {k} {len(v)} has p-value {p:.4f}. Need more data for this!")
        else:
            stat, p = mannwhitneyu(X, Y, alternative="greater", method="exact")
            mwu.append(p < alp)
            if p < alp:
                sig_imp.append(k)
            #     print(f"Speed improvements for {k} has p-value {p:.4f} and IS significant.")
            # else:
            #     print(f"Speed improvements for {k} has p-value {p:.4f} and is NOT significant.")
    print(f"Speed improvements for {len(list(filter(lambda x: x, mwu)))/len(mwu)*100:.1f}% of valid test drivers are significant.")
    
    median_without = [np.median(original_speeds[k]) for k in sig_imp]
    median_with = [np.median(speed_improvements[k]) for k in sig_imp]
    median_time_saving = [m1 - m2 for m1,m2 in zip(median_without, median_with)]
    print(f"Median time saving for significant drivers: {np.mean(median_time_saving):.2f}s with std {np.std(median_time_saving):.2f}s")
    print(f"totaled {sum(median_time_saving):.2f}s out of {sum(median_without):.2f}s which is {sum(median_time_saving)/sum(median_without)*100:.2f}%.")

    # plot for each speed improvements a subplot
    fig, ax = plt.subplots(5, 5, figsize=(12,8))
    ax = ax.flatten()
    keys = random.sample(list(speed_improvements.keys()), 25)
    #keys = speed_improvements.keys()
    values = [speed_improvements[k] for k in keys]

    i = 0
    #for i, (k,v) in enumerate(zip(keys, values)):
    for k,v in zip(keys, values):
        if evaluation_targets[k]['type'] == 'WDF':
             continue
        ax[i].hist(v, bins=20, color='skyblue', edgecolor='black', alpha=0.5)
        ax[i].hist(original_speeds[k], bins=20, color='lightcoral', edgecolor='black', alpha=0.5)
        ax[i].set_title(f"{k} {evaluation_targets[k]['type']}")
        ax[i].set_xlabel("Time in seconds")
        ax[i].set_ylabel("Frequency")
        ax[i].grid(True)
        i += 1
    
    fig.legend(["With improvements", "Original"], loc='upper center', ncol=2)
    fig.tight_layout()
    # #plt.show()

    # speed improvements for WDF drivers with caching are shite, its much worse
    # for WDM it depends, mostly with caching the same, some are worse some are better...
    # wait for those with __debug__ but without caching

    if not save_tex:
        fig.savefig('figures/pathingResults.svg')
    else:
        # To save it for the thesis        
        fig.savefig('figures/pathingResults.pdf', format="pdf", dpi=1200, bbox_inches="tight", transparent=True)


if __name__ == "__main__":
    save_tex = False

    import os
    os.system('clear')

    #createEvaluationTargetList()
    pathingResults(save_tex=save_tex)
    
    # cleanup DB connections
    close_connection()
