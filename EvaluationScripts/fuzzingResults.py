#!/usr/bin/env python3
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.legend import Legend
Line2D._us_dashSeq    = property(lambda self: self._dash_pattern[1])
Line2D._us_dashOffset = property(lambda self: self._dash_pattern[0])
Legend._ncol = property(lambda self: self._ncols)
from dbConnection import run_query, close_connection

import numpy as np

def fuzzingResults(save_tex=False):
    print(f"Fuzzing statistics")


    # how many timeout and regular
    query = """SELECT COUNT(DISTINCT drivers.id) FROM public."fuzzPayload"
                JOIN public."fuzzPayload_fuzzingResults" ON public."fuzzPayload_fuzzingResults"."fuzzPayload_id" = public."fuzzPayload".id
                JOIN public."fuzzingResults" ON public."fuzzingResults".id = public."fuzzPayload_fuzzingResults"."fuzzingResults_id"
                JOIN drivers ON drivers.fuzzing_results = public."fuzzingResults".id
				WHERE type = 'timeout';"""
    result = run_query(query)
    timeout_drivers = result[0][0]

    # query = """SELECT COUNT(DISTINCT drivers.id) FROM public."fuzzPayload"
    #             JOIN public."fuzzPayload_fuzzingResults" ON public."fuzzPayload_fuzzingResults"."fuzzPayload_id" = public."fuzzPayload".id
    #             JOIN public."fuzzingResults" ON public."fuzzingResults".id = public."fuzzPayload_fuzzingResults"."fuzzingResults_id"
    #             JOIN drivers ON drivers.fuzzing_results = public."fuzzingResults".id
	# 			WHERE type = 'regular';"""
    # result = run_query(query)
    # regular_drivers = result[0][0]
    # print(f"Regular drivers: {regular_drivers}")

    query = """SELECT drivers.id as driver_id, ioctl, drivers.tag, files.filename FROM public."fuzzPayload"
                JOIN public."fuzzPayload_fuzzingResults" ON public."fuzzPayload_fuzzingResults"."fuzzPayload_id" = public."fuzzPayload".id
                JOIN public."fuzzingResults" ON public."fuzzingResults".id = public."fuzzPayload_fuzzingResults"."fuzzingResults_id"
                JOIN drivers ON drivers.fuzzing_results = public."fuzzingResults".id
                JOIN files ON files.id = drivers.file
                WHERE type = 'crash';"""
    result = run_query(query)
    crash_drivers = {}
    for row in result:
        driver_id, ioctl, tag, filename = row
        if driver_id not in crash_drivers:
            crash_drivers[driver_id] = {
                "tag": tag,
                "filename": filename
            }
        if 'ioctl' not in crash_drivers[driver_id]:
            crash_drivers[driver_id]['ioctl'] = []
        crash_drivers[driver_id]['ioctl'] = crash_drivers[driver_id]['ioctl'] + [ioctl]
    tagReplace = {
        "known_vulnerable": "Known Vulnerable",
        "unknown": "Unknown",
        "vulnerable": "Vulnerable",
        "not_vulnerable": "Not Vulnerable",
    }
    # latex table of crash drivers, where for each driver the tag, sorted by tag:
    # how many different ioctl codes have crashes, and how many of the ioctl codes have how many crashing payloads
    print("Latex table for crash drivers")
    for driver_id in sorted(crash_drivers.keys(), key=lambda x: crash_drivers[x]["tag"]):
        driver = crash_drivers[driver_id]
        tag = driver["tag"]
        filename = driver["filename"]
        crashes = len(driver['ioctl'])
        ioctls = len(list(set(driver['ioctl']))) # unique ioctls
        print(f"{filename} & {tagReplace[tag]} & {ioctls} & {crashes} \\\\")


    # how many drivers were done, how many errored, i.e. fuzzing queue, how many in queue for ARM or AMD
    query = """SELECT COUNT(DISTINCT public."fuzzQueue".driver) FROM public."fuzzQueue"
                    JOIN drivers ON drivers.id = public."fuzzQueue".driver
                    JOIN files ON files.id = drivers.file
                WHERE architecture = 'AMD64';"""
    result = run_query(query)
    tried_fuzzing_drivers_amd = result[0][0]

    query = """SELECT COUNT(DISTINCT public."fuzzQueue".driver) FROM public."fuzzQueue"
                    JOIN drivers ON drivers.id = public."fuzzQueue".driver
                    JOIN files ON files.id = drivers.file
                WHERE architecture = 'ARM64';"""
    result = run_query(query)
    tried_fuzzing_drivers_arm = result[0][0]
    print(f"Fuzzing queue unique drivers: {tried_fuzzing_drivers_amd} (AMD64), {tried_fuzzing_drivers_arm} (ARM64)")

    query = """SELECT COUNT(DISTINCT public."fuzzQueue".id) FROM public."fuzzQueue"
                    JOIN drivers ON drivers.id = public."fuzzQueue".driver
                    JOIN files ON files.id = drivers.file
                WHERE architecture = 'AMD64';"""
    result = run_query(query)
    tried_fuzzing_configuration_amd = result[0][0]

    query = """SELECT COUNT(DISTINCT public."fuzzQueue".id), public."fuzzQueue".id FROM drivers
                    JOIN public."fuzzQueue" ON drivers.id = public."fuzzQueue".driver
                    JOIN public."fuzzPayload_fuzzQueue" ON public."fuzzPayload_fuzzQueue"."fuzzQueue_id" = public."fuzzQueue".id
                    JOIN public."fuzzPayload" ON public."fuzzPayload".id = public."fuzzPayload_fuzzQueue"."fuzzPayload_id"
                    JOIN files ON files.id = drivers.file
                    WHERE state = 'errored' AND architecture = 'AMD64'
                GROUP BY public."fuzzQueue".id;"""
    result = run_query(query)
    errored_config_combinations_fuzzing_amd = sum([x[0] for x in result])

    query = """SELECT COUNT(DISTINCT public."fuzzQueue".id), public."fuzzQueue".id FROM drivers
                    JOIN public."fuzzQueue" ON drivers.id = public."fuzzQueue".driver
                    JOIN public."fuzzPayload_fuzzQueue" ON public."fuzzPayload_fuzzQueue"."fuzzQueue_id" = public."fuzzQueue".id
                    JOIN public."fuzzPayload" ON public."fuzzPayload".id = public."fuzzPayload_fuzzQueue"."fuzzPayload_id"
                    JOIN files ON files.id = drivers.file
                    WHERE state = 'done' AND architecture = 'AMD64'
                GROUP BY public."fuzzQueue".id;"""
    result = run_query(query)
    done_config_combinations_fuzzing_amd = sum([x[0] for x in result])

    print(f"Fuzzing queue configurations (AMD64): tried {tried_fuzzing_configuration_amd} (total), {errored_config_combinations_fuzzing_amd} errored, {done_config_combinations_fuzzing_amd} done")

    query = """WITH time_diffs AS (
                    SELECT
                        finished_at - LAG(finished_at) OVER (ORDER BY finished_at) AS time_diff
                    FROM public."fuzzQueue"
                    WHERE finished_at IS NOT NULL AND state = 'errored'
                )
                SELECT * FROM time_diffs
                WHERE time_diff IS NOT NULL;"""
    result = run_query(query)
    result = np.array(list(map(lambda x: x[0].total_seconds(), result)))/60
    mean, median, Q3 = np.mean(result), np.median(result), np.quantile(result, 0.75)
    print(f"Time (in minutes) between fuzzing runs that have state error: mean {mean:.1f}, median {median:.1f}, q75 {Q3:.1f}")

    query = """WITH time_diffs AS (
                    SELECT
                        finished_at - LAG(finished_at) OVER (ORDER BY finished_at) AS time_diff
                    FROM public."fuzzQueue"
                    WHERE finished_at IS NOT NULL AND state = 'done'
                )
                SELECT * FROM time_diffs
                WHERE time_diff IS NOT NULL;"""
    result = run_query(query)
    result = np.array(list(map(lambda x: x[0].total_seconds(), result)))/(60*60)
    mean, median, Q3 = np.mean(result), np.median(result), np.quantile(result, 0.75)
    print(f"Time (in hours) between fuzzing runs that have state done: mean {mean:.1f}, median {median:.1f}, q75 {Q3:.1f}")

    query = """SELECT COUNT(*) FROM public."fuzzQueue"
                    WHERE dos_device_str LIKE '%\\\\%' OR dos_device_str LIKE '%\\%%' OR dos_device_str LIKE '%:%';"""
    result = run_query(query)
    wrong_dos_device_str = result[0][0]
    query = """SELECT COUNT(*) FROM public."fuzzQueue";"""
    result = run_query(query)
    total_tried_fuzzing_drivers = result[0][0]
    percent_wrong_dos_device_str = wrong_dos_device_str / total_tried_fuzzing_drivers*100
    print(f"Drivers with special characters in dos_device_str, i.e. those that likely failed: {wrong_dos_device_str} ({percent_wrong_dos_device_str:.1f}%)")

    # for those that were successfully fuzzed
    print(f"Timeout drivers: {timeout_drivers}")
    print(f"Crash drivers: {len(crash_drivers)}")

    # total executions run across all drivers
    query = """SELECT SUM(total_execs) FROM public."fuzzingResults";"""
    result = run_query(query)
    total_execs = result[0][0]
    print(f"Total executions: {total_execs}")

if __name__ == "__main__":
    save_tex = False

    import os
    os.system('clear')

    fuzzingResults(save_tex=save_tex)
    
    # cleanup DB connections
    close_connection()
