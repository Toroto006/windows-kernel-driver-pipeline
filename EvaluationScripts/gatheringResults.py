#!/usr/bin/env python3
import matplotlib.pyplot as plt
import matplotlib.pyplot as colors
from matplotlib.lines import Line2D
from matplotlib.legend import Legend
Line2D._us_dashSeq    = property(lambda self: self._dash_pattern[1])
Line2D._us_dashOffset = property(lambda self: self._dash_pattern[0])
Legend._ncol = property(lambda self: self._ncols)
from dbConnection import run_query, close_connection

import matplotlib.dates as mdates
import matplotlib.ticker as tkr  
from datetime import date

def gatheringResults1(save_tex=False):
    print("Statistics and graphs on the gathering of drivers.")

    # general statistics
    query = """SELECT COUNT(*) FROM public."ogFiles"
        JOIN "files" ON files.id = public."ogFiles".file
		JOIN "drivers" ON drivers.file = files.id;"""
    results = run_query(query)
    og_files_with_drivers = results[0][0]
    print(f"Total amount of origin files that are a driver (includes duplicates): {og_files_with_drivers}")

    query = """SELECT COUNT(DISTINCT drivers.file) FROM drivers;"""
    results = run_query(query)
    drivers = results[0][0]
    amount_duplicates = og_files_with_drivers - drivers
    percent_duplicates = amount_duplicates / drivers * 100
    print(f"Total amount of drivers: {drivers}, meaning that {amount_duplicates} were found in different locations ({percent_duplicates:.2f}%)")

    # distribution across types:
    query = """SELECT COUNT(type), type FROM "pathResults"
                JOIN drivers ON drivers.path_results = "pathResults".id
                GROUP BY type;"""
    results = run_query(query)
    print(f"Amount of drivers per type: {results}")

    ### breakdown of the drivers by their origin
    # all Microsoft Update (<name>) are one type of origin
    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
		JOIN public."ogFiles" ON drivers.file = public."ogFiles".file
        WHERE public."ogFiles".origin LIKE 'Microsoft Update %'
		AND public."ogFiles".origin NOT LIKE 'Microsoft Update (ven%'
		AND public."ogFiles".origin NOT LIKE 'Microsoft Update (vid%';"""
    results = run_query(query)
    ms_update_names = results[0][0]
    print(f"Amount of drivers from Microsoft Update without bruting: {ms_update_names}")
    # any of those with name prefix vid or ven are seperate, given those are vendor ids
    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
		JOIN public."ogFiles" ON drivers.file = public."ogFiles".file
        WHERE public."ogFiles".origin LIKE 'Microsoft Update (ven%';"""
    results = run_query(query)
    ms_update_ven = results[0][0]
    print(f"Amount of drivers from Microsoft Update with ven: {ms_update_ven}")

    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
		JOIN public."ogFiles"  ON drivers.file = public."ogFiles".file
        WHERE public."ogFiles".origin LIKE 'Microsoft Update (vid%';"""
    results = run_query(query)
    ms_update_vid = results[0][0]
    print(f"Amount of drivers from Microsoft Update with vid: {ms_update_vid}")

    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
		JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin LIKE 'Microsoft Update%';"""
    results = run_query(query)
    ms_update_total = results[0][0]
    print(f"Total amount of drivers from Microsoft Update: {ms_update_total} (perc name {ms_update_names/ms_update_total*100:.2f}%, ven {ms_update_ven/ms_update_total*100:.2f}%, vid {ms_update_vid/ms_update_total*100:.2f}%)")

    percent_found_by_ms_update = ms_update_total / drivers * 100
    print(f"Meaning {percent_found_by_ms_update:.2f}% of all drivers were found by Microsoft Update")

    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
		JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin LIKE 'Microsoft Update%'
        AND drivers.tag = 'known_vulnerable';"""
    results = run_query(query)
    ms_update_vuln = results[0][0]

    query = """SELECT COUNT(DISTINCT id) FROM "knownVulnerableDrivers";"""
    results = run_query(query)
    known_vulnerable_drivers = results[0][0]
    percent_ms_update_vuln = ms_update_vuln / known_vulnerable_drivers * 100
    print(f"and {ms_update_vuln} of those are known vulnerable drivers ({percent_ms_update_vuln:.2f}% of all)")
    
    # VT Query and TOP 100 VT are from VirusTotal queries
    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
		JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin LIKE '%VT %';"""
    results = run_query(query)
    vt_queries_total = results[0][0]

    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
		JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin LIKE '%VT %'
        AND drivers.tag = 'known_vulnerable';"""
    results = run_query(query)
    vt_queries_vuln = results[0][0]
    percent_vt_queries_vuln = vt_queries_vuln / known_vulnerable_drivers * 100
    print(f"Amount of drivers from VirusTotal queries: {vt_queries_total} where {vt_queries_vuln} are known vulnerable ({percent_vt_queries_vuln:.2f}% of all)")

    # those downloaded from projects are loldrivers, physmem_drivers and CalendoniaProject
    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
        JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin LIKE 'loldrivers%';"""
    results = run_query(query)
    loldrivers = results[0][0]
    print(f"Amount of drivers from loldrivers: {loldrivers}")

    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
        JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin LIKE 'physmem_drivers%';"""
    results = run_query(query)
    physmem_drivers = results[0][0]
    print(f"Amount of drivers from physmem_drivers: {physmem_drivers}")

    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
        JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin LIKE 'CalendoniaProject%';"""
    results = run_query(query)
    calendonia_drivers = results[0][0]
    print(f"Amount of drivers from CalendoniaProject: {calendonia_drivers}")

    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
        JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin LIKE '%github%';"""
    results = run_query(query)
    project_total = results[0][0]
    print(f"Total amount of drivers from vulnerability projects: {project_total}")

    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
        JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE (public."ogFiles".origin LIKE '%github%')
        AND drivers.tag = 'known_vulnerable'
	 	AND drivers.file IN (SELECT "file" FROM "knownVulnerableDrivers" WHERE "file" IS NOT NULL);"""
    results = run_query(query)
    project_vuln = results[0][0]
    percent_project_vuln = project_vuln / known_vulnerable_drivers * 100
    print(f"and {project_vuln} of those are known vulnerable drivers which covers {percent_project_vuln:.2f}% of all known vulnerable drivers.")
    
    # not all github project drivers with tag known vulnerable are in the knownVulnerableDrivers table
    query = """SELECT files.filename, drivers.tag, files.sha256 FROM "drivers"
            JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
            JOIN files ON files.id = drivers.file
            WHERE (public."ogFiles".origin LIKE '%github%')
            AND drivers.file NOT IN (SELECT "file" FROM "knownVulnerableDrivers" WHERE "file" IS NOT NULL)
        ORDER BY drivers.tag, files.filename;"""
    results = run_query(query)
    print(f"Drivers with tag known_vulnerable {len(list(filter(lambda x: x[1] == 'known_vulnerable', results)))} and total {len(results)} not in known vulnerable list.")
    for name, tag, sha in results:
        print(f"{sha} {tag} {name}")

    # CDC are driver from the CDC
    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
        JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin LIKE '%CDC%';"""
    results = run_query(query)
    cdc_drivers = results[0][0]

    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
        JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin LIKE '%CDC%'
        AND drivers.tag = 'known_vulnerable';"""
    results = run_query(query)
    cdc_vuln = results[0][0]

    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
        JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin LIKE '%CDC%'
        AND drivers.tag = 'vulnerable';"""
    results = run_query(query)
    cdc_vulnerable = results[0][0]
    print(f"Amount of drivers from CDC: {cdc_drivers}, of which {cdc_vuln} are known vulnerable and {cdc_vulnerable} are vulnerable.")
    # in more detail for each client
    query = """WITH cdc_categories AS (
                    SELECT DISTINCT origin
                    FROM public."ogFiles"
                    WHERE public."ogFiles".origin LIKE '%CDC%'
                ),
                categorized_drivers AS (
                    SELECT
                        drivers.file,
                        drivers.tag,
                        CASE 
                            WHEN public."ogFiles".origin IN (SELECT origin FROM cdc_categories) THEN public."ogFiles".origin
                            ELSE 'Other'
                        END AS category
                    FROM drivers
                    JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
                )

                SELECT 
                    category, tag,
                    COUNT(*) AS num_files
                FROM categorized_drivers
                GROUP BY category, tag
                ORDER BY category;"""
    results = run_query(query)
    clients = dict([ (v, f'CDC Client {i}') for i,v in enumerate(set(map(lambda x: x[0], results))) if v != 'Other'])
    # create a table with those values
    total_per_client = {}
    cleaned_results = {}
    for res in results:
        if res[0] == 'Other':
            continue
        client = clients[res[0]]
        if client not in total_per_client:
            total_per_client[client] = res[2]
        else:
            total_per_client[client] += res[2]
        
        if client not in cleaned_results:
            cleaned_results[client] = {
                res[1]: res[2]
            }
        else:
            cleaned_results[client][res[1]] = res[2]
    print(f"CDC Clients: {cleaned_results}")
    print(f"Per CDC Client: {total_per_client}")

    # those with Manual in the name were manually downloaded and added
    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
        JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin LIKE '%anual%';"""
    results = run_query(query)
    manual_drivers = results[0][0]
    print(f"Amount of manually added drivers: {manual_drivers}")

    # all others
    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
        JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin NOT LIKE 'Microsoft Update%'
        AND public."ogFiles".origin NOT LIKE '%VT %'
        AND public."ogFiles".origin NOT LIKE '%github%'
        AND public."ogFiles".origin NOT LIKE '%CDC%'
        AND public."ogFiles".origin NOT LIKE '%anual%';"""
    results = run_query(query)
    other_origin_drivers = results[0][0]

    query = """SELECT COUNT(DISTINCT drivers.file) FROM "drivers"
        JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
        WHERE public."ogFiles".origin NOT LIKE 'Microsoft Update%'
        AND public."ogFiles".origin NOT LIKE '%VT %'
        AND public."ogFiles".origin NOT LIKE '%github%'
        AND public."ogFiles".origin NOT LIKE '%CDC%'
        AND public."ogFiles".origin NOT LIKE '%anual%'
        AND drivers.tag = 'known_vulnerable';"""
    results = run_query(query)
    other_origin_vuln = results[0][0]
    print(f"Amount of drivers from other sources: {other_origin_drivers} of which {other_origin_vuln} are known vulnerable.")
    
    # Thank you ChatGPT! This query was a pain to get right:
    query = """WITH categorized_drivers AS (
                    SELECT
                        drivers.file,
                        COUNT(DISTINCT CASE 
                            WHEN public."ogFiles".origin LIKE '%CDC%' THEN 'CDC'
                            WHEN public."ogFiles".origin LIKE '%github%' THEN 'GitHub Projects'
                            WHEN public."ogFiles".origin LIKE '%VT %' THEN 'VirusTotal'
                            WHEN public."ogFiles".origin LIKE '%anual%' THEN 'Manual'
                            WHEN public."ogFiles".origin LIKE 'Microsoft Update%' THEN 'Microsoft Update'
                            ELSE 'Other'
                        END) AS origin_count,
                        MAX(CASE 
                            WHEN public."ogFiles".origin LIKE '%CDC%' THEN 'CDC'
                            WHEN public."ogFiles".origin LIKE '%github%' THEN 'GitHub Projects'
                            WHEN public."ogFiles".origin LIKE '%VT %' THEN 'VirusTotal'
                            WHEN public."ogFiles".origin LIKE '%anual%' THEN 'Manual'
                            WHEN public."ogFiles".origin LIKE 'Microsoft Update%' THEN 'Microsoft Update'
                            ELSE 'Other'
                        END) AS category
                    FROM drivers
                    JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
                    GROUP BY drivers.file
                )

                SELECT 
                    CASE 
                        WHEN origin_count = 1 THEN category
                        ELSE 'Multiple Origins'
                    END AS final_category,
                    COUNT(*) AS driver_count
                FROM categorized_drivers
                GROUP BY final_category;"""
    results = run_query(query)
    categories = dict(sorted(dict(results).items(), key=lambda item: item[1], reverse=True))
    assert sum(categories.values()) == drivers, f"Sum of categories ({sum(categories.values())}) does not match total amount of drivers ({drivers})."

    # add the percentages to the categories key itself (as X%)
    mod_categories = {}
    for key in categories.keys():
        mod_categories[f"{key} ({categories[key]/drivers*100:.1f}%)"] = categories[key]

    # Plot these resulting categories in a pie chart, the multiple sources in a different type
    plt.style.use('bmh')
    plt.gca().axis("equal")
    fig, ax = plt.subplots(figsize=(6,3))
    if not save_tex:
        ax.set_xlabel("Origin of drivers")
    #plt.xticks(rotation=0)

    # explode=categories.values().apply(lambda x: 0.2 if x < 10 else 0)
    patches, texts = plt.pie(mod_categories.values(), startangle=90)
    fig.legend(patches, mod_categories.keys(), bbox_to_anchor=(1,0.5), loc="center right", fontsize=10, 
           bbox_transform=plt.gcf().transFigure)
    fig.subplots_adjust(left=0.0, bottom=0.1, right=0.8)
    # Set aspect ratio to be equal so that pie is drawn as a circle.
    #plt.axis('equal')

    #fig.tight_layout()
    #plt.show()

    if not save_tex:
        fig.savefig('figures/gatheringResults1.svg')
    else:
        # To save it for the thesis        
        fig.savefig('figures/gatheringResults1.pdf', format="pdf", dpi=1200, bbox_inches="tight", transparent=True)

def gatheringResults2(save_tex=False):
    print("Time gathering of drivers.")

    # all drivers with their creation date
    query = """WITH daily_counts AS (
                    SELECT
                        created_at::date AS date,
                        COUNT(file) AS daily_count
                    FROM drivers
                    GROUP BY created_at::date
                    ORDER BY created_at::date
                )
                SELECT
                    date,
                    SUM(daily_count) OVER (ORDER BY date) AS cumulative_drivers
                FROM daily_counts
                ORDER BY date;"""
    drivers_created = dict(run_query(query))

    # now get a subset of the origin files that are not drivers
    query = f"""WITH sub_set AS (
                    SELECT public."ogFiles".file, public."ogFiles".created_at
                    FROM public."ogFiles"
                    ORDER BY RANDOM()
                    LIMIT (SELECT COUNT(*) * 0.5 FROM public."ogFiles")
                ),
                daily_counts AS (
                    SELECT
                        created_at::date AS date,
                        COUNT(file) AS daily_count
                    FROM sub_set
                    GROUP BY created_at::date
                    ORDER BY created_at::date
                )
                SELECT
                    date,
                    SUM(daily_count) OVER (ORDER BY date) AS cumulative_drivers
                FROM daily_counts
                ORDER BY date;"""
    non_driver_origin_files = dict([ (d, val*2) for d, val in run_query(query) ])

    # adding all vulnerable drivers as x's
    query = """SELECT created_at::date, COUNT(*) FROM "drivers"
                WHERE tag = 'known_vulnerable' OR tag = 'vulnerable' OR tag = 'poced'
                GROUP BY created_at::date
                ORDER BY created_at::date;"""
    known_vulnerable_drivers = dict(run_query(query))
    for key in known_vulnerable_drivers.keys():
        known_vulnerable_drivers[key] = drivers_created[key]

    fig, ax1 = plt.subplots(figsize=(6,3))
    plt.grid(False)
    #ax.set_xlabel("Origin of drivers")
    #plt.xticks(rotation=0)

    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%d/%m'))
    plt.gca().xaxis.set_major_locator(mdates.DayLocator(interval=14))

    color = 'tab:blue'
    if not save_tex:
        ax1.set_xlabel('Time of Addition to Pipeline')
    ax1.set_ylabel('Origin Files', color=color)
    ax1.plot(non_driver_origin_files.keys(), non_driver_origin_files.values(), color=color)
    ax1.tick_params(axis='y', labelcolor=color)
    #ax1.set_ylim(0, 1_100_000)

    def sizeof_fmt(x, pos):
        for x_unit in ['', 'k', 'M', 'G', 'T']:
            if x < 1000:
                if x_unit == 'k' or x_unit == '':
                    return f"{x:3.0f}{x_unit}"
                else:
                    return f"{x:3.1f}{x_unit}"
            x /= 1000
    ax1.yaxis.set_major_formatter(tkr.FuncFormatter(sizeof_fmt))

    ax2 = ax1.twinx()  # instantiate a second Axes that shares the same x-axis

    color = 'tab:green'
    ax2.set_ylabel('Drivers', color=color)  # we already handled the x-label with ax1
    ax2.plot(drivers_created.keys(), drivers_created.values(), color=color)
    ax2.tick_params(axis='y', labelcolor=color)
    #ax2.set_ylim(0, 45000)

    # add the known vulnerable drivers
    ax2.scatter(known_vulnerable_drivers.keys(), known_vulnerable_drivers.values(), color='red', marker='x', s=10, zorder=10)

    # add events in the timeline
    # query to see origins at those dates: SELECT DISTINCT public."ogFiles".origin FROM public."ogFiles" WHERE  public."ogFiles".created_at::date = '2024-04-12'::date
    event_color = 'tab:orange'
    event_color_alpha = 0.45
    trans = ax1.get_xaxis_transform()
    events = [
        (date(2024, 4, 12), '0', 0.7), # CDC Client 1, loldrivers, some manual drivers
        (date(2024, 4, 17), '1', 0.7), # VT Top 100, IG drivers, ARM Windows Drivers
        (date(2024, 4, 30), '2', 0.7), # 3 VT queries
        (date(2024, 5, 22), '3', 0.7), # physmem_drivers, CalendoniaProject
        (date(2024, 5, 28), '4', 0.7), # microsoft updated but only names
        (date(2024, 6, 4), '5', 0.3), # microsoft updated with ven and vid
        (date(2024, 6, 19), '6', 0.3), # fixed microsoft update bug of not enough tmp storage
        (date(2024, 7, 3), '7', 0.3), # started extracting with 7zip
        (date(2024, 7, 16), '8', 0.3), # brute forcing found more drivers
    ]
    for x, label, height in events:
        ax1.axvline(x, color=event_color, alpha=event_color_alpha, linestyle='--', lw=1)
        plt.text(x, height, f' {label}', color=event_color, transform=trans)

    fig.tight_layout()  

    #fig.tight_layout()
    #plt.show()

    if not save_tex:
        fig.savefig('figures/gatheringResults2.svg')
    else:
        # To save it for the thesis        
        fig.savefig('figures/gatheringResults2.pdf', format="pdf", dpi=1200, bbox_inches="tight", transparent=True)

def gatheringResults3(save_tex=False):
    print("General statistics about the collection of files/drivers.")
    def sizeof_fmt(num):
        for x in ['B', 'KB', 'MB', 'GB', 'TB']:
            if num < 1024.0:
                return f"{num:3.2f} {x}"
            num /= 1024
    
    # general statistics

    # total amount of extractions done, both zip and cab extraction
    query = """SELECT COUNT(DISTINCT public."ogFiles".file) FROM public."ogFiles"
                WHERE public."ogFiles".origin LIKE '%extraction%'
                AND public."ogFiles".origin NOT LIKE '%7z%';;"""
    results = run_query(query)
    pure_extractions = results[0][0]
    query = """SELECT COUNT(DISTINCT public."ogFiles".file) FROM public."ogFiles"
                WHERE public."ogFiles".origin LIKE '%extraction%7z%';"""
    results = run_query(query)
    zip_extractions = results[0][0]
    total_extractions = pure_extractions + zip_extractions
    print(f"Total amount of extractions done: {total_extractions} ({pure_extractions} pure, {zip_extractions} zip)")

    # drivers found in extractions:
    query = """SELECT COUNT(DISTINCT drivers.id) FROM drivers
                JOIN public."ogFiles" ON public."ogFiles".file = drivers.file
                WHERE public."ogFiles".origin LIKE '%extraction%';"""
    results = run_query(query)
    drivers_in_extractions = results[0][0]
    query = """SELECT COUNT(DISTINCT drivers.id) FROM drivers;"""
    total_drivers = run_query(query)[0][0]
    percent_of_all_drivers = drivers_in_extractions / total_drivers * 100
    print(f"Drivers found in extractions: {drivers_in_extractions} ({percent_of_all_drivers:.2f}% of all drivers)")

    query = """WITH driver_data AS (
                    SELECT size, architecture, path
                    FROM drivers
                    JOIN files ON drivers.file = files.id
                )
                SELECT 
                    (SELECT COUNT(*) FROM driver_data) AS total_drivers,
                    (SELECT SUM(size) FROM driver_data) AS total_size,
                    architecture, COUNT(*) AS count_per_architecture
                FROM driver_data
                GROUP BY architecture;"""
    results = run_query(query)
    total_drivers = results[0][0]
    total_size_drivers = results[0][1]
    per_architecture = dict([ (arch, count) for _, _, arch, count in results ])
    print(f"{total_drivers} drivers; Total size of collection downloaded {sizeof_fmt(total_size_drivers)}")
    print(f"Per architecture amount of drivers: {per_architecture}")

    query = """WITH file_data AS (
                    SELECT size, path
                    FROM files
                )
                SELECT 
                    (SELECT COUNT(*) FROM file_data) AS total_files,
                    (SELECT SUM(size) FROM file_data) AS total_size,
                    (SELECT SUM(size) FROM file_data WHERE path IS NOT NULL AND LENGTH(path) > 0) AS stored_size
                FROM file_data;"""
    results = run_query(query)
    total_files = results[0][0]
    total_size = results[0][1]
    stored_size = results[0][2]
    print(f"{total_files} files; Total size of collection downloaded {sizeof_fmt(total_size)} ({sizeof_fmt(stored_size)} bytes stored currently after cleanup).")

    # query = """SELECT size, COUNT(size)
    #             FROM files
    #             GROUP BY size
    #             ORDER BY size ASC;"""
    # results = run_query(query)

    # fig, ax = plt.subplots(figsize=(6,3))
    # plt.style.use('bmh')
    # plt.grid(False)
    # #ax.set_xlabel("Origin of drivers")
    # #plt.xticks(rotation=0)

    # ax.bar([s for s, _ in results], [c for _, c in results], alpha=0.5)
    # ax.set_xscale('log')
    # ax.set_yscale('log')
    # ax.set_xlabel('File Size (bytes)')

    # size distribution of the origin files in general and the drivers
    # bins = 50000
    # query = f"""WITH size_bins AS (
    #                 SELECT
    #                     width_bucket(size, 1, (SELECT MAX(size) FROM drivers JOIN files ON drivers.file = files.id), {bins}) AS bin,
    #                     COUNT(*) AS count,
    #                     MIN(size) AS min_size,
    #                     MAX(size) AS max_size
    #                 FROM drivers
    #                 JOIN files ON drivers.file = files.id
    #                 GROUP BY bin
    #             )
    #             SELECT count, max_size
    #             FROM size_bins
    #             ORDER BY bin;"""
    # driver_sizes = run_query(query)
    # query = f"""WITH size_bins AS (
    #                 SELECT
    #                     width_bucket(size, 1, (SELECT MAX(size) FROM public."ogFiles" JOIN files ON public."ogFiles".file = files.id), {bins}) AS bin,
    #                     COUNT(*) AS count,
    #                     MAX(size) AS max_size
    #                 FROM public."ogFiles"
    #                 JOIN files ON public."ogFiles".file = files.id
    #                 GROUP BY bin
    #             )
    #             SELECT count, max_size
    #             FROM size_bins
    #             ORDER BY bin;"""
    # og_sizes = run_query(query)

    # fig, ax = plt.subplots(figsize=(6,3))
    # plt.style.use('bmh')
    # plt.grid(False)
    # #ax.set_xlabel("Origin of drivers")
    # #plt.xticks(rotation=0)

    # ax.hist([c for c, _ in og_sizes], bins=[b for _, b in og_sizes], alpha=0.5, label='Origin Files')
    # ax.hist([c for c, _ in driver_sizes], bins=[b for _, b in driver_sizes], alpha=0.5, label='Drivers')
    # ax.set_xscale('log')
    # ax.set_yscale('log')
    # ax.set_xlabel('File Size (bytes)')
    # ax.set_ylabel('Count')
    # ax.legend()

    # fig.tight_layout()  

    # if not save_tex:
    #     fig.savefig('figures/gatheringResults3.svg')
    # else:
    #     # To save it for the thesis    #     
    #     fig.savefig('figures/gatheringResults3.pdf', format="pdf", dpi=1200, bbox_inches="tight", transparent=True)

    # doing a real distribution plot is waay to slow, so lets calculate the mean and median and amount of files in a few percentiles

    query = """SELECT AVG(size), PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY size) AS median,
                    PERCENTILE_CONT(0.25) WITHIN GROUP (ORDER BY size) AS q1,
                    PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY size) AS q3,
                    PERCENTILE_CONT(0.01) WITHIN GROUP (ORDER BY size) AS p1,
                    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY size) AS p99
                FROM files;"""
    results = run_query(query)
    avg_size = results[0][0]
    median_size = results[0][1]
    q1_size = results[0][2]
    q3_size = results[0][3]
    p1_size = results[0][4]
    p99_size = results[0][5]
    print(f"Files average size: {sizeof_fmt(avg_size)}, Median size: {sizeof_fmt(median_size)}, Q1: {sizeof_fmt(q1_size)}, Q3: {sizeof_fmt(q3_size)}, P1: {sizeof_fmt(p1_size)}, P99: {sizeof_fmt(p99_size)}")
    # biggest file
    query = """SELECT MAX(size) FROM files;"""
    results = run_query(query)
    max_size = results[0][0]
    print(f"Biggest file: {sizeof_fmt(max_size)}")

    query = """SELECT AVG(size), PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY size) AS median,
                    PERCENTILE_CONT(0.25) WITHIN GROUP (ORDER BY size) AS q1,
                    PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY size) AS q3,
                    PERCENTILE_CONT(0.01) WITHIN GROUP (ORDER BY size) AS p1,
                    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY size) AS p99
                FROM files
                JOIN drivers ON drivers.file = files.id;"""
    results = run_query(query)
    driver_avg_size = results[0][0]
    driver_median_size = results[0][1]
    driver_q1_size = results[0][2]
    driver_q3_size = results[0][3]
    driver_p1_size = results[0][4]
    driver_p99_size = results[0][5]
    print(f"Driver average size: {sizeof_fmt(driver_avg_size)}, Median size: {sizeof_fmt(driver_median_size)}, Q1: {sizeof_fmt(driver_q1_size)}, Q3: {sizeof_fmt(driver_q3_size)}, P1: {sizeof_fmt(driver_p1_size)}, P99: {sizeof_fmt(driver_p99_size)}")

if __name__ == "__main__":
    save_tex = False

    import os
    os.system('clear')

    gatheringResults1(save_tex=save_tex)
    gatheringResults2(save_tex=save_tex)
    gatheringResults3(save_tex=save_tex)
    
    # cleanup DB connections
    close_connection()
