#!/usr/bin/env python3
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.legend import Legend
Line2D._us_dashSeq    = property(lambda self: self._dash_pattern[1])
Line2D._us_dashOffset = property(lambda self: self._dash_pattern[0])
Legend._ncol = property(lambda self: self._ncols)
from dbConnection import run_query, close_connection

import numpy as np

def interestingFunctions(save_tex=False):
    print(f"Interesting Functions statistics")

    query = """SELECT COUNT(id), id, name FROM public."functions"
                    JOIN "functions_staticResults" ON "functions_staticResults"."functions_id" = "functions".id
                GROUP BY id
                ORDER BY interesting, name;"""
    result = run_query(query)
    all_functions = {}
    for count, id, name in result:
        if id not in all_functions:
            all_functions[name] = {
                "id": id,
                "count": count
            }
    print(f"Interesting functions: {len(all_functions)}")

    query = """SELECT COUNT(DISTINCT "drivers".id), "functions".name FROM "functions"
                    JOIN "functions_staticResults" ON "functions_staticResults"."functions_id" = "functions".id
                    JOIN "staticResults" ON "staticResults".id = "functions_staticResults"."staticResults_id"
                    JOIN drivers ON drivers.static_results = "staticResults".id
                    WHERE drivers.tag = 'known_vulnerable'
                GROUP BY "functions".id;"""
    result = run_query(query)
    known_vulnerable_functions = {}
    for count, name in result:
        known_vulnerable_functions[name] = count
    
    query = """SELECT COUNT(DISTINCT drivers.id) FROM drivers
				JOIN "pathResults" ON drivers.path_results = "pathResults".id
                JOIN files ON files.id = drivers.file
                WHERE drivers.tag = 'known_vulnerable'
                AND "pathResults".type = 'WDM' AND (architecture = 'ARM64' or architecture = 'AMD64');"""
    known_vulnerable_wdm_with_files = run_query(query)[0][0]
    query = """SELECT COUNT(DISTINCT drivers.id) FROM drivers
				JOIN "pathResults" ON drivers.path_results = "pathResults".id
                JOIN files ON files.id = drivers.file
                WHERE drivers.tag = 'known_vulnerable'
                AND "pathResults".type = 'WDF' AND (architecture = 'ARM64' or architecture = 'AMD64');"""
    known_vulnerable_wdf_drivers_with_files = run_query(query)[0][0]
    print(f"Known vulnerable WDM drivers with files: {known_vulnerable_wdm_with_files} and WDF drivers with files: {known_vulnerable_wdf_drivers_with_files}")

    query = """SELECT COUNT(DISTINCT drivers.id) FROM drivers
				JOIN "pathResults" ON drivers.path_results = "pathResults".id
                JOIN files ON files.id = drivers.file
                WHERE drivers.tag = 'known_vulnerable'
                AND "pathResults".type = 'unknown' AND (architecture = 'ARM64' or architecture = 'AMD64');"""
    known_vulnerable_unk_drivers_with_files = run_query(query)[0][0]
    print(f"Known vulnerable unknown drivers with files: {known_vulnerable_unk_drivers_with_files}")

    functions = list(reversed(
        ['MmMapIoSpace', 'MmMapIoSpaceEx', 'IoCreateSymbolicLink', 'ZwMapViewOfSection', 'WdfDeviceCreateSymbolicLink', 'ZwOpenSection', 'IoAllocateMdl', 'SePrivilegeCheck', 'WdfDeviceCreateDeviceInterface', 'IoCreateDevice', 'WdfIoQueueCreate']
    ))

    search_in = ','.join([f"'{fct}'" for fct in functions])

    # first those that are known vulnerabale
    query = f"""SELECT "functions".name, COUNT(DISTINCT "drivers".id) FROM "functions"
                    JOIN "functions_staticResults" ON "functions_staticResults"."functions_id" = "functions".id
                    JOIN "staticResults" ON "staticResults".id = "functions_staticResults"."staticResults_id"
                    JOIN drivers ON drivers.static_results = "staticResults".id
                    JOIN "pathResults" ON drivers.path_results = "pathResults".id
                    WHERE drivers.tag = 'known_vulnerable'
                    AND "pathResults".type = 'unknown'
                    AND "functions".name IN ({search_in})
                GROUP BY "functions".id
                ORDER BY count DESC;"""
    result = run_query(query)
    inters_fct_unknown_driver= dict(result)
    query = f"""SELECT "functions".name, COUNT(DISTINCT "drivers".id) FROM "functions"
                    JOIN "functions_staticResults" ON "functions_staticResults"."functions_id" = "functions".id
                    JOIN "staticResults" ON "staticResults".id = "functions_staticResults"."staticResults_id"
                    JOIN drivers ON drivers.static_results = "staticResults".id
                    JOIN "pathResults" ON drivers.path_results = "pathResults".id
                    WHERE drivers.tag = 'known_vulnerable'
                    AND "pathResults".type = 'WDF'
                    AND "functions".name IN ({search_in})
                GROUP BY "functions".id
                ORDER BY count DESC;"""
    result = run_query(query)
    inters_fct_wdf_driver= dict(result)
    query = f"""SELECT "functions".name, COUNT(DISTINCT "drivers".id) FROM "functions"
                    JOIN "functions_staticResults" ON "functions_staticResults"."functions_id" = "functions".id
                    JOIN "staticResults" ON "staticResults".id = "functions_staticResults"."staticResults_id"
                    JOIN drivers ON drivers.static_results = "staticResults".id
                    JOIN "pathResults" ON drivers.path_results = "pathResults".id
                    WHERE drivers.tag = 'known_vulnerable'
                    AND "pathResults".type = 'WDM'
                    AND "functions".name IN ({search_in})
                GROUP BY "functions".id
                ORDER BY count DESC;"""
    result = run_query(query)
    inters_fct_wdm_driver= dict(result)

    # now the same for all others

    query = """SELECT COUNT(DISTINCT drivers.id) FROM drivers
				JOIN "pathResults" ON drivers.path_results = "pathResults".id
                JOIN files ON files.id = drivers.file
                WHERE drivers.tag != 'known_vulnerable'
                AND "pathResults".type = 'WDM' AND (architecture = 'ARM64' or architecture = 'AMD64');"""
    others_wdm_with_files = run_query(query)[0][0]
    query = """SELECT COUNT(DISTINCT drivers.id) FROM drivers
				JOIN "pathResults" ON drivers.path_results = "pathResults".id
                JOIN files ON files.id = drivers.file
                WHERE drivers.tag != 'known_vulnerable'
                AND "pathResults".type = 'WDF' AND (architecture = 'ARM64' or architecture = 'AMD64');"""
    others_wdf_drivers_with_files = run_query(query)[0][0]
    print(f"Others WDM drivers with files: {others_wdm_with_files} and WDF drivers with files: {others_wdf_drivers_with_files}")

    query = """SELECT COUNT(DISTINCT drivers.id) FROM drivers
				JOIN "pathResults" ON drivers.path_results = "pathResults".id
                JOIN files ON files.id = drivers.file
                WHERE drivers.tag != 'known_vulnerable'
                AND "pathResults".type = 'unknown' AND (architecture = 'ARM64' or architecture = 'AMD64');"""
    others_unk_drivers_with_files = run_query(query)[0][0]

    query = f"""SELECT "functions".name, COUNT(DISTINCT "drivers".id) FROM "functions"
                    JOIN "functions_staticResults" ON "functions_staticResults"."functions_id" = "functions".id
                    JOIN "staticResults" ON "staticResults".id = "functions_staticResults"."staticResults_id"
                    JOIN drivers ON drivers.static_results = "staticResults".id
                    JOIN "pathResults" ON drivers.path_results = "pathResults".id
                    WHERE drivers.tag != 'known_vulnerable'
                    AND "pathResults".type = 'unknown'
                    AND "functions".name IN ({search_in})
                GROUP BY "functions".id
                ORDER BY count DESC;"""
    result = run_query(query)
    others_inters_fct_unknown_driver= dict(result)
    query = f"""SELECT "functions".name, COUNT(DISTINCT "drivers".id) FROM "functions"
                    JOIN "functions_staticResults" ON "functions_staticResults"."functions_id" = "functions".id
                    JOIN "staticResults" ON "staticResults".id = "functions_staticResults"."staticResults_id"
                    JOIN drivers ON drivers.static_results = "staticResults".id
                    JOIN "pathResults" ON drivers.path_results = "pathResults".id
                    WHERE drivers.tag != 'known_vulnerable'
                    AND "pathResults".type = 'WDF'
                    AND "functions".name IN ({search_in})
                GROUP BY "functions".id
                ORDER BY count DESC;"""
    result = run_query(query)
    others_inters_fct_wdf_driver= dict(result)
    query = f"""SELECT "functions".name, COUNT(DISTINCT "drivers".id) FROM "functions"
                    JOIN "functions_staticResults" ON "functions_staticResults"."functions_id" = "functions".id
                    JOIN "staticResults" ON "staticResults".id = "functions_staticResults"."staticResults_id"
                    JOIN drivers ON drivers.static_results = "staticResults".id
                    JOIN "pathResults" ON drivers.path_results = "pathResults".id
                    WHERE drivers.tag != 'known_vulnerable'
                    AND "pathResults".type = 'WDM'
                    AND "functions".name IN ({search_in})
                GROUP BY "functions".id
                ORDER BY count DESC;"""
    result = run_query(query)
    others_inters_fct_wdm_driver= dict(result)

    # caclulate percentages
    perc_fct_wdf = [inters_fct_wdf_driver[fct]/known_vulnerable_wdf_drivers_with_files*100 if fct in inters_fct_wdf_driver else 0 for fct in functions]
    perc_fct_wdm = [inters_fct_wdm_driver[fct]/known_vulnerable_wdm_with_files*100 if fct in inters_fct_wdm_driver else 0 for fct in functions]
    perc_fct_unk = [inters_fct_unknown_driver[fct]/known_vulnerable_unk_drivers_with_files*100 if fct in inters_fct_unknown_driver else 0 for fct in functions]

    perc_others_fct_wdf = [others_inters_fct_wdf_driver[fct]/others_wdf_drivers_with_files*100 if fct in others_inters_fct_wdf_driver else 0 for fct in functions]
    perc_others_fct_wdm = [others_inters_fct_wdm_driver[fct]/others_wdm_with_files*100 if fct in others_inters_fct_wdm_driver else 0 for fct in functions]
    perc_others_fct_unk = [others_inters_fct_unknown_driver[fct]/others_unk_drivers_with_files*100 if fct in others_inters_fct_unknown_driver else 0 for fct in functions]

    for fct, (wdf, wdm, unk) in zip(functions, zip(perc_fct_wdf, perc_fct_wdm, perc_fct_unk)):
        if wdf + wdm + unk < 5:
            print(f"{fct} has ")
            if wdf > 0:
                print(f"\t{inters_fct_wdf_driver[fct]} known vulnerable WDF drivers ({wdf:.2f}%)")
            if wdm > 0:
                print(f"\t{inters_fct_wdm_driver[fct]} known vulnerable WDM drivers ({wdm:.2f}%)")
            if unk > 0:
                print(f"\t{inters_fct_unknown_driver[fct]} known vulnerable unknown drivers ({unk:.2f}%)")

    # vertical bar chart with three per interesting function (WDF/WDM/Unknown),
    # showing percent of known vulnerable drivers have this function
    fig, ax = plt.subplots(1, 2, figsize=(8,3), sharey=True)
    
    # not used are ZwMapViewOfSectionEx, ...

    line_thick = 0.25

    X = np.arange(len(functions))
    ax[0].barh(X, perc_fct_wdf, color='tab:orange', label='WDF', height=line_thick)
    ax[0].barh(X+0.25, perc_fct_wdm, color='tab:green', label='WDM', height=line_thick)
    ax[0].barh(X-0.25, perc_fct_unk, color='tab:blue', label='Unknown', height=line_thick)
    ax[0].set_yticks([i for i in range(len(functions))], functions)
    ax[0].set_xlabel("% known vuln. drivers")

    ax[1].barh(X, perc_others_fct_wdf, color='tab:orange', label='WDF', height=line_thick)
    ax[1].barh(X+0.25, perc_others_fct_wdm, color='tab:green', label='WDM', height=line_thick)
    ax[1].barh(X-0.25, perc_others_fct_unk, color='tab:blue', label='Unknown', height=line_thick)
    ax[1].set_xlabel("% other drivers")

    fig.tight_layout()
    #plt.show()

    if not save_tex:
        fig.savefig('figures/interestingFunctions.svg')
    else:
        # To save it for the thesis
        fig.savefig('figures/interestingFunctions.pdf', format="pdf", dpi=1200, bbox_inches="tight", transparent=True)


if __name__ == "__main__":
    save_tex = False

    import os
    os.system('clear')

    interestingFunctions(save_tex=save_tex)
    
    # cleanup DB connections
    close_connection()
