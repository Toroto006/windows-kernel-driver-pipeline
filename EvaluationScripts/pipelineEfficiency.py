#!/usr/bin/env python3
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.legend import Legend
Line2D._us_dashSeq    = property(lambda self: self._dash_pattern[1])
Line2D._us_dashOffset = property(lambda self: self._dash_pattern[0])
Legend._ncol = property(lambda self: self._ncols)
from dbConnection import run_query, close_connection

def pipelineEfficiency(save_tex=False):
    print("Pipeline Efficiency for Known Vulnerable Drivers:")
    # Get count of known vulnerable drivers
    query = """SELECT COUNT(*) FROM "knownVulnerableDrivers";"""
    results = run_query(query)
    known_vulnerable_drivers = results[0][0]
    print(f"Count of known vulnerable drivers: {known_vulnerable_drivers}")

    # How many of them have actual files, i.e. are even in the pipeline
    query = """SELECT COUNT(*) FROM "knownVulnerableDrivers" WHERE "file" IS NOT NULL;"""
    results = run_query(query)
    known_vulnerable_drivers_with_files = results[0][0]
    print(f"Count of known vulnerable drivers with files: {known_vulnerable_drivers_with_files}")
    perc_kvd_with_files = known_vulnerable_drivers_with_files / known_vulnerable_drivers * 100
    print(f"Percentage of known vulnerable drivers with files: {perc_kvd_with_files:.2f}%")

    # How many of those files are recognized by the pipeline as drivers, i.e. have a driver with that file id
    query = """SELECT COUNT(*) FROM "drivers" WHERE "file" IN (SELECT "file" FROM "knownVulnerableDrivers" WHERE "file" IS NOT NULL);"""
    results = run_query(query)
    recognized_as_drivers = results[0][0]
    perc_rec_as_drivers = recognized_as_drivers / known_vulnerable_drivers_with_files * 100
    print(f"Of those existing {recognized_as_drivers} were recognized as drivers, which is {perc_rec_as_drivers:.2f}%")

    # How many of those recognized drivers are either ARM64 or AMD64 (the only two that the Pathfinder supports)
    query = """SELECT COUNT(*) FROM "drivers"
        JOIN "files" ON drivers.file = files.id
        WHERE "file" IN (SELECT "file" FROM "knownVulnerableDrivers" WHERE "file" IS NOT NULL)
        AND files."architecture" IN ('ARM64', 'AMD64');"""
    results = run_query(query)
    recognized_as_drivers_arch = results[0][0]
    perc_correct_arch = recognized_as_drivers_arch / recognized_as_drivers * 100
    print(f"Of those recognized {recognized_as_drivers_arch} were either ARM64 or AMD64, which is {perc_correct_arch:.2f}%")

    # for all those that do have a driver with the corresponding file id, how many of them are likely vulnerable
    # where the likely vulnerable means that the pathResults entry for this driver has a ret_code of more than 0
    query = """SELECT COUNT(*) FROM "drivers"
        JOIN "files" ON drivers.file = files.id
        JOIN "pathResults" ON drivers.path_results = public."pathResults".id
        WHERE "file" IN (SELECT "file" FROM "knownVulnerableDrivers" WHERE "file" IS NOT NULL)
        AND files."architecture" IN ('ARM64', 'AMD64')
        AND "pathResults".ret_code > 0;"""
    results = run_query(query)
    ioctl_identified_files = results[0][0]
    perc_ioctl_ident = ioctl_identified_files / recognized_as_drivers_arch * 100
    print(f"Of those recognized {ioctl_identified_files} had their IOCTL handlers identified, which is {perc_ioctl_ident:.2f}%")

    # How many of those with an IOCTL handler were identified as likely vulnerable
    query = """SELECT COUNT(*) FROM "drivers"
        JOIN "files" ON drivers.file = files.id
        JOIN "pathResults" ON drivers.path_results = public."pathResults".id
        WHERE "file" IN (SELECT "file" FROM "knownVulnerableDrivers" WHERE "file" IS NOT NULL)
        AND files."architecture" IN ('ARM64', 'AMD64')
        AND "pathResults".ret_code > 100;"""
    results = run_query(query)
    vulnerable_files = results[0][0]
    perc_likely_vul = vulnerable_files / recognized_as_drivers_arch * 100
    print(f"Of those with an IOCTL handler {vulnerable_files} were identified as likely vulnerable, which is {perc_likely_vul:.2f}%")

    #print(f"This means of the orignal {known_vulnerable_drivers} known vulnerable drivers, {known_vulnerable_drivers_with_files} were in the pipeline, {recognized_as_drivers} were recognized as drivers, {recognized_as_drivers_arch} were ARM64 or AMD64, {ioctl_identified_files} had their IOCTL handlers identified and {vulnerable_files} were identified as likely vulnerable.")
    perc_total_with_files_likely_vul = vulnerable_files / known_vulnerable_drivers_with_files * 100
    print(f"This means of the existing {known_vulnerable_drivers_with_files} known vulnerable drivers were {vulnerable_files} identified as likely vulnerable: {perc_total_with_files_likely_vul:.2f}%")

    # Plot these results in a bar chart
    fig, ax = plt.subplots(figsize=(6,3))
    if not save_tex:
        ax.set_xlabel("Amount of Drivers")

    # add label rotation
    plt.xticks(rotation=0)
    plt.tick_params(left = False) 

    # Data
    steps = ['Known Vulnerable Drivers', 'Have Files Saved', 'Recognized as Driver', 'Are ARM64 or AMD64', 'Identified IOCTL handlers', 'Deemed Likely Vulnerable']
    values = [known_vulnerable_drivers, known_vulnerable_drivers_with_files, recognized_as_drivers, recognized_as_drivers_arch, ioctl_identified_files, vulnerable_files]
    ax.barh(list(reversed(steps)), list(reversed(values)), color='tab:blue')

    # write the percentage values on top of the bars
    percentage = list(reversed([100, perc_kvd_with_files, perc_rec_as_drivers, perc_correct_arch, perc_ioctl_ident, perc_likely_vul]))
    for i, v in enumerate(percentage):
        ax.text(28, i, f"{v:.1f}%", va='center')
        
    fig.tight_layout()
    #plt.show()

    if not save_tex:
        fig.savefig('figures/pipelineEfficiency.svg')
    else:
        # To save it for the thesis        
        fig.savefig('figures/pipelineEfficiency.pdf', format="pdf", dpi=1200, bbox_inches="tight", transparent=True)


if __name__ == "__main__":
    save_tex = False

    import os
    os.system('clear')

    pipelineEfficiency(save_tex=save_tex)
    
    # cleanup DB connections
    close_connection()
