#!/usr/bin/env python3
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.legend import Legend
Line2D._us_dashSeq    = property(lambda self: self._dash_pattern[1])
Line2D._us_dashOffset = property(lambda self: self._dash_pattern[0])
Legend._ncol = property(lambda self: self._ncols)
from dbConnection import run_query, close_connection

import numpy as np
import matplotlib.ticker as tkr  

def sizeof_fmt(num, pos):
    for x in ['B', 'KB', 'MB', '', 'TB']:
        if num < 1024.0:
            return f"{num:3.0f}{x}"
        num /= 1024

def sizeof_fmt_si(x, pos):
    for x_unit in ['', 'k', 'M', 'G', 'T']:
        if x < 1000:
            return f"{x:3.0f}{x_unit}"
        x /= 1000

def housekeeperResults(save_tex=False):
    print(f"Housekeeper statistics")

    query = """SELECT files.id, filename, path FROM files 
                JOIN notes ON notes.isfor = files.id
                WHERE filename LIKE '%.xrs'
                AND notes.title = 'magic'
                AND notes.content NOT LIKE '%PE%executable%';"""
    xrs_files_that_are_not_exes = run_query(query)
    print(f"XRS files that are not executables: {len(xrs_files_that_are_not_exes)}")

    query = """SELECT
                LOWER(SPLIT_PART(filename, '.', array_length(string_to_array(filename, '.'), 1))) AS extension,
                COUNT(*) AS extension_count
            FROM files
            WHERE LENGTH(SPLIT_PART(filename, '.', array_length(string_to_array(filename, '.'), 1))) <= 5
            GROUP BY LOWER(SPLIT_PART(filename, '.', array_length(string_to_array(filename, '.'), 1)))
            ORDER BY extension_count DESC;"""
    all_result = run_query(query)

    query = """SELECT 
                LOWER(SPLIT_PART(filename, '.', array_length(string_to_array(filename, '.'), 1))) AS extension, 
                SUM(size) AS total_size
            FROM files
            WHERE LENGTH(SPLIT_PART(filename, '.', array_length(string_to_array(filename, '.'), 1))) <= 5
            GROUP BY extension
            ORDER BY total_size DESC;"""
    all_result_size = run_query(query)

    query = """SELECT COUNT(*) FROM files;"""
    total_files_count = run_query(query)[0][0]
    query = """SELECT SUM(size) FROM files;"""
    total_files_size = run_query(query)[0][0]

    # create the graphic
    X = 15
    amount_files = all_result[:X]
    amount_files_size = all_result_size[:X]
    percent_covered_top_X = sum([row[1] for row in amount_files]) / total_files_count * 100
    percent_covered_top_X_size = sum([row[1] for row in amount_files_size]) / total_files_size * 100
    print(f"Top {X} extensions cover {percent_covered_top_X:.2f}% of all extensions by count and {percent_covered_top_X_size:.2f}% by size")

    # Plot these amount_filess in a bar chart
    plt.grid(False)
    fig, ax = plt.subplots(2, 1, figsize=(5,4))
    plt.xticks(rotation=45)

    extensions = [row[0] for row in amount_files]
    counts = [row[1] for row in amount_files]
    def color_ext(ext):
        if ext in ['xml', 'wtl', 'htm', 'html', 'txt', 'log', 'ini', 'mui', 'mum', 'rdata', 'text', 'data']:
            # any text files except inf are useless
            return 'tab:gray'
        if ext in ['inf', 'cat']:
            return 'tab:green'
        if ext in ['dll', 'sys']:
            return 'tab:red'
        if ext in ['cab', 'exe']:
            return 'tab:orange'
        else:
            return 'tab:blue'
    colors = list(map(color_ext, extensions))

    ax[0].bar(extensions, counts, color=colors)
    ax[0].set_xticklabels(extensions, rotation=30)
    ax[0].set_ylabel('Count')
    #ax[0].set_xlabel('Extension of File')
    ax[0].yaxis.set_major_formatter(tkr.FuncFormatter(sizeof_fmt_si))
    
    # plot the size of the files
    extensions = [row[0] for row in amount_files_size]
    # shorten all too long exten names 

    sizes = [row[1] for row in amount_files_size]
    colors = list(map(color_ext, extensions))
    ax[1].bar(extensions, sizes, color=colors)
    ax[1].set_xticklabels(extensions, rotation=30)
    ax[1].set_ylabel('Size in GB')
    if not save_tex:
        ax[1].set_xlabel('Extension of File')
    ax[1].yaxis.set_major_formatter(tkr.FuncFormatter(sizeof_fmt))

    fig.tight_layout()
    #plt.show()

    if not save_tex:
        fig.savefig('figures/housekeeperResults.svg')
    else:
        # To save it for the thesis
        fig.savefig('figures/housekeeperResults.pdf', format="pdf", dpi=1200, bbox_inches="tight", transparent=True)

if __name__ == "__main__":
    save_tex = False

    import os
    os.system('clear')

    housekeeperResults(save_tex=save_tex)
    
    # cleanup DB connections
    close_connection()
