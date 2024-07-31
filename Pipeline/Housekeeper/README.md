# Housekeeper Module: Storage Cleanup & Extraction

## Overview

The Housekeeper module is designed to manage storage by extracting known archive formats and removing unnecessary files to optimize pipeline storage efficiency.
Given storage constraints, the module extracts archives while also deleting files that are no longer needed.
It operates by downloading files from the Coordinator, which provides an endpoint for specific file types like Microsoft Cabinet archives and installer executables.
Extraction is performed using cabextract and 7-Zip, with the extracted files being reintroduced to the pipeline, maintaining a reference to the original file.

## File Removal

In addition to extraction, Housekeeper removes files deemed unnecessary based on the Coordinator's identification results.
Files unlikely to contain drivers, such as most text files (excluding INF files), are deleted.
Successfully extracted archives are removed from the filesystem, though their database entries are preserved to avoid redundant inspections.
This approach ensures efficient storage management while keeping the pipeline's database up-to-date.