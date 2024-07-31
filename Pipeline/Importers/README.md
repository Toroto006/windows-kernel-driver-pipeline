# Driver Importers

## Overview

This folder includes a set of tools designed to import Windows kernel drivers to the pipeline.
These include the Manual Importer, VirusTotal Importer and CDC Importer.

## Importers

### Manual Importer
The [Manual Importer](./recursiveFileImporter.py) allows users to recursively search a specified folder for driver files and upload any new files not already present in the pipeline.
The user defines the origin string for each file, and duplicate files are linked to existing entries, updating only the origin if it’s new.
This importer supports collecting drivers from various sources, including manual downloads and operational Windows systems.

### VirusTotal Importer
The [VirusTotal Importer](./smartVTscrape.py) utilizes the VirusTotal file download API to retrieve Windows drivers that match specific queries.
This method is optimized to minimize API usage by avoiding redundant downloads.

### CDC Importer
The CDC importer is nothing more than a combination of a [parser](./gatherMDEfiles.py) for the Microsoft XDR result and then the VirusTotal importer.