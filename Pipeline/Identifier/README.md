# Identifier Module: File Classification

## Overview

The Identifier module is part of a file classification pipeline designed to complete missing metadata and determine file types, with a focus on identifying Windows drivers. It integrates with the Coordinator module to process and store identification results. Building on the Malice File Info Plugin, the Identifier replaces the original web service with a polling loop for unidentified files, leveraging tools like ExifTool and TrID for accurate file type detection.

## Features

- **File Classification**: Uses heuristic methods to determine if a file is a Windows executable based on TrID results, MIME type, file extension, and architecture.
- **Driver Detection**: Examines the Portable Executable (PE) header to identify Windows drivers by checking for imports from `ntoskrnl.exe` or `wdfldr.sys`.
- **Metadata Extraction**: For files identified as Windows drivers, it extracts and stores key strings such as SDDL strings, "PhysicalMemory," and symbolic device names.

## Acknowledgement
The "base image" for this container is [malice-plugin/fileinfo](https://github.com/malice-plugins/fileinfo).

## License
This project is under [GPLv3](../../LICENSE), but because this module is heavily based on malice-plugin/fileinfo any part of that previous project is still under [LICENSE.old](./LICENSE.old).
