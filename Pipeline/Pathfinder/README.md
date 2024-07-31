# Pathfinder Module: Static Reachability Analysis

## Overview

This is an advanced module built upon and extending VMware Threat Analysis Unit's driver analysis script.
It interacts with the Coordinator module to update driver metadata, including driver frameworks, IOCTL handler addresses, kernel API paths, and WDF functions used.
The module executes the customized IDAPython script using IDA Pro 8.4, with results communicated through a result file managed via Python's subprocess functionality.

## Key Features
- **Enhanced Driver Compatibility**: Supports ARM64 drivers by integrating new [type information libraries](./WinARMTil/) and improving recognition of driver IOCTL handlers for AMD64.
- **Improved Script Execution**: Optimizations include replacing global variable debug conditions and reducing redundant decompilation operations to speed up analysis.
- **Extended Functionality**: Adds features like decompilation context retrieval and WDF import list completion, improving Windows Driver Framework drivers verification speed.
- **IOCTL Code Extraction**: Implements a new feature to identify Input/Output Control Codes using various checks to aid in fuzzing efforts through the Fuzzifier.

## Usage
To use Pathfinder, integrate it with the Coordinator module and run the modified IDAPython script with IDA Pro.
**DO NOT FORGET TO START WITH** `$env:PYTHONOPTIMIZE = 'x'` as failure to do so causes errors.
The results will be written to a specified location, which Pathfinder will then read and process.
For detailed setup and configuration instructions, refer to the original blog post.

## Acknowledgments

Pathfinder is based on and a [modified set of scripts](./VDR/) of the VMware TAU’s [Threat Analysis Unit - Hunting Vulnerable Kernel Drivers](https://blogs.vmware.com/security/2023/10/hunting-vulnerable-kernel-drivers.html) blog post.
We extend our gratitude to VMware TAU for their work that significantly informed the development of this module.

## License
This project is under [GPLv3](../../LICENSE).