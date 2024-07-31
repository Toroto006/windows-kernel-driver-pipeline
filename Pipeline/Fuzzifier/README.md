# Fuzzifier Module: Automated Dynamic Analysis

## Overview
The Fuzzifier is the final analytical module, designed for fuzz testing to identify vulnerabilities in drivers.
This module requires significant computational resources and relies on the outputs from previous modules.
Utilizing [Intel's kAFL](https://github.com/IntelLabs/kAFL/), the Fuzzifier automates the fuzzing of selected drivers, featuring a custom wrapper and integration with a modified Windows kernel driver fuzzing harness.

## Requirements
- Dedicated hardware meeting specific criteria for kAFL
- kAFL installed with a modified Linux kernel
- Valid kAFL environment setup (i.e. venv as per documentation)
- Access to the Coordinator API

## What the Fuzzifier does
1. Retrieve the next driver fuzzing configuration from the fuzzing queue.
2. Prepare the virtual machine as specified by kAFL.
3. Execute `kAFL fuzz` using Python's subprocess library.
4. Collect and send relevant data to the Coordinator, then clean up for the next target.

Errors during setup or fuzzing are logged, and the configuration is marked as unsuccessful. Successful runs are marked accordingly, and the process repeats for the next driver.

## Modifications to kAFL fuzzing harness
- Templating and recompiling the fuzzing agent for each driver
- Handling and validating fuzzing payloads and IOCTL codes
- Enforcing crashes on detecting potential memory access issues to save payloads for inspection

## License
This project is under [GPLv3](../../LICENSE), but the original file for the [vuln_test.c.template](./vuln_test.c.template) file is the MIT license.