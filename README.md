# Efficient Pipelining for Windows Driver Vulnerability Research

## Overview

This repository contains the source code for the system developed to enhance Windows kernel driver security during my master thesis.
The system is designed to continuously gather, analyze, and evaluate Windows device drivers for potential vulnerabilities and present these results to security researchers in an efficient way.

An export of my final presentation can be found at [FinalPresentation](./FinalPresentation.pdf), whereas the thesis itself is [here](./MasterThesis.pdf).

## Motivation

The Windows operating system's widespread use in business operations necessitates robust security measures, particularly concerning kernel drivers.
These drivers operate with high-level privileges and are a prime target for attacks due to their critical role in interfacing applications with hardware components.
Despite Microsoft's driver signing requirements and use of frameworks like Windows Driver Model, Windows Driver Framework, and Driver Module Framework, vulnerabilities in these drivers can still be exploited by threat actors. 

## Challenges
1. **Collection and Centralization**: There is no centralized repository for all Windows drivers, and existing block lists are incomplete, complicating the identification of already known vulnerable drivers.
2. **Dynamic and Static Analysis**: Executing drivers for dynamic analysis requires specific environments, while static analysis is hindered by driver complexity and lack of ARM architecture support.
3. **Optimization of Research Time**: Avoiding false positives and negatives is crucial to efficiently allocate security researchers time and resources.

## Solution

The solution implemented in this thesis involves a system that:

1. **Continuous Collection**: Gathers drivers from multiple sources.
2. **Vulnerability Analysis**: Checks drivers against known vulnerabilities and applies both static and dynamic analysis techniques, through IDA Pro scripting and automated fuzz testing with kAFL.
3. **Prioritization**: Highlights the most likely vulnerable drivers for researchers to focus on.

The system has processed over 27,000 drivers during the time of the thesis.
140 were manually reviewed, resulting in the identification of 14 unique drivers with 28 vulnerabilities --- four of which were already published, and ten were previously unknown.

## Repository Contents

- [Pipeline](./Pipeline/): The implementation of the driver collection and analysis system.
- [EvaluationScripts](./EvaluationScripts/README.md): Implementation of statistic and result figure generation for the thesis.

## Industry Collaboration

The project benefited from collaboration with industry experts, including access to a Security Operations Center (SOC) team and an operationally active Red Team, which provided invaluable resources and insights.

## Contribution
Contributions are welcome. Please follow the guidelines outlined in [CONTRIBUTING.md](./CONTRIBUTING.md) for submitting issues, feature requests, or pull requests.

## License

This project is licensed under the GPLv3 License whereever possible. See the [LICENSE](./LICENSE) file for details.
Some parts of this work are further under the MIT License because previous work on which these parts are based on are under MIT.