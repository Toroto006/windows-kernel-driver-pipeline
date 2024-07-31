# UpdateCataloger Module: Fully Automated Importer

## Overview
UpdateCataloger is a fully automated tool for periodically searching and importing new Windows drivers from the Microsoft Update Catalog. It utilizes a modified version of the [get_microsoft_updates.py](./get_microsoft_updates.py) script to enhance functionality with caching and logging features. The caching layer minimizes redundant requests by storing previously retrieved metadata, while detailed logging identifies when search queries reach their result limits, aiding in query refinement.

## Features
- **Automated Search and Download**: Periodically searches for new driver updates using a comprehensive list of search queries.
- **Caching Layer**: Reduces redundant metadata and download requests by caching previously seen results.
- **Logging**: Identifies search queries hitting result limits, helping to narrow search scopes.
- **Extensive Query Coverage**: Includes all possible vendor IDs (0x0000 to 0xFFFF), a curated list of component manufacturers, and specific device-related keywords.

## Acknowledgements
Special thanks to the creators of `get_microsoft_updates.py` for the foundational script on which this module is based upon.

## License
This project is under [GPLv3](../../LICENSE), but the [get_microsoft_updates.py](./get_microsoft_updates.py) file is based on an MIT licensed work, hence under [LICENCE_get_microsoft_updates](./LICENCE_get_microsoft_updates).