# Coordinator Module
## Overview
The [Coordinator](./coordinator.py) module is the central component of the pipeline, responsible for coordinating file movement through various analysis modules and storing metadata. It comprises of mainly two containers: a PostgreSQL database container for metadata storage and a Python container running a Flask web server for database access.
Both containers use persistent volumes for data storage, and Flask-SQLAlchemy facilitates interaction with the database via Object-Relational Mapping (ORM).
These containers can be started through the [docker-compose](./docker-compose.yml) file.

## Database Schema and ORM
The database schema, defined using Database Markup Language (DBML) file [databaseDefinition.dbml](./databaseDefinition.dbml), consists of 14 tables to manage a diverse dataset.
DBML simplifies database design by abstracting complexities irrelevant to the schema design. The schema is developed and converted to a PostgreSQL definition using dbdiagram.io.
The ORM model, created with Flask-SQLAlchemy, translates the DBML definition into SQLAlchemy ORM, manually addressing many-to-many relationships and unique multi-indexes.

## Identifying Vulnerable Drivers
The Coordinator module identifies known vulnerable drivers by aggregating data from Microsoft recommended driver block rules, loldrivers.io, and a manually compiled list of vulnerable drivers using the script in [knownVulnerableDrivers](./knownVulnerableDrivers/).

## Exposed Endpoints
The Coordinator module exposes HTTP endpoints for various tasks within the pipeline. These endpoints are categorized into note-taking, file operations, origin file operations, extractions, certificate operations, pathing operations, fuzzing operations, fuzzing queue management, driver filtering, and miscellaneous tasks. Each category supports specific functions, such as updating file information, managing origin files, and coordinating fuzzing processes, ensuring efficient pipeline operation and data retrieval.

## License
This project is under [GPLv3](../../LICENSE), but the [peresults.py](./peresults.py) is based on another published work, hence has its own license at [LICENSE_peresults](./LICENSE_peresults).