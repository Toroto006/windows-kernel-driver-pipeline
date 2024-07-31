FROM python:3.11-slim

RUN pip3 install beautifulsoup4 requests

RUN mkdir /catalogUpdater
WORKDIR /catalogUpdater

COPY catalogUpdater.py /catalogUpdater/
COPY get_microsoft_updates.py /catalogUpdater/
COPY utils.py /catalogUpdater/

# wait
#ENTRYPOINT [ "tail", "-f", "/dev/null" ]
ENTRYPOINT [ "python3", "-O", "catalogUpdater.py" ]