FROM python:3.11-slim

RUN mkdir /app

RUN apt-get update && apt-get install -y \
    cabextract p7zip-full

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN pip3 install --upgrade pip && \
    pip3 install -r requirements.txt

COPY housekeeper.py /app/housekeeper.py
COPY utils.py /app/utils.py

# infinite loop to keep the container running
#ENTRYPOINT ["tail", "-f", "/dev/null"]
ENTRYPOINT [ "python3", "-O", "housekeeper.py" ]