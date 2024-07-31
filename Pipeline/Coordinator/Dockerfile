FROM python:3.11-slim

RUN mkdir /app /tmp/uploads

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN pip3 install --upgrade pip && \
    pip3 install -r requirements.txt

RUN apt update && apt install -y binutils
#COPY StaticAnalyzer/peresults.py /app/peresults.py

COPY coordinator.py /app/coordinator.py
COPY models.py /app/models.py
COPY peresults.py /app/peresults.py
COPY knownVulnerableDrivers.csv /app/knownVulnerableDrivers.csv
COPY interestingFunctions.csv /app/interestingFunctions.csv

# infinite loop to keep the container running
#ENTRYPOINT ["tail", "-f", "/dev/null"]
ENTRYPOINT [ "python3", "coordinator.py" ]