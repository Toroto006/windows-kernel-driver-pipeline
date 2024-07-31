FROM --platform=linux/amd64 python:3.9.19-slim-bullseye

RUN apt update && \
    apt install -y texlive dvipng texlive-latex-extra texlive-fonts-recommended cm-super

RUN mkdir /evaluation
COPY . /evaluation

RUN python3 -m pip install -r /evaluation/requirements.txt
WORKDIR /evaluation

ENTRYPOINT [ "tail", "-f", "/dev/null" ]
#ENTRYPOINT [ "python3", "runAll.py" ]