# This Dockerfile is a modified version of https://github.com/bskaggs/ghidra-docker/blob/master/Dockerfile

FROM openjdk:11-slim

ARG GHIDRA_VERSION=10.0.4_PUBLIC_20210928
ARG GHIDRA_SHA256=1ce9bdf2d7f6bdfe5dccd06da828af31bc74acfd800f71ade021d5211e820d5e

RUN useradd -m ghidra && \
    mkdir -p /srv/repositories && \
    chown -R ghidra: /srv/repositories
COPY --chown=ghidra:ghidra launch.sh.patch /tmp/

RUN apt-get update \
  && apt-get install -y python3-pip python3-dev \
  && apt-get install unzip \
  && cd /usr/local/bin \
  && ln -s /usr/bin/python3 python \
  && pip3 install --upgrade pip

RUN apt-get install -y libgtk2.0 libidn11 libglu1-mesa

WORKDIR /opt
RUN apt-get update && apt-get install -y wget gettext-base patch && \
    wget -q -O ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.0.4_build/ghidra_${GHIDRA_VERSION}.zip 
RUN echo "${GHIDRA_SHA256} *ghidra.zip" | sha256sum -c && \
    unzip ghidra.zip && \
    rm ghidra.zip && \
    ln -s ghidra* ghidra && \
    cd ghidra && \
    patch -p0 < /tmp/launch.sh.patch && \ 
    rm -rf docs && \
    cd .. && \
    chown -R ghidra: ghidra*

COPY requirements.txt /opt/requirements.txt
RUN pip3 install -r /opt/requirements.txt

# Create /opt/ghidraaas working folder
RUN mkdir -p /opt/ghidraaas
RUN chown ghidra:ghidra /opt/ghidraaas

RUN mkdir -p /opt/ghidra_projects
RUN chown ghidra:ghidra /opt/ghidra_projects

USER ghidra
WORKDIR /opt/ghidraaas

ENV ghidra_home=/opt/ghidra

COPY --chown=ghidra:ghidra flask_api.py flask_api.py
COPY --chown=ghidra:ghidra ghidra_plugins /opt/ghidra_plugins/

RUN mkdir /opt/ghidraaas/config
COPY --chown=ghidra:ghidra config/docker_config.json /opt/ghidraaas/config/config.json

ENTRYPOINT gunicorn -w 2 -t 300 -b 0.0.0.0:8080 flask_api:app
