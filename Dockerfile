# This Dockerfile is a modified version of https://github.com/bskaggs/ghidra-docker/blob/master/Dockerfile

FROM openjdk:11-slim
MAINTAINER anmarcel "anmarcel@cisco.com"

ARG GHIDRA_VERSION=9.1.2_PUBLIC_20200212
ARG GHIDRA_SHA256=ebe3fa4e1afd7d97650990b27777bb78bd0427e8e70c1d0ee042aeb52decac61

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
    wget -q -O ghidra.zip https://ghidra-sre.org/ghidra_${GHIDRA_VERSION}.zip 
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
