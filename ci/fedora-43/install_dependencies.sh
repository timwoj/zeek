#! /usr/bin/env bash

dnf -y install \
    bison \
    ccache \
    cmake \
    cppzmq-devel \
    diffutils \
    findutils \
    flex \
    gawk \
    gcc \
    gcc-c++ \
    git \
    jq \
    libpcap-devel \
    make \
    nodejs-devel \
    openssl \
    openssl-devel \
    procps-ng \
    python3 \
    python3-devel \
    python3-pip\
    sqlite \
    swig \
    which \
    zlib-devel \
    crypto-policies-scripts

pip3 install websockets junit2html
