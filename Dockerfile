FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential cmake git \
    libgmp3-dev libprocps-dev python-markdown python3-markdown libboost-all-dev libssl-dev pkg-config libsodium-dev \
    default-jre default-jdk python3 python3-pip

RUN pip3 install pytest py_ecc

WORKDIR /app

RUN git config --global url."https://".insteadOf git:// \
    && git clone https://github.com/HeiniDebes/libsnark-lego.git \
    && cd libsnark-lego \
    && git submodule init && git submodule update \
    && sed -i 's/<libff\/algebra\/fields\/field_utils.hpp>/<libff\/algebra\/field_utils\/field_utils.hpp>/' /app/libsnark-lego/depends/libfqfft/libfqfft/evaluation_domain/domains/basic_radix2_domain_aux.tcc \
    && sed -i 's/<libff\/algebra\/fields\/field_utils.hpp>/<libff\/algebra\/field_utils\/field_utils.hpp>/' /app/libsnark-lego/depends/libfqfft/libfqfft/evaluation_domain/domains/basic_radix2_domain.tcc \
    && mkdir build && cd build \
    && cmake -DMULTICORE=ON -DPERFORMANCE=ON .. \
    && make