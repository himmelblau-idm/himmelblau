FROM rustembedded/cross:powerpc64le-unknown-linux-gnu-0.2.1@sha256:a5e4bbca797a6e00ea65377b82384056ca07a7b334c578b168a1764299069fcd

RUN dpkg --add-architecture powerpc64le && \
    apt-get update && \
    apt-get install --assume-yes libudev-dev

RUN pkg-config --list-all && pkg-config --libs libudev && \
    pkg-config --modversion libudev