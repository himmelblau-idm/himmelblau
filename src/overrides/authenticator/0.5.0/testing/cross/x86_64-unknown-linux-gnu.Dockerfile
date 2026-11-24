FROM rustembedded/cross:x86_64-unknown-linux-gnu-0.2.1@sha256:9f368a726a8ba08559451cd64160f7d2b47f6180ad024a46e31d29cc85dd81ff

RUN apt-get update && \
    apt-get install --assume-yes libudev-dev

RUN pkg-config --list-all && pkg-config --libs libudev && \
    pkg-config --modversion libudev