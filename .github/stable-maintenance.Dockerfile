FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS rust-toolchain

FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS maintenance-tools

RUN cargo install --root /opt/maintenance-tools cargo-vet --version 0.10.2 --locked \
    && cargo install --root /opt/maintenance-tools cargo-audit --version 0.22.2 --locked \
    && cargo install --root /opt/maintenance-tools crate2nix --version 0.15.0 --locked

FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

ARG UBUNTU_SNAPSHOT=20260924T000000Z

ENV DEBIAN_FRONTEND=noninteractive \
    HIMMELBLAU_ALLOW_MISSING_SELINUX=1 \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# The minimal Ubuntu base does not include a CA bundle, but apt snapshots are
# served over HTTPS. Bootstrap trust from the pristine pinned Rust base rather
# than the later stage that executes third-party Cargo build scripts.
COPY --from=rust-toolchain \
    /etc/ssl/certs/ca-certificates.crt \
    /etc/ssl/certs/ca-certificates.crt

# Crate sources and the project tree are mounted read-only at runtime. The
# snapshot is deliberately updated only through a reviewed Dockerfile change
# so rebuilding this image selects the same native package revisions.
RUN apt-get update --snapshot "$UBUNTU_SNAPSHOT" \
    && apt-get install --snapshot "$UBUNTU_SNAPSHOT" --yes --no-install-recommends \
        autoconf \
        build-essential \
        ca-certificates \
        checkpolicy \
        cmake \
        gettext \
        git \
        libcap-dev \
        libclang-dev \
        libdbus-1-dev \
        libkrb5-dev \
        libpam0g-dev \
        libpcre2-dev \
        libsqlite3-dev \
        libssl-dev \
        libtool \
        libtss2-dev \
        libudev-dev \
        libunistring-dev \
        pkg-config \
        policycoreutils \
        python3 \
        systemd \
        tpm-udev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=maintenance-tools \
    /opt/maintenance-tools/bin/cargo-vet \
    /opt/maintenance-tools/bin/cargo-audit \
    /opt/maintenance-tools/bin/crate2nix \
    /usr/local/bin/

COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
