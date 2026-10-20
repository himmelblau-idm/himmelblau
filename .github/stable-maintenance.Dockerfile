FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS rust-toolchain
RUN rustup component add rustfmt --toolchain 1.98.0

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
RUN printf '%s\n' \
        'Acquire::Retries "3";' \
        'Acquire::http::Timeout "30";' \
        'Acquire::https::Timeout "30";' \
        'APT::Update::Error-Mode "any";' \
        > /etc/apt/apt.conf.d/80maintenance-network

# Recover individual transient downloads, but stop a persistent outage from
# consuming the whole maintenance job. Never fall back to a live package set.
# A measured cold build fetched 66.6 MB of indexes at 241 kB/s, then needed
# another 220 MB of packages. Allow transfer and unpacking time at that rate.
# Worker failures expose the reason before APT retries (ordinary Ign lines do
# not). Keep only failure messages from worker debug, not its configuration or
# request dumps. Bash pipefail preserves APT failure through the streaming filter.
# Retry an exhausted index refresh only for explicit transient HTTP failures.
# Keep the same signed snapshot and the combined provisioning deadline; never
# retry integrity/configuration failures or replay package installation.
RUN timeout --kill-after=15s 35m /bin/bash -o pipefail -ec ' \
    apt_get() { \
        LC_ALL=C apt-get -o Debug::pkgAcquire::Worker=true "$@" 2>&1 \
            | sed -u -e "/^ -> /d" \
                -e "/^ <- /{ /:400%20URI%20Failure/!d; s/%20/ /g; s/^/apt-download-debug: /; }"; \
    }; \
    apt_update() ( \
        log=$(mktemp) || exit $?; \
        cleanup() { rm -- "$log"; }; \
        trap cleanup EXIT; \
        for delay in 60 120 240 0; do \
            if apt_get update --snapshot "$UBUNTU_SNAPSHOT" | tee "$log"; then \
                exit 0; \
            else \
                statuses=("${PIPESTATUS[@]}"); \
            fi; \
            if [ "${statuses[1]}" -ne 0 ]; then exit "${statuses[1]}"; fi; \
            status=${statuses[0]}; \
            if [ "$status" -ne 100 ] || [ "$delay" -eq 0 ] || ! \
                awk "/^E: Failed to fetch / { seen++; if (\$0 !~ /^E: Failed to fetch [^[:space:]]+[[:space:]]+(408|429|500|502|503|504)[[:space:]]/) bad=1; next } /^E: Some index files failed to download\\./ { next } /^E:/ { bad=1 } END { exit !(seen && !bad) }" "$log"; then \
                exit "$status"; \
            fi; \
            echo "apt-provision: stage=update retry_wait_seconds=$delay"; \
            sleep "$delay" || exit $?; \
        done \
    ); \
    echo "apt-provision: stage=update"; \
    apt_update \
    && echo "apt-provision: stage=install" \
    && apt_get install --snapshot "$UBUNTU_SNAPSHOT" --yes --no-install-recommends \
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
        nodejs \
        pkg-config \
        policycoreutils \
        python3 \
        systemd \
        tpm-udev \
    && rm -rf /var/lib/apt/lists/*'

COPY --from=maintenance-tools \
    /opt/maintenance-tools/bin/cargo-vet \
    /opt/maintenance-tools/bin/cargo-audit \
    /opt/maintenance-tools/bin/crate2nix \
    /usr/local/bin/

COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
