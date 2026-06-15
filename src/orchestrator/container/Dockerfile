# syntax=docker/dockerfile:1
FROM registry.opensuse.org/opensuse/tumbleweed:latest

LABEL org.opencontainers.image.title="himmelblau playwright orchestrator"
LABEL org.opencontainers.image.description="Runtime Playwright bridge container for himmelblaud-orchestrator"
LABEL org.himmelblau.orchestrator.bridge_protocol="0.2"

RUN --mount=type=cache,id=himmelblau-orchestrator-zypp-cache,target=/var/cache/zypp \
    zypper --non-interactive refresh && \
    zypper --non-interactive dup --no-recommends --allow-vendor-change && \
    zypper --non-interactive install --no-recommends \
        ca-certificates \
        chromium \
        dejavu-fonts \
        fontconfig \
        google-noto-sans-fonts \
        google-noto-serif-fonts \
        liberation-fonts \
        mozilla-nss-tools \
        nodejs \
        npm

RUN fc-cache -f && \
    mkdir -p /opt/himmelblau-orchestrator && \
    npm --prefix /opt/himmelblau-orchestrator init --yes

RUN --mount=type=cache,id=himmelblau-orchestrator-npm-cache,target=/root/.npm \
    npm --prefix /opt/himmelblau-orchestrator install \
        --omit=dev \
        --no-audit \
        --no-fund \
        --prefer-offline \
        --foreground-scripts \
        playwright-core@1.59.1

COPY orchestrator-playwright-bridge.mjs /opt/himmelblau-orchestrator/orchestrator-playwright-bridge.mjs

RUN ln -sf /opt/himmelblau-orchestrator/orchestrator-playwright-bridge.mjs /usr/local/bin/orchestrator-playwright-bridge && \
    chmod 0755 /opt/himmelblau-orchestrator/orchestrator-playwright-bridge.mjs && \
    mkdir -p /tmp/orchestrator/profile

ENV PLAYWRIGHT_CHROMIUM=/usr/bin/chromium
