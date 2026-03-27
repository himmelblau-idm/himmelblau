FROM registry.opensuse.org/opensuse/tumbleweed:latest

LABEL org.opencontainers.image.title="himmelblau playwright orchestrator"
LABEL org.opencontainers.image.description="Runtime Playwright bridge container for himmelblaud-orchestrator"

RUN zypper --non-interactive refresh && \
    zypper --non-interactive dup --allow-vendor-change && \
    zypper --non-interactive install \
        ca-certificates \
        chromium \
        dejavu-fonts \
        fontconfig \
        google-noto-sans-fonts \
        google-noto-serif-fonts \
        liberation-fonts \
        mozilla-nss-tools \
        nodejs \
        npm && \
    fc-cache -f && \
    mkdir -p /opt/himmelblau-orchestrator && \
    npm --prefix /opt/himmelblau-orchestrator init --yes && \
    npm --prefix /opt/himmelblau-orchestrator install --omit=dev playwright-core@1.52.0 && \
    zypper clean --all && \
    rm -rf /var/cache/zypp /root/.npm

COPY src/orchestrator/container/orchestrator-playwright-bridge.mjs /opt/himmelblau-orchestrator/orchestrator-playwright-bridge.mjs

RUN ln -sf /opt/himmelblau-orchestrator/orchestrator-playwright-bridge.mjs /usr/local/bin/orchestrator-playwright-bridge && \
    chmod 0755 /opt/himmelblau-orchestrator/orchestrator-playwright-bridge.mjs && \
    mkdir -p /tmp/orchestrator/profile

ENV PLAYWRIGHT_CHROMIUM=/usr/bin/chromium
