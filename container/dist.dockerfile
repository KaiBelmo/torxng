FROM localhost/searxng/searxng:builder AS builder
FROM docker.io/searxng/base:searxng AS dist

COPY --chown=977:977 --from=builder /usr/local/searxng/.venv/ ./.venv/
COPY --chown=977:977 --from=builder /usr/local/searxng/searx/ ./searx/
COPY --chown=977:977 ./container/ ./
COPY --chown=977:977 ./searx/version_frozen.py ./searx/

ARG CREATED="0001-01-01T00:00:00Z"
ARG VERSION="unknown"
ARG VCS_URL="unknown"
ARG VCS_REVISION="unknown"

LABEL org.opencontainers.image.created="$CREATED" \
    org.opencontainers.image.description="SearXNG is a metasearch engine. Users are neither tracked nor profiled. Tor-only build: needs a Tor SOCKS proxy (SEARXNG_TOR_PROXY)." \
    org.opencontainers.image.documentation="https://docs.searxng.org/admin/installation-docker" \
    org.opencontainers.image.licenses="AGPL-3.0-or-later" \
    org.opencontainers.image.revision="$VCS_REVISION" \
    org.opencontainers.image.source="$VCS_URL" \
    org.opencontainers.image.title="SearXNG" \
    org.opencontainers.image.url="https://searxng.org" \
    org.opencontainers.image.version="$VERSION"

# Tor-only build: SearXNG refuses to start without a reachable Tor SOCKS proxy
# with remote DNS. Inside a container, 127.0.0.1:9050 (the built-in default)
# is the container itself, where no Tor runs, so the image points at a Tor
# container named "tor" on the same network instead. SEARXNG_TOR_PROXY
# replaces outgoing.proxies of settings.yml; override it to use another Tor,
# e.g. "docker run --network host -e SEARXNG_TOR_PROXY=socks5h://127.0.0.1:9050".
# entrypoint.sh stops with an explanation if the proxy is not reachable.
# Ready-made stack with Tor: container/docker-compose.yml (torxng/README.md).
ENV __SEARXNG_VERSION="$VERSION" \
    SEARXNG_TOR_PROXY="socks5h://tor:9050" \
    __SEARXNG_SETTINGS_PATH="$__SEARXNG_CONFIG_PATH/settings.yml" \
    GRANIAN_PROCESS_NAME="searxng" \
    GRANIAN_INTERFACE="wsgi" \
    GRANIAN_HOST="::" \
    GRANIAN_PORT="8080" \
    GRANIAN_WEBSOCKETS="false" \
    GRANIAN_BLOCKING_THREADS="4" \
    GRANIAN_WORKERS_KILL_TIMEOUT="30s" \
    GRANIAN_BLOCKING_THREADS_IDLE_TIMEOUT="5m"

# "*_PATH" ENVs are defined in base images
VOLUME $__SEARXNG_CONFIG_PATH
VOLUME $__SEARXNG_DATA_PATH

EXPOSE 8080

ENTRYPOINT ["/usr/local/searxng/entrypoint.sh"]
