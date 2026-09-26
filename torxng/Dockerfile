# TorXNG core image: SearXNG from this repository's searx/ tree, locked to
# Tor-only operation and trimmed for low-end machines.
#
# It is assembled like the official image (container/dist.dockerfile: runtime
# base + virtualenv + searx/ + container files), but from pieces:
#   official  = the official image built from the same upstream commit
#               (12f8b6515); source of the virtualenv
#   venv      = its virtualenv minus files never used at runtime
#   trim      = the official searx/ package made identical to this tree,
#               minus files never used at runtime, recompiled; plus this
#               repository's (Tor-only) container/entrypoint.sh and
#               container/settings.template.yml
#   final     = the upstream runtime base (the exact base layer of the
#               official image, pinned by digest) + venv + trim
# so files removed here really are absent from the image, which is smaller
# than the official one (an overlay on top of it could only add layers).
#
# Build contexts (see docker-compose.yml):
#   default context  = repository root; the root .dockerignore only lets
#                      searx/**, container/entrypoint.sh and
#                      container/*.template.* through, which is exactly
#                      what is needed
#   "torxng-core"    = torxng/core/ (Tor-only guard, wrapper entrypoint,
#                      build helper)
# Manual build from the repository root:
#   docker build -f torxng/Dockerfile --build-context torxng-core=torxng/core .

ARG SEARXNG_IMAGE=docker.io/searxng/searxng:2026.9.25-12f8b6515
# Runtime base of that official image (same single layer, checked with
# "docker image inspect ... RootFS.Layers"): Void Linux + Python 3.14, user
# searxng (977:977), /etc/searxng and /var/cache/searxng.
ARG SEARXNG_BASE=docker.io/searxng/base:searxng@sha256:57672c5e1195cec8d2d6022cb06b9fea6e6a01da640d374ccfa6784cabcc5804
ARG SEARXNG_VERSION=2026.9.25-12f8b6515

# ---------------------------------------------------------------------------
FROM ${SEARXNG_IMAGE} AS official

# ---------------------------------------------------------------------------
# virtualenv without build-time-only files (C sources/headers and Cython
# files of lxml, type stubs, test suites, venv activation scripts)
FROM official AS venv
RUN set -eu; \
    site=$(echo ./.venv/lib/python3*/site-packages); \
    find "$site" -type d \( -name tests -o -name test \) -prune -exec rm -rf {} +; \
    find "$site" -type f \( -name '*.pyx' -o -name '*.pxd' -o -name '*.pxi' -o -name '*.c' \
        -o -name '*.h' -o -name '*.pyi' \) -delete; \
    rm -rf "$site/lxml/includes"; \
    rm -f ./.venv/bin/activate*; \
    ./.venv/bin/python -c "import lxml.etree, curl_cffi, babel, flask, granian, typer, pygments, valkey, msgspec"

# ---------------------------------------------------------------------------
FROM official AS trim
# TorXNG source repository: written into searx/version_frozen.py, it is the
# "Source code" link in the footer of every page (AGPL-3.0 section 13: users of
# the network service must be offered the source of this modified version)
ARG TORXNG_GIT_URL=https://github.com/KaiBelmo/torxng
ARG TORXNG_GIT_BRANCH=master

COPY ./searx/ /src/searx/
COPY ./container/entrypoint.sh ./container/settings.template.yml /opt/torxng/container/
COPY --from=torxng-core overlay_sync.py tor_only_guard.py entrypoint-tor-only.sh /opt/torxng/

# 1. overlay_sync.py: make ./searx identical to the tree (CRLF -> LF for a
#    Windows checkout, stale upstream files removed, precompressed static
#    assets kept only where their source is unchanged)
# 2. trim files never used at runtime:
#    - searx/data/lid.176.ftz: fastText language model, dead since fasttext
#      was removed from SearXNG
#    - searx/translations/**/*.po: translation sources; babel/gettext only
#      read the compiled messages.mo next to them
#    - searx/static/**/*.map: JavaScript/CSS source maps (developer tools)
# 3. recompile: the official image uses --invalidation-mode=unchecked-hash,
#    i.e. Python never compares .pyc files with their source; stale bytecode
#    would silently shadow the new code, so every __pycache__ is rebuilt.
RUN set -eu; \
    sed -i 's/\r$//' /opt/torxng/entrypoint-tor-only.sh /opt/torxng/tor_only_guard.py \
        /opt/torxng/container/entrypoint.sh /opt/torxng/container/settings.template.yml; \
    ./.venv/bin/python /opt/torxng/overlay_sync.py /src/searx ./searx; \
    sed -i -E \
        -e "s#^GIT_URL = .*#GIT_URL = \"${TORXNG_GIT_URL}\"#" \
        -e "s#^GIT_BRANCH = .*#GIT_BRANCH = \"${TORXNG_GIT_BRANCH}\"#" \
        ./searx/version_frozen.py; \
    grep -q "^GIT_URL = \"${TORXNG_GIT_URL}\"" ./searx/version_frozen.py; \
    rm -f ./searx/data/lid.176.ftz; \
    find ./searx/translations -type f -name '*.po' -delete; \
    find ./searx/static -type f \( -name '*.map' -o -name '*.map.gz' -o -name '*.map.br' \) -delete; \
    find ./searx -type d -name __pycache__ -prune -exec rm -rf {} +; \
    ./.venv/bin/python -m compileall -q -f -j 0 --invalidation-mode=unchecked-hash ./searx/; \
    chmod 0755 /opt/torxng/entrypoint-tor-only.sh /opt/torxng/container/entrypoint.sh; \
    chmod 0644 /opt/torxng/tor_only_guard.py /opt/torxng/container/settings.template.yml

# ---------------------------------------------------------------------------
FROM ${SEARXNG_BASE}
ARG SEARXNG_IMAGE
ARG SEARXNG_BASE
ARG SEARXNG_VERSION

COPY --chown=977:977 --from=venv /usr/local/searxng/.venv/ ./.venv/
COPY --chown=977:977 --from=trim /usr/local/searxng/searx/ ./searx/
COPY --chown=977:977 --from=trim /opt/torxng/container/entrypoint.sh /opt/torxng/container/settings.template.yml ./
COPY --from=trim /opt/torxng/tor_only_guard.py /opt/torxng/entrypoint-tor-only.sh ./

LABEL org.opencontainers.image.title="TorXNG (Tor-only SearXNG fork)" \
      org.opencontainers.image.description="TorXNG: SearXNG metasearch engine, Tor-only, hardened and trimmed" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.version="${SEARXNG_VERSION}" \
      org.opencontainers.image.base.name="${SEARXNG_BASE}" \
      torxng.searxng.official-image="${SEARXNG_IMAGE}"

# Same runtime environment as container/dist.dockerfile, except that
# SEARXNG_TOR_PROXY is NOT set: the Tor proxy is part of the deployed
# settings.yml (socks5h://tor:9050), which the guard validates as a whole, and
# the built-in default (127.0.0.1) is refused by the guard. Plus tuning for
# small machines:
# - GRANIAN_WORKERS=1: one Python process (each worker holds a full copy of
#   the app, about 80-100 MB RSS)
# - GRANIAN_BLOCKING_THREADS=2 (upstream 4): threads that run the WSGI app,
#   i.e. requests the single worker handles concurrently. A search fans out
#   to the engines in its own threads, so 2 is enough for a personal
#   instance and bounds CPU/memory on a low-end PC; further requests wait in
#   granian's backlog (override in docker-compose.yml if needed).
# - PYTHONDONTWRITEBYTECODE=1: the root filesystem is read-only, Python must
#   not try to write .pyc files (all bytecode is precompiled above)
ENV __SEARXNG_VERSION="${SEARXNG_VERSION}" \
    __SEARXNG_SETTINGS_PATH="$__SEARXNG_CONFIG_PATH/settings.yml" \
    GRANIAN_PROCESS_NAME="searxng" \
    GRANIAN_INTERFACE="wsgi" \
    GRANIAN_HOST="::" \
    GRANIAN_PORT="8080" \
    GRANIAN_WEBSOCKETS="false" \
    GRANIAN_WORKERS="1" \
    GRANIAN_BLOCKING_THREADS="2" \
    GRANIAN_WORKERS_KILL_TIMEOUT="30s" \
    GRANIAN_BLOCKING_THREADS_IDLE_TIMEOUT="5m" \
    PYTHONDONTWRITEBYTECODE="1"

# "*_PATH" ENVs are defined in the base image
VOLUME $__SEARXNG_CONFIG_PATH
VOLUME $__SEARXNG_DATA_PATH

EXPOSE 8080

# Never run as root (uid/gid of the "searxng" user of the base image).
# Root-only steps of the upstream entrypoint (update-ca-certificates, chown)
# are skipped automatically for non-root users.
USER 977:977

# Tor-only guard first (exit 78 unless all egress goes through socks5h://),
# then this repository's container/entrypoint.sh (upstream's, plus a Tor
# reachability check that only runs when SEARXNG_TOR_PROXY is set).
ENTRYPOINT ["/usr/local/searxng/entrypoint-tor-only.sh"]
