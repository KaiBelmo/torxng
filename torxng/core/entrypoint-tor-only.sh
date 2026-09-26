#!/bin/sh
# Entry point of the TorXNG core image.
#
# 1. tor_only_guard.py validates the SearXNG settings and exits with code 78
#    (EX_CONFIG) unless every outgoing request is configured to go through Tor
#    (using_tor_proxy + socks5h:// proxies only, none on loopback). There is
#    no way to skip it.
# 2. exec container/entrypoint.sh of this repository (upstream's volume
#    checks and granian, plus a Tor reachability check when SEARXNG_TOR_PROXY
#    is set). SearXNG itself refuses to start without Tor as well.
set -u

/usr/local/searxng/.venv/bin/python /usr/local/searxng/tor_only_guard.py
rc=$?
if [ "$rc" -ne 0 ]; then
    exit "$rc"
fi

exec /usr/local/searxng/entrypoint.sh "$@"
