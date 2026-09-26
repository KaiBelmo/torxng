# Tor daemon for the TorXNG stack: SOCKS proxy for SearXNG (the only way out of
# the "isolated" network) and host of the v3 onion service.
FROM docker.io/library/alpine:3.22

# tor: the daemon (Alpine 3.22 community ships the 0.4.9 series)
# curl: used by the container healthcheck (fetches check.torproject.org via SOCKS)
RUN apk add --no-cache tor curl \
 && install -d -o tor -g tor -m 700 /var/lib/tor

COPY torrc /etc/tor/torrc.template
COPY entrypoint.sh /usr/local/bin/tor-entrypoint.sh
# Strip CR in case the files were checked out with CRLF on Windows (the root
# .gitattributes forces LF, this is only a safety net) and make the script
# executable regardless of the file mode on the build host.
RUN sed -i 's/\r$//' /etc/tor/torrc.template /usr/local/bin/tor-entrypoint.sh \
 && chmod 0644 /etc/tor/torrc.template \
 && chmod 0755 /usr/local/bin/tor-entrypoint.sh \
 && TOR_CONTROL_PASSWORD= sh -n /usr/local/bin/tor-entrypoint.sh

# The named volume mounted here keeps the onion service identity key
# (hs_ed25519_secret_key), so the .onion address survives container rebuilds.
VOLUME /var/lib/tor

# Tor never needs root: SocksPort/ControlPort are unprivileged ports and the
# onion service port is virtual. The container runs with a read-only root
# filesystem; the rendered torrc lives in /tmp (tmpfs).
USER tor

ENTRYPOINT ["/usr/local/bin/tor-entrypoint.sh"]
