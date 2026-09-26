# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tor-only guard of the TorXNG core image.

Runs before SearXNG starts (see entrypoint-tor-only.sh). It loads and validates
the SearXNG settings exactly like the application does (``import searx``, which
reads /etc/searxng/settings.yml and applies the environment overrides) but does
NOT import ``searx.webapp`` (no network, no engines are loaded).

The container refuses to start (exit code 78, EX_CONFIG) with a one-line
reason unless ALL outgoing traffic is configured to go through Tor:

- ``outgoing.using_tor_proxy`` is true,
- ``outgoing.proxies`` is set, covers both http and https requests and every
  proxy URL starts with ``socks5h://`` (host names resolved by the Tor exit),
- every ``outgoing.networks[*].proxies`` and every engine-level ``proxies`` or
  ``network: {proxies: ...}`` uses only ``socks5h://`` URLs,
- no proxy points to a loopback address: no Tor runs inside the core container
  (the built-in default of this branch, ``socks5h://127.0.0.1:9050``, is meant
  for a local Tor daemon with ``make run``; here Tor is the ``tor`` service),
- the environment variable ``SEARXNG_TOR_PROXY`` (which replaces
  ``outgoing.proxies``), if set, is a ``socks5h://`` URL,
- ``outgoing.verify`` is not false (TLS certificates of the engines must be
  verified, otherwise a malicious exit relay could read and modify traffic),
- ``outgoing.tor_control.host`` is empty: in this deployment SearXNG must not
  hold Tor ControlPort credentials (full control over tor, e.g. choosing the
  guard; the ControlPort only listens on 127.0.0.1 inside the tor container),
- none of the proxy environment variables ``http_proxy``, ``https_proxy``,
  ``all_proxy``, ``no_proxy`` (any letter case) is set: libcurl honours them,
  and ``NO_PROXY`` would make it bypass the SOCKS proxy for matching hosts.

There is deliberately no switch to disable this check: a clearnet instance is
a different product (the benchmark uses the stock upstream image for that). The
SearXNG code of this branch enforces Tor as well (it refuses to start without
``using_tor_proxy`` and socks5h:// proxies); the guard is the stricter,
deployment-specific layer in front of it and fails before any code runs.
"""

from __future__ import annotations

import ipaddress
import os
import sys
import typing as t
from urllib.parse import urlsplit

EX_OK = 0
EX_CONFIG = 78
PREFIX = "tor-only-guard"
PROXY_ENV_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
TOR_PROXY_ENV = "SEARXNG_TOR_PROXY"


class GuardError(Exception):
    """Configuration does not guarantee Tor-only egress."""


def iter_proxy_urls(proxies: t.Any, where: str) -> t.Iterator[tuple[str, str]]:
    """Yield ``(pattern, url)`` for a SearXNG ``proxies`` value (str, or dict
    of pattern -> str | list[str])."""
    if isinstance(proxies, str):
        yield "all://", proxies
        return
    if isinstance(proxies, dict):
        for pattern, urls in proxies.items():
            if isinstance(urls, str):
                urls = [urls]
            if not isinstance(urls, (list, tuple)) or not urls:
                raise GuardError(f"{where}: proxies[{pattern!r}] must be a URL or a non-empty list of URLs")
            for url in urls:
                yield str(pattern), url
        return
    raise GuardError(f"{where}: unsupported proxies value of type {type(proxies).__name__}")


def is_loopback_host(host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_proxy_host(url: str, where: str) -> None:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError as exc:
        raise GuardError(f"{where}: proxy URL is not valid ({exc})") from None
    if not host:
        raise GuardError(f"{where}: proxy URL has no host (expected socks5h://tor:9050)")
    if is_loopback_host(host):
        # With use_default_settings the proxies of settings.yml are MERGED with
        # the built-in {"all://": "socks5h://127.0.0.1:9050"}: only an "all://"
        # entry replaces the default.
        raise GuardError(
            f"{where}: proxy host {host} is a loopback address, but no Tor runs inside the core container "
            "(the built-in default all:// socks5h://127.0.0.1:9050 is for a local Tor daemon) - "
            "set the 'all://' proxy to socks5h://tor:9050"
        )


def check_proxies(proxies: t.Any, where: str, require_full_coverage: bool) -> None:
    covered: set[str] = set()
    count = 0
    for pattern, url in iter_proxy_urls(proxies, where):
        count += 1
        if not isinstance(url, str) or not url.startswith("socks5h://"):
            raise GuardError(f"{where}: proxy {url!r} is not a socks5h:// URL (Tor with remote DNS is required)")
        check_proxy_host(url, where)
        # same pattern semantics as searx.network.client._proxy_kwargs
        if pattern.startswith("https"):
            covered.add("https")
        elif pattern.startswith("http"):
            covered.add("http")
        else:
            covered.update(("http", "https"))
    if count == 0:
        raise GuardError(f"{where}: proxies is empty")
    if require_full_coverage and covered != {"http", "https"}:
        missing = ", ".join(sorted({"http", "https"} - covered))
        raise GuardError(f"{where}: proxies do not cover {missing} requests (use the 'all://' pattern)")


def check_environment(environ: t.Mapping[str, str]) -> None:
    found = sorted(name for name in environ if name.lower() in PROXY_ENV_VARS)
    if found:
        raise GuardError(
            f"proxy environment variable(s) set: {', '.join(found)} (libcurl would honour them; "
            "NO_PROXY bypasses the SOCKS proxy) - remove them from the container environment"
        )
    tor_proxy = environ.get(TOR_PROXY_ENV)
    if tor_proxy is not None and not tor_proxy.startswith("socks5h://"):
        raise GuardError(
            f"{TOR_PROXY_ENV} is set but is not a socks5h:// URL (Tor with remote DNS is required, "
            "e.g. socks5h://tor:9050)"
        )
    if tor_proxy is not None:
        check_proxy_host(tor_proxy, TOR_PROXY_ENV)


def check(settings: dict[str, t.Any]) -> str:
    outgoing = settings.get("outgoing") or {}

    if outgoing.get("verify") is False:
        raise GuardError("outgoing.verify must not be false (TLS certificates of the engines must be verified)")

    tor_control = outgoing.get("tor_control") or {}
    if isinstance(tor_control, dict) and str(tor_control.get("host") or "").strip():
        raise GuardError(
            "outgoing.tor_control.host must be empty: SearXNG must not hold Tor ControlPort credentials "
            "in this deployment (use torxng/benchmark/show_circuits.py on the host instead)"
        )

    if outgoing.get("using_tor_proxy") is not True:
        raise GuardError("outgoing.using_tor_proxy must be true")

    proxies = outgoing.get("proxies")
    if not proxies:
        raise GuardError("outgoing.proxies is not set (expected socks5h://tor:9050)")
    check_proxies(proxies, "outgoing.proxies", require_full_coverage=True)

    for name, network in (outgoing.get("networks") or {}).items():
        if isinstance(network, dict) and network.get("proxies"):
            check_proxies(network["proxies"], f"outgoing.networks.{name}.proxies", require_full_coverage=False)
        if isinstance(network, dict) and network.get("using_tor_proxy") is False:
            raise GuardError(f"outgoing.networks.{name}.using_tor_proxy must not be false")

    for engine in settings.get("engines") or []:
        name = engine.get("name", "?")
        if engine.get("proxies"):
            check_proxies(engine["proxies"], f"engine {name!r} proxies", require_full_coverage=False)
        network = engine.get("network")
        if isinstance(network, dict):
            if network.get("proxies"):
                check_proxies(network["proxies"], f"engine {name!r} network.proxies", require_full_coverage=False)
            if network.get("using_tor_proxy") is False:
                raise GuardError(f"engine {name!r} network.using_tor_proxy must not be false")

    urls = sorted({url for _, url in iter_proxy_urls(proxies, "outgoing.proxies")})
    return f"OK: using_tor_proxy=true, outgoing.proxies={', '.join(urls)}"


def main() -> int:
    try:
        check_environment(os.environ)
    except GuardError as exc:
        print(f"{PREFIX}: REFUSING TO START: {exc}", file=sys.stderr, flush=True)
        return EX_CONFIG

    try:
        # loads + validates settings.yml (and SEARXNG_* env overrides)
        import searx  # pylint: disable=import-outside-toplevel
    except Exception as exc:  # pylint: disable=broad-except
        reason = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        print(f"{PREFIX}: REFUSING TO START: invalid SearXNG settings ({reason})", file=sys.stderr, flush=True)
        return EX_CONFIG

    try:
        message = check(searx.settings)
    except GuardError as exc:
        print(f"{PREFIX}: REFUSING TO START: {exc}", file=sys.stderr, flush=True)
        return EX_CONFIG
    print(f"{PREFIX}: {message}", flush=True)
    return EX_OK


if __name__ == "__main__":
    sys.exit(main())
