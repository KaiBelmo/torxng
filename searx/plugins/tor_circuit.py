# SPDX-License-Identifier: AGPL-3.0-or-later
"""A plugin that shows the exits of the Tor circuits used for the outgoing
requests of SearXNG, if the user searches for ``circuit``.

For each entry of the proxy pool of the default network (one entry per Tor
circuit, see ``outgoing.tor_circuits``) one request is sent to
:py:obj:`CHECK_URL`, the requests are sent in parallel.  The answer of the Tor
Project tells whether the request came from a Tor exit and the IP of the exit.

If the ControlPort of the Tor client is configured (``outgoing.tor_control``),
the BUILT exit circuits (purpose ``GENERAL`` or, since Tor 0.4.8, ``CONFLUX_*``,
see :py:obj:`searx.network.tor_control.EXIT_PURPOSES`) are read from it and the exit relay
(nickname and country) and the number of hops of the circuit of each probe are
shown.  The ControlPort is queried after the probes, so the circuits used by
the probes are already built.  The circuit of a probe is found by
:py:obj:`match_circuit`:

- Tor isolates streams with different SOCKS credentials on different circuits
  (``IsolateSOCKSAuth``), the circuit carrying the SOCKS username of the proxy
  URL of the probe is its circuit (exact, even if the exit relay has several
  IPs).

- Only if no circuit carries that username (e.g. proxy URLs without
  credentials), the circuit whose exit relay has the IP of the probe is taken
  (marked in the answer, the IP of the relay in the consensus may differ from
  the IP seen by :py:obj:`CHECK_URL`).

.. attention::

   The guard and middle relays of the circuits are never shown and never
   looked up.  The guard is the entry point of the Tor client into the Tor
   network; when the same Tor daemon also runs the onion service of SearXNG,
   revealing it to visitors is the first step of a *guard discovery* attack
   against the onion service (the attack the vanguards of Tor proposal 292,
   *Mesh-based vanguards*, defend against).  The exit relays are visible to the
   search engines anyway.

The result is cached for :py:obj:`CACHE_TTL` seconds and shared by all users,
repeated queries do not send new requests over Tor or open new ControlPort
sessions.

The plugin is only active when ``outgoing.using_tor_proxy`` is set and it is
not in the default plugin list: the admin has to register it explicitly.  A
``plugins:`` section in the settings replaces the default list, so the other
plugins that should stay available have to be listed as well:

.. code:: yaml

   outgoing:
     using_tor_proxy: true
     proxies:
       all://: socks5h://127.0.0.1:9050
     tor_circuits: 3
     tor_control:
       host: 127.0.0.1
       port: 9051
       password: "..."

   plugins:
     # .. the default plugins from searx/settings.yml ..
     searx.plugins.tor_circuit.SXNGPlugin:
       active: false

Once registered, every user can enable the plugin in the preferences
(``active`` only sets the default).
"""

import typing as t

import dataclasses
import logging
import threading
from ipaddress import ip_address
from time import monotonic
from urllib.parse import unquote, urlsplit

from flask_babel import gettext  # pyright: ignore[reportUnknownVariableType]

from searx import get_setting
from searx.network import Request, get_network, multi_requests
from searx.network.tor_control import EXIT_PURPOSES, Circuit, Relay, TorControl, TorControlError
from searx.plugins import Plugin, PluginInfo
from searx.result_types import EngineResults

if t.TYPE_CHECKING:
    import flask
    from searx.extended_types import SXNG_Request, SXNG_Response
    from searx.plugins import PluginCfg
    from searx.search import SearchWithPlugins

log = logging.getLogger("searx.plugins.tor_circuit")

CHECK_URL = "https://check.torproject.org/api/ip"
"""URL that returns ``{"IsTor": <bool>, "IP": "<ip>"}`` for the requesting IP."""

CACHE_TTL = 60
"""Seconds the result is cached (for all users)."""


@dataclasses.dataclass(frozen=True)
class Probe:
    """Result of the request over one entry of the proxy pool (one circuit)."""

    index: int
    is_tor: bool | None
    ip: str | None  # pylint: disable=invalid-name
    error: str | None


@dataclasses.dataclass(frozen=True)
class ExitInfo:
    """What the plugin keeps of a circuit: the exit relay and the number of
    hops, the guard and middle relays are dropped."""

    id: str
    exit: Relay | None
    hops: int
    socks_username: str = ""
    time_created: str = ""

    @classmethod
    def from_circuit(cls, circ: Circuit) -> "ExitInfo":
        return cls(
            id=circ.id,
            exit=circ.exit,
            hops=len(circ.path),
            socks_username=circ.socks_username,
            time_created=circ.time_created,
        )


@dataclasses.dataclass(frozen=True)
class CircuitResult:
    """A probe and the circuit it was sent over (if known)."""

    probe: Probe
    circuit: ExitInfo | None
    by_ip: bool
    """The circuit was matched by the exit IP (not by the SOCKS username)."""


def probe_timeout() -> float:
    """Timeout of a probe, the request has to pass the Tor network."""
    request_timeout = float(get_setting("outgoing.request_timeout", 3.0))
    extra_proxy_timeout = float(get_setting("outgoing.extra_proxy_timeout", 0) or 0)
    return max(5.0, request_timeout + extra_proxy_timeout)


def probe_exits() -> list[Probe]:
    """Send one request to :py:obj:`CHECK_URL` over each entry of the proxy
    pool of the default network, the requests are sent in parallel.  Never
    raises, a failed request is reported in :py:obj:`Probe.error`."""
    pool_size = len(get_network().proxy_pool)
    timeout = probe_timeout()
    request_list = [
        Request.get(CHECK_URL, proxy_index=i, timeout=timeout, raise_for_httperror=False) for i in range(pool_size)
    ]
    try:
        responses = multi_requests(request_list)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        log.warning("probing the Tor circuits failed: %r", exc)
        return [Probe(i, None, None, type(exc).__name__) for i in range(pool_size)]
    return [_parse_probe(i, resp) for i, resp in enumerate(responses)]


def _parse_probe(index: int, resp: "SXNG_Response | Exception") -> Probe:
    if isinstance(resp, Exception):
        return Probe(index, None, None, type(resp).__name__)
    if resp.status_code != 200:
        return Probe(index, None, None, f"HTTP {resp.status_code}")
    try:
        data = t.cast("dict[str, t.Any]", resp.json())
        is_tor = data.get("IsTor")
        ip = ip_address(str(data["IP"])).compressed
    except Exception:  # pylint: disable=broad-exception-caught
        return Probe(index, None, None, "invalid response")
    return Probe(index, is_tor if isinstance(is_tor, bool) else None, ip, None)


def control_circuits() -> list[ExitInfo]:
    """Returns the BUILT exit circuits (:py:obj:`EXIT_PURPOSES
    <searx.network.tor_control.EXIT_PURPOSES>`) from the ControlPort of the Tor
    client, reduced to their exit relay (IP and country resolved) and number of
    hops.  Returns an empty list if ``outgoing.tor_control.host`` is unset or on
    errors."""
    host = get_setting("outgoing.tor_control.host", "")
    if not host:
        return []
    port = get_setting("outgoing.tor_control.port", 9051)
    password = get_setting("outgoing.tor_control.password", "") or ""
    try:
        with TorControl(str(host), int(port), str(password)) as ctrl:
            return [
                ExitInfo.from_circuit(c) for c in ctrl.circuits() if c.status == "BUILT" and c.purpose in EXIT_PURPOSES
            ]
    except (OSError, TorControlError, ValueError) as exc:
        log.warning("reading the circuits from the Tor ControlPort %s:%s failed: %s", host, port, exc)
        return []


def socks_username(proxies: tuple[tuple[str, str], ...]) -> str:
    """Returns the SOCKS username of the proxy used for an HTTPS request by an
    entry of :py:obj:`searx.network.network.Network.proxy_pool` (the last
    ``all://`` proxy wins over ``https://``, like in the HTTP client), or an
    empty string if the proxy URL has no credentials."""
    all_urls = [url for pattern, url in proxies if not pattern.startswith("http")]
    https_urls = [url for pattern, url in proxies if pattern.startswith("https")]
    urls = all_urls or https_urls
    if not urls:
        return ""
    try:
        username = urlsplit(urls[-1]).username
    except ValueError:
        return ""
    return unquote(username) if username else ""


def _recency(circ: ExitInfo) -> tuple[str, int]:
    return (circ.time_created, int(circ.id) if circ.id.isdigit() else -1)


def match_circuit(circuits: list[ExitInfo], username: str, exit_ip: str | None) -> tuple[ExitInfo | None, bool]:
    """Returns the circuit of a probe and whether it was matched by the exit IP.

    The circuit carrying the SOCKS ``username`` is taken (the most recent one,
    Tor may keep an older circuit of this username).  Only if no circuit
    carries the username, a circuit without SOCKS username whose exit relay has
    the ``exit_ip`` is taken (circuits of other SOCKS usernames are never used
    by this probe)."""
    if username:
        candidates = [c for c in circuits if c.socks_username == username]
        if candidates:
            return max(candidates, key=_recency), False
    if exit_ip:
        candidates = [c for c in circuits if not c.socks_username and c.exit and c.exit.ip == exit_ip]
        if candidates:
            return max(candidates, key=_recency), True
    return None, False


def _collect() -> list[CircuitResult]:
    pool = get_network().proxy_pool
    probes = probe_exits()
    circuits = control_circuits() if any(p.ip for p in probes) else []
    results: list[CircuitResult] = []
    for probe in probes:
        circ, by_ip = None, False
        if probe.ip:
            username = socks_username(pool[probe.index]) if probe.index < len(pool) else ""
            circ, by_ip = match_circuit(circuits, username, probe.ip)
        results.append(CircuitResult(probe, circ, by_ip))
    return results


class _ResultCache:  # pylint: disable=too-few-public-methods

    def __init__(self) -> None:
        self.lock: threading.Lock = threading.Lock()
        self.created: float = 0.0
        self.results: list[CircuitResult] | None = None


_CACHE = _ResultCache()


def circuit_results() -> list[CircuitResult]:
    """Returns the (cached) results of the probes.  The results are collected
    at most once per :py:obj:`CACHE_TTL`, concurrent requests wait for the
    request that collects them."""
    with _CACHE.lock:
        if _CACHE.results is None or monotonic() - _CACHE.created >= CACHE_TTL:
            _CACHE.results = _collect()
            _CACHE.created = monotonic()
        return _CACHE.results


def clear_cache() -> None:
    """Drop the cached results."""
    with _CACHE.lock:
        _CACHE.results = None


def _exit_label(relay: Relay | None) -> str:
    if relay is None:
        return "?"
    label = relay.nickname or relay.fingerprint[:8] or "?"
    if relay.country:
        label = f"{label} ({relay.country.upper()})"
    return label


@t.final
class SXNGPlugin(Plugin):
    """Show the exits of the Tor circuits of the outgoing requests."""

    id = "tor_circuit"
    keywords = ["circuit", "circuits", "tor-circuit", "exit-ip"]

    def __init__(self, plg_cfg: "PluginCfg") -> None:
        super().__init__(plg_cfg)
        self.info = PluginInfo(
            id=self.id,
            name=gettext("Tor circuits"),
            description=gettext(
                "Shows the Tor circuits SearXNG uses for its requests to the search engines:"
                " the exit IP and exit relay of each circuit (guard and middle relays are hidden)."
            ),
            examples=["circuit"],
            preference_section="query",
        )

    def init(self, app: "flask.Flask") -> bool:  # pylint: disable=unused-argument
        return bool(get_setting("outgoing.using_tor_proxy"))

    def post_search(self, request: "SXNG_Request", search: "SearchWithPlugins") -> EngineResults:
        results = EngineResults()

        if search.search_query.pageno > 1:
            return results
        if search.search_query.query.strip().lower() not in self.keywords:
            return results

        circuit_list = circuit_results()
        total = len(circuit_list)
        exits = len({c.probe.ip for c in circuit_list if c.probe.ip})
        results.add(
            results.types.Answer(
                answer=gettext("Tor circuits: %(total)s, distinct exit IPs: %(exits)s", total=total, exits=exits)
            )
        )

        tor_label = {True: gettext("yes"), False: gettext("no"), None: gettext("unknown")}
        for item in circuit_list:
            probe = item.probe
            args: dict[str, t.Any] = {"num": probe.index + 1, "total": total}
            if probe.error or not probe.ip:
                answer = gettext("Circuit %(num)s/%(total)s - request failed (%(reason)s)") % {
                    **args,
                    "reason": probe.error,
                }
                results.add(results.types.Answer(answer=answer))
                continue

            args.update(ip=probe.ip, tor=tor_label[probe.is_tor])
            if item.circuit is None:
                msg = gettext(
                    "Circuit %(num)s/%(total)s - exit IP %(ip)s (Tor: %(tor)s)"
                    " - exit relay unknown (ControlPort not configured or no matching circuit)"
                )
            else:
                args.update(exit=_exit_label(item.circuit.exit), hops=item.circuit.hops)
                if item.by_ip:
                    msg = gettext(
                        "Circuit %(num)s/%(total)s - exit IP %(ip)s (Tor: %(tor)s) - exit relay"
                        " (matched by exit IP) %(exit)s, %(hops)s hops (guard and middle hidden)"
                    )
                else:
                    msg = gettext(
                        "Circuit %(num)s/%(total)s - exit IP %(ip)s (Tor: %(tor)s) - exit relay"
                        " %(exit)s, %(hops)s hops (guard and middle hidden)"
                    )
            results.add(results.types.Answer(answer=msg % args))

        return results
