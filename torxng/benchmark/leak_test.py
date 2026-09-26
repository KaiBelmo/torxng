#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fail-closed / leak test for the TorXNG stack (stdlib only, run on the host).

    python leak_test.py [--compose-file ../docker-compose.yml] [--base-url http://127.0.0.1:8080]

The stack must be running (docker compose up -d). Checks:

1. core has no default route (internal Docker network)            [asserted]
2. core cannot reach the internet directly by host name           [asserted]
3. core cannot reach the internet directly by IP (no DNS needed)  [asserted]
4. a search through the stack works and leaves via Tor exits      [asserted,
   SKIPPED/partial if the tor_circuit plugin is not installed]
4b. core's SOCKS path (socks5h://tor:9050) exits via Tor; distinct
   SOCKS credentials get distinct circuits (IsolateSOCKSAuth)     [asserted]
4c. tor refuses SOCKS requests that carry a raw IP address, i.e. a
   locally resolved destination (SafeSocks 1)                     [asserted]
5. DNS resolution of example.com inside core                      [info]
6. onion address of the instance                                  [info]
7. the core image refuses to start with a clearnet configuration, with
   the built-in defaults (Tor on 127.0.0.1, where the container runs no
   Tor) and with socks5:// (Tor-only guard, exit code 78; throwaway
   container, no network)                                          [asserted]

Together, checks 1-3, 4c and 7 show three independent layers: the image does
not start without Tor (7), the container has no route around Tor (1-3), and
Tor itself rejects requests whose destination was resolved outside Tor (4c).
The fourth layer, SearXNG's own refusal to run without Tor (Tor-only build),
sits behind the guard (torxng/README.md, section 3).

Exit code 0 if no asserted check failed, 1 otherwise.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
VENV_PYTHON = "/usr/local/searxng/.venv/bin/python"

PASS, FAIL, SKIP, INFO = "PASS", "FAIL", "SKIPPED", "INFO"

# Executed inside core with the venv python. Prints exactly one line:
# "REACHED <status>" (= leak) or "BLOCKED <exception>" (= expected).
PROBE_URL = r"""
import sys, urllib.request
url = sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=5) as r:
        print("REACHED", r.status)
except urllib.error.HTTPError as e:
    print("REACHED", e.code)
except Exception as e:
    print("BLOCKED", type(e).__name__, getattr(e, "reason", e))
"""

# Executed inside core: fetch check.torproject.org through the tor container
# with N distinct SOCKS credentials (= N isolated circuits), print one JSON
# line per credential.
PROBE_TOR_EXIT = r"""
import json, sys
from curl_cffi import requests
for i in range(int(sys.argv[1])):
    proxy = f"socks5h://leaktest-{i}:x@tor:9050"
    try:
        r = requests.get("https://check.torproject.org/api/ip", proxy=proxy, timeout=40)
        print("EXIT", json.dumps(r.json()))
    except Exception as e:
        print("ERROR", type(e).__name__, str(e).splitlines()[0][:120])
"""

# Executed inside core: an IP-literal destination through the SOCKS port.
# With SafeSocks 1 tor must reject it (curl reports a SOCKS error).
PROBE_SAFESOCKS = r"""
from curl_cffi import requests
try:
    r = requests.get("https://1.1.1.1/", proxy="socks5h://leaktest-safesocks:x@tor:9050", timeout=30)
    print("REACHED", r.status_code)
except Exception as e:
    print("REFUSED", type(e).__name__, str(e).splitlines()[0][:160])
"""

PROBE_DNS = r"""
import socket
try:
    infos = socket.getaddrinfo("example.com", 443, proto=socket.IPPROTO_TCP)
    print("RESOLVED", sorted({i[4][0] for i in infos}))
except Exception as e:
    print("NOT RESOLVED", type(e).__name__, e)
"""


class Compose:
    def __init__(self, files: list[Path]):
        self.base = ["docker", "compose"]
        for f in files:
            self.base += ["-f", str(f)]

    def run(self, args: list[str], timeout: float = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*self.base, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )

    def exec(self, service: str, *cmd: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*self.base, "exec", "-T", service, *cmd],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )


def last_line(proc: subprocess.CompletedProcess[str]) -> str:
    out = (proc.stdout or "").strip().splitlines()
    if out:
        return out[-1]
    err = (proc.stderr or "").strip().splitlines()
    return f"(exit {proc.returncode}) " + (err[-1] if err else "no output")


def route_to_ip(hex_le: str) -> str:
    """/proc/net/route stores IPv4 addresses as little-endian hex."""
    try:
        return socket.inet_ntoa(struct.pack("<I", int(hex_le, 16)))
    except (ValueError, struct.error, OSError):
        return hex_le


def check_default_route(compose: Compose) -> tuple[str, str]:
    proc = compose.exec("core", "cat", "/proc/net/route")
    if proc.returncode != 0:
        return FAIL, f"cannot read /proc/net/route: {last_line(proc)}"
    routes = []
    default = False
    for line in proc.stdout.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 3:
            continue
        routes.append(f"{route_to_ip(cols[1])} via {route_to_ip(cols[2])} dev {cols[0]}")
        if cols[1] == "00000000":
            default = True
    if default:
        return FAIL, f"default route present ({', '.join(routes)})"
    return PASS, f"no default route; IPv4 routes: {', '.join(routes) or 'none'}"


def check_blocked(compose: Compose, urls: list[str]) -> tuple[str, str]:
    details = []
    status = PASS
    for url in urls:
        proc = compose.exec("core", VENV_PYTHON, "-c", PROBE_URL, url)
        line = last_line(proc)
        details.append(f"{url} -> {line}")
        if not line.startswith("BLOCKED"):
            status = FAIL
    return status, "; ".join(details)


def http_json(url: str, timeout: float) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def extract_ips(text: str) -> list[str]:
    ips = []
    for token in re.findall(r"[0-9A-Fa-f:.]{7,}", text):
        token = token.strip(".:")
        try:
            ips.append(ipaddress.ip_address(token).compressed)
        except ValueError:
            continue
    return ips


def answer_texts(data: dict) -> list[str]:
    texts = []
    for answer in data.get("answers") or []:
        if isinstance(answer, dict):
            texts.append(str(answer.get("answer") or answer.get("content") or ""))
        else:
            texts.append(str(answer))
    return texts


def check_search_via_tor(base_url: str, timeout: float) -> tuple[str, str]:
    base = base_url.rstrip("/")
    try:
        config = http_json(base + "/config", timeout)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return FAIL, f"GET /config failed: {exc}"
    plugin_names = {str(p.get("name")) for p in config.get("plugins", [])}
    has_circuit_plugin = any("circuit" in name for name in plugin_names)

    if has_circuit_plugin:
        try:
            data = http_json(base + "/search?" + urllib.parse.urlencode({"q": "circuit", "format": "json"}), timeout)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return FAIL, f"search 'circuit' failed: {exc}"
        texts = [t for t in answer_texts(data) if "Tor:" in t]
        if not texts:
            return FAIL, "tor_circuit plugin installed but no circuit answers returned"
        exit_ips = sorted({ip for t in texts for ip in extract_ips(t.split("path:")[0])})
        tor_yes = sum("Tor: yes" in t for t in texts)
        tor_no = [t for t in texts if "Tor: no" in t]
        for t in texts:
            print(f"    {t}")
        if tor_no:
            return FAIL, f"{len(tor_no)} circuit(s) report 'Tor: no'"
        if tor_yes and exit_ips:
            return PASS, f"{tor_yes}/{len(texts)} circuits exit via Tor; exit IPs: {', '.join(exit_ips)}"
        return FAIL, "no 'Tor: yes' answer with an exit IP"

    # interim: plugin not installed -> only prove that searching works
    try:
        data = http_json(base + "/search?" + urllib.parse.urlencode({"q": "test", "format": "json"}), timeout)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return FAIL, f"tor_circuit plugin not installed and search 'test' failed: {exc}"
    n = len(data.get("results") or [])
    if n == 0:
        return FAIL, f"tor_circuit plugin not installed and search 'test' returned no results ({data.get('unresponsive_engines')})"
    return SKIP, (
        f"partial: tor_circuit plugin not installed, exit IPs of the search not verified; search 'test' "
        f"returned {n} results (core has no other route than Tor, see checks 1-3 and 4b)"
    )


def check_tor_exit_from_core(compose: Compose, circuits: int = 3) -> tuple[str, str]:
    proc = compose.exec("core", VENV_PYTHON, "-c", PROBE_TOR_EXIT, str(circuits), timeout=180)
    exits, errors = [], []
    for line in (proc.stdout or "").splitlines():
        if line.startswith("EXIT "):
            try:
                exits.append(json.loads(line[5:]))
            except ValueError:
                errors.append(line)
        elif line.startswith("ERROR"):
            errors.append(line)
    if not exits and not errors:
        return FAIL, f"probe failed: {last_line(proc)}"
    not_tor = [e for e in exits if not e.get("IsTor")]
    ips = [str(e.get("IP")) for e in exits]
    detail = f"exit IPs per SOCKS credential: {', '.join(ips) or 'none'}; distinct: {len(set(ips))}/{len(ips)}"
    if errors:
        detail += f"; errors: {'; '.join(errors)}"
    if not_tor or errors or not exits:
        return FAIL, detail
    return PASS, "all IsTor=true; " + detail


def check_safesocks(compose: Compose) -> tuple[str, str]:
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 5))
    proc = compose.exec("core", VENV_PYTHON, "-c", PROBE_SAFESOCKS, timeout=90)
    line = last_line(proc)
    if not line.startswith("REFUSED"):
        return FAIL, f"IP literal through the SOCKS port: {line}"
    logs = compose.run(["logs", "--no-color", "--since", since, "tor"])
    log_text = logs.stdout or ""
    if "only an IP address" in log_text and "Rejecting" in log_text:
        evidence = "tor log: 'giving Tor only an IP address ... Rejecting.' (SafeSocks)"
    else:
        evidence = "no SafeSocks rejection line in the tor log (tor rate-limits this warning)"
    return PASS, f"IP literal https://1.1.1.1/ via socks5h -> {line}; {evidence}"


GUARD_CASES = {
    "clearnet (using_tor_proxy: false)": "use_default_settings: true\noutgoing:\n  using_tor_proxy: false\n",
    # the built-in default proxy socks5h://127.0.0.1:9050 is the container itself
    "built-in defaults (Tor on 127.0.0.1)": "use_default_settings: true\n",
    "socks5:// proxy (local DNS)": (
        "use_default_settings: true\noutgoing:\n  using_tor_proxy: true\n"
        "  proxies:\n    all://: socks5://tor:9050\n"
    ),
}


def check_guard(image: str) -> tuple[str, str]:
    details = []
    status = PASS
    for name, content in GUARD_CASES.items():
        with tempfile.TemporaryDirectory(prefix="tor-guard-") as tmp:
            Path(tmp, "settings.yml").write_text(content, encoding="utf-8")
            proc = subprocess.run(
                ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
                 "-e", "SEARXNG_SECRET=leak-test", "-v", f"{tmp}:/etc/searxng:ro", image],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False,
            )
        reason = next((ln for ln in (proc.stdout + proc.stderr).splitlines() if "tor-only-guard" in ln), "no guard output")
        details.append(f"{name}: exit {proc.returncode} ({reason.strip()})")
        if proc.returncode != 78:
            status = FAIL
    return status, "; ".join(details)


def check_dns(compose: Compose) -> tuple[str, str]:
    proc = compose.exec("core", VENV_PYTHON, "-c", PROBE_DNS)
    return INFO, last_line(proc)


def check_onion(compose: Compose) -> tuple[str, str]:
    proc = compose.exec("tor", "cat", "/var/lib/tor/searxng/hostname")
    if proc.returncode != 0:
        return INFO, f"hostname not available: {last_line(proc)}"
    return INFO, f"http://{proc.stdout.strip()}/"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--compose-file",
        type=Path,
        action="append",
        help="compose file(s) of the stack (default: ../docker-compose.yml); may be repeated",
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8080", help="URL of the Tor profile (frontend)")
    parser.add_argument("--timeout", type=float, default=90.0, help="HTTP timeout for the search check")
    parser.add_argument("--image", default="torxng/core:latest", help="core image for check 7")
    args = parser.parse_args(argv)

    compose = Compose(args.compose_file or [HERE.parent / "docker-compose.yml"])

    checks = [
        ("1", "no default route in core", lambda: check_default_route(compose)),
        (
            "2",
            "direct egress by host name blocked",
            lambda: check_blocked(compose, ["https://check.torproject.org/api/ip"]),
        ),
        (
            "3",
            "direct egress by IP blocked (no DNS)",
            lambda: check_blocked(compose, ["https://1.1.1.1/", "https://[2606:4700:4700::1111]/"]),
        ),
        ("4", "search works through Tor", lambda: check_search_via_tor(args.base_url, args.timeout)),
        ("4b", "core's SOCKS path exits via Tor", lambda: check_tor_exit_from_core(compose)),
        ("4c", "tor refuses IP-literal SOCKS requests (SafeSocks)", lambda: check_safesocks(compose)),
        ("5", "DNS inside core (example.com)", lambda: check_dns(compose)),
        ("6", "onion address", lambda: check_onion(compose)),
        ("7", "core image refuses a clearnet config (guard)", lambda: check_guard(args.image)),
    ]

    results = []
    for num, name, func in checks:
        print(f"[{num}] {name} ...", flush=True)
        try:
            status, detail = func()
        except (subprocess.SubprocessError, OSError) as exc:
            status, detail = FAIL, f"{type(exc).__name__}: {exc}"
        print(f"[{num}] {status}: {detail}", flush=True)
        results.append((num, name, status, detail))

    print()
    print("| # | check | result | detail |")
    print("|---|---|---|---|")
    for num, name, status, detail in results:
        print(f"| {num} | {name} | {status} | {detail.replace('|', '/')} |")

    failed = [r for r in results if r[2] == FAIL]
    print()
    print("RESULT:", "FAIL" if failed else "PASS", f"({len(failed)} asserted check(s) failed)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
