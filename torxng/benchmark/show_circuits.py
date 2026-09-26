#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator tool: show the full paths (guard -> middle -> exit) of the Tor
circuits of the TorXNG stack (stdlib only, run on the host).

    python show_circuits.py [--compose-file ../docker-compose.yml] [--password-file ../secrets/tor_control_password] [--all] [--no-lookup]

OPERATOR ONLY, never expose this output on a web page: the guard relay is
the entry point of every circuit of the onion service's tor client, and
knowing it is the first step of a guard discovery attack (an adversary who
learns the guard can try to observe or compromise it to deanonymise the
service). That is why SearXNG itself has no ControlPort access in this
deployment and its "circuit" answer shows only the exit side.

How it works: the ControlPort listens on 127.0.0.1:9051 INSIDE the tor
container. The script runs ``docker compose exec -T tor nc 127.0.0.1 9051``
and writes the control session (AUTHENTICATE, GETINFO, QUIT) to its stdin, so
the password never appears in a process argument list. The password is read
on the host from torxng/secrets/tor_control_password, the same file that
docker-compose.yml mounts into the tor container as the Compose secret
/run/secrets/tor_control_password.

Shown by default: BUILT circuits with purpose GENERAL or CONFLUX_LINKED
(Tor 0.4.8+ builds exit circuits as conflux sets of two linked legs). The
SOCKS username (sxng-<i>) identifies SearXNG's isolated circuit pool entry
(outgoing.tor_circuits). --all also lists onion service circuits.
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STACK_DIR = HERE.parent
TOR_CONTROL_PY = STACK_DIR.parent / "searx" / "network" / "tor_control.py"
EXIT_PURPOSES = {"GENERAL", "CONFLUX_LINKED"}


def load_tor_control():
    """Load searx/network/tor_control.py by path (stdlib-only module, no need
    to install SearXNG on the host)."""
    spec = importlib.util.spec_from_file_location("torxng_tor_control", TOR_CONTROL_PY)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {TOR_CONTROL_PY}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def read_password(path: Path) -> str:
    """Read the ControlPort password file (same rules as tor-entrypoint.sh:
    surrounding CR/LF stripped, UTF-8/ASCII)."""
    if path.is_dir():
        raise SystemExit(
            f"{path} is a directory: Docker creates one when the secret file is missing at 'docker compose up'. "
            "Remove it, create the file (see torxng/README.md) and recreate the tor container."
        )
    if not path.is_file():
        raise SystemExit(f"{path} does not exist (the ControlPort is disabled without it, see torxng/README.md)")
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in raw:
        raise SystemExit(f"{path} is UTF-16 encoded; write it as ASCII/UTF-8 (see torxng/README.md)")
    password = raw.decode("utf-8-sig").strip("\r\n")
    if not password:
        raise SystemExit(f"{path} is empty (the ControlPort is disabled)")
    return password


def quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def control_session(compose: list[str], password: str, commands: list[str]) -> list[str]:
    """Run one control session inside the tor container, return the reply lines."""
    script = "".join(f"{line}\r\n" for line in [f"AUTHENTICATE {quote(password)}", *commands, "QUIT"])
    proc = subprocess.run(
        [*compose, "exec", "-T", "tor", "nc", "-w", "15", "127.0.0.1", "9051"],
        input=script,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    lines = [line.rstrip("\r") for line in proc.stdout.splitlines()]
    if not lines:
        raise SystemExit(f"no reply from the ControlPort (exit {proc.returncode}): {proc.stderr.strip()}")
    if not lines[0].startswith("250"):
        raise SystemExit(f"ControlPort refused the session: {lines[0]}")
    return lines


def getinfo_values(lines: list[str]) -> dict[str, list[str]]:
    """Parse GETINFO replies: ``250-key=value`` and ``250+key=`` + data lines + ``.``."""
    values: dict[str, list[str]] = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(("250-", "250+")) and "=" in line:
            key, _, value = line[4:].partition("=")
            if line[3] == "+":
                data = []
                i += 1
                while i < len(lines) and lines[i] != ".":
                    data.append(lines[i][1:] if lines[i].startswith("..") else lines[i])
                    i += 1
                values[key] = data
            else:
                values[key] = [value]
        elif line.startswith(("5", "4")):
            values.setdefault("__errors__", []).append(line)
        i += 1
    return values


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--compose-file", type=Path, default=STACK_DIR / "docker-compose.yml")
    parser.add_argument(
        "--password-file",
        type=Path,
        default=STACK_DIR / "secrets" / "tor_control_password",
        help="ControlPort password file (default: torxng/secrets/tor_control_password)",
    )
    parser.add_argument("--all", action="store_true", help="show all BUILT circuits (also onion service ones)")
    parser.add_argument("--no-lookup", action="store_true", help="skip relay IP / country lookups")
    args = parser.parse_args(argv)

    password = read_password(args.password_file)
    compose = ["docker", "compose", "-f", str(args.compose_file)]
    tc = load_tor_control()

    status = getinfo_values(control_session(compose, password, ["GETINFO circuit-status"]))
    circuits = [c for c in tc.TorControl.parse_circuit_status(status.get("circuit-status", [])) if c.status == "BUILT"]
    if not args.all:
        circuits = [c for c in circuits if c.purpose in EXIT_PURPOSES]
    circuits.sort(key=lambda c: (c.socks_username or "~", int(c.id) if c.id.isdigit() else 0))

    relays: dict[str, tuple[str, str]] = {}
    if not args.no_lookup and circuits:
        fingerprints = sorted({r.fingerprint for c in circuits for r in c.path if r.fingerprint})
        ns = getinfo_values(control_session(compose, password, [f"GETINFO ns/id/{fp}" for fp in fingerprints]))
        ips: dict[str, str] = {}
        for fp in fingerprints:
            for line in ns.get(f"ns/id/{fp}", []):
                parts = line.split()
                if parts and parts[0] == "r" and len(parts) >= 8:
                    ips[fp] = parts[6]
        cc = getinfo_values(
            control_session(compose, password, [f"GETINFO ip-to-country/{ip}" for ip in sorted(set(ips.values()))])
        )
        for fp, ip in ips.items():
            country = (cc.get(f"ip-to-country/{ip}") or ["??"])[0]
            relays[fp] = (ip, country.upper())

    def fmt(relay) -> str:
        ip, country = relays.get(relay.fingerprint, ("?", "??"))
        name = relay.nickname or "?"
        if args.no_lookup:
            return f"{name} (${relay.fingerprint[:8]})"
        return f"{name} ({country}, {ip}, ${relay.fingerprint[:8]})"

    print(f"{len(circuits)} BUILT circuit(s){'' if args.all else ' with purpose ' + '/'.join(sorted(EXIT_PURPOSES))}")
    print("OPERATOR ONLY - do not publish guard relays (guard discovery against the onion service)\n")
    for circ in circuits:
        roles = ["guard", "middle", "exit"] if len(circ.path) == 3 else [f"hop{i + 1}" for i in range(len(circ.path))]
        path = " -> ".join(f"{role}: {fmt(relay)}" for role, relay in zip(roles, circ.path))
        owner = f"SOCKS {circ.socks_username}" if circ.socks_username else "no SOCKS user"
        print(f"circuit {circ.id:>4} [{circ.purpose}, {owner}]")
        print(f"    {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
