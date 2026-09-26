# SPDX-License-Identifier: AGPL-3.0-or-later
"""Minimal client for the control protocol of a Tor daemon (ControlPort_).

Only the small subset of the protocol that is needed to inspect the circuits of
a Tor client is implemented (no ``stem`` dependency): ``AUTHENTICATE``,
``GETINFO`` and ``QUIT``.

.. code:: python

   with TorControl("127.0.0.1", 9051, password="secret") as ctrl:
       for circ in ctrl.circuits():
           print(circ.id, circ.status, circ.exit)

Error replies of the daemon (and a connection that is closed in the middle of
a reply) raise :py:obj:`TorControlError`, network errors are raised as
:py:obj:`OSError` (e.g. :py:obj:`TimeoutError`, :py:obj:`ConnectionRefusedError`).
A command that does not complete within :py:obj:`TorControl.deadline` raises
:py:obj:`TimeoutError`.

.. attention::

   The guard (first hop) of the circuits identifies the entry point of the Tor
   client into the Tor network.  If the same Tor daemon runs an onion service,
   revealing its guard is the first step of a *guard discovery* attack against
   the onion service.  :py:obj:`TorControl.circuits` therefore resolves only
   the exit relay; the guard and middle relays must never be shown to users.

.. _ControlPort:
   https://spec.torproject.org/control-spec/
"""

__all__ = ["TorControlError", "Relay", "Circuit", "TorControl", "EXIT_PURPOSES"]

import dataclasses
import io
import re
import socket
import time

from collections.abc import Iterable
from ipaddress import ip_address

# The replies 551 (internal error, e.g. no GeoIP data) and 552 (unrecognized
# key, e.g. unknown relay) to lookups of a single relay are not fatal.
_LOOKUP_ERRORS = ("551", "552")

_KEYWORD = re.compile(r'(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|\S*)')
_ESCAPE = re.compile(r'\\([0-7]{1,3}|.)', re.S)
_C_ESCAPES = {"n": "\n", "r": "\r", "t": "\t"}

MAX_LINE_LENGTH = 65536
"""Maximum length (bytes) of a reply line, a longer line raises :py:obj:`TorControlError`."""

MAX_REPLY_LINES = 10000
"""Maximum number of lines (including the lines of data blocks) of one reply."""

EXIT_PURPOSES = frozenset({"GENERAL", "CONFLUX_LINKED", "CONFLUX_UNLINKED"})
"""Purposes of the circuits a Tor client uses for its streams to the internet
(exit circuits).  Since Tor 0.4.8 (conflux) these circuits are reported with
purpose ``CONFLUX_LINKED`` (``CONFLUX_UNLINKED`` while linking) instead of
``GENERAL``.  Circuits of onion services (``HS_*``), ``TESTING`` and others are
not exit circuits."""


class TorControlError(Exception):
    """Error reply from Tor's control port or a broken control connection.  The
    three digit status ``code`` of the reply is empty if the error is not a
    reply of the daemon."""

    def __init__(self, message: str, code: str = ""):
        super().__init__(message)
        self.code: str = code


@dataclasses.dataclass(frozen=True)
class Relay:
    """A Tor relay (a hop of a circuit)."""

    fingerprint: str
    nickname: str
    ip: str | None = None  # pylint: disable=invalid-name
    country: str | None = None


@dataclasses.dataclass(frozen=True)
class Circuit:
    """A circuit of the Tor client, the ``path`` is ordered from the guard to
    the last hop."""

    id: str
    status: str
    """LAUNCHED, BUILT, GUARD_WAIT, EXTENDED, FAILED or CLOSED"""
    path: tuple[Relay, ...]
    purpose: str = ""
    socks_username: str = ""
    """SOCKS username of the streams on this circuit (``IsolateSOCKSAuth``)."""
    socks_password: str = ""
    time_created: str = ""
    """TIME_CREATED of the circuit (ISO 8601, UTC)."""

    @property
    def exit(self) -> Relay | None:
        """The last hop of the circuit (``None`` if the path is empty)."""
        return self.path[-1] if self.path else None


class TorControl:
    """Connection to the ControlPort of a Tor daemon.  Used as a context
    manager, the connection is opened and authenticated on enter and closed on
    exit."""

    def __init__(self, host: str, port: int, password: str = "", timeout: float = 5.0):
        self.host: str = host
        self.port: int = port
        self.password: str = password
        self.timeout: float = timeout
        """Timeout (sec) of the connect and of each read from the socket."""
        self._sock: socket.socket | None = None
        self._reader: io.BufferedIOBase | None = None
        self._broken: bool = False

    @property
    def deadline(self) -> float:
        """Maximum time (sec) of one command (send the command and read the
        complete reply): twice the :py:obj:`timeout`."""
        return 2 * self.timeout

    def __enter__(self) -> "TorControl":
        self.connect()
        try:
            self.authenticate()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        # after a broken (e.g. timed out) exchange QUIT would only wait again
        if self._sock is not None and not self._broken:
            try:
                self._command("QUIT")
            except (OSError, TorControlError):
                pass
        self.close()

    def connect(self) -> None:
        """Open the TCP connection to the control port."""
        self.close()
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._reader = self._sock.makefile("rb")
        self._broken = False

    def close(self) -> None:
        """Close the connection (no ``QUIT`` is sent)."""
        reader, sock = self._reader, self._sock
        self._reader, self._sock = None, None
        for obj in (reader, sock):
            if obj is not None:
                try:
                    obj.close()
                except OSError:
                    pass

    def authenticate(self) -> None:
        """Authenticate with the password (``HashedControlPassword``), without a
        password the ``AUTHENTICATE`` command has no argument (``CookieAuthentication``
        is not supported)."""
        if self.password:
            escaped = self.password.replace("\\", "\\\\").replace('"', '\\"')
            self._command(f'AUTHENTICATE "{escaped}"')
        else:
            self._command("AUTHENTICATE")

    def getinfo(self, key: str) -> list[str]:
        """Returns the lines of the value of ``key``; an empty value returns an
        empty list."""
        if not key or any(c.isspace() for c in key):
            raise ValueError(f"invalid GETINFO key: {key!r}")

        prefix = key + "="
        values: list[str] = []
        for _code, text, data in self._command(f"GETINFO {key}"):
            if text.startswith(prefix):
                if text[len(prefix) :]:
                    values.append(text[len(prefix) :])
                values.extend(data)
        return values

    def circuits(self, resolve: bool = True) -> list[Circuit]:
        """Returns the circuits of the Tor client.  With ``resolve``, IP and
        country of the exit relay (the last hop) of the BUILT exit circuits
        (:py:obj:`EXIT_PURPOSES`, the circuits used for outgoing requests) are
        looked up.  The guard and middle relays are never looked up (guard
        discovery, see module documentation)."""
        circuits = self.parse_circuit_status(self.getinfo("circuit-status"))
        if not resolve:
            return circuits

        cache: dict[str, tuple[str | None, str | None]] = {}
        result: list[Circuit] = []
        for circ in circuits:
            if circ.status == "BUILT" and circ.purpose in EXIT_PURPOSES and circ.path:
                circ = dataclasses.replace(circ, path=(*circ.path[:-1], self._resolve(circ.path[-1], cache)))
            result.append(circ)
        return result

    def relay_address(self, fingerprint: str) -> str | None:
        """Returns the IP of the relay from the consensus or ``None`` if the
        relay is unknown."""
        try:
            lines = self.getinfo(f"ns/id/{fingerprint.lstrip('$')}")
        except TorControlError as exc:
            if exc.code in _LOOKUP_ERRORS:
                return None
            raise

        for line in lines:
            fields = line.split()
            # r <nickname> <identity> [<digest>] <date> <time> <IP> <ORPort> <DirPort>
            if len(fields) >= 8 and fields[0] == "r":
                try:
                    return ip_address(fields[-3]).compressed
                except ValueError:
                    return None
        return None

    def country(self, ip: str) -> str | None:  # pylint: disable=invalid-name
        """Returns the country code of the ``ip`` from Tor's GeoIP data or
        ``None`` if the country is unknown."""
        try:
            lines = self.getinfo(f"ip-to-country/{ip}")
        except TorControlError as exc:
            if exc.code in _LOOKUP_ERRORS:
                return None
            raise

        value = lines[0].strip() if lines else ""
        if value in ("", "??"):
            return None
        return value

    @staticmethod
    def parse_circuit_status(lines: Iterable[str]) -> list[Circuit]:
        """Parse the lines of ``GETINFO circuit-status``, the grammar of a line
        is::

            CircuitID SP CircStatus [SP Path] [SP KEY=VALUE ...]
        """
        circuits: list[Circuit] = []
        for line in lines:
            tokens = line.split(maxsplit=2)
            if len(tokens) < 2:
                continue
            circ_id, status = tokens[0], tokens[1]
            rest = tokens[2] if len(tokens) > 2 else ""

            path: tuple[Relay, ...] = ()
            first, _, remainder = rest.partition(" ")
            if first and (first.startswith("$") or "=" not in first):
                path = tuple(_parse_long_name(name) for name in first.split(",") if name)
                rest = remainder

            keywords = {match.group(1): _unquote(match.group(2)) for match in _KEYWORD.finditer(rest)}
            circuits.append(
                Circuit(
                    id=circ_id,
                    status=status,
                    path=path,
                    purpose=keywords.get("PURPOSE", ""),
                    socks_username=keywords.get("SOCKS_USERNAME", ""),
                    socks_password=keywords.get("SOCKS_PASSWORD", ""),
                    time_created=keywords.get("TIME_CREATED", ""),
                )
            )
        return circuits

    def _resolve(self, relay: Relay, cache: dict[str, tuple[str | None, str | None]]) -> Relay:
        if not relay.fingerprint:
            return relay
        if relay.fingerprint not in cache:
            ip = self.relay_address(relay.fingerprint)
            cache[relay.fingerprint] = (ip, self.country(ip) if ip else None)
        ip, country = cache[relay.fingerprint]
        return dataclasses.replace(relay, ip=ip, country=country)

    def _command(self, line: str) -> list[tuple[str, str, list[str]]]:
        """Send a command and read the reply, raise :py:obj:`TorControlError`
        if the status of the reply is not 250."""
        if "\r" in line or "\n" in line:
            raise ValueError("control commands must not contain line breaks")
        if self._sock is None:
            raise TorControlError("not connected to the Tor control port")
        if self._broken:
            raise TorControlError("Tor control connection is broken")

        deadline = time.monotonic() + self.deadline
        try:
            self._sock.sendall(line.encode("utf-8") + b"\r\n")
            reply = self._read_reply(deadline)
        except BaseException:
            # the state of the connection is unknown (e.g. half read reply)
            self._broken = True
            raise

        for code, text, _data in reply:
            if code != "250":
                raise TorControlError(f"{code} {text}", code=code)
        return reply

    def _read_reply(self, deadline: float) -> list[tuple[str, str, list[str]]]:
        """Read one complete reply, a list of ``(code, text, data)`` tuples;
        ``data`` are the lines of a data block (``250+key=``)."""
        reply: list[tuple[str, str, list[str]]] = []
        count = 0
        while True:
            line = self._readline(deadline)
            if len(line) < 4 or not line[:3].isdigit() or line[3] not in " -+":
                raise TorControlError(f"malformed reply from Tor control port: {line!r}")
            code, sep, text = line[:3], line[3], line[4:]

            data: list[str] = []
            if sep == "+":
                while (data_line := self._readline(deadline)) != ".":
                    # dot-escaping: a leading "." of a data line is doubled
                    data.append(data_line[1:] if data_line.startswith(".") else data_line)

            count += 1 + len(data)
            if count > MAX_REPLY_LINES:
                raise TorControlError(f"reply from Tor control port exceeds {MAX_REPLY_LINES} lines")
            reply.append((code, text, data))
            if sep == " ":
                return reply

    def _readline(self, deadline: float) -> str:
        if self._reader is None or self._sock is None:
            raise TorControlError("not connected to the Tor control port")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Tor control command timed out")
        self._sock.settimeout(min(self.timeout, remaining))

        raw = self._reader.readline(MAX_LINE_LENGTH)
        if not raw.endswith(b"\n"):
            if len(raw) >= MAX_LINE_LENGTH:
                raise TorControlError(f"reply line from Tor control port exceeds {MAX_LINE_LENGTH} bytes")
            raise TorControlError("Tor control connection closed unexpectedly")
        return raw.decode("utf-8", errors="replace").rstrip("\r\n")


def _unquote(value: str) -> str:
    """Decode a QuotedString of the control protocol (C escapes, non-ASCII
    bytes are escaped octal), other values are returned unchanged."""
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        return value

    def unescape(match: re.Match[str]) -> str:
        esc = match.group(1)
        if esc[0] in "01234567":
            return chr(int(esc, 8) & 0xFF)
        return _C_ESCAPES.get(esc, esc)

    text = _ESCAPE.sub(unescape, value[1:-1])
    try:
        return text.encode("latin-1").decode("utf-8")
    except UnicodeError:
        return text


def _parse_long_name(name: str) -> Relay:
    """Parse a LongName of a relay: ``$FINGERPRINT~Nickname``,
    ``$FINGERPRINT=Nickname`` or ``$FINGERPRINT`` (``Nickname`` of very old Tor
    versions has no fingerprint)."""
    if not name.startswith("$"):
        return Relay(fingerprint="", nickname=name)
    name = name[1:]
    for sep in ("~", "="):
        if sep in name:
            fingerprint, nickname = name.split(sep, 1)
            return Relay(fingerprint=fingerprint, nickname=nickname)
    return Relay(fingerprint=name, nickname="")
