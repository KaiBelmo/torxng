# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import io
import typing as t

from mock import MagicMock, call, patch

from searx.network.tor_control import EXIT_PURPOSES, MAX_LINE_LENGTH, Circuit, Relay, TorControl, TorControlError
from tests import SearxTestCase

if t.TYPE_CHECKING:
    from _typeshed import WriteableBuffer

FP_A, FP_B, FP_C, FP_D, FP_E, FP_F = ("A" * 40, "B" * 40, "C" * 40, "D" * 40, "E" * 40, "F" * 40)
FP_G, FP_H = ("0" * 40, "1" * 40)

CIRCUIT_STATUS = [
    f"1 BUILT ${FP_A}~nickA,${FP_B}~nickB,${FP_C}~nickC BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL"
    " TIME_CREATED=2026-09-26T10:00:00.000000",
    f"2 EXTENDED ${FP_A}~nickA,${FP_D}~nickD BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL",
    "3 LAUNCHED BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL",
    f"4 BUILT ${FP_A}~nickA,${FP_E}~nickE,${FP_F}~nickF PURPOSE=HS_CLIENT_REND",
]


def crlf(*lines: str) -> bytes:
    return "".join(line + "\r\n" for line in lines).encode("utf-8")


def ns_reply(fp: str, nick: str, ip: str) -> bytes:
    return crlf(
        f"250+ns/id/{fp}=",
        f"r {nick} qg9Pd0KhR7ihDxkUsZ4twAAAAAA 2026-09-26 09:00:00 {ip} 9001 0",
        "s Fast Guard Running Stable Valid",
        ".",
        "250 OK",
    )


def country_reply(ip: str, country: str) -> bytes:
    return crlf(f"250-ip-to-country/{ip}={country}", "250 OK")


class ChunkedRaw(io.RawIOBase):
    """Raw stream that returns at most ``size`` bytes per read (a reply split
    across several reads from the socket)."""

    def __init__(self, data: bytes, size: int):
        self._data = data
        self._size = size
        self._pos = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: "WriteableBuffer") -> int:
        view = memoryview(buffer)
        chunk = self._data[self._pos : self._pos + min(self._size, len(view))]
        view[: len(chunk)] = chunk
        self._pos += len(chunk)
        return len(chunk)


def fake_socket(replies: bytes, chunk_size: int = 0) -> MagicMock:
    sock = MagicMock()
    if chunk_size:
        sock.makefile.return_value = io.BufferedReader(ChunkedRaw(replies, chunk_size))
    else:
        sock.makefile.return_value = io.BytesIO(replies)
    return sock


def sent(sock: MagicMock) -> list[bytes]:
    return [c.args[0] for c in sock.sendall.call_args_list]


class TestParseCircuitStatus(SearxTestCase):

    def test_sample(self):
        circuits = TorControl.parse_circuit_status(CIRCUIT_STATUS)
        self.assertEqual([c.id for c in circuits], ["1", "2", "3", "4"])
        self.assertEqual([c.status for c in circuits], ["BUILT", "EXTENDED", "LAUNCHED", "BUILT"])
        self.assertEqual([c.purpose for c in circuits], ["GENERAL", "GENERAL", "GENERAL", "HS_CLIENT_REND"])

        self.assertEqual(
            circuits[0].path,
            (Relay(FP_A, "nickA"), Relay(FP_B, "nickB"), Relay(FP_C, "nickC")),
        )
        self.assertEqual(circuits[0].exit, Relay(FP_C, "nickC"))
        self.assertEqual(circuits[1].exit, Relay(FP_D, "nickD"))
        self.assertEqual(circuits[3].exit, Relay(FP_F, "nickF"))

        self.assertEqual(circuits[2].path, ())
        self.assertIsNone(circuits[2].exit)

    def test_long_name_forms(self):
        circuits = TorControl.parse_circuit_status([f"7 BUILT ${FP_A}=nickA,${FP_B},${FP_C}~nickC PURPOSE=GENERAL"])
        self.assertEqual(
            circuits,
            [
                Circuit(
                    id="7",
                    status="BUILT",
                    path=(Relay(FP_A, "nickA"), Relay(FP_B, ""), Relay(FP_C, "nickC")),
                    purpose="GENERAL",
                )
            ],
        )

    def test_no_keywords_and_empty_lines(self):
        circuits = TorControl.parse_circuit_status(["", "8 CLOSED", f"9 FAILED ${FP_A}~nickA"])
        self.assertEqual(
            circuits,
            [
                Circuit(id="8", status="CLOSED", path=()),
                Circuit(id="9", status="FAILED", path=(Relay(FP_A, "nickA"),)),
            ],
        )

    def test_quoted_keyword_values(self):
        line = f'5 BUILT ${FP_A}~nickA SOCKS_USERNAME="a PURPOSE=FAKE b" PURPOSE=CONFLUX_LINKED'
        circuits = TorControl.parse_circuit_status([line])
        self.assertEqual(circuits[0].purpose, "CONFLUX_LINKED")
        self.assertEqual(circuits[0].socks_username, "a PURPOSE=FAKE b")

    def test_socks_credentials_and_time_created(self):
        lines = [
            # quoted (QuotedString, as sent by Tor)
            f'1 BUILT ${FP_A}~nickA,${FP_B}~nickB,${FP_C}~nickC BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL'
            ' TIME_CREATED=2026-09-26T10:00:00.000000 SOCKS_USERNAME="sxng-0" SOCKS_PASSWORD="1a2b3c4d"',
            # unquoted
            f"2 BUILT ${FP_A}~nickA PURPOSE=GENERAL SOCKS_USERNAME=sxng-1 SOCKS_PASSWORD=salt",
            # escaped quote, backslash and octal escaped UTF-8 bytes
            '3 LAUNCHED PURPOSE=GENERAL SOCKS_USERNAME="a\\"b\\\\c" SOCKS_PASSWORD="\\303\\244"',
            # absent
            f"4 BUILT ${FP_A}~nickA PURPOSE=GENERAL",
        ]
        circuits = TorControl.parse_circuit_status(lines)
        self.assertEqual(
            [(c.socks_username, c.socks_password, c.time_created) for c in circuits],
            [
                ("sxng-0", "1a2b3c4d", "2026-09-26T10:00:00.000000"),
                ("sxng-1", "salt", ""),
                ('a"b\\c', "\u00e4", ""),
                ("", "", ""),
            ],
        )
        self.assertEqual(circuits[0].exit, Relay(FP_C, "nickC"))
        self.assertEqual(circuits[2].path, ())
        # backwards compatible defaults
        self.assertEqual(Circuit(id="9", status="BUILT", path=()).socks_username, "")


class TestTorControlSession(SearxTestCase):

    def test_session(self):
        circuit_status = [
            *CIRCUIT_STATUS,
            # conflux exit circuit (Tor 0.4.8+), same exit as circuit 1: looked up once
            f"5 BUILT ${FP_A}~nickA,${FP_G}~nickG,${FP_C}~nickC PURPOSE=CONFLUX_LINKED",
            # exit unknown in the consensus
            f"6 BUILT ${FP_A}~nickA,${FP_D}~nickD,${FP_H}~nickH PURPOSE=GENERAL",
            # conflux circuit while linking, exit without GeoIP country
            f"7 BUILT ${FP_A}~nickA,${FP_B}~nickB,${FP_G}~nickG PURPOSE=CONFLUX_UNLINKED",
            # not an exit circuit
            f"8 BUILT ${FP_A}~nickA,${FP_B}~nickB,${FP_E}~nickE PURPOSE=TESTING",
        ]
        replies = b"".join(
            [
                crlf("250 OK"),
                crlf("250+circuit-status=", *circuit_status, ".", "250 OK"),
                ns_reply(FP_C, "nickC", "192.0.2.3"),
                country_reply("192.0.2.3", "nl"),
                crlf(f'552 Unrecognized key "ns/id/{FP_H}"'),
                ns_reply(FP_G, "nickG", "192.0.2.7"),
                country_reply("192.0.2.7", "??"),
                crlf("250 closing connection"),
            ]
        )
        sock = fake_socket(replies)

        with patch("searx.network.tor_control.socket.create_connection", return_value=sock) as create_connection:
            with TorControl("127.0.0.1", 9051, password='pa"ss\\word', timeout=3.0) as ctrl:
                circuits = ctrl.circuits()

        create_connection.assert_called_once_with(("127.0.0.1", 9051), timeout=3.0)
        # only the exit relays are looked up, never a guard or middle relay
        self.assertEqual(
            sent(sock),
            [
                b'AUTHENTICATE "pa\\"ss\\\\word"\r\n',
                b"GETINFO circuit-status\r\n",
                f"GETINFO ns/id/{FP_C}\r\n".encode(),
                b"GETINFO ip-to-country/192.0.2.3\r\n",
                f"GETINFO ns/id/{FP_H}\r\n".encode(),
                f"GETINFO ns/id/{FP_G}\r\n".encode(),
                b"GETINFO ip-to-country/192.0.2.7\r\n",
                b"QUIT\r\n",
            ],
        )
        sock.close.assert_called_once_with()

        self.assertEqual(len(circuits), 8)
        self.assertEqual(
            circuits[0].path,
            (Relay(FP_A, "nickA"), Relay(FP_B, "nickB"), Relay(FP_C, "nickC", ip="192.0.2.3", country="nl")),
        )
        self.assertEqual(circuits[4].purpose, "CONFLUX_LINKED")
        self.assertEqual(circuits[4].exit, Relay(FP_C, "nickC", ip="192.0.2.3", country="nl"))
        self.assertEqual(circuits[5].exit, Relay(FP_H, "nickH"))
        self.assertEqual(
            circuits[6].path,
            (Relay(FP_A, "nickA"), Relay(FP_B, "nickB"), Relay(FP_G, "nickG", ip="192.0.2.7", country=None)),
        )
        # circuits that are not BUILT or not exit circuits (HS_*, TESTING) are not resolved
        self.assertEqual(circuits[1].path, (Relay(FP_A, "nickA"), Relay(FP_D, "nickD")))
        self.assertEqual(circuits[2].path, ())
        self.assertEqual(circuits[3].purpose, "HS_CLIENT_REND")
        self.assertEqual(circuits[3].exit, Relay(FP_F, "nickF"))
        self.assertEqual(circuits[7].exit, Relay(FP_E, "nickE"))

    def test_exit_purposes(self):
        self.assertEqual(EXIT_PURPOSES, {"GENERAL", "CONFLUX_LINKED", "CONFLUX_UNLINKED"})
        for purpose in ("HS_CLIENT_REND", "HS_SERVICE_INTRO", "HS_VANGUARDS", "TESTING", "CONTROLLER"):
            self.assertNotIn(purpose, EXIT_PURPOSES)

    def test_no_password_and_no_resolve(self):
        replies = crlf("250 OK", "250-circuit-status=", "250 OK", "250 closing connection")
        sock = fake_socket(replies)
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            with TorControl("127.0.0.1", 9051) as ctrl:
                self.assertEqual(ctrl.circuits(resolve=False), [])
        self.assertEqual(sent(sock), [b"AUTHENTICATE\r\n", b"GETINFO circuit-status\r\n", b"QUIT\r\n"])

    def test_circuit_status_forms(self):
        replies = crlf(
            "250 OK",
            # empty data block
            "250+circuit-status=",
            ".",
            "250 OK",
            # single line form, a conflux exit circuit: the exit is resolved
            f"250-circuit-status=1 BUILT ${FP_A}~nickA,${FP_B}~nickB,${FP_C}~nickC PURPOSE=CONFLUX_LINKED",
            "250 OK",
        )
        replies += ns_reply(FP_C, "nickC", "192.0.2.3") + country_reply("192.0.2.3", "nl")
        sock = fake_socket(replies)
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            ctrl = TorControl("127.0.0.1", 9051)
            ctrl.connect()
            ctrl.authenticate()
            self.assertEqual(ctrl.circuits(), [])
            circuits = ctrl.circuits()
            ctrl.close()
        self.assertEqual(len(circuits), 1)
        self.assertEqual(circuits[0].purpose, "CONFLUX_LINKED")
        self.assertEqual(circuits[0].exit, Relay(FP_C, "nickC", ip="192.0.2.3", country="nl"))
        self.assertEqual(circuits[0].path[:2], (Relay(FP_A, "nickA"), Relay(FP_B, "nickB")))

    def test_authentication_failed(self):
        sock = fake_socket(crlf("515 Authentication failed: Password did not match HashedControlPassword value"))
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            with self.assertRaises(TorControlError) as ctx:
                with TorControl("127.0.0.1", 9051, password="wrong"):
                    self.fail("authentication should fail")
        self.assertEqual(ctx.exception.code, "515")
        self.assertIn("Authentication failed", str(ctx.exception))
        # no QUIT after a failed authentication, but the socket is closed
        self.assertEqual(sent(sock), [b'AUTHENTICATE "wrong"\r\n'])
        sock.close.assert_called_once_with()

    def test_relay_address_unknown(self):
        sock = fake_socket(crlf("250 OK", f'552 Unrecognized key "ns/id/{FP_A}"', "250 closing connection"))
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            with TorControl("127.0.0.1", 9051) as ctrl:
                self.assertIsNone(ctrl.relay_address("$" + FP_A))
        self.assertEqual(sent(sock)[1], f"GETINFO ns/id/{FP_A}\r\n".encode())

    def test_relay_address_legacy_r_line(self):
        replies = b"".join(
            [
                crlf("250 OK"),
                crlf(
                    f"250+ns/id/{FP_A}=",
                    "r nickA qg9Pd0KhR7ihDxkUsZ4twAAAAAA bG9yZW0gaXBzdW0 2026-09-26 09:00:00 198.51.100.7 443 80",
                    ".",
                    "250 OK",
                ),
                crlf("250-ip-to-country/198.51.100.7=", "250 OK"),
            ]
        )
        sock = fake_socket(replies)
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            ctrl = TorControl("127.0.0.1", 9051)
            ctrl.connect()
            ctrl.authenticate()
            self.assertEqual(ctrl.relay_address(FP_A), "198.51.100.7")
            self.assertIsNone(ctrl.country("198.51.100.7"))

    def test_getinfo_error(self):
        sock = fake_socket(crlf("250 OK", '552 Unrecognized key "foo"', "250 closing connection"))
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            with TorControl("127.0.0.1", 9051) as ctrl:
                with self.assertRaises(TorControlError) as ctx:
                    ctrl.getinfo("foo")
                self.assertEqual(ctx.exception.code, "552")
                with self.assertRaises(ValueError):
                    ctrl.getinfo("foo bar")
        # an error reply does not break the connection: QUIT is sent
        self.assertEqual(sent(sock)[-1], b"QUIT\r\n")

    def test_connection_error(self):
        with patch("searx.network.tor_control.socket.create_connection", side_effect=ConnectionRefusedError()):
            with self.assertRaises(OSError):
                with TorControl("127.0.0.1", 9051):
                    self.fail("connection should fail")

    def test_command_with_line_break(self):
        sock = fake_socket(crlf("250 OK"))
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            ctrl = TorControl("127.0.0.1", 9051, password="x\r\nSIGNAL SHUTDOWN")
            ctrl.connect()
            with self.assertRaises(ValueError):
                ctrl.authenticate()
        sock.sendall.assert_not_called()

    def test_not_connected(self):
        with self.assertRaises(TorControlError):
            TorControl("127.0.0.1", 9051).getinfo("version")

    def test_reply_split_across_reads(self):
        replies = crlf(
            "250 OK",
            "250+circuit-status=",
            *CIRCUIT_STATUS,
            ".",
            "250 OK",
            "250+config-text=",
            "..leading dot",
            ".",
            "250 OK",
        )
        sock = fake_socket(replies, chunk_size=3)
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            ctrl = TorControl("127.0.0.1", 9051)
            ctrl.connect()
            ctrl.authenticate()
            circuits = ctrl.circuits(resolve=False)
            self.assertEqual(ctrl.getinfo("config-text"), [".leading dot"])
        self.assertEqual(circuits, TorControl.parse_circuit_status(CIRCUIT_STATUS))

    def test_connection_closed_mid_reply(self):
        truncated = [
            crlf("250+circuit-status=", CIRCUIT_STATUS[0]),  # data block without "."
            crlf("250-circuit-status="),  # no final line
            b"250 O",  # incomplete line
            b"",  # nothing at all
        ]
        for data in truncated:
            sock = fake_socket(crlf("250 OK") + data)
            with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
                with TorControl("127.0.0.1", 9051) as ctrl:
                    with self.assertRaises(TorControlError):
                        ctrl.circuits(resolve=False)
                    # the connection is broken, no further command is sent
                    with self.assertRaises(TorControlError):
                        ctrl.getinfo("version")
            # no QUIT on a broken connection, the socket is closed
            self.assertEqual(sent(sock), [b"AUTHENTICATE\r\n", b"GETINFO circuit-status\r\n"])
            sock.close.assert_called_once_with()

    def test_malformed_reply(self):
        sock = fake_socket(b"HTTP/1.0 400 Bad Request\r\n")
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            with self.assertRaises(TorControlError):
                with TorControl("127.0.0.1", 9051):
                    self.fail("not a Tor control port")

    def test_line_too_long(self):
        sock = fake_socket(crlf("250 OK") + b"250-circuit-status=" + b"x" * MAX_LINE_LENGTH + b"\r\n250 OK\r\n")
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            with TorControl("127.0.0.1", 9051) as ctrl:
                with self.assertRaises(TorControlError) as ctx:
                    ctrl.circuits(resolve=False)
        self.assertIn("exceeds", str(ctx.exception))
        self.assertEqual(sent(sock)[-1], b"GETINFO circuit-status\r\n")

    def test_too_many_reply_lines(self):
        replies = crlf("250 OK", "250+circuit-status=", *CIRCUIT_STATUS, ".", "250 OK")
        sock = fake_socket(replies)
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            with patch("searx.network.tor_control.MAX_REPLY_LINES", 3):
                with TorControl("127.0.0.1", 9051) as ctrl:
                    with self.assertRaises(TorControlError) as ctx:
                        ctrl.circuits(resolve=False)
        self.assertIn("exceeds 3 lines", str(ctx.exception))
        self.assertEqual(sent(sock)[-1], b"GETINFO circuit-status\r\n")

    def test_command_deadline(self):
        replies = crlf("250 OK", "250+circuit-status=", *CIRCUIT_STATUS, ".", "250 OK")
        sock = fake_socket(replies)
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            with patch("searx.network.tor_control.time") as mock_time:
                # AUTHENTICATE: start, one line; GETINFO: start, first line
                # (1.5 sec left), second line (deadline of 2 x 5 sec reached)
                mock_time.monotonic.side_effect = [0.0, 0.1, 100.0, 108.5, 110.0]
                with TorControl("127.0.0.1", 9051, timeout=5.0) as ctrl:
                    with self.assertRaises(TimeoutError):
                        ctrl.circuits(resolve=False)
        self.assertEqual(sock.settimeout.call_args_list, [call(5.0), call(1.5)])
        # no QUIT after the timeout
        self.assertEqual(sent(sock), [b"AUTHENTICATE\r\n", b"GETINFO circuit-status\r\n"])
        sock.close.assert_called_once_with()

    def test_socket_timeout(self):
        sock = fake_socket(b"")
        sock.makefile.return_value = MagicMock(readline=MagicMock(side_effect=[b"250 OK\r\n", TimeoutError()]))
        with patch("searx.network.tor_control.socket.create_connection", return_value=sock):
            with TorControl("127.0.0.1", 9051) as ctrl:
                with self.assertRaises(TimeoutError):
                    ctrl.getinfo("version")
        # no QUIT (would wait another timeout)
        self.assertEqual(sent(sock), [b"AUTHENTICATE\r\n", b"GETINFO version\r\n"])
