# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import threading
import time

from curl_cffi.requests.exceptions import Timeout
from mock import Mock, patch
from parameterized.parameterized import parameterized

import searx
import searx.network
import searx.plugins
import searx.preferences

from searx.extended_types import sxng_request
from searx.network.network import Network
from searx.network.tor_control import Circuit, Relay
from searx.plugins import tor_circuit
from searx.plugins.tor_circuit import CHECK_URL, ExitInfo, match_circuit, socks_username
from searx.result_types import Answer

from tests import SearxTestCase, SearxTorTestCase
from .test_plugins import do_post_search


def new_circuit(
    circ_id: str, exit_ip: str, nick: str, username: str = "", time_created: str = "", purpose: str = "GENERAL"
) -> Circuit:
    return Circuit(
        id=circ_id,
        status="BUILT",
        path=(
            Relay("A" * 40, f"{nick}Guard", country="de"),
            Relay("B" * 40, f"{nick}Middle", country="nl"),
            Relay("C" * 40, f"{nick}Exit", ip=exit_ip, country="se"),
        ),
        purpose=purpose,
        socks_username=username,
        time_created=time_created,
    )


# circuit without SOCKS username, matched by the exit IP of the second probe
IP_CIRCUIT = new_circuit("1", "1.2.3.1", "ip")


def exit_answer(num: int, ip: str, nick: str, by_ip: bool = False, total: int = 3, tor: str = "yes") -> Answer:
    matched = " (matched by exit IP)" if by_ip else ""
    return Answer(
        answer=f"Circuit {num}/{total} - exit IP {ip} (Tor: {tor}) - exit relay{matched} {nick}Exit (SE),"
        " 3 hops (guard and middle hidden)"
    )


def unknown_answer(num: int, ip: str) -> Answer:
    return Answer(
        answer=f"Circuit {num}/3 - exit IP {ip} (Tor: yes)"
        " - exit relay unknown (ControlPort not configured or no matching circuit)"
    )


def summary_answer(total: int, exits: int) -> Answer:
    return Answer(answer=f"Tor circuits: {total}, distinct exit IPs: {exits}")


def get_storage(app) -> searx.plugins.PluginStorage:
    storage = searx.plugins.PluginStorage()
    storage.load_settings({"searx.plugins.tor_circuit.SXNGPlugin": {"active": True}})
    storage.init(app)
    return storage


class PluginTorCircuitDefaultProfile(SearxTestCase):

    def test_plugin_active(self):
        # Tor-only build: the plugin can be activated with the default profile
        self.assertEqual(1, len(get_storage(self.app)))


class TorCircuitHelpers(SearxTestCase):

    @parameterized.expand(
        [
            ((("all://", "socks5h://sxng-3:abc@127.0.0.1:9050"),), "sxng-3"),
            ((("https://", "socks5h://u1:p@h:1"), ("all://", "socks5h://u2:p@h:1")), "u2"),
            ((("http://", "socks5h://u1:p@h:1"), ("https://", "socks5h://u3:p@h:1")), "u3"),
            ((("http://", "socks5h://u1:p@h:1"),), ""),
            ((("all://", "socks5h://127.0.0.1:9050"),), ""),
            ((("all://", "socks5h://user%40x:p@h:1"),), "user@x"),
            ((), ""),
        ]
    )
    def test_socks_username(self, proxies: tuple[tuple[str, str], ...], username: str):
        self.assertEqual(socks_username(proxies), username)

    def test_exit_info_drops_guard_and_middle(self):
        info = ExitInfo.from_circuit(new_circuit("7", "1.2.3.4", "x", username="u0", time_created="T"))
        self.assertEqual(info, ExitInfo("7", Relay("C" * 40, "xExit", ip="1.2.3.4", country="se"), 3, "u0", "T"))

    def test_match_circuit(self):
        old = ExitInfo.from_circuit(new_circuit("5", "1.2.3.4", "old", username="u0"))
        new = ExitInfo.from_circuit(new_circuit("12", "1.2.3.4", "new", username="u0"))
        early = ExitInfo.from_circuit(
            new_circuit("20", "1.2.3.5", "early", username="u1", time_created="2026-09-26T09:00:00.000000")
        )
        late = ExitInfo.from_circuit(
            new_circuit("8", "1.2.3.5", "late", username="u1", time_created="2026-09-26T10:00:00.000000")
        )
        plain = ExitInfo.from_circuit(new_circuit("30", "1.2.3.6", "plain"))
        circuits = [old, new, early, late, plain]

        # most recent circuit of the username: highest id, TIME_CREATED first
        self.assertEqual(match_circuit(circuits, "u0", "9.9.9.9"), (new, False))
        self.assertEqual(match_circuit(circuits, "u1", None), (late, False))
        # fallback: exit IP of a circuit without username
        self.assertEqual(match_circuit(circuits, "u2", "1.2.3.6"), (plain, True))
        self.assertEqual(match_circuit(circuits, "", "1.2.3.6"), (plain, True))
        # circuits of other usernames are never matched by the exit IP
        self.assertEqual(match_circuit(circuits, "u2", "1.2.3.4"), (None, False))
        self.assertEqual(match_circuit(circuits, "", None), (None, False))


class PluginTorCircuit(SearxTorTestCase):  # pylint: disable=too-many-public-methods

    def setUp(self):
        super().setUp()
        tor_circuit.clear_cache()
        self.addCleanup(tor_circuit.clear_cache)

        self.storage = get_storage(self.app)
        self.pref = searx.preferences.Preferences(["simple"], ["general"], {}, self.storage)
        self.pref.parse_dict({"locale": "en"})

        # SOCKS usernames of the pool entries (tor_circuits: 3)
        self.users = [socks_username(entry) for entry in searx.network.get_network().proxy_pool]
        self.assertEqual(self.users, ["sxng-0", "sxng-1", "sxng-2"])

        self.failing: set[int] = set()
        self.exit_ips = ["1.2.3.0", "1.2.3.1", "1.2.3.2"]
        patcher = patch("searx.plugins.tor_circuit.multi_requests", side_effect=self.fake_multi_requests)
        self.multi_requests = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch("searx.plugins.tor_circuit.TorControl")
        self.tor_control = patcher.start()
        self.addCleanup(patcher.stop)
        self.ctrl = self.tor_control.return_value.__enter__.return_value
        self.ctrl.circuits.return_value = [
            IP_CIRCUIT,
            # not BUILT / not GENERAL: never used for a probe
            Circuit(id="2", status="EXTENDED", path=(Relay("D" * 40, "extNick", ip="1.2.3.2"),), purpose="GENERAL"),
            Circuit(id="3", status="BUILT", path=(Relay("E" * 40, "hsNick", ip="1.2.3.2"),), purpose="HS_CLIENT_REND"),
        ]

        self.clock = [1000.0]
        patcher = patch("searx.plugins.tor_circuit.monotonic", side_effect=lambda: self.clock[0])
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_multi_requests(self, request_list):
        responses = []
        for req in request_list:
            i = req.kwargs["proxy_index"]
            if i in self.failing:
                responses.append(Timeout("Timeout"))
            else:
                data = {"IsTor": True, "IP": self.exit_ips[i]}
                responses.append(Mock(status_code=200, json=Mock(return_value=data)))
        return responses

    def post_search(self, query: str = "circuit", pageno: int = 1) -> list[Answer]:
        with self.app.test_request_context():
            sxng_request.preferences = self.pref
            search = do_post_search(query, self.storage, pageno=pageno, user_plugins=["tor_circuit"])
            return list(search.result_container.answers)

    def test_plugin_store_init(self):
        self.assertEqual(1, len(self.storage))
        # not in the default plugin list, has to be registered by the admin
        self.assertNotIn("searx.plugins.tor_circuit.SXNGPlugin", searx.get_setting("plugins"))
        self.assertNotIn("tor_circuit", [p.id for p in searx.plugins.STORAGE])

    @parameterized.expand(["circuit", "circuits", "tor-circuit", "exit-ip"])
    def test_circuits(self, query: str):
        answers = self.post_search(query)

        self.assertEqual(
            answers,
            [
                summary_answer(3, 3),
                unknown_answer(1, "1.2.3.0"),
                exit_answer(2, "1.2.3.1", "ip", by_ip=True),
                unknown_answer(3, "1.2.3.2"),
            ],
        )

        # one request per circuit, sent in parallel by one multi_requests call
        self.multi_requests.assert_called_once()
        request_list = self.multi_requests.call_args.args[0]
        self.assertEqual([r.url for r in request_list], [CHECK_URL] * 3)
        self.assertEqual([r.kwargs["proxy_index"] for r in request_list], [0, 1, 2])
        for r in request_list:
            self.assertEqual(r.kwargs["timeout"], 8.0)  # request_timeout 3.0 + extra_proxy_timeout 5.0
            self.assertIs(r.kwargs["raise_for_httperror"], False)

        self.tor_control.assert_called_once_with("127.0.0.1", 9051, "test")

    def test_guard_and_middle_hidden(self):
        self.ctrl.circuits.return_value = [
            new_circuit(str(i), ip, f"c{i}", self.users[i]) for i, ip in enumerate(self.exit_ips)
        ]
        answers = self.post_search()
        self.assertEqual(answers[1:], [exit_answer(i + 1, ip, f"c{i}") for i, ip in enumerate(self.exit_ips)])
        text = " ".join(a.answer for a in answers)
        self.assertNotIn("Guard", text)
        self.assertNotIn("Middle", text)
        self.assertNotIn("(DE)", text)
        self.assertNotIn("(NL)", text)

    def test_conflux_circuits(self):
        # Tor 0.4.8+ reports the exit circuits with purpose CONFLUX_*
        self.ctrl.circuits.return_value = [
            new_circuit("10", "1.2.3.0", "linked", username=self.users[0], purpose="CONFLUX_LINKED"),
            new_circuit("11", "1.2.3.1", "unlinked", username=self.users[1], purpose="CONFLUX_UNLINKED"),
            # not an exit circuit, even with the username and exit IP of a probe
            new_circuit("12", "1.2.3.2", "hs", username=self.users[2], purpose="HS_CLIENT_REND"),
        ]
        answers = self.post_search()
        self.assertEqual(
            answers,
            [
                summary_answer(3, 3),
                exit_answer(1, "1.2.3.0", "linked"),
                exit_answer(2, "1.2.3.1", "unlinked"),
                unknown_answer(3, "1.2.3.2"),
            ],
        )

    def test_username_match_wins(self):
        # multi-homed exit: the relay IP in the consensus (9.9.9.9) is not the
        # IP seen by check.torproject.org (1.2.3.1), IP_CIRCUIT has this IP
        self.ctrl.circuits.return_value = [IP_CIRCUIT, new_circuit("7", "9.9.9.9", "multi", username=self.users[1])]
        answers = self.post_search()
        self.assertEqual(answers[2], exit_answer(2, "1.2.3.1", "multi"))

    def test_same_exit_ip_different_usernames(self):
        self.exit_ips = ["1.2.3.7"] * 3
        self.ctrl.circuits.return_value = [
            new_circuit("10", "1.2.3.7", "c", username=self.users[2]),
            new_circuit("11", "1.2.3.7", "a", username=self.users[0]),
            new_circuit("12", "1.2.3.7", "b", username=self.users[1]),
        ]
        answers = self.post_search()
        self.assertEqual(
            answers,
            [
                summary_answer(3, 1),
                exit_answer(1, "1.2.3.7", "a"),
                exit_answer(2, "1.2.3.7", "b"),
                exit_answer(3, "1.2.3.7", "c"),
            ],
        )

    def test_most_recent_circuit_of_username(self):
        self.ctrl.circuits.return_value = [
            new_circuit("5", "1.2.3.0", "old", username=self.users[0]),
            new_circuit("12", "5.5.5.5", "new", username=self.users[0]),
            new_circuit("20", "1.2.3.1", "early", username=self.users[1], time_created="2026-09-26T09:00:00.000000"),
            new_circuit("8", "6.6.6.6", "late", username=self.users[1], time_created="2026-09-26T10:00:00.000000"),
        ]
        answers = self.post_search()
        self.assertEqual(answers[1], exit_answer(1, "1.2.3.0", "new"))
        self.assertEqual(answers[2], exit_answer(2, "1.2.3.1", "late"))

    def test_ip_fallback_ignores_other_usernames(self):
        # the circuit of sxng-1 has the exit IP of the sxng-0 probe, which has
        # no circuit of its own: its exit is unknown, not the exit of sxng-1
        self.ctrl.circuits.return_value = [new_circuit("7", "1.2.3.0", "other", username=self.users[1])]
        answers = self.post_search()
        self.assertEqual(answers[1], unknown_answer(1, "1.2.3.0"))
        self.assertEqual(answers[2], exit_answer(2, "1.2.3.1", "other"))

    def test_pool_without_credentials(self):
        # tor_circuits 0/1: one proxy URL without SOCKS credentials
        network = Network(proxies="socks5h://127.0.0.1:9050", using_tor_proxy=True, tor_circuits=0)
        self.assertEqual(len(network.proxy_pool), 1)
        self.ctrl.circuits.return_value = [
            new_circuit("4", "1.2.3.0", "tb", username="tor-browser"),
            new_circuit("5", "1.2.3.0", "plain"),
        ]
        with patch("searx.plugins.tor_circuit.get_network", return_value=network):
            answers = self.post_search()
        self.assertEqual(answers, [summary_answer(1, 1), exit_answer(1, "1.2.3.0", "plain", by_ip=True, total=1)])
        self.assertEqual([r.kwargs["proxy_index"] for r in self.multi_requests.call_args.args[0]], [0])

    @parameterized.expand(
        [
            ("circuit", 2),
            ("circuit lorem", 1),
            ("lorem ipsum", 1),
        ]
    )
    def test_not_triggered(self, query: str, pageno: int):
        self.assertEqual(self.post_search(query, pageno=pageno), [])
        self.multi_requests.assert_not_called()
        self.tor_control.assert_not_called()

    def test_control_port_error(self):
        self.tor_control.return_value.__enter__.side_effect = ConnectionRefusedError("refused")
        with self.assertLogs("searx.plugins.tor_circuit", level="WARNING"):
            answers = self.post_search()
        self.assertEqual(
            answers,
            [
                summary_answer(3, 3),
                unknown_answer(1, "1.2.3.0"),
                unknown_answer(2, "1.2.3.1"),
                unknown_answer(3, "1.2.3.2"),
            ],
        )

    def test_one_probe_failed(self):
        self.failing = {1}
        answers = self.post_search()
        self.assertEqual(
            answers,
            [
                summary_answer(3, 2),
                unknown_answer(1, "1.2.3.0"),
                Answer(answer="Circuit 2/3 - request failed (Timeout)"),
                unknown_answer(3, "1.2.3.2"),
            ],
        )

    def test_invalid_responses(self):
        responses = [
            Mock(status_code=503),
            Mock(status_code=200, json=Mock(side_effect=ValueError("no JSON"))),
            Mock(status_code=200, json=Mock(return_value={"IsTor": False, "IP": "not an IP"})),
        ]
        self.multi_requests.side_effect = None
        self.multi_requests.return_value = responses
        answers = self.post_search()
        self.assertEqual(
            answers,
            [
                summary_answer(3, 0),
                Answer(answer="Circuit 1/3 - request failed (HTTP 503)"),
                Answer(answer="Circuit 2/3 - request failed (invalid response)"),
                Answer(answer="Circuit 3/3 - request failed (invalid response)"),
            ],
        )
        # without an exit IP there is nothing to look up in the ControlPort
        self.tor_control.assert_not_called()

    def test_not_tor(self):
        self.multi_requests.side_effect = None
        self.multi_requests.return_value = [
            Mock(status_code=200, json=Mock(return_value={"IsTor": False, "IP": "1.2.3.1"})),
        ] * 3
        answers = self.post_search()
        self.assertIn(summary_answer(3, 1), answers)
        self.assertIn(exit_answer(1, "1.2.3.1", "ip", by_ip=True, tor="no"), answers)

    def test_multi_requests_raises(self):
        self.multi_requests.side_effect = RuntimeError("event loop is gone")
        with self.assertLogs("searx.plugins.tor_circuit", level="WARNING"):
            answers = self.post_search()
        self.assertEqual(
            answers,
            [summary_answer(3, 0)]
            + [Answer(answer=f"Circuit {i}/3 - request failed (RuntimeError)") for i in (1, 2, 3)],
        )

    def test_control_port_not_configured(self):
        with patch.dict(searx.settings["outgoing"]["tor_control"], {"host": ""}):
            answers = self.post_search()
        self.tor_control.assert_not_called()
        self.assertIn(unknown_answer(2, "1.2.3.1"), answers)
        self.assertEqual(len(answers), 4)

    def test_cache(self):
        first = self.post_search()

        # within CACHE_TTL: no new probes, no new ControlPort session
        self.clock[0] += tor_circuit.CACHE_TTL - 1
        self.exit_ips = ["5.5.5.5"] * 3
        self.assertEqual(self.post_search(), first)
        self.assertEqual(self.post_search("exit-ip"), first)
        self.multi_requests.assert_called_once()
        self.tor_control.assert_called_once()

        # CACHE_TTL expired: collected again
        self.clock[0] += 2
        answers = self.post_search()
        self.assertEqual(self.multi_requests.call_count, 2)
        self.assertEqual(self.tor_control.call_count, 2)
        self.assertEqual(answers[0], summary_answer(3, 1))

    def test_cache_concurrent_requests(self):
        entered, release = threading.Event(), threading.Event()

        def slow_multi_requests(request_list):
            entered.set()
            release.wait(5)
            return self.fake_multi_requests(request_list)

        self.multi_requests.side_effect = slow_multi_requests
        results = []

        def worker():
            results.append(tor_circuit.circuit_results())

        first = threading.Thread(target=worker)
        first.start()
        self.assertTrue(entered.wait(5))
        second = threading.Thread(target=worker)
        second.start()
        time.sleep(0.1)  # the second request waits for the lock
        release.set()
        first.join(5)
        second.join(5)

        self.multi_requests.assert_called_once()
        self.assertEqual(len(results), 2)
        self.assertIs(results[0], results[1])
