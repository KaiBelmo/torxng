# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

from curl_cffi.requests.exceptions import RequestException
from mock import Mock, patch
from parameterized.parameterized import parameterized

from flask_babel import gettext

import searx.plugins
import searx.preferences

from searx.extended_types import sxng_request
from searx.plugins.tor_check import url_exit_list
from searx.result_types import Answer

from tests import SearxTestCase
from .test_plugins import do_post_search

EXIT_LIST = "ExitAddress 8.8.8.8 2026-01-01 00:00:00\n"


class PluginTorCheck(SearxTestCase):

    def setUp(self):
        super().setUp()
        engines = {}

        self.storage = searx.plugins.PluginStorage()
        self.storage.load_settings({"searx.plugins.tor_check.SXNGPlugin": {"active": True}})
        self.storage.init(self.app)
        self.pref = searx.preferences.Preferences(["simple"], ["general"], engines, self.storage)
        self.pref.parse_dict({"locale": "en"})

    def post_search(self, remote_addr: str, query: str = "tor-check", pageno: int = 1) -> list[Answer]:
        with self.app.test_request_context(environ_base={"REMOTE_ADDR": remote_addr}):
            sxng_request.preferences = self.pref
            search = do_post_search(query, self.storage, pageno=pageno, user_plugins=["tor_check"])
            return list(search.result_container.answers)

    def test_plugin_store_init(self):
        self.assertEqual(1, len(self.storage))

    @parameterized.expand(
        [
            ("127.0.0.1", "127.0.0.1"),
            ("10.0.0.5", "10.0.0.5"),
            ("172.17.0.2", "172.17.0.2"),
            ("::1", "::1"),
            ("fe80::1", "fe80::1"),
            ("fd0f:a306:f289:0000:0000:0000:ffff:aaaa", "fd0f:a306:f289::ffff:aaaa"),
        ]
    )
    def test_local_or_proxied_address(self, remote_addr: str, compressed: str):
        with patch("searx.plugins.tor_check.get") as get:
            answers = self.post_search(remote_addr)
        get.assert_not_called()
        msg = gettext(
            "The request reached SearXNG from a local or proxied address, the Tor exit-node check is not applicable:"
        )
        self.assertEqual(answers, [Answer(answer=f"{msg} {compressed}")])

    def test_using_tor(self):
        with patch("searx.plugins.tor_check.get", return_value=Mock(text=EXIT_LIST)) as get:
            answers = self.post_search("8.8.8.8")
        get.assert_called_once_with(url_exit_list)
        msg = gettext("You are using Tor and it looks like you have the external IP address")
        self.assertEqual(answers, [Answer(answer=f"{msg} 8.8.8.8")])

    def test_not_using_tor(self):
        with patch("searx.plugins.tor_check.get", return_value=Mock(text=EXIT_LIST)):
            answers = self.post_search("9.9.9.9")
        msg = gettext("You are not using Tor and you have the external IP address")
        self.assertEqual(answers, [Answer(answer=f"{msg} 9.9.9.9")])

    def test_download_error(self):
        with patch("searx.plugins.tor_check.get", side_effect=RequestException("x")):
            answers = self.post_search("9.9.9.9")
        msg = gettext("Could not download the list of Tor exit-nodes from")
        self.assertEqual(answers, [Answer(answer=f"{msg} {url_exit_list}")])

    @parameterized.expand(
        [
            ("tor-check", 2),
            ("tor-check lorem ipsum", 1),
            ("lorem ipsum", 1),
        ]
    )
    def test_not_triggered(self, query: str, pageno: int):
        with patch("searx.plugins.tor_check.get", return_value=Mock(text=EXIT_LIST)) as get:
            answers = self.post_search("8.8.8.8", query=query, pageno=pageno)
            answers += self.post_search("127.0.0.1", query=query, pageno=pageno)
        get.assert_not_called()
        self.assertEqual(answers, [])
