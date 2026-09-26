# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

from ipaddress import ip_address

from mock import Mock, patch

import searx.limiter
from searx.botdetection import config, get_network, link_token, valkeydb
from searx.extended_types import sxng_request

from tests import SearxTestCase

HEADERS = {"User-Agent": "Dummy agent", "Accept-Language": "en-US"}


class LinkTokenPing(SearxTestCase):

    def setUp(self):
        super().setUp()
        self.cfg = searx.limiter.get_cfg()
        self.setattr4test(config, "CFG", self.cfg)
        # the default test profile has no valkey DB
        self.setattr4test(valkeydb, "CLIENT", None)

    def mock_valkey(self, token: str) -> Mock:
        valkey_client = Mock()
        valkey_client.get.return_value = token.encode("utf-8")
        self.setattr4test(valkeydb, "CLIENT", valkey_client)
        return valkey_client

    def test_ping_without_valkey(self):
        with self.app.test_request_context(environ_base={"REMOTE_ADDR": "1.2.3.4"}, headers=HEADERS):
            with patch.object(config, "get_global_cfg") as get_global_cfg:
                self.assertIsNone(link_token.ping(sxng_request, "12345678"))
            get_global_cfg.assert_not_called()

    def test_ping_valid_token(self):
        valkey_client = self.mock_valkey("abcdefgh12345678")

        with self.app.test_request_context(environ_base={"REMOTE_ADDR": "1.2.3.4"}, headers=HEADERS):
            link_token.ping(sxng_request, "abcdefgh12345678")
            ping_key = link_token.get_ping_key(get_network(ip_address("1.2.3.4"), self.cfg), sxng_request)

        self.assertTrue(ping_key.startswith(link_token.PING_KEY))
        valkey_client.set.assert_called_once_with(ping_key, 1, ex=link_token.PING_LIVE_TIME)

    def test_ping_invalid_token(self):
        valkey_client = self.mock_valkey("abcdefgh12345678")

        with self.app.test_request_context(environ_base={"REMOTE_ADDR": "1.2.3.4"}, headers=HEADERS):
            link_token.ping(sxng_request, "12345678")

        valkey_client.set.assert_not_called()

    def test_client_css_without_valkey(self):
        token = link_token.get_token()
        self.assertEqual(token, "12345678")

        response = self.client.get(f"/client{token}.css", headers={**HEADERS, "X-Forwarded-For": "1.2.3.4"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/css")
