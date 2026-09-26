# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import typing as t

from mock import patch

from searx.engines import load_engine
from tests import SearxTestCase


class TestRadioBrowserTor(SearxTestCase):
    """Tor-only build: the radio_browser engine must not resolve its servers
    with the local DNS resolver (the socket functions raise if they are
    called)."""

    def setUp(self):
        super().setUp()
        for func in ('getaddrinfo', 'gethostbyaddr', 'gethostbyname'):
            patcher = patch(f'socket.{func}', side_effect=AssertionError(f'local DNS lookup: socket.{func}'))
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def load(**engine_args: t.Any) -> t.Any:
        engine_data = {'name': 'radio browser', 'engine': 'radio_browser', 'shortcut': 'rb', **engine_args}
        return load_engine(engine_data)

    def test_tor_without_servers(self):
        with self.assertLogs('searx.engines', level='ERROR') as logs:
            self.assertIsNone(self.load())
        self.assertIn('local DNS resolver', '\n'.join(logs.output))

    def test_engine_opt_out(self):
        # an engine can't opt out of Tor
        with self.assertLogs('searx.engines', level='ERROR'):
            self.assertIsNone(self.load(using_tor_proxy=False))

    def test_tor_with_servers(self):
        engine = self.load(servers=['https://de1.api.radio-browser.info'])
        assert engine is not None
        engine.init(None)
        params: dict[str, t.Any] = {'pageno': 1, 'searxng_locale': 'all'}
        engine.request('jazz', params)
        self.assertTrue(params['url'].startswith('https://de1.api.radio-browser.info/json/stations/search?'))

    def test_server_list_tor(self):
        # defense in depth: server_list() never does a DNS lookup with Tor
        engine = self.load(servers=['https://de1.api.radio-browser.info'])
        assert engine is not None
        engine.servers = []
        with self.assertRaises(RuntimeError):
            engine.server_list()
