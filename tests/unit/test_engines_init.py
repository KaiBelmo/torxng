# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import typing as t

from mock import patch

from searx import settings, engines
from tests import SearxTestCase


class TestEnginesInit(SearxTestCase):

    def test_initialize_engines_default(self):
        engine_list = [
            {'engine': 'dummy', 'name': 'engine1', 'shortcut': 'e1'},
            {'engine': 'dummy', 'name': 'engine2', 'shortcut': 'e2'},
        ]

        engines.load_engines(engine_list)
        self.assertEqual(len(engines.engines), 2)
        self.assertIn('engine1', engines.engines)
        self.assertIn('engine2', engines.engines)

    def test_initialize_engines_include_onions(self):
        # Tor-only build: the onion engines are always loaded
        self.assertIs(settings['outgoing']['using_tor_proxy'], True)
        self.set_outgoing(extra_proxy_timeout=100.0)
        engine_list = [
            {
                'engine': 'dummy',
                'name': 'engine1',
                'shortcut': 'e1',
                'categories': 'general',
                'timeout': 20.0,
                'onion_url': 'http://engine1.onion',
            },
            {'engine': 'dummy', 'name': 'engine2', 'shortcut': 'e2', 'categories': 'onions'},
        ]

        engines.load_engines(engine_list)
        self.assertEqual(len(engines.engines), 2)
        self.assertIn('engine1', engines.engines)
        self.assertIn('engine2', engines.engines)
        self.assertIn('onions', engines.categories)
        self.assertIn('http://engine1.onion', engines.engines['engine1'].search_url)
        self.assertEqual(engines.engines['engine1'].timeout, 120.0)

    def set_outgoing(self, **kwargs: t.Any):
        patcher = patch.dict(settings['outgoing'], kwargs)
        patcher.start()
        self.addCleanup(patcher.stop)

    def load_engine_timeout(self, **engine_args: t.Any) -> float:
        engine_list = [
            {'engine': 'dummy', 'name': 'engine1', 'shortcut': 'e1', 'timeout': 20.0, **engine_args},
        ]
        engines.load_engines(engine_list)
        return engines.engines['engine1'].timeout

    def test_extra_proxy_timeout_tor(self):
        # engines without onion_url get the extra_proxy_timeout as well
        self.set_outgoing(extra_proxy_timeout=5.5)
        self.assertEqual(self.load_engine_timeout(), 25.5)

    def test_engine_opt_out(self):
        # Tor-only build: an engine can't opt out of Tor
        self.set_outgoing(extra_proxy_timeout=5.5)
        self.assertEqual(self.load_engine_timeout(using_tor_proxy=False), 25.5)
        self.assertIs(engines.using_tor_proxy(engines.engines['engine1']), True)

    def test_missing_name_field(self):
        engine_list = [
            {'engine': 'dummy', 'shortcut': 'e1', 'categories': 'general'},
        ]
        with self.assertLogs('searx.engines', level='ERROR') as cm:  # pylint: disable=invalid-name
            engines.load_engines(engine_list)
            self.assertEqual(len(engines.engines), 0)
            self.assertEqual(cm.output[0], 'ERROR:searx.engines:An engine does not have a "name" field')

    def test_missing_engine_field(self):
        engine_list = [
            {'name': 'engine2', 'shortcut': 'e2', 'categories': 'onions'},
        ]
        with self.assertLogs('searx.engines', level='ERROR') as cm:  # pylint: disable=invalid-name
            engines.load_engines(engine_list)
            self.assertEqual(len(engines.engines), 0)
            self.assertEqual(
                cm.output[0], 'ERROR:searx.engines:The "engine" field is missing for the engine named "engine2"'
            )
