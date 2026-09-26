# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import importlib
import typing as t

from mock import Mock, patch
from parameterized import parameterized

from tests import SearxTestCase


class StopScript(Exception):
    """Raised by the (mocked) first request of a script."""


class TestUpdateScripts(SearxTestCase):
    """Tor-only build: the update scripts in :origin:`searxng_extra/update`
    initialize the network (Tor) and check it before they send their first
    request (without the initialization, a request fails, see
    :py:obj:`searx.network.network.NOT_INITIALIZED`)."""

    @parameterized.expand(
        [
            ('update_ahmia_blacklist', 'main', 'searx.network.get'),
            ('update_currencies', 'main', 'send_wikidata_query'),
            ('update_engine_traits', 'cli', 'fetch_traits_map'),
            ('update_external_bangs', 'main', 'http_get'),
            ('update_firefox_version', 'main', 'searx.network.get'),
            ('update_osm_keys_tags', 'main', 'send_wikidata_query'),
            ('update_wikidata', 'main', 'fetch_units'),
        ]
    )
    def test_initialize_network(self, script: str, entry_point: str, first_request: str):
        module = importlib.import_module(f'searxng_extra.update.{script}')
        if '.' not in first_request:
            first_request = f'{module.__name__}.{first_request}'

        manager = Mock()
        with (
            patch('searx.network.initialize') as initialize,
            patch('searx.network.check_network_configuration') as check_network_configuration,
            patch(first_request, side_effect=StopScript) as request,
            patch('builtins.print'),
        ):
            manager.attach_mock(initialize, 'initialize')
            manager.attach_mock(check_network_configuration, 'check_network_configuration')
            manager.attach_mock(request, 'request')
            with self.assertRaises(StopScript):
                getattr(module, entry_point)()

        self.assertEqual(
            [name for name, _args, _kwargs in manager.mock_calls],
            ['initialize', 'check_network_configuration', 'request'],
        )

    def test_engine_descriptions(self):
        module: t.Any = importlib.import_module('searxng_extra.update.update_engine_descriptions')
        with patch('searx.search.initialize', side_effect=StopScript) as initialize:
            with self.assertRaises(StopScript):
                module.initialize()
        initialize.assert_called_once_with(check_network=True)
