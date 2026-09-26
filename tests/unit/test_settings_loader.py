# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import typing as t
from pathlib import Path

import os
from unittest.mock import patch

from parameterized import parameterized

import searx
from searx.exceptions import SearxSettingsException
from searx import settings_loader
from searx.settings_defaults import DEFAULT_TOR_PROXY, SCHEMA, apply_schema, apply_tor_only
from tests import SearxTestCase


def _settings(f_name):
    return str(Path(__file__).parent.absolute() / "settings" / f_name)


class TestLoad(SearxTestCase):

    def test_load_zero(self):
        with self.assertRaises(SearxSettingsException):
            settings_loader.load_yaml('/dev/zero')

        with self.assertRaises(SearxSettingsException):
            settings_loader.load_yaml(_settings("syntaxerror_settings.yml"))

        self.assertEqual(settings_loader.load_yaml(_settings("empty_settings.yml")), {})


class TestDefaultSettings(SearxTestCase):

    def test_load(self):
        settings, msg = settings_loader.load_settings(load_user_settings=False)
        self.assertTrue(msg.startswith('load the default settings from'))
        self.assertFalse(settings['general']['debug'])
        self.assertIsInstance(settings['general']['instance_name'], str)
        self.assertEqual(settings['server']['secret_key'], "ultrasecretkey")
        self.assertIsInstance(settings['server']['port'], int)
        self.assertIsInstance(settings['server']['bind_address'], str)
        self.assertIsInstance(settings['engines'], list)
        self.assertIsInstance(settings['doi_resolvers'], dict)
        self.assertIsInstance(settings['default_doi_resolver'], str)

    def test_tor_defaults(self):
        # Tor-only build: the default settings use the SOCKS port of a local Tor daemon
        settings, _ = settings_loader.load_settings(load_user_settings=False)
        outgoing: t.Any = settings['outgoing']
        self.assertIs(outgoing['using_tor_proxy'], True)
        self.assertEqual(outgoing['proxies'], {'all://': DEFAULT_TOR_PROXY})
        self.assertEqual(DEFAULT_TOR_PROXY, 'socks5h://127.0.0.1:9050')


class TestUserSettings(SearxTestCase):

    def test_is_use_default_settings(self):
        self.assertFalse(settings_loader.is_use_default_settings({}))
        self.assertTrue(settings_loader.is_use_default_settings({'use_default_settings': True}))
        self.assertTrue(settings_loader.is_use_default_settings({'use_default_settings': {}}))
        with self.assertRaises(ValueError):
            self.assertFalse(settings_loader.is_use_default_settings({'use_default_settings': 1}))
        with self.assertRaises(ValueError):
            self.assertFalse(settings_loader.is_use_default_settings({'use_default_settings': 0}))

    @parameterized.expand(
        [
            _settings("not_exists.yml"),
            "/folder/not/exists",
        ]
    )
    def test_user_settings_not_found(self, path: str):
        with patch.dict(os.environ, {'SEARXNG_SETTINGS_PATH': path}):
            with self.assertRaises(EnvironmentError):
                _s, _m = settings_loader.load_settings()

    def test_user_settings(self):
        with patch.dict(os.environ, {'SEARXNG_SETTINGS_PATH': _settings("user_settings_simple.yml")}):
            settings, msg = settings_loader.load_settings()
            self.assertTrue(msg.startswith('merge the default settings'))
            self.assertEqual(settings['server']['secret_key'], "user_secret_key")
            self.assertEqual(settings['server']['default_http_headers']['Custom-Header'], "Custom-Value")

    def test_user_settings_remove(self):
        with patch.dict(os.environ, {'SEARXNG_SETTINGS_PATH': _settings("user_settings_remove.yml")}):
            settings, msg = settings_loader.load_settings()
            self.assertTrue(msg.startswith('merge the default settings'))
            self.assertEqual(settings['server']['secret_key'], "user_secret_key")
            self.assertEqual(settings['server']['default_http_headers']['Custom-Header'], "Custom-Value")
            engine_names = [engine['name'] for engine in settings['engines']]
            self.assertNotIn('wikinews', engine_names)
            self.assertNotIn('wikibooks', engine_names)
            self.assertIn('wikipedia', engine_names)

    def test_user_settings_remove2(self):
        with patch.dict(os.environ, {'SEARXNG_SETTINGS_PATH': _settings("user_settings_remove2.yml")}):
            settings, msg = settings_loader.load_settings()
            self.assertTrue(msg.startswith('merge the default settings'))
            self.assertEqual(settings['server']['secret_key'], "user_secret_key")
            self.assertEqual(settings['server']['default_http_headers']['Custom-Header'], "Custom-Value")
            engine_names = [engine['name'] for engine in settings['engines']]
            self.assertNotIn('wikinews', engine_names)
            self.assertNotIn('wikibooks', engine_names)
            self.assertIn('wikipedia', engine_names)
            wikipedia = list(filter(lambda engine: (engine.get('name')) == 'wikipedia', settings['engines']))
            self.assertEqual(wikipedia[0]['engine'], 'wikipedia')
            self.assertEqual(wikipedia[0]['tokens'], ['secret_token'])
            newengine = list(filter(lambda engine: (engine.get('name')) == 'newengine', settings['engines']))
            self.assertEqual(newengine[0]['engine'], 'dummy')

    def test_user_settings_keep_only(self):
        with patch.dict(os.environ, {'SEARXNG_SETTINGS_PATH': _settings("user_settings_keep_only.yml")}):
            settings, msg = settings_loader.load_settings()
            self.assertTrue(msg.startswith('merge the default settings'))
            engine_names = [engine['name'] for engine in settings['engines']]
            self.assertEqual(engine_names, ['wikibooks', 'wikinews', 'wikipedia', 'newengine'])
            # wikipedia has been removed, then added again with the "engine" section of user_settings_keep_only.yml
            self.assertEqual(len(settings['engines'][2]), 1)

    def test_custom_settings(self):
        with patch.dict(os.environ, {'SEARXNG_SETTINGS_PATH': _settings("user_settings.yml")}):
            settings, msg = settings_loader.load_settings()
            self.assertTrue(msg.startswith('load the user settings from'))
            self.assertEqual(settings['server']['port'], 9000)
            self.assertEqual(settings['server']['secret_key'], "user_settings_secret")
            engine_names = [engine['name'] for engine in settings['engines']]
            self.assertEqual(engine_names, ['wikidata', 'wikibooks', 'wikinews', 'wikiquote'])


class TestOutgoingSchema(SearxTestCase):

    TOR_ENVIRON = {
        'SEARXNG_USING_TOR_PROXY': 'true',
        'SEARXNG_TOR_CIRCUITS': '4',
        'SEARXNG_TOR_CONTROL_HOST': 'tor',
        'SEARXNG_TOR_CONTROL_PORT': '9052',
        'SEARXNG_TOR_CONTROL_PASSWORD': 'secret',
    }

    @staticmethod
    def outgoing(cfg: dict[str, t.Any]) -> dict[str, t.Any]:
        settings: dict[str, t.Any] = {'outgoing': cfg}
        apply_schema(settings, {'outgoing': SCHEMA['outgoing']}, [])
        return settings['outgoing']

    def test_extra_proxy_timeout(self):
        value = SCHEMA['outgoing']['extra_proxy_timeout']
        self.assertEqual(value(10.0), 10.0)
        self.assertEqual(value(10), 10)
        with self.assertRaises(ValueError):
            value("10")

    def test_tor_defaults(self):
        with patch.dict(os.environ):
            for name in self.TOR_ENVIRON:
                os.environ.pop(name, None)
            outgoing = self.outgoing({})
        self.assertIs(outgoing['using_tor_proxy'], True)
        self.assertEqual(outgoing['extra_proxy_timeout'], 0)
        self.assertEqual(outgoing['tor_circuits'], 0)
        self.assertEqual(outgoing['tor_control'], {'host': '', 'port': 9051, 'password': ''})

    def test_tor_values(self):
        cfg = {
            'using_tor_proxy': True,
            'extra_proxy_timeout': 5.5,
            'tor_circuits': 3,
            'tor_control': {'host': '127.0.0.1', 'port': 9051, 'password': 'test'},
        }
        outgoing = self.outgoing(cfg)
        self.assertEqual(outgoing['extra_proxy_timeout'], 5.5)
        self.assertEqual(outgoing['tor_circuits'], 3)
        self.assertEqual(outgoing['tor_control'], {'host': '127.0.0.1', 'port': 9051, 'password': 'test'})

    def test_tor_environ(self):
        # the environment takes precedence over the values from settings.yml
        cfg = {'using_tor_proxy': False, 'tor_circuits': 2, 'tor_control': {'host': '127.0.0.1'}}
        with patch.dict(os.environ, self.TOR_ENVIRON):
            outgoing = self.outgoing(cfg)
        self.assertIs(outgoing['using_tor_proxy'], True)
        # tor_circuits is converted to an integer, the port is converted where it is used
        self.assertEqual(outgoing['tor_circuits'], 4)
        self.assertEqual(outgoing['tor_control'], {'host': 'tor', 'port': '9052', 'password': 'secret'})

    def test_tor_circuits(self):
        value = SCHEMA['outgoing']['tor_circuits']
        with patch.dict(os.environ):
            os.environ.pop('SEARXNG_TOR_CIRCUITS', None)
            self.assertEqual(value(0), 0)
            self.assertEqual(value(32), 32)
            self.assertEqual(value('8'), 8)
            for invalid in (-1, 33, '33', 'three', True, 3.0):
                with self.assertRaises(ValueError):
                    value(invalid)

    def test_tor_circuits_invalid_environ(self):
        with patch.dict(os.environ, {'SEARXNG_TOR_CIRCUITS': '64'}):
            with self.assertLogs('searx', level='ERROR') as logs:
                with self.assertRaises(ValueError):
                    self.outgoing({})
        self.assertIn('outgoing.tor_circuits: 64 is not in the range 0..32', logs.output[0])


class TestTorOnly(SearxTestCase):
    """Tor-only build: :py:obj:`searx.settings_defaults.apply_tor_only`."""

    PROXY_ERROR = 'Tor-only build: outgoing.proxies must be a socks5h:// Tor proxy (set SEARXNG_TOR_PROXY)'

    def setUp(self):
        super().setUp()
        patcher = patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ('SEARXNG_TOR_PROXY', 'SEARXNG_USING_TOR_PROXY'):
            os.environ.pop(name, None)

    @staticmethod
    def settings(**outgoing: t.Any) -> dict[str, t.Any]:
        settings: dict[str, t.Any] = {'outgoing': outgoing}
        apply_schema(settings, {'outgoing': SCHEMA['outgoing']}, [])
        apply_tor_only(settings)
        return settings

    def assert_tor_only_error(self, message: str, **outgoing: t.Any):
        with self.assertRaises(ValueError) as ctx:
            self.settings(**outgoing)
        self.assertEqual(str(ctx.exception), message)

    def test_tor(self):
        settings = self.settings(proxies={'all://': 'socks5h://127.0.0.1:9050'})
        self.assertIs(settings['outgoing']['using_tor_proxy'], True)
        self.assertEqual(settings['outgoing']['proxies'], {'all://': 'socks5h://127.0.0.1:9050'})
        # a list of proxies, a proxy for each scheme
        proxies = {'https://': ['socks5h://tor1:9050', 'socks5h://tor2:9050'], 'http://': 'socks5h://tor1:9050'}
        self.assertEqual(self.settings(proxies=proxies)['outgoing']['proxies'], proxies)

    def test_using_tor_proxy_false(self):
        message = 'Tor-only build: outgoing.using_tor_proxy must be true'
        self.assert_tor_only_error(message, using_tor_proxy=False, proxies='socks5h://127.0.0.1:9050')
        os.environ['SEARXNG_USING_TOR_PROXY'] = 'false'
        self.assert_tor_only_error(message, using_tor_proxy=True, proxies='socks5h://127.0.0.1:9050')

    def test_proxies(self):
        for proxies in (None, '', {}, {'all://': []}):
            self.assert_tor_only_error(self.PROXY_ERROR, proxies=proxies)
        # without socks5h:// the host names are resolved by the local DNS resolver
        for proxies in (
            'socks5://127.0.0.1:9050',
            {'all://': 'http://proxy:8080'},
            {'all://': ['socks5h://127.0.0.1:9050', 'socks4://127.0.0.1:9050']},
            {'https://': 'socks5h://127.0.0.1:9050', 'http://': 'http://proxy:8080'},
        ):
            self.assert_tor_only_error(self.PROXY_ERROR, proxies=proxies)

    def test_tor_proxy_environ(self):
        os.environ['SEARXNG_TOR_PROXY'] = 'socks5h://tor:9050'
        # the environment replaces the proxies (and fixes an empty value)
        for proxies in (None, {'https://': 'socks5h://127.0.0.1:9050', 'http://': 'socks5h://127.0.0.1:9050'}):
            settings = self.settings(proxies=proxies)
            self.assertEqual(settings['outgoing']['proxies'], {'all://': 'socks5h://tor:9050'})
        # but not using_tor_proxy: false
        os.environ['SEARXNG_USING_TOR_PROXY'] = 'false'
        self.assert_tor_only_error('Tor-only build: outgoing.using_tor_proxy must be true')

    def test_tor_proxy_environ_invalid(self):
        for value, message in (
            ('socks5://tor:9050', 'must be a socks5h:// URL, not a socks5:// URL'),
            ('http://user:secret@proxy:8080', 'must be a socks5h:// URL, not a http:// URL'),
            ('', 'must be a socks5h:// URL, not a ?:// URL'),
            ('tor:9050', 'must be a socks5h:// URL, not a tor:// URL'),
            ('socks5h://tor', 'must be a socks5h://host:port URL, host or port is missing'),
            ('socks5h://:9050', 'must be a socks5h://host:port URL, host or port is missing'),
            ('socks5h://tor:port', 'must be a socks5h://host:port URL, host or port is missing'),
            ('socks5h://tor:0', 'must be a socks5h://host:port URL, host or port is missing'),
            ('socks5h://[::1:9050', 'must be a socks5h://host:port URL, host or port is missing'),
        ):
            os.environ['SEARXNG_TOR_PROXY'] = value
            with self.assertRaises(ValueError) as ctx:
                self.settings(proxies='socks5h://127.0.0.1:9050')
            self.assertEqual(str(ctx.exception), f'Tor-only build: SEARXNG_TOR_PROXY {message}', value)
            # the value may contain credentials, they are not in the message
            self.assertNotIn('secret', str(ctx.exception))

    def test_init_settings(self):
        """SearXNG refuses to start (``searx.init_settings``), the settings are
        not changed."""
        settings = searx.settings.copy()
        for name, value in (('SEARXNG_USING_TOR_PROXY', 'false'), ('SEARXNG_TOR_PROXY', 'socks5://x:1')):
            with patch.dict(os.environ, {name: value}):
                with self.assertRaises(ValueError) as ctx:
                    searx.init_settings()
            self.assertTrue(str(ctx.exception).startswith('Tor-only build: '), str(ctx.exception))
            self.assertEqual(searx.settings, settings)

        with patch.dict(os.environ, {'SEARXNG_TOR_PROXY': 'socks5h://tor:9050'}):
            searx.init_settings()
        self.assertEqual(searx.settings['outgoing']['proxies'], {'all://': 'socks5h://tor:9050'})
