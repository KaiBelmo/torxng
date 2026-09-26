# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import typing as t

from curl_cffi.requests.exceptions import HTTPError, Timeout
from mock import Mock, patch

import searx.autocomplete
from searx import settings
from searx.exceptions import SearxEngineTooManyRequestsException
from tests import SearxTestCase

URL = 'https://example.org/suggest?q=searxng'


class TestAutocompleteRequest(SearxTestCase):

    def setUp(self):
        super().setUp()
        # Tor-only build: the default timeout is request_timeout + extra_proxy_timeout
        self.set_outgoing(request_timeout=2.5, extra_proxy_timeout=7.0)

    def set_outgoing(self, **kwargs: t.Any):
        patcher = patch.dict(settings['outgoing'], kwargs)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_update_kwargs(self):
        kwargs: dict[str, t.Any] = {'headers': {'Accept': 'application/json'}}
        self.assertIs(searx.autocomplete.update_kwargs(kwargs), kwargs)
        self.assertEqual(
            kwargs,
            {'headers': {'Accept': 'application/json'}, 'timeout': 9.5, 'raise_for_httperror': True},
        )

    def test_default_timeout(self):
        self.assertIs(settings['outgoing']['using_tor_proxy'], True)
        with patch('searx.autocomplete.http_get') as http_get:
            searx.autocomplete.get(URL)
        http_get.assert_called_once_with(URL, timeout=9.5, raise_for_httperror=True)

    def test_explicit_timeout(self):
        with patch('searx.autocomplete.http_get') as http_get:
            searx.autocomplete.get(URL, timeout=1.0)
        http_get.assert_called_once_with(URL, timeout=1.0, raise_for_httperror=True)

    def test_raise_for_httperror(self):
        with patch('searx.autocomplete.http_get') as http_get:
            searx.autocomplete.get(URL, raise_for_httperror=False)
        self.assertIs(http_get.call_args.kwargs['raise_for_httperror'], True)

    def test_kwargs_passed_through(self):
        with patch('searx.autocomplete.http_get') as http_get:
            searx.autocomplete.get(URL, headers={'User-Agent': 'x'}, enable_http3=True, cookies={'a': 'b'})
        http_get.assert_called_once_with(
            URL,
            headers={'User-Agent': 'x'},
            enable_http3=True,
            cookies={'a': 'b'},
            timeout=9.5,
            raise_for_httperror=True,
        )

    def test_post(self):
        with patch('searx.autocomplete.http_post') as http_post:
            searx.autocomplete.post(URL, data={'q': 'searxng'})
        http_post.assert_called_once_with(URL, data={'q': 'searxng'}, timeout=9.5, raise_for_httperror=True)

    def test_backend(self):
        response = Mock(ok=True, json=lambda: ['searxng', ['searxng docker', 'searxng tor']])
        with patch('searx.autocomplete.http_get', return_value=response) as http_get:
            results = searx.autocomplete.search_autocomplete('brave', 'searxng', 'en')
        self.assertEqual(results, ['searxng docker', 'searxng tor'])
        self.assertEqual(http_get.call_args.kwargs['timeout'], 9.5)
        self.assertIs(http_get.call_args.kwargs['raise_for_httperror'], True)
        self.assertIs(http_get.call_args.kwargs['enable_http3'], True)

    def test_backend_errors(self):
        # the exceptions of raise_for_httperror and of the network are caught
        for exc in (SearxEngineTooManyRequestsException(), HTTPError('HTTP error 500'), Timeout('Timeout')):
            with patch('searx.autocomplete.http_get', side_effect=exc):
                self.assertEqual(searx.autocomplete.search_autocomplete('brave', 'searxng', 'en'), [])
