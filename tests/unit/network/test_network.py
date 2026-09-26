# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import typing as t

import asyncio
import copy
from urllib.parse import urlsplit

from curl_cffi.requests.exceptions import ProxyError, RequestException, Timeout
from mock import AsyncMock, Mock, patch

import searx
import searx.engines
import searx.network
from searx import settings
from searx.network.client import AsyncClient, get_loop
from searx.network.network import (
    DEFAULT_NAME,
    NETWORKS,
    NOT_INITIALIZED,
    NOT_INITIALIZED_MESSAGE,
    TOR_CIRCUIT_SALT,
    Network,
    check_network_configuration,
    done,
    expand_tor_circuits,
    initialize,
    url_for_log,
)
from tests import SearxTestCase, SearxTorTestCase


class TestNetwork(SearxTestCase):
    # pylint: disable=protected-access

    def test_simple(self):
        network = Network()

        self.assertEqual(next(network._local_addresses_cycle), None)
        self.assertEqual(next(network._proxies_cycle), ())

    def test_ipaddress_cycle(self):
        network = NETWORKS['ipv6']
        self.assertEqual(next(network._local_addresses_cycle), '::')
        self.assertEqual(next(network._local_addresses_cycle), '::')

        network = NETWORKS['ipv4']
        self.assertEqual(next(network._local_addresses_cycle), '0.0.0.0')
        self.assertEqual(next(network._local_addresses_cycle), '0.0.0.0')

        network = Network(local_addresses=['192.168.0.1', '192.168.0.2'])
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.1')
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.2')
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.1')

        network = Network(local_addresses=['192.168.0.0/30'])
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.1')
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.2')
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.1')
        self.assertEqual(next(network._local_addresses_cycle), '192.168.0.2')

        network = Network(local_addresses=['fe80::/10'])
        self.assertEqual(next(network._local_addresses_cycle), 'fe80::1')
        self.assertEqual(next(network._local_addresses_cycle), 'fe80::2')
        self.assertEqual(next(network._local_addresses_cycle), 'fe80::3')

        with self.assertRaises(ValueError):
            Network(local_addresses=['not_an_ip_address'])

    def test_proxy_cycles(self):
        network = Network(proxies='http://localhost:1337')
        self.assertEqual(next(network._proxies_cycle), (('all://', 'http://localhost:1337'),))

        network = Network(proxies={'https': 'http://localhost:1337', 'http': 'http://localhost:1338'})
        self.assertEqual(
            next(network._proxies_cycle), (('https://', 'http://localhost:1337'), ('http://', 'http://localhost:1338'))
        )
        self.assertEqual(
            next(network._proxies_cycle), (('https://', 'http://localhost:1337'), ('http://', 'http://localhost:1338'))
        )

        network = Network(
            proxies={'https': ['http://localhost:1337', 'http://localhost:1339'], 'http': 'http://localhost:1338'}
        )
        self.assertEqual(
            next(network._proxies_cycle), (('https://', 'http://localhost:1337'), ('http://', 'http://localhost:1338'))
        )
        self.assertEqual(
            next(network._proxies_cycle), (('https://', 'http://localhost:1339'), ('http://', 'http://localhost:1338'))
        )

        with self.assertRaises(ValueError):
            Network(proxies=1)

    def test_get_kwargs_clients(self):
        kwargs = {
            'verify': True,
            'max_redirects': 5,
            'timeout': 2,
            'allow_redirects': True,
        }
        kwargs_client = Network.extract_kwargs_clients(kwargs)

        self.assertEqual(len(kwargs_client), 2)
        self.assertEqual(len(kwargs), 2)

        self.assertEqual(kwargs['timeout'], 2)
        self.assertEqual(kwargs['allow_redirects'], True)

        self.assertTrue(kwargs_client['verify'])
        self.assertEqual(kwargs_client['max_redirects'], 5)

        kwargs = {'impersonate': 'chrome99_android', 'curl_options': {1: 'x'}, 'timeout': 1}
        kwargs_client = Network.extract_kwargs_clients(kwargs)
        self.assertEqual(kwargs_client, {'impersonate': 'chrome99_android', 'curl_options': {1: 'x'}})
        self.assertEqual(kwargs, {'timeout': 1})

        # proxy_index is an argument of Network.get_client, not of curl
        kwargs = {'proxy_index': 2, 'timeout': 1}
        kwargs_client = Network.extract_kwargs_clients(kwargs)
        self.assertEqual(kwargs_client, {'proxy_index': 2})
        self.assertEqual(kwargs, {'timeout': 1})

    async def test_get_client(self):
        network = Network(verify=True)
        client1 = await network.get_client()
        client2 = await network.get_client(verify=True)
        client3 = await network.get_client(max_redirects=10)
        client4 = await network.get_client(verify=True)
        client5 = await network.get_client(verify=False)
        client6 = await network.get_client(max_redirects=10)

        self.assertEqual(client1, client2)
        self.assertEqual(client1, client4)
        self.assertNotEqual(client1, client3)
        self.assertNotEqual(client1, client5)
        self.assertEqual(client3, client6)

        client7 = await network.get_client(impersonate="chrome99_android", enable_http3=True)
        self.assertNotEqual(client1, client7)

        await network.aclose()

    async def test_aclose(self):
        network = Network(verify=True)
        await network.get_client()
        await network.aclose()

    async def test_request(self):
        a_text = 'Lorem Ipsum'
        response = Mock(status_code=200, text=a_text)
        with patch.object(AsyncClient, 'request', return_value=response):
            network = Network(enable_http=True)
            response = await network.request('GET', 'https://example.com/')
            self.assertEqual(response.text, a_text)
            await network.aclose()


class TestNetworkRequestRetries(SearxTestCase):

    TEXT = 'Lorem Ipsum'

    def setUp(self):
        self.init_test_settings()

    @classmethod
    def get_response_404_then_200(cls):
        first = True

        async def get_response(*args, **kwargs):  # pylint: disable=unused-argument
            nonlocal first
            if first:
                first = False
                return Mock(status_code=403, text=TestNetworkRequestRetries.TEXT)
            return Mock(status_code=200, text=TestNetworkRequestRetries.TEXT)

        return get_response

    async def test_retries_ok(self):
        with patch.object(AsyncClient, 'request', new=TestNetworkRequestRetries.get_response_404_then_200()):
            network = Network(enable_http=True, retries=1, retry_on_http_error=403)
            response = await network.request('GET', 'https://example.com/', raise_for_httperror=False)
            self.assertEqual(response.text, TestNetworkRequestRetries.TEXT)
            await network.aclose()

    async def test_retries_fail_int(self):
        with patch.object(AsyncClient, 'request', new=TestNetworkRequestRetries.get_response_404_then_200()):
            network = Network(enable_http=True, retries=0, retry_on_http_error=403)
            response = await network.request('GET', 'https://example.com/', raise_for_httperror=False)
            self.assertEqual(response.status_code, 403)
            await network.aclose()

    async def test_retries_fail_list(self):
        with patch.object(AsyncClient, 'request', new=TestNetworkRequestRetries.get_response_404_then_200()):
            network = Network(enable_http=True, retries=0, retry_on_http_error=[403, 429])
            response = await network.request('GET', 'https://example.com/', raise_for_httperror=False)
            self.assertEqual(response.status_code, 403)
            await network.aclose()

    async def test_retries_fail_bool(self):
        with patch.object(AsyncClient, 'request', new=TestNetworkRequestRetries.get_response_404_then_200()):
            network = Network(enable_http=True, retries=0, retry_on_http_error=True)
            response = await network.request('GET', 'https://example.com/', raise_for_httperror=False)
            self.assertEqual(response.status_code, 403)
            await network.aclose()

    async def test_retries_exception_then_200(self):
        request_count = 0

        async def get_response(*args, **kwargs):  # pylint: disable=unused-argument
            nonlocal request_count
            request_count += 1
            if request_count < 3:
                raise RequestException('fake exception')
            return Mock(status_code=200, text=TestNetworkRequestRetries.TEXT)

        with patch.object(AsyncClient, 'request', new=get_response):
            network = Network(enable_http=True, retries=2)
            response = await network.request('GET', 'https://example.com/', raise_for_httperror=False)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.text, TestNetworkRequestRetries.TEXT)
            await network.aclose()

    async def test_retries_exception(self):
        async def get_response(*args, **kwargs):
            raise RequestException('fake exception')

        with patch.object(AsyncClient, 'request', new=get_response):
            network = Network(enable_http=True, retries=0)
            with self.assertRaises(RequestException):
                await network.request('GET', 'https://example.com/', raise_for_httperror=False)
            await network.aclose()


class TestNetworkStreamRetries(SearxTestCase):

    TEXT = 'Lorem Ipsum'

    def setUp(self):
        self.init_test_settings()

    @classmethod
    def get_response_exception_then_200(cls):
        first = True

        def stream(*args, **kwargs):  # pylint: disable=unused-argument
            nonlocal first
            if first:
                first = False
                raise RequestException('fake exception')
            return Mock(status_code=200, text=TestNetworkStreamRetries.TEXT)

        return stream

    async def test_retries_ok(self):
        with patch.object(AsyncClient, 'stream', new=TestNetworkStreamRetries.get_response_exception_then_200()):
            network = Network(enable_http=True, retries=1, retry_on_http_error=403)
            response = await network.stream('GET', 'https://example.com/')
            self.assertEqual(response.text, TestNetworkStreamRetries.TEXT)
            await network.aclose()

    async def test_retries_fail(self):
        with patch.object(AsyncClient, 'stream', new=TestNetworkStreamRetries.get_response_exception_then_200()):
            network = Network(enable_http=True, retries=0, retry_on_http_error=403)
            with self.assertRaises(RequestException):
                await network.stream('GET', 'https://example.com/')
            await network.aclose()

    async def test_retries_exception(self):
        first = True

        def stream(*args, **kwargs):  # pylint: disable=unused-argument
            nonlocal first
            if first:
                first = False
                return Mock(status_code=403, text=TestNetworkRequestRetries.TEXT)
            return Mock(status_code=200, text=TestNetworkRequestRetries.TEXT)

        with patch.object(AsyncClient, 'stream', new=stream):
            network = Network(enable_http=True, retries=0, retry_on_http_error=403)
            response = await network.stream('GET', 'https://example.com/', raise_for_httperror=False)
            self.assertEqual(response.status_code, 403)
            await network.aclose()


class TestExpandTorCircuits(SearxTestCase):

    def test_noop(self):
        self.assertIsNone(expand_tor_circuits(None, 3))
        self.assertEqual(expand_tor_circuits({}, 3), {})
        self.assertEqual(expand_tor_circuits('socks5h://tor:9050', 0), 'socks5h://tor:9050')
        self.assertEqual(expand_tor_circuits('socks5h://tor:9050', 1), 'socks5h://tor:9050')
        # nothing to expand
        self.assertEqual(expand_tor_circuits('http://proxy:8080', 3), 'http://proxy:8080')

    def test_str(self):
        proxies = expand_tor_circuits('socks5h://tor:9050', 3, salt='abc')
        urls = ['socks5h://sxng-0:abc@tor:9050', 'socks5h://sxng-1:abc@tor:9050', 'socks5h://sxng-2:abc@tor:9050']
        self.assertEqual(proxies, {'all://': urls})
        self.assertEqual(len(set(urls)), 3)
        for url in urls:
            parts = urlsplit(url)
            self.assertEqual((parts.hostname, parts.port), ('tor', 9050))

    def test_default_salt(self):
        self.assertRegex(TOR_CIRCUIT_SALT, r'^[0-9a-f]{8}$')
        self.assertEqual(
            expand_tor_circuits('socks5h://tor:9050', 2),
            {
                'all://': [
                    f'socks5h://sxng-0:{TOR_CIRCUIT_SALT}@tor:9050',
                    f'socks5h://sxng-1:{TOR_CIRCUIT_SALT}@tor:9050',
                ]
            },
        )

    def test_invalid_salt(self):
        with self.assertRaises(ValueError):
            expand_tor_circuits('socks5h://tor:9050', 2, salt='a:b@c')

    def test_mixed(self):
        proxies = {
            'socks5': 'socks5://tor:9050',
            'http': 'http://proxy:8080',
            'https': ['socks5h://u:p@tor:9050', 'socks5h://[::1]:9050/path'],
        }
        original = copy.deepcopy(proxies)
        expanded = expand_tor_circuits(proxies, 2, salt='s')
        self.assertEqual(proxies, original)  # the argument is not modified
        self.assertEqual(
            expanded,
            {
                'socks5': 'socks5://tor:9050',
                'http': 'http://proxy:8080',
                'https': [
                    'socks5h://u:p@tor:9050',
                    'socks5h://sxng-0:s@[::1]:9050/path',
                    'socks5h://sxng-1:s@[::1]:9050/path',
                ],
            },
        )
        assert isinstance(expanded, dict)
        for url in expanded['https']:
            self.assertTrue(url.startswith('socks5h://'))
        parts = urlsplit(expanded['https'][2])
        self.assertEqual((parts.username, parts.password, parts.hostname, parts.port), ('sxng-1', 's', '::1', 9050))


class TestNetworkTorCircuits(SearxTestCase):
    # pylint: disable=protected-access

    def setUp(self):
        super().setUp()
        Network._TOR_CHECK_RESULT.clear()
        self.addCleanup(Network._TOR_CHECK_RESULT.clear)

    def test_cycle(self):
        network = Network(proxies='socks5h://tor:9050', using_tor_proxy=True, tor_circuits=3)
        proxies = [next(network._proxies_cycle) for _ in range(4)]
        self.assertEqual(network.tor_circuits, 3)
        self.assertEqual(len(set(proxies[:3])), 3)
        self.assertEqual(proxies[3], proxies[0])
        self.assertEqual(proxies[:3], network.proxy_pool)
        self.assertEqual(proxies[1], (('all://', f'socks5h://sxng-1:{TOR_CIRCUIT_SALT}@tor:9050'),))

    def test_no_expansion(self):
        expected = [(('all://', 'socks5h://tor:9050'),)]
        network = Network(proxies='socks5h://tor:9050', using_tor_proxy=True, tor_circuits=1)
        self.assertEqual(network.proxy_pool, expected)
        network = Network(proxies='socks5h://tor:9050', using_tor_proxy=False, tor_circuits=3)
        self.assertEqual(network.proxy_pool, expected)
        self.assertEqual(next(network._proxies_cycle), expected[0])

    def test_proxy_pool(self):
        self.assertEqual(Network().proxy_pool, [()])

        network = Network(
            proxies={'https': ['http://a:1', 'http://b:1'], 'http': ['http://c:1', 'http://d:1', 'http://e:1']}
        )
        pool = network.proxy_pool
        self.assertEqual(len(pool), 6)
        self.assertEqual(len(set(pool)), 6)
        self.assertEqual(pool, [next(network._proxies_cycle) for _ in range(6)])

        # the property returns a copy
        pool.clear()
        self.assertEqual(len(network.proxy_pool), 6)

    async def test_get_client_proxy_index(self):
        network = Network(proxies='socks5h://tor:9050', using_tor_proxy=True, tor_circuits=3)
        pool = network.proxy_pool
        with patch.object(Network, 'check_tor_proxy', new=AsyncMock(return_value=True)) as check_tor_proxy:
            client1 = await network.get_client(proxy_index=1)
            client4 = await network.get_client(proxy_index=4)
            client2 = await network.get_client(proxy_index=2)
        self.assertIs(client1, client4)
        self.assertIsNot(client1, client2)
        self.assertEqual([c.args[1] for c in check_tor_proxy.await_args_list], [pool[1], pool[2]])
        # proxy_index does not move the round-robin
        self.assertEqual(next(network._proxies_cycle), pool[0])
        await network.aclose()

    async def test_get_client_not_tor(self):
        network = Network(proxies='socks5h://tor:9050', using_tor_proxy=True, tor_circuits=3)
        with patch.object(Network, 'check_tor_proxy', new=AsyncMock(return_value=False)):
            with self.assertRaises(ProxyError):
                await network.get_client(proxy_index=0)
        self.assertEqual(network._clients, {})

    def test_request_proxy_index(self):
        network = Network(proxies='socks5h://tor:9050', using_tor_proxy=True, tor_circuits=3)
        response = Mock(status_code=200, text='Lorem Ipsum')
        with patch('searx.network.get_context_network', return_value=network):
            with patch.object(Network, 'check_tor_proxy', new=AsyncMock(return_value=True)):
                with patch.object(AsyncClient, 'request', new=AsyncMock(return_value=response)) as request:
                    resp = searx.network.get('https://example.org/', proxy_index=2, timeout=1)
        self.assertIs(resp, response)
        self.assertNotIn('proxy_index', request.call_args_list[0].kwargs)
        self.assertEqual([key[3] for key in network._clients], [network.proxy_pool[2]])
        asyncio.run_coroutine_threadsafe(network.aclose(), get_loop()).result(3)

    async def test_check_tor_proxy(self):
        self.use_real_tor_check()
        client = Mock(get=AsyncMock())
        self.assertFalse(await Network.check_tor_proxy(client, (('all://', 'socks5://tor:9050'),)))
        self.assertFalse(await Network.check_tor_proxy(client, ()))
        client.get.assert_not_called()

        proxies = (('all://', 'socks5h://sxng-0:x@tor:9050'),)
        client = Mock(get=AsyncMock(return_value=Mock(json=lambda: {'IsTor': True})))
        self.assertTrue(await Network.check_tor_proxy(client, proxies))
        # the result is cached
        self.assertTrue(await Network.check_tor_proxy(client, proxies))
        client.get.assert_awaited_once_with('https://check.torproject.org/api/ip', timeout=15)
        self.assertIs(Network._TOR_CHECK_RESULT[proxies], True)

    def test_check_network_configuration(self):
        default = Network(proxies='socks5h://tor:9050', using_tor_proxy=True, tor_circuits=3)
        other = Network(proxies='socks5h://tor:9050', using_tor_proxy=True, tor_circuits=3)
        networks = {DEFAULT_NAME: default, 'other': other}
        calls = []

        async def get_client(network, proxy_index=None, **kwargs):  # pylint: disable=unused-argument
            calls.append((network, proxy_index))

        with patch.dict(NETWORKS, networks, clear=True), patch.object(Network, 'get_client', new=get_client):
            check_network_configuration()
        # the default network checks each Tor circuit, the other networks one client
        self.assertEqual(calls, [(default, 0), (default, 1), (default, 2), (other, None)])

    def test_check_network_configuration_without_tor(self):
        """Tor-only build: a network without Tor fails the check."""
        default = Network(proxies='socks5h://tor:9050', using_tor_proxy=True)
        networks = {DEFAULT_NAME: default, 'clear': Network()}
        with patch.dict(NETWORKS, networks, clear=True), patch('searx.network.network.new_client') as new_client:
            with self.assertLogs('searx.network', level='ERROR') as logs:
                with self.assertRaises(RuntimeError):
                    check_network_configuration()
        self.assertIn('clear: the network does not use Tor', logs.output[-1])
        # the check stops at the first network that fails
        self.assertEqual(new_client.call_count, 1)

    def test_check_network_configuration_not_initialized(self):
        with patch.dict(NETWORKS, {DEFAULT_NAME: NOT_INITIALIZED}, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                check_network_configuration()
        self.assertEqual(str(ctx.exception), 'Tor-only build: the network is not initialized')

    def test_check_network_configuration_error(self):
        default = Network(proxies='socks5h://tor:9050', using_tor_proxy=True, tor_circuits=3)
        other = Network(proxies='socks5h://tor:9050', using_tor_proxy=True, tor_circuits=3)
        networks = {DEFAULT_NAME: default, 'other': other}
        calls = []

        async def get_client(network, proxy_index=None, **kwargs):  # pylint: disable=unused-argument
            calls.append((network, proxy_index))
            if proxy_index == 1:
                raise ProxyError('Network configuration problem: not using Tor')

        with patch.dict(NETWORKS, networks, clear=True), patch.object(Network, 'get_client', new=get_client):
            with patch('searx.network.network.TOR_CHECK_RETRY_DELAYS', (0, 0)):
                with self.assertLogs('searx.network', level='WARNING') as logs:
                    with self.assertRaises(RuntimeError):
                        check_network_configuration()
        # the failing circuit is checked 3 times, then the check stops (fail
        # fast): neither the remaining circuit nor the other network is checked
        self.assertEqual(calls, [(default, 0), (default, 1), (default, 1), (default, 1)])
        self.assertEqual([r.levelname for r in logs.records], ['WARNING', 'WARNING', 'ERROR'])

    def test_check_network_configuration_retry(self):
        """A transient failure of the Tor check at startup (timeout, then OK)."""
        self.use_real_tor_check()
        network = Network(proxies='socks5h://tor:9050', using_tor_proxy=True)
        answers = [Timeout('Timeout'), Mock(json=lambda: {'IsTor': True})]
        with patch.dict(NETWORKS, {DEFAULT_NAME: network}, clear=True):
            with patch.object(AsyncClient, 'get', new=AsyncMock(side_effect=answers)) as client_get:
                with patch('searx.network.network.TOR_CHECK_RETRY_DELAYS', (0, 0)):
                    with self.assertLogs('searx.network', level='WARNING'):
                        check_network_configuration()
        self.assertEqual(client_get.await_count, 2)
        self.assertIs(Network._TOR_CHECK_RESULT[network.proxy_pool[0]], True)
        self.assertEqual(len(network._clients), 1)
        asyncio.run_coroutine_threadsafe(network.aclose(), get_loop()).result(3)

    def test_check_network_configuration_not_tor(self):
        """IsTor is false 3 times: SearXNG refuses to start."""
        self.use_real_tor_check()
        network = Network(proxies='socks5h://tor:9050', using_tor_proxy=True)
        answer = Mock(json=lambda: {'IsTor': False})
        with patch.dict(NETWORKS, {DEFAULT_NAME: network}, clear=True):
            with patch.object(AsyncClient, 'get', new=AsyncMock(return_value=answer)) as client_get:
                with patch('searx.network.network.TOR_CHECK_RETRY_DELAYS', (0, 0)):
                    with self.assertLogs('searx.network', level='WARNING'):
                        with self.assertRaises(RuntimeError):
                            check_network_configuration()
        self.assertEqual(client_get.await_count, 3)
        self.assertNotIn(network.proxy_pool[0], Network._TOR_CHECK_RESULT)
        self.assertEqual(network._clients, {})

    async def test_check_tor_proxy_transient(self):
        """Failed checks are not cached (except the deterministic not-socks5h
        case), a later check can succeed."""
        self.use_real_tor_check()
        proxies = (('all://', 'socks5h://sxng-0:x@tor:9050'),)
        failures = [
            Timeout('Timeout'),
            Mock(json=Mock(side_effect=ValueError('no JSON'))),
            Mock(json=lambda: {}),
            Mock(json=lambda: {'IsTor': False}),
        ]
        for failure in failures:
            if isinstance(failure, Exception):
                client = Mock(get=AsyncMock(side_effect=failure))
            else:
                client = Mock(get=AsyncMock(return_value=failure))
            with self.assertLogs('searx.network', level='WARNING'):
                self.assertFalse(await Network.check_tor_proxy(client, proxies))
            self.assertNotIn(proxies, Network._TOR_CHECK_RESULT)

        client = Mock(get=AsyncMock(return_value=Mock(json=lambda: {'IsTor': True})))
        self.assertTrue(await Network.check_tor_proxy(client, proxies))
        self.assertIs(Network._TOR_CHECK_RESULT[proxies], True)

        # not socks5h: cached False, no request
        client = Mock(get=AsyncMock())
        proxies = (('all://', 'socks5://tor:9050'),)
        self.assertFalse(await Network.check_tor_proxy(client, proxies))
        self.assertIs(Network._TOR_CHECK_RESULT[proxies], False)
        client.get.assert_not_called()

    async def test_get_client_recheck(self):
        """A client is only used when its proxies passed the Tor check, after a
        failed check the next client is checked again."""
        self.use_real_tor_check()
        network = Network(proxies='socks5h://tor:9050', using_tor_proxy=True)
        answers = [Timeout('Timeout'), Mock(json=lambda: {'IsTor': True})]
        with patch.object(AsyncClient, 'get', new=AsyncMock(side_effect=answers)):
            with self.assertLogs('searx.network', level='WARNING'):
                with self.assertRaises(ProxyError):
                    await network.get_client()
            self.assertEqual(network._clients, {})
            client = await network.get_client()
        self.assertIs(await network.get_client(), client)
        await network.aclose()

    async def test_get_client_concurrent(self):
        """Concurrent calls during the Tor check share one client."""

        async def slow_check(client, proxies):  # pylint: disable=unused-argument
            await asyncio.sleep(0.01)
            return True

        network = Network(proxies='socks5h://tor:9050', using_tor_proxy=True)
        with patch.object(Network, 'check_tor_proxy', new=AsyncMock(side_effect=slow_check)):
            client1, client2 = await asyncio.gather(network.get_client(), network.get_client())
        self.assertIs(client1, client2)
        self.assertEqual(list(network._clients.values()), [client1])
        await network.aclose()


class TestNetworkTorParameters(SearxTestCase):
    """With using_tor_proxy, the proxies are socks5h:// URLs and they cover each
    scheme of the network."""

    def test_covered(self):
        for proxies in (
            'socks5h://tor:9050',
            {'all://': 'socks5h://tor:9050'},
            {'https': 'socks5h://tor:9050', 'http': 'socks5h://tor:9050'},
            {'https:': ['socks5h://tor:9050'], 'http:': ['socks5h://tor:9050']},
            {'https://': 'socks5h://tor:9050', 'http://': 'socks5h://tor:9050'},
        ):
            Network(proxies=proxies, using_tor_proxy=True, enable_http=True)

        # without HTTP, a https:// proxy is enough
        for key in ('https', 'https:', 'https://'):
            Network(proxies={key: 'socks5h://tor:9050'}, using_tor_proxy=True, enable_http=False)

    def test_not_covered(self):
        for proxies, enable_http, missing in (
            ({'https': 'socks5h://tor:9050'}, True, 'http://'),
            ({'https:': 'socks5h://tor:9050'}, True, 'http://'),
            ({'https://': 'socks5h://tor:9050'}, True, 'http://'),
            ({'http': 'socks5h://tor:9050'}, False, 'https://'),
            (None, False, 'https://'),
            ({}, True, 'https://, http://'),
        ):
            with self.assertRaises(ValueError) as ctx:
                Network(proxies=proxies, using_tor_proxy=True, enable_http=enable_http)
            self.assertIn(f'missing: {missing} ', str(ctx.exception))

    def test_socks5h(self):
        for proxies in (
            {'all://': 'socks5://tor:9050'},
            {'all://': ['socks5h://tor:9050', 'socks4://tor:9050']},
            {'https': 'socks5h://tor:9050', 'http': 'http://user:secret@proxy:8080'},
        ):
            with self.assertRaises(ValueError) as ctx:
                Network(proxies=proxies, using_tor_proxy=True, enable_http=True)
            self.assertIn('requires socks5h:// proxies', str(ctx.exception))
            # the proxy URL may contain credentials, they are not in the message
            self.assertNotIn('secret', str(ctx.exception))

    def test_no_tor(self):
        # the Network class is generic, without Tor the proxies are not checked
        # (Tor-only build: initialize() never creates such a network)
        Network(proxies={'https': 'http://proxy:8080'}, enable_http=True)
        Network(proxies=None, enable_http=True)

    def test_tor_circuits_range(self):
        Network(proxies='socks5h://tor:9050', using_tor_proxy=True, tor_circuits=32)
        for tor_circuits in (-1, 33):
            with self.assertRaises(ValueError):
                Network(proxies='socks5h://tor:9050', using_tor_proxy=True, tor_circuits=tor_circuits)


class TestNetworkInitialize(SearxTestCase):
    """Tor-only build: every network uses Tor, :py:obj:`initialize` refuses
    outgoing settings without Tor."""

    # pylint: disable=protected-access

    def setUp(self):
        super().setUp()
        saved_networks = dict(NETWORKS)

        def restore_networks():
            NETWORKS.clear()
            NETWORKS.update(saved_networks)

        self.addCleanup(restore_networks)

    @staticmethod
    def load_engines() -> list[dict[str, t.Any]]:
        engine_list: list[dict[str, t.Any]] = [
            {'engine': 'dummy', 'name': 'engine1', 'shortcut': 'e1'},
            {'engine': 'dummy', 'name': 'engine2', 'shortcut': 'e2', 'using_tor_proxy': True},
            {
                'engine': 'dummy',
                'name': 'engine3',
                'shortcut': 'e3',
                'network': {'proxies': 'socks5h://tor:9050', 'using_tor_proxy': False},
            },
            {'engine': 'dummy', 'name': 'engine4', 'shortcut': 'e4', 'network': 'engine2'},
        ]
        searx.engines.load_engines(engine_list)
        return engine_list

    @staticmethod
    def outgoing(**kwargs: t.Any) -> dict[str, t.Any]:
        outgoing = copy.deepcopy(settings['outgoing'])
        outgoing.update(kwargs)
        return outgoing

    def test_global_tor(self):
        engine_list = self.load_engines()
        outgoing = self.outgoing(
            using_tor_proxy=True,
            proxies={'all://': 'socks5h://tor:9050'},
            networks={'clear': {'using_tor_proxy': False}},
        )
        with patch('searx.network.network.new_client') as new_client:
            initialize(engine_list, outgoing)
        # initialize() does not open a connection
        new_client.assert_not_called()

        for name in (DEFAULT_NAME, 'ipv4', 'ipv6', 'image_proxy', 'clear', 'engine1', 'engine2', 'engine3', 'engine4'):
            self.assertIs(NETWORKS[name].using_tor_proxy, True, name)
        self.assertIs(NETWORKS['engine4'], NETWORKS['engine2'])
        self.assertEqual(next(NETWORKS['engine1']._proxies_cycle), (('all://', 'socks5h://tor:9050'),))

    def test_tor_off(self):
        engine_list = self.load_engines()
        networks = dict(NETWORKS)
        outgoing = self.outgoing(using_tor_proxy=False, proxies={'all://': 'socks5h://tor:9050'})
        with self.assertRaises(ValueError) as ctx:
            initialize(engine_list, outgoing)
        self.assertEqual(str(ctx.exception), 'Tor-only build: outgoing.using_tor_proxy must be true')
        # the networks are not replaced
        self.assertEqual(NETWORKS, networks)

    def test_without_tor_proxy(self):
        engine_list = self.load_engines()
        for proxies in (None, '', {}, {'all://': []}, 'http://proxy:8080', {'all://': 'socks5://tor:9050'}):
            with self.assertRaises(ValueError) as ctx:
                initialize(engine_list, self.outgoing(using_tor_proxy=True, proxies=proxies))
            self.assertEqual(
                str(ctx.exception),
                'Tor-only build: outgoing.proxies must be a socks5h:// Tor proxy (set SEARXNG_TOR_PROXY)',
                proxies,
            )

    def test_engine_without_proxy(self):
        # an engine can't opt out of Tor with its own (empty) proxies: fail closed
        engine_list = [{'engine': 'dummy', 'name': 'engine6', 'shortcut': 'e6', 'network': {'proxies': None}}]
        searx.engines.load_engines(engine_list)
        with self.assertRaises(ValueError) as ctx:
            initialize(engine_list, self.outgoing())
        self.assertIn('engine6', str(ctx.exception))

    def test_scheme_not_covered(self):
        # only a https:// proxy but the engine may send http:// requests
        engine_list = [{'engine': 'dummy', 'name': 'engine5', 'shortcut': 'e5', 'enable_http': True}]
        searx.engines.load_engines(engine_list)
        outgoing = self.outgoing(using_tor_proxy=True, proxies={'https': 'socks5h://tor:9050'})
        with self.assertRaises(ValueError) as ctx:
            initialize(engine_list, outgoing)
        self.assertIn('engine5', str(ctx.exception))
        self.assertIn('missing: http://', str(ctx.exception))

    def test_tor_circuits(self):
        engine_list = self.load_engines()
        # a value from the environment (SEARXNG_TOR_CIRCUITS) is a string
        outgoing = self.outgoing(using_tor_proxy=True, proxies='socks5h://tor:9050', tor_circuits='3')
        initialize(engine_list, outgoing)
        for name in (DEFAULT_NAME, 'image_proxy', 'engine1', 'engine3'):
            self.assertEqual(NETWORKS[name].tor_circuits, 3, name)
            self.assertEqual(len(NETWORKS[name].proxy_pool), 3, name)

    def test_tor_circuits_range(self):
        engine_list = self.load_engines()
        outgoing = self.outgoing(using_tor_proxy=True, proxies='socks5h://tor:9050', tor_circuits=33)
        with self.assertRaises(ValueError) as ctx:
            initialize(engine_list, outgoing)
        self.assertIn('outgoing.tor_circuits', str(ctx.exception))


class TestNotInitialized(SearxTestCase):
    """Tor-only build: before :py:obj:`initialize`, the default network is a
    fail-closed placeholder, no request is sent (no direct connection)."""

    URL = 'https://example.org/'

    def setUp(self):
        super().setUp()
        patcher = patch.dict(NETWORKS, {DEFAULT_NAME: NOT_INITIALIZED}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        # no network is set for the thread: the requests use the default network
        self.setattr4test(searx.network, 'THREADLOCAL', type(searx.network.THREADLOCAL)())

    def test_request(self):
        with patch('searx.network.network.new_client') as new_client:
            for request in (searx.network.get, searx.network.post, searx.network.head):
                with self.assertRaises(RuntimeError) as ctx:
                    request(self.URL)
                self.assertEqual(str(ctx.exception), NOT_INITIALIZED_MESSAGE)
            with self.assertRaises(RuntimeError):
                searx.network.stream('GET', self.URL)
            responses = searx.network.multi_requests([searx.network.Request.get(self.URL)])
        self.assertIsInstance(responses[0], RuntimeError)
        new_client.assert_not_called()
        self.assertEqual(NOT_INITIALIZED._clients, {})  # pylint: disable=protected-access
        self.assertTrue(NOT_INITIALIZED_MESSAGE.startswith('Tor-only build:'))

    def test_done(self):
        # after done() (e.g. at exit), the placeholder is the default network again
        NETWORKS['other'] = Network(proxies='socks5h://tor:9050', using_tor_proxy=True)
        done()
        self.assertEqual(NETWORKS, {DEFAULT_NAME: NOT_INITIALIZED})

    def test_initialize(self):
        initialize([], copy.deepcopy(settings['outgoing']))
        network = NETWORKS[DEFAULT_NAME]
        self.assertIsNot(network, NOT_INITIALIZED)
        self.assertIs(network.using_tor_proxy, True)
        self.assertEqual(network.proxy_pool, [(('all://', 'socks5h://127.0.0.1:9050'),)])


class TestTorProfile(SearxTorTestCase):
    """End-to-end check of the Tor profile tests/unit/settings/test_tor.yml."""

    def test_tor_profile(self):
        self.assertEqual(settings['outgoing']['tor_control'], {'host': '127.0.0.1', 'port': 9051, 'password': 'test'})

        pool = NETWORKS[DEFAULT_NAME].proxy_pool
        self.assertEqual(len(pool), 3)
        for proxies in pool:
            self.assertTrue(all(url.startswith('socks5h://sxng-') for _, url in proxies))

        self.assertIs(NETWORKS['dummy engine'].using_tor_proxy, True)
        # timeout: 3 + extra_proxy_timeout: 5.0
        self.assertEqual(searx.engines.engines['dummy engine'].timeout, 8.0)


class TestUrlForLog(SearxTestCase):
    """The search terms of an engine request must not end up in the logs of a
    production instance (privacy of the users)."""

    URL = 'https://user:secret@search.example.org/search/my%20query?q=my+query&page=2#frag'

    def test_production_redacts_query_and_path(self):
        self.setattr4test(searx, 'sxng_debug', False)
        logged = url_for_log(self.URL)
        self.assertEqual(logged, 'https://search.example.org/...')
        for secret in ('query', 'secret', 'user', 'page', 'frag'):
            self.assertNotIn(secret, logged)

    def test_debug_keeps_full_url(self):
        self.setattr4test(searx, 'sxng_debug', True)
        self.assertEqual(url_for_log(self.URL), self.URL)

    def test_no_host(self):
        self.setattr4test(searx, 'sxng_debug', False)
        self.assertEqual(url_for_log('not a url'), '...')
        self.assertEqual(url_for_log('http://[::1]:8080/x?q=1'), 'http://[::1]:8080/...')

    def test_failed_request_warning_is_redacted(self):
        self.setattr4test(searx, 'sxng_debug', False)
        network = Network()
        response = Mock(status_code=500, url='https://search.example.org/?q=my+query')
        response.request = Mock(method='GET', url='https://search.example.org/?q=my+query')
        with patch('searx.network.network.raise_for_httperror', side_effect=RuntimeError('HTTP 500')):
            with self.assertLogs('searx.network', level='WARNING') as cm:
                with self.assertRaises(RuntimeError):
                    network.patch_response(response, True)
        self.assertEqual(len(cm.output), 1)
        self.assertIn('HTTP Request failed: GET https://search.example.org/...', cm.output[0])
        self.assertNotIn('my+query', cm.output[0])
