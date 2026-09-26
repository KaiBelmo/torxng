# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import typing as t

import asyncio
import os

from curl_cffi import CurlOpt
from curl_cffi.requests.exceptions import RequestException
from mock import patch

from searx.network.client import AsyncClient, new_client
from tests import SearxTestCase


def _new_client(proxies: dict[str, str], enable_http: bool = False) -> AsyncClient:
    return new_client(enable_http, True, False, False, 10, proxies, None, 30)


class TestNewClientNoProxy(SearxTestCase):
    """With a proxy, CURLOPT_NOPROXY is set to an empty string: libcurl must not
    bypass the proxy for the hosts in the no_proxy / NO_PROXY environment."""

    async def test_all_proxy(self):
        client = _new_client({'all://': 'socks5h://127.0.0.1:9050'})
        self.assertEqual(client.curl_options[CurlOpt.NOPROXY], '')
        await client.aclose()

    async def test_https_proxy(self):
        client = _new_client({'https://': 'socks5h://127.0.0.1:9050'})
        self.assertEqual(client.curl_options[CurlOpt.NOPROXY], '')
        await client.aclose()

    async def test_no_proxy(self):
        client = _new_client({})
        self.assertNotIn(CurlOpt.NOPROXY, client.curl_options)
        await client.aclose()

        # the http:// proxy is not used when HTTP is disabled
        client = _new_client({'http://': 'socks5h://127.0.0.1:9050'})
        self.assertNotIn(CurlOpt.NOPROXY, client.curl_options)
        await client.aclose()


class TestNoProxyEnviron(SearxTestCase):
    """libcurl honours the no_proxy environment variable, unless CURLOPT_NOPROXY
    is set.  Local only: a fake SOCKS5 proxy and a fake HTTP server on
    127.0.0.1."""

    async def test_noproxy_environ(self):
        socks_log: list[bytes] = []
        direct_log: list[bytes] = []

        async def socks_proxy(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                greeting = await reader.readexactly(2)
                await reader.readexactly(greeting[1])
                writer.write(b'\x05\x00')  # no authentication
                await writer.drain()
                socks_log.append(await reader.read(262))
                writer.write(b'\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00')  # connection not allowed
                await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                writer.close()

        async def http_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                direct_log.append(await reader.readuntil(b'\r\n\r\n'))
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
                await writer.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                writer.close()

        socks_server = await asyncio.start_server(socks_proxy, '127.0.0.1', 0)
        direct_server = await asyncio.start_server(http_server, '127.0.0.1', 0)
        proxy = f"socks5h://127.0.0.1:{socks_server.sockets[0].getsockname()[1]}"
        url = f"http://127.0.0.1:{direct_server.sockets[0].getsockname()[1]}/"

        async def fetch(client: AsyncClient) -> t.Any:
            try:
                return await client.get(url, timeout=5)
            except RequestException as e:
                return e
            finally:
                await client.aclose()

        try:
            with patch.dict(os.environ, {'no_proxy': '127.0.0.1', 'NO_PROXY': '127.0.0.1'}):
                # without CURLOPT_NOPROXY libcurl connects directly
                await fetch(AsyncClient(proxy=proxy))
                self.assertEqual((len(direct_log), len(socks_log)), (1, 0))

                # new_client: the request is sent to the proxy (which refuses it)
                result = await fetch(_new_client({'all://': proxy}, enable_http=True))
                self.assertIsInstance(result, RequestException)
                self.assertEqual((len(direct_log), len(socks_log)), (1, 1))
        finally:
            socks_server.close()
            direct_server.close()
