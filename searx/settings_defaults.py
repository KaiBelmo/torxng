# SPDX-License-Identifier: AGPL-3.0-or-later
"""Implementation of the default settings."""

from __future__ import annotations

import typing as t
import numbers
import errno
import os
import logging
from base64 import b64decode
from collections.abc import Iterator
from os.path import dirname, abspath
from urllib.parse import urlsplit

import msgspec

from typing_extensions import override
from .brand import SettingsBrand
from .sxng_locales import sxng_locales
from ._settings import SettingsPref

searx_dir = abspath(dirname(__file__))

logger = logging.getLogger('searx')
OUTPUT_FORMATS = ['html', 'csv', 'json', 'rss']
SXNG_LOCALE_TAGS = ['all', 'auto'] + list(l[0] for l in sxng_locales)
SIMPLE_STYLE = ('auto', 'light', 'dark', 'black')
CATEGORIES_AS_TABS: dict[str, dict[str, t.Any]] = {
    'general': {},
    'images': {},
    'videos': {},
    'news': {},
    'map': {},
    'music': {},
    'it': {},
    'science': {},
    'files': {},
    'social media': {},
}
STR_TO_BOOL = {
    '0': False,
    'false': False,
    'off': False,
    '1': True,
    'true': True,
    'on': True,
}
_UNDEFINED = object()
TOR_CIRCUITS_MAX = 32
"""Maximum value of ``outgoing.tor_circuits``."""

TOR_ONLY = 'Tor-only build'
"""Prefix of the error messages of :py:obj:`apply_tor_only` and
:py:obj:`check_tor_only`, this fork of SearXNG sends all requests over Tor."""

DEFAULT_TOR_PROXY = 'socks5h://127.0.0.1:9050'
"""The ``outgoing.proxies`` of :origin:`searx/settings.yml`: the SOCKS port of a
local Tor daemon (the Tor Browser listens on port 9150)."""

TOR_PROXY_ENV = 'SEARXNG_TOR_PROXY'
"""Environment variable with a single ``socks5h://host:port`` URL, it replaces
``outgoing.proxies`` by ``{'all://': <url>}``."""

# This type definition for SettingsValue.type_definition is incomplete, but it
# helps to significantly reduce the most common error messages regarding type
# annotations.
TypeDefinition: t.TypeAlias = (  # pylint: disable=invalid-name
    tuple[None, bool, type]
    | tuple[None, type, type]
    | tuple[None, type]
    | tuple[bool, type]
    | tuple[type, type]
    | tuple[type]
    | tuple[str | int, ...]
)

TypeDefinitionArg: t.TypeAlias = type | TypeDefinition  # pylint: disable=invalid-name


class SettingsValue:
    """Check and update a setting value"""

    def __init__(
        self,
        type_definition_arg: TypeDefinitionArg,
        default: t.Any = None,
        environ_name: str | None = None,
    ):
        self.type_definition: TypeDefinition = (
            type_definition_arg if isinstance(type_definition_arg, tuple) else (type_definition_arg,)
        )
        self.default: t.Any = default
        self.environ_name: str | None = environ_name

    @property
    def type_definition_repr(self):
        types_str = [td.__name__ if isinstance(td, type) else repr(td) for td in self.type_definition]
        return ', '.join(types_str)

    def check_type_definition(self, value: t.Any) -> None:
        if value in self.type_definition:
            return
        type_list = tuple(t for t in self.type_definition if isinstance(t, type))
        if not isinstance(value, type_list):
            raise ValueError('The value has to be one of these types/values: {}'.format(self.type_definition_repr))

    def __call__(self, value: t.Any) -> t.Any:
        if value == _UNDEFINED:
            value = self.default
        # override existing value with environ
        if self.environ_name and self.environ_name in os.environ:
            value = os.environ[self.environ_name]
            if self.type_definition == (bool,):
                value = STR_TO_BOOL[value.lower()]

        self.check_type_definition(value)
        return value


class SettingSublistValue(SettingsValue):
    """Check the value is a sublist of type definition."""

    @override
    def check_type_definition(self, value: list[t.Any]) -> None:
        if not isinstance(value, list):
            raise ValueError('The value has to a list')
        for item in value:
            if not item in self.type_definition[0]:
                raise ValueError('{} not in {}'.format(item, self.type_definition))


class SettingsDirectoryValue(SettingsValue):
    """Check and update a setting value that is a directory path"""

    @override
    def check_type_definition(self, value: t.Any) -> t.Any:
        super().check_type_definition(value)
        if not os.path.isdir(value):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), value)

    @override
    def __call__(self, value: t.Any) -> t.Any:
        if value == '':
            value = self.default
        return super().__call__(value)


class SettingsBytesValue(SettingsValue):
    """str are base64 decoded"""

    @override
    def __call__(self, value: t.Any) -> t.Any:
        if isinstance(value, str):
            value = b64decode(value)
        return super().__call__(value)


class SettingsIntRangeValue(SettingsValue):
    """An integer in the range ``min_value..max_value``, a string (e.g. a value
    from the environment) is converted to an integer."""

    def __init__(self, min_value: int, max_value: int, default: int = 0, environ_name: str | None = None):
        super().__init__((int, str), default, environ_name)
        self.min_value: int = min_value
        self.max_value: int = max_value

    @override
    def __call__(self, value: t.Any) -> t.Any:
        value = super().__call__(value)
        if isinstance(value, bool):
            raise ValueError(f'{value!r} is not an integer')
        try:
            value = int(value)
        except ValueError:
            raise ValueError(f'{value!r} is not an integer') from None
        if not self.min_value <= value <= self.max_value:
            raise ValueError(f'{value} is not in the range {self.min_value}..{self.max_value}')
        return value


def apply_schema(settings: dict[str, t.Any], schema: dict[str, t.Any], path_list: list[str]):
    error = False
    for key, value in schema.items():
        if isinstance(value, type) and issubclass(value, msgspec.Struct):
            try:
                # Type Validation at runtime:
                # https://jcristharif.com/msgspec/structs.html#type-validation
                cfg_dict = settings.get(key)
                if cfg_dict is None:
                    cfg_dict = {}
                cfg_json = msgspec.json.encode(cfg_dict)
                settings[key] = msgspec.json.decode(cfg_json, type=value)
            except msgspec.ValidationError as e:
                # To get a more meaningful error message, we need to replace the
                # `$` by the (doted) name space.  For example if ValidationError
                # was raised for the field `name` in structure at `foo.bar`:
                #     Expected `str`, got `int` - at `$.name`
                # is converted to:
                #     Expected `str`, got `int` - at `foo.bar.name`
                msg = str(e)
                msg = msg.replace("`$.", "`" + ".".join([*path_list, key]) + ".")
                logger.error(msg)
                error = True
        elif isinstance(value, SettingsValue):
            try:
                settings[key] = value(settings.get(key, _UNDEFINED))
            except Exception as e:  # pylint: disable=broad-except
                # don't stop now: check other values
                msg = ".".join([*path_list, key]) + f": {e}"
                logger.error(msg)
                error = True
        elif isinstance(value, dict):
            error = error or apply_schema(settings.setdefault(key, {}), schema[key], [*path_list, key])
        else:
            settings.setdefault(key, value)
    if len(path_list) == 0 and error:
        raise ValueError("Invalid settings.yml")
    return error


def _iter_proxy_urls(proxies: t.Any) -> Iterator[t.Any]:
    """The URLs of an ``outgoing.proxies`` value (``str`` or ``{pattern: url |
    [url, ..]}``), values of an unexpected type are returned as they are."""
    if isinstance(proxies, dict):
        for urls in t.cast(dict[str, t.Any], proxies).values():
            if isinstance(urls, list):
                yield from t.cast(list[t.Any], urls)
            else:
                yield urls
    elif proxies:
        yield proxies


def check_tor_only(outgoing: dict[str, t.Any]) -> None:
    """This fork of SearXNG is Tor-only, a :py:obj:`ValueError` (the message
    starts with :py:obj:`TOR_ONLY`) is raised if

    - ``outgoing.using_tor_proxy`` is not true or
    - ``outgoing.proxies`` is empty or one of its URLs is not a ``socks5h://``
      URL (the host names are resolved by Tor).

    The networks check the other details (e.g. a proxy for each scheme), see
    :py:obj:`searx.network.network.Network.check_tor_parameters`.
    """
    if outgoing.get('using_tor_proxy') is not True:
        raise ValueError(f'{TOR_ONLY}: outgoing.using_tor_proxy must be true')
    urls = list(_iter_proxy_urls(outgoing.get('proxies')))
    if not urls or not all(isinstance(url, str) and url.startswith('socks5h://') for url in urls):
        raise ValueError(f'{TOR_ONLY}: outgoing.proxies must be a socks5h:// Tor proxy (set {TOR_PROXY_ENV})')


def apply_tor_only(settings: dict[str, t.Any]) -> None:
    """Applies the environment variable :py:obj:`TOR_PROXY_ENV` to
    ``outgoing.proxies`` and checks the result with :py:obj:`check_tor_only`.
    Has to be called after :py:obj:`apply_schema` (``SEARXNG_USING_TOR_PROXY``
    is applied by the schema).

    A value of :py:obj:`TOR_PROXY_ENV` that is not a ``socks5h://host:port`` URL
    raises a :py:obj:`ValueError`.
    """
    outgoing: dict[str, t.Any] = settings['outgoing']
    tor_proxy = os.environ.get(TOR_PROXY_ENV)
    if tor_proxy is not None:
        try:
            parts = urlsplit(tor_proxy)
            scheme, host, port = parts.scheme, parts.hostname, parts.port
        except ValueError:  # e.g. an invalid port or IPv6 address
            scheme, host, port = '', None, None
        # don't show the value in the error messages, it may contain credentials
        if not tor_proxy.startswith('socks5h://'):
            raise ValueError(f'{TOR_ONLY}: {TOR_PROXY_ENV} must be a socks5h:// URL, not a {scheme or "?"}:// URL')
        if not host or not port:
            raise ValueError(f'{TOR_ONLY}: {TOR_PROXY_ENV} must be a socks5h://host:port URL, host or port is missing')
        outgoing['proxies'] = {'all://': tor_proxy}
    check_tor_only(outgoing)


SCHEMA: dict[str, t.Any] = {
    'general': {
        'debug': SettingsValue(bool, False, 'SEARXNG_DEBUG'),
        'instance_name': SettingsValue(str, 'SearXNG'),
        'privacypolicy_url': SettingsValue((None, False, str), None),
        'contact_url': SettingsValue((None, False, str), None),
        'donation_url': SettingsValue((bool, str), "https://docs.searxng.org/donate.html"),
        'enable_metrics': SettingsValue(bool, True),
        'open_metrics': SettingsValue(str, ''),
    },
    'brand': SettingsBrand,
    'search': {
        'safe_search': SettingsValue((0, 1, 2), 0),
        'autocomplete': SettingsValue(str, 'duckduckgo'),
        'autocomplete_min': SettingsValue(int, 4),
        'favicon_resolver': SettingsValue(str, ''),
        'default_lang': SettingsValue(tuple(SXNG_LOCALE_TAGS + ['']), ''),
        'languages': SettingSublistValue(SXNG_LOCALE_TAGS, SXNG_LOCALE_TAGS),  # type: ignore
        'ban_time_on_fail': SettingsValue(numbers.Real, 5),
        'max_ban_time_on_fail': SettingsValue(numbers.Real, 120),
        'suspended_times': {
            'SearxEngineAccessDenied': SettingsValue(numbers.Real, 86400),
            'SearxEngineCaptcha': SettingsValue(numbers.Real, 86400),
            'SearxEngineTooManyRequests': SettingsValue(numbers.Real, 3600),
            'cf_SearxEngineCaptcha': SettingsValue(numbers.Real, 1296000),
            'cf_SearxEngineAccessDenied': SettingsValue(numbers.Real, 86400),
            'recaptcha_SearxEngineCaptcha': SettingsValue(numbers.Real, 604800),
        },
        'formats': SettingsValue(list, OUTPUT_FORMATS),
        'max_page': SettingsValue(int, 0),
    },
    'server': {
        'port': SettingsValue((int, str), 8888, 'SEARXNG_PORT'),
        'bind_address': SettingsValue(str, '127.0.0.1', 'SEARXNG_BIND_ADDRESS'),
        'limiter': SettingsValue(bool, False, 'SEARXNG_LIMITER'),
        'public_instance': SettingsValue(bool, False, 'SEARXNG_PUBLIC_INSTANCE'),
        'secret_key': SettingsValue(str, environ_name='SEARXNG_SECRET'),
        'base_url': SettingsValue((False, str), False, 'SEARXNG_BASE_URL'),
        'image_proxy': SettingsValue(bool, False, 'SEARXNG_IMAGE_PROXY'),
        'http_protocol_version': SettingsValue(('1.0', '1.1'), '1.0'),
        'method': SettingsValue(('POST', 'GET'), 'GET', 'SEARXNG_METHOD'),
        'default_http_headers': SettingsValue(dict, {}),
    },
    # redis is deprecated ..
    'redis': {
        'url': SettingsValue((None, False, str), False, 'SEARXNG_REDIS_URL'),
    },
    'valkey': {
        'url': SettingsValue((None, False, str), False, 'SEARXNG_VALKEY_URL'),
    },
    'ui': {
        'static_path': SettingsDirectoryValue(str, os.path.join(searx_dir, 'static')),
        'templates_path': SettingsDirectoryValue(str, os.path.join(searx_dir, 'templates')),
        'default_theme': SettingsValue(str, 'simple'),
        'default_locale': SettingsValue(str, ''),
        'theme_args': {
            'simple_style': SettingsValue(SIMPLE_STYLE, 'auto'),
        },
        'center_alignment': SettingsValue(bool, False),
        'results_on_new_tab': SettingsValue(bool, False),
        'query_in_title': SettingsValue(bool, False),
        'cache_url': SettingsValue(str, 'https://web.archive.org/web/'),
        'search_on_category_select': SettingsValue(bool, True),
        'hotkeys': SettingsValue(('default', 'vim'), 'default'),
        'url_formatting': SettingsValue(('pretty', 'full', 'host'), 'pretty'),
    },
    "preferences": SettingsPref,
    'outgoing': {
        'useragent_suffix': SettingsValue(str, ''),
        'request_timeout': SettingsValue(numbers.Real, 3.0),
        'enable_http2': SettingsValue(bool, True),
        'verify': SettingsValue((bool, str), True),
        'max_request_timeout': SettingsValue((None, numbers.Real), None),
        'pool_connections': SettingsValue(int, 100),
        # default maximum redirect
        # from https://github.com/psf/requests/blob/8c211a96cdbe9fe320d63d9e1ae15c5c07e179f8/requests/models.py#L55
        'max_redirects': SettingsValue(int, 30),
        'retries': SettingsValue(int, 0),
        'proxies': SettingsValue((None, str, dict), None),
        'source_ips': SettingsValue((None, str, list), None),
        # Tor configuration (Tor-only build: see apply_tor_only)
        'using_tor_proxy': SettingsValue(bool, True, 'SEARXNG_USING_TOR_PROXY'),
        'extra_proxy_timeout': SettingsValue(numbers.Real, 0),
        'tor_circuits': SettingsIntRangeValue(0, TOR_CIRCUITS_MAX, 0, 'SEARXNG_TOR_CIRCUITS'),
        'tor_control': {
            'host': SettingsValue(str, '', 'SEARXNG_TOR_CONTROL_HOST'),
            'port': SettingsValue((int, str), 9051, 'SEARXNG_TOR_CONTROL_PORT'),
            'password': SettingsValue(str, '', 'SEARXNG_TOR_CONTROL_PASSWORD'),
        },
        'networks': {},
    },
    'plugins': SettingsValue(dict, {}),
    'categories_as_tabs': SettingsValue(dict, CATEGORIES_AS_TABS),
    'engines': SettingsValue(list, []),
    'doi_resolvers': {},
}
