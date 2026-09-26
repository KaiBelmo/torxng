# SPDX-License-Identifier: AGPL-3.0-or-later
"""Search radio stations from RadioBrowser by `Advanced station search API`_.

.. _Advanced station search API:
   https://de1.api.radio-browser.info/#Advanced_station_search

Upstream resolves the list of the API servers by DNS lookups of
``all.api.radio-browser.info`` with the resolver of the system.  This fork is
Tor-only (:ref:`using_tor_proxy <settings outgoing>`), a local DNS lookup would
bypass Tor: the engine needs a static list of servers (:py:obj:`servers`),
otherwise it is not loaded.

.. code:: yaml

   - name: radio browser
     engine: radio_browser
     servers:
       - https://de1.api.radio-browser.info

"""

import typing as t

import os
import random
import socket
from urllib.parse import urlencode

import babel
from flask_babel import gettext

from searx import settings
from searx.enginelib import EngineCache
from searx.enginelib.traits import EngineTraits
from searx.locales import language_tag

about = {
    "website": "https://www.radio-browser.info/",
    "wikidata_id": "Q111664849",
    "official_api_documentation": "https://de1.api.radio-browser.info/",
    "use_official_api": True,
    "require_api_key": False,
    "results": "JSON",
}
language_support = True
paging = True
categories = ["music", "radio"]

page_size = 10

station_filters = []  # ['countrycode', 'language']
"""A list of filters to be applied to the search of radio stations.  By default
none filters are applied. Valid filters are:

``language``
  Filter stations by selected language.  For instance the ``de`` from ``:de-AU``
  will be translated to `german` and used in the argument ``language=``.

``countrycode``
  Filter stations by selected country.  The 2-digit countrycode of the station
  comes from the region the user selected.  For instance ``:de-AU`` will filter
  out all stations not in ``AU``.

.. note::

   RadioBrowser has registered a lot of languages and countrycodes unknown to
   :py:obj:`babel` and note that when searching for radio stations, users are
   more likely to search by name than by region or language.

"""

servers: list[str] = []
"""A static list of API servers (e.g. ``https://de1.api.radio-browser.info``).
If empty, the servers are resolved by DNS lookups with the resolver of the
system, which is not possible when Tor is used."""

CACHE: EngineCache
"""Persistent (SQLite) key/value cache that deletes its values after ``expire``
seconds."""


def _using_tor_proxy() -> bool:
    # ``using_tor_proxy`` is an engine attribute (see searx.engines.using_tor_proxy)
    return bool(settings["outgoing"]["using_tor_proxy"] or globals().get("using_tor_proxy"))


def setup(_engine_settings: dict[str, t.Any]) -> bool:
    """With Tor, the engine is only loaded if there is a static list of
    :py:obj:`servers` (no local DNS lookups)."""
    if _using_tor_proxy() and not servers:
        logger.error(
            "the engine uses Tor, but the list of servers can only be resolved with the"
            " local DNS resolver (bypasses Tor): set 'servers' in the engine settings,"
            " the engine is disabled"
        )
        return False
    return True


def init(_):
    global CACHE  # pylint: disable=global-statement
    CACHE = EngineCache("radio_browser")

    # In an environment with competing processes, the initial loading of the
    # cache is required only once.
    eng_state: str | None = CACHE.get("eng_state")
    if not eng_state or not eng_state.startswith("STATE:"):
        CACHE.set("eng_state", f"STATE: being initialized by PID {os.getpid()}")
        try:
            server_list()
        except Exception:
            CACHE.set("eng_state", f"ERROR: initialization by PID {os.getpid()} failed.")
            raise
    else:
        logger.debug(eng_state)


def server_list() -> list[str]:

    if servers:
        return list(servers)

    if _using_tor_proxy():
        # never resolve the servers with the local DNS resolver (bypasses Tor)
        raise RuntimeError("radio_browser: no static list of servers, DNS lookups would bypass Tor")

    srv_list: list[str] = CACHE.get("servers", [])
    if srv_list:
        return srv_list

    # hint: can take up to 40sec!
    ips = socket.getaddrinfo("all.api.radio-browser.info", 80, 0, 0, socket.IPPROTO_TCP)
    for ip_tuple in ips:
        _ip: str = ip_tuple[4][0]  # type: ignore
        try:
            url = socket.gethostbyaddr(_ip)[0]
        except socket.herror:
            # https://github.com/searxng/searxng/issues/5439
            continue
        srv = "https://" + url
        if srv not in srv_list:
            srv_list.append(srv)

    # update server list once in 24h
    CACHE.set(key="servers", value=srv_list, expire=60 * 60 * 24)

    return srv_list


def request(query, params):

    srv_list = server_list()
    if not srv_list:
        logger.error("Fetched server list is empty!")
        params["url"] = None
        return

    server = random.choice(srv_list)

    args = {
        "name": query,
        "order": "votes",
        "offset": (params["pageno"] - 1) * page_size,
        "limit": page_size,
        "hidebroken": "true",
        "reverse": "true",
    }

    if "language" in station_filters:
        lang = traits.get_language(params["searxng_locale"])  # type: ignore
        if lang:
            args["language"] = lang

    if "countrycode" in station_filters:
        if len(params["searxng_locale"].split("-")) > 1:
            countrycode = params["searxng_locale"].split("-")[-1].upper()
            if countrycode in traits.custom["countrycodes"]:  # type: ignore
                args["countrycode"] = countrycode

    params["url"] = f"{server}/json/stations/search?{urlencode(args)}"


def response(resp):
    results = []

    json_resp = resp.json()

    for result in json_resp:
        url = result["homepage"]
        if not url:
            url = result["url_resolved"]

        content = []
        tags = ", ".join(result.get("tags", "").split(","))
        if tags:
            content.append(tags)
        for x in ["state", "country"]:
            v = result.get(x)
            if v:
                v = str(v).strip()
                content.append(v)

        metadata = []
        codec = result.get("codec")
        if codec and codec.lower() != "unknown":
            metadata.append(f"{codec} " + gettext("radio"))
        for x, y in [
            (gettext("bitrate"), "bitrate"),
            (gettext("votes"), "votes"),
            (gettext("clicks"), "clickcount"),
        ]:
            v = result.get(y)
            if v:
                v = str(v).strip()
                metadata.append(f"{x} {v}")
        results.append(
            {
                "url": url,
                "title": result["name"],
                "thumbnail": result.get("favicon", "").replace("http://", "https://"),
                "content": " | ".join(content),
                "metadata": " | ".join(metadata),
                "iframe_src": result["url_resolved"].replace("http://", "https://"),
            }
        )

    return results


def fetch_traits(engine_traits: EngineTraits):
    """Fetch languages and countrycodes from RadioBrowser

    - ``traits.languages``: `list of languages API`_
    - ``traits.custom['countrycodes']``: `list of countries API`_

    .. _list of countries API: https://de1.api.radio-browser.info/#List_of_countries
    .. _list of languages API: https://de1.api.radio-browser.info/#List_of_languages
    """
    # pylint: disable=import-outside-toplevel

    init(None)
    from babel.core import get_global

    from searx.network import get  # see https://github.com/searxng/searxng/issues/762

    babel_reg_list = get_global("territory_languages").keys()

    server = server_list()[0]

    resp = get(
        f"{server}/json/languages",
        timeout=5,
    )
    if not resp.ok:
        raise RuntimeError("Response from radio-browser languages is not OK.")

    language_list = resp.json()

    resp = get(
        f"{server}/json/countries",
        timeout=5,
    )
    if not resp.ok:
        raise RuntimeError("Response from radio-browser countries is not OK.")

    country_list = resp.json()

    for lang in language_list:
        babel_lang = lang.get("iso_639")
        if not babel_lang:
            # the language doesn't have any iso code, and hence can't be parsed
            # print(f"ERROR: lang - no iso code in {lang}")
            continue
        try:
            sxng_tag = language_tag(babel.Locale.parse(babel_lang, sep="-"))
        except babel.UnknownLocaleError:
            # print(f"ERROR: language tag {babel_lang} is unknown by babel")
            continue

        eng_tag = lang["name"]
        conflict = engine_traits.languages.get(sxng_tag)
        if conflict:
            if conflict != eng_tag:
                print("CONFLICT: babel %s --> %s, %s" % (sxng_tag, conflict, eng_tag))
            continue
        engine_traits.languages[sxng_tag] = eng_tag

    countrycodes = set()
    for region in country_list:
        # country_list contains duplicates that differ only in upper/lower case
        _reg = region["iso_3166_1"].upper()
        if _reg not in babel_reg_list:
            print(f"ERROR: region tag {region['iso_3166_1']} is unknown by babel")
            continue
        countrycodes.add(_reg)

    countrycodes = list(countrycodes)
    countrycodes.sort()
    engine_traits.custom["countrycodes"] = countrycodes
