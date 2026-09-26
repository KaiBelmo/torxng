# SPDX-License-Identifier: AGPL-3.0-or-later
"""Simple implementation to store TrackerPatterns data in a SQL database."""

# pylint: disable=too-many-branches

import typing as t

__all__ = ["TrackerPatternsDB"]

import re
import threading
import time
from collections.abc import Callable, Iterator
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from curl_cffi.requests.exceptions import RequestException

from searx import get_setting
from searx.data.core import get_cache, log
from searx.network import get as http_get

if t.TYPE_CHECKING:
    from searx.cache import CacheRowType


RuleType = tuple[str, list[str], list[str]]


def _start_thread(target: Callable[[], None]) -> None:
    """Run ``target`` in a daemon thread."""
    threading.Thread(target=target, name="tracker_patterns", daemon=True).start()


@t.final
class TrackerPatternsDB:
    # pylint: disable=missing-class-docstring

    ctx_name = "data_tracker_patterns"

    # ClearURL rule lists, the first one that responds HTTP 200 is used
    CLEAR_LIST_URL = [
        "https://cdn.jsdelivr.net/gh/clearurls/rules@refs/heads/gh-pages/data.minify.json",
        "https://rules2.clearurls.xyz/data.minify.json",
        "https://rules1.clearurls.xyz/data.minify.json",
    ]

    class Fields:
        # pylint: disable=too-few-public-methods, invalid-name
        url_regexp: t.Final = 0  # URL (regular expression) match condition of the link
        url_ignore: t.Final = 1  # URL (regular expression) to ignore
        del_args: t.Final = 2  # list of URL arguments (regular expression) to delete

    LOADED_PROPERTY = "tracker_patterns loaded"

    RETRY_INTERVAL = 300
    """Seconds to wait before a failed (or a still running) initialization is
    started again (the property is shared by all workers)."""

    def __init__(self):
        self.cache = get_cache()
        self._init_lock = threading.Lock()

    def init(self, background: bool = False):
        """Load the rules if they are not loaded yet, at most one load is
        started per :py:obj:`RETRY_INTERVAL`.  With ``background`` the rules
        are loaded in a daemon thread and the method returns immediately (used
        in the request path, the startup may block)."""
        if self.cache.properties(self.LOADED_PROPERTY) == "OK":
            return
        with self._init_lock:
            state = self.cache.properties(self.LOADED_PROPERTY)
            if state == "OK":
                return
            if state and time.time() - self.cache.properties.m_time(self.LOADED_PROPERTY) < self.RETRY_INTERVAL:
                # initialization is running (in parallel) or has recently failed
                return
            # To avoid parallel initializations, the property is set first
            self.cache.properties.set(self.LOADED_PROPERTY, "LOADING")
        if background:
            _start_thread(self._load_and_mark)
        else:
            self._load_and_mark()
        # F I X M E:
        #     do we need a maintenance .. remember: database is stored
        #     in /tmp and will be rebuild during the reboot anyway

    def _load_and_mark(self):
        try:
            loaded = self.load()
        except Exception:  # pylint: disable=broad-exception-caught
            # an exception must not stop the startup (plugin init)
            log.exception("TRACKER_PATTERNS: loading the ClearURL rules failed")
            loaded = False
        # FAILED: try again after RETRY_INTERVAL (e.g. Tor circuit was not ready)
        self.cache.properties.set(self.LOADED_PROPERTY, "OK" if loaded else "FAILED")

    def load(self) -> bool:
        """Load the rules into the cache, returns ``False`` if no rules could
        be loaded."""
        log.debug("init searx.data.TRACKER_PATTERNS")
        rows: "list[CacheRowType]" = []

        for rule in self.iter_clear_list():
            key = rule[self.Fields.url_regexp]
            value = (
                rule[self.Fields.url_ignore],
                rule[self.Fields.del_args],
            )
            rows.append((key, value, None))

        if not rows:
            return False
        self.cache.setmany(rows, ctx=self.ctx_name)
        return True

    def add(self, rule: RuleType):
        key = rule[self.Fields.url_regexp]
        value = (
            rule[self.Fields.url_ignore],
            rule[self.Fields.del_args],
        )
        self.cache.set(key=key, value=value, ctx=self.ctx_name, expire=None)

    def rules(self) -> Iterator[RuleType]:
        # called for each result URL of a search: never download in the
        # request path, use the rules that are already loaded
        self.init(background=True)
        for key, value in self.cache.pairs(ctx=self.ctx_name):
            yield key, value[0], value[1]

    @staticmethod
    def download_timeout() -> float:
        """Timeout for downloading a rule list: ``outgoing.request_timeout``
        (plus ``outgoing.extra_proxy_timeout`` when using Tor), at least 3 sec."""
        timeout = float(get_setting("outgoing.request_timeout", 3.0))
        if get_setting("outgoing.using_tor_proxy", False):
            timeout += float(get_setting("outgoing.extra_proxy_timeout", 0) or 0)
        return max(3.0, timeout)

    def iter_clear_list(self) -> Iterator[RuleType]:
        timeout = self.download_timeout()
        for url in self.CLEAR_LIST_URL:
            log.debug("TRACKER_PATTERNS: Trying to fetch %s...", url)
            try:
                resp = http_get(url, timeout=timeout)

            except RequestException as exc:
                log.warning("TRACKER_PATTERNS: RequestException while fetching %s: %s", url, exc)
                continue

            if resp.status_code != 200:
                log.warning(f"TRACKER_PATTERNS: ClearURL ignore HTTP {resp.status_code} {url}")
                continue

            try:
                rules: list[RuleType] = [
                    (
                        rule["urlPattern"].replace("\\\\", "\\"),  # fix javascript regex syntax
                        [pattern.replace("\\\\", "\\") for pattern in rule.get("exceptions", [])],
                        rule.get("rules", []),
                    )
                    for rule in resp.json()["providers"].values()
                ]
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                # e.g. a mirror answers HTTP 200 with a HTML page
                log.warning("TRACKER_PATTERNS: invalid ClearURL rule list %s: %r", url, exc)
                continue

            yield from rules
            return

        log.error("TRACKER_PATTERNS: failed fetching ClearURL rule lists")

    def clean_url(self, url: str) -> bool | str:
        """The URL arguments are normalized and cleaned of tracker parameters.

        Returns bool ``True`` to use URL unchanged (``False`` to ignore URL).
        If URL should be modified, the returned string is the new URL to use.
        """

        new_url = url
        parsed_new_url = urlparse(url=new_url)

        for rule in self.rules():

            query_str: str = parsed_new_url.query
            if not query_str:
                # There are no more query arguments in the parsed_new_url on
                # which rules can be applied, stop iterating over the rules.
                break

            if not re.match(rule[self.Fields.url_regexp], new_url):
                # no match / ignore pattern
                continue

            do_ignore = False
            for pattern in rule[self.Fields.url_ignore]:
                if re.match(pattern, new_url):
                    do_ignore = True
                    break

            if do_ignore:
                # pattern is in the list of exceptions / ignore pattern
                # HINT:
                #    we can't break the outer pattern loop since we have
                #    overlapping urlPattern like ".*"
                continue

            query_args: list[tuple[str, str]] = list(parse_qsl(parsed_new_url.query))
            if query_args:
                # remove tracker arguments from the url-query part
                for name, val in query_args.copy():
                    # remove URL arguments
                    for pattern in rule[self.Fields.del_args]:
                        if re.match(pattern, name):
                            log.debug(
                                "TRACKER_PATTERNS: %s remove tracker arg: %s='%s'", parsed_new_url.netloc, name, val
                            )
                            query_args.remove((name, val))

                parsed_new_url = parsed_new_url._replace(query=urlencode(query_args))
                new_url = urlunparse(parsed_new_url)

            else:
                # The query argument for URLs like:
                # - 'http://example.org?q='       --> query_str is 'q=' and query_args is []
                # - 'http://example.org?/foo/bar' --> query_str is 'foo/bar' and  query_args is []
                # is a simple string and not a key/value dict.
                for pattern in rule[self.Fields.del_args]:
                    if re.match(pattern, query_str):
                        log.debug("TRACKER_PATTERNS: %s remove tracker arg: '%s'", parsed_new_url.netloc, query_str)
                        parsed_new_url = parsed_new_url._replace(query="")
                        new_url = urlunparse(parsed_new_url)
                        break

        if new_url != url:
            return new_url

        return True


if __name__ == "__main__":
    db = TrackerPatternsDB()
    for r in db.rules():
        print(r)
