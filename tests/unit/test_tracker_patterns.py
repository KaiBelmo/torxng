# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import os
import shutil
import tempfile
import threading

from curl_cffi.requests.exceptions import RequestException
from mock import Mock, call, patch

from searx.cache import ExpireCacheCfg, ExpireCacheSQLite
from searx.data.tracker_patterns import TrackerPatternsDB, _start_thread

from tests import SearxTestCase, SearxTorTestCase

RULES = {
    "providers": {
        "example": {
            "urlPattern": "^https?:\\/\\/(?:[a-z0-9-]+\\.)*?example\\.org",
            "rules": ["utm_source"],
            "exceptions": [],
        }
    }
}

URLS = TrackerPatternsDB.CLEAR_LIST_URL


def ok_response() -> Mock:
    return Mock(status_code=200, json=Mock(return_value=RULES))


def new_db(test: SearxTestCase) -> TrackerPatternsDB:
    """TrackerPatternsDB with its own (empty) cache DB."""
    tmp = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, tmp, True)
    db = TrackerPatternsDB()
    db.cache = ExpireCacheSQLite.build_cache(
        ExpireCacheCfg(name="TEST_TRACKER_PATTERNS", db_url=os.path.join(tmp, "cache.db"))
    )
    return db


class TrackerPatternsInit(SearxTestCase):

    def test_success_not_downloaded_again(self):
        db = new_db(self)
        with patch("searx.data.tracker_patterns.http_get", return_value=ok_response()) as http_get:
            db.init()
            db.init()
            rules = list(db.rules())
        http_get.assert_called_once_with(URLS[0], timeout=3.0)
        self.assertEqual(rules, [(RULES["providers"]["example"]["urlPattern"], [], ["utm_source"])])
        self.assertEqual(db.cache.properties(db.LOADED_PROPERTY), "OK")
        self.assertEqual(db.clean_url("https://www.example.org/?utm_source=x&q=1"), "https://www.example.org/?q=1")

    def test_failure_then_success(self):
        db = new_db(self)
        with patch("searx.data.tracker_patterns.http_get", side_effect=RequestException("x")) as http_get:
            with self.assertLogs("searx.data", level="ERROR"):
                db.init()
            self.assertEqual(http_get.call_args_list, [call(url, timeout=3.0) for url in URLS])
            self.assertEqual(list(db.rules()), [])
            self.assertEqual(db.cache.properties(db.LOADED_PROPERTY), "FAILED")

            # within RETRY_INTERVAL: no new download (e.g. once per result)
            db.init()
            self.assertEqual(http_get.call_count, len(URLS))

        self.setattr4test(TrackerPatternsDB, "RETRY_INTERVAL", -1)
        with patch("searx.data.tracker_patterns.http_get", return_value=ok_response()) as http_get:
            db.init()
            http_get.assert_called_once_with(URLS[0], timeout=3.0)
        self.assertEqual(len(list(db.rules())), 1)
        self.assertEqual(db.cache.properties(db.LOADED_PROPERTY), "OK")

    def test_http_errors(self):
        db = new_db(self)
        with patch("searx.data.tracker_patterns.http_get", return_value=Mock(status_code=503)) as http_get:
            with self.assertLogs("searx.data", level="ERROR"):
                db.init()
        self.assertEqual(http_get.call_count, len(URLS))
        self.assertEqual(db.cache.properties(db.LOADED_PROPERTY), "FAILED")

        self.setattr4test(TrackerPatternsDB, "RETRY_INTERVAL", -1)
        responses = [Mock(status_code=503), ok_response()]
        with patch("searx.data.tracker_patterns.http_get", side_effect=responses) as http_get:
            with self.assertLogs("searx.data", level="WARNING"):
                db.init()
        self.assertEqual(http_get.call_args_list, [call(URLS[0], timeout=3.0), call(URLS[1], timeout=3.0)])
        self.assertEqual(db.cache.properties(db.LOADED_PROPERTY), "OK")

    def test_parallel_initialization(self):
        db = new_db(self)
        db.cache.properties.set(db.LOADED_PROPERTY, "LOADING")
        with patch("searx.data.tracker_patterns.http_get", return_value=ok_response()) as http_get:
            db.init()
        http_get.assert_not_called()

        # a stale LOADING marker (e.g. worker killed) expires after RETRY_INTERVAL
        self.setattr4test(TrackerPatternsDB, "RETRY_INTERVAL", -1)
        with patch("searx.data.tracker_patterns.http_get", return_value=ok_response()) as http_get:
            db.init()
        http_get.assert_called_once()
        self.assertEqual(db.cache.properties(db.LOADED_PROPERTY), "OK")

    def test_invalid_rule_list(self):
        # HTTP 200 with a body that is not a ClearURL rule list: next mirror
        responses = [
            Mock(status_code=200, json=Mock(side_effect=ValueError("Expecting value"))),
            Mock(status_code=200, json=Mock(return_value={"providers": []})),
            ok_response(),
        ]
        db = new_db(self)
        with patch("searx.data.tracker_patterns.http_get", side_effect=responses) as http_get:
            with self.assertLogs("searx.data", level="WARNING") as ctx:
                db.init()
        self.assertEqual(http_get.call_args_list, [call(url, timeout=3.0) for url in URLS])
        self.assertEqual(len(ctx.output), 2)
        self.assertEqual(db.cache.properties(db.LOADED_PROPERTY), "OK")
        self.assertEqual(len(list(db.rules())), 1)

    def test_exception_does_not_escape_init(self):
        # e.g. at startup (plugin init), the worker has to boot anyway
        db = new_db(self)
        with patch("searx.data.tracker_patterns.http_get", side_effect=RuntimeError("no event loop")):
            with self.assertLogs("searx.data", level="ERROR"):
                db.init()
        self.assertEqual(db.cache.properties(db.LOADED_PROPERTY), "FAILED")

    def test_rules_never_download_in_request_path(self):
        db = new_db(self)
        with patch("searx.data.tracker_patterns.http_get", return_value=ok_response()) as http_get:
            with patch("searx.data.tracker_patterns._start_thread") as start_thread:
                # not loaded: a background load is started, rules() returns at once
                self.assertEqual(list(db.rules()), [])
                self.assertEqual(list(db.rules()), [])
                http_get.assert_not_called()
                start_thread.assert_called_once()
                self.assertEqual(db.cache.properties(db.LOADED_PROPERTY), "LOADING")

                # run the background load
                start_thread.call_args.args[0]()
                http_get.assert_called_once_with(URLS[0], timeout=3.0)
                self.assertEqual(len(list(db.rules())), 1)
                start_thread.assert_called_once()
        self.assertEqual(db.cache.properties(db.LOADED_PROPERTY), "OK")

    def test_background_retry_after_failure(self):
        db = new_db(self)
        with patch("searx.data.tracker_patterns.http_get", side_effect=RequestException("x")):
            with self.assertLogs("searx.data", level="ERROR"):
                db.init()

        self.setattr4test(TrackerPatternsDB, "RETRY_INTERVAL", -1)
        with patch("searx.data.tracker_patterns.http_get", return_value=ok_response()):
            with patch("searx.data.tracker_patterns._start_thread", side_effect=lambda target: target()) as start:
                rules = list(db.rules())
        start.assert_called_once()
        self.assertEqual(len(rules), 1)

    def test_start_thread(self):
        done = threading.Event()
        _start_thread(done.set)
        self.assertTrue(done.wait(5))

    def test_download_timeout(self):
        self.assertEqual(TrackerPatternsDB.download_timeout(), 3.0)


class TrackerPatternsTor(SearxTorTestCase):

    def test_download_timeout(self):
        # request_timeout 3.0 + extra_proxy_timeout 5.0
        self.assertEqual(TrackerPatternsDB.download_timeout(), 8.0)
        db = new_db(self)
        with patch("searx.data.tracker_patterns.http_get", return_value=ok_response()) as http_get:
            db.init()
        http_get.assert_called_once_with(URLS[0], timeout=8.0)
