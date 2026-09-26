# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

import pathlib
import os
import aiounittest
import mock

os.environ.pop('SEARXNG_SETTINGS_PATH', None)
os.environ['SEARXNG_DISABLE_ETC_SETTINGS'] = '1'


class SearxTestLayer:
    """Base layer for non-robot tests."""

    __name__ = 'SearxTestLayer'

    @classmethod
    def setUp(cls):
        pass

    @classmethod
    def tearDown(cls):
        pass

    @classmethod
    def testSetUp(cls):
        pass

    @classmethod
    def testTearDown(cls):
        pass


class SearxTestCase(aiounittest.AsyncTestCase):
    """Base test case for non-robot tests.

    This fork is Tor-only, the test profiles use a Tor proxy on 127.0.0.1.
    The check of the Tor proxies
    (:py:obj:`searx.network.network.Network.check_tor_proxy`) is patched and
    always succeeds, no request is sent to check.torproject.org (see
    :py:obj:`SearxTestCase.use_real_tor_check`).

    Don't import :py:obj:`searx.webapp` at the top of a test module: the import
    initializes the network and checks Tor, the check is only patched in
    :py:obj:`SearxTestCase.init_test_settings` (called by ``setUp``).
    """

    layer = SearxTestLayer

    SETTINGS_FOLDER = pathlib.Path(__file__).parent / "unit" / "settings"
    TEST_SETTINGS = "test_settings.yml"

    def setUp(self):
        self.init_test_settings()

    def patch_tor_check(self):
        """Patch :py:obj:`searx.network.network.Network.check_tor_proxy` (always
        ``True``) for the duration of the test and clear the cached results of
        the check."""
        # pylint: disable=import-outside-toplevel, protected-access
        from searx.network.network import Network

        Network._TOR_CHECK_RESULT.clear()
        self.addCleanup(Network._TOR_CHECK_RESULT.clear)

        # pylint: disable=attribute-defined-outside-init
        self.tor_check_patcher = mock.patch.object(Network, "check_tor_proxy", new=mock.AsyncMock(return_value=True))
        self.tor_check_patcher.start()
        self.addCleanup(self.tor_check_patcher.stop)

    def use_real_tor_check(self):
        """Stop the patch of :py:obj:`patch_tor_check`, for the tests of the
        check itself (they have to mock the HTTP client)."""
        self.tor_check_patcher.stop()

    def setattr4test(self, obj, attr, value):
        """setattr(obj, attr, value) but reset to the previous value in the
        cleanup."""
        previous_value = getattr(obj, attr)

        def cleanup_patch():
            setattr(obj, attr, previous_value)

        self.addCleanup(cleanup_patch)
        setattr(obj, attr, value)

    def init_test_settings(self):
        """Sets ``SEARXNG_SETTINGS_PATH`` environment variable an initialize
        global ``settings`` variable and the ``logger`` from a test config in
        :origin:`tests/unit/settings/`.

        The initialization checks the Tor proxies, the check is patched (see
        :py:obj:`SearxTestCase.patch_tor_check`).
        """

        os.environ['SEARXNG_SETTINGS_PATH'] = str(self.SETTINGS_FOLDER / self.TEST_SETTINGS)
        self.patch_tor_check()

        # pylint: disable=import-outside-toplevel
        import searx
        import searx.locales
        import searx.plugins
        import searx.search
        import searx.webapp

        # https://flask.palletsprojects.com/en/stable/config/#builtin-configuration-values
        # searx.webapp.app.config["DEBUG"] = True
        searx.webapp.app.config["TESTING"] = True  # to get better error messages
        searx.webapp.app.config["EXPLAIN_TEMPLATE_LOADING"] = True

        searx.init_settings()

        # searx.search.initialize will:
        # - load the engines and
        # - initialize searx.network, searx.metrics, searx.processors and searx.search.checker
        #
        # Same order as in searx.webapp.init: the network is initialized before
        # the plugins.

        searx.search.initialize(
            check_network=True,
            enable_metrics=searx.get_setting("general.enable_metrics"),  # type: ignore
        )
        # The plugins of the previous test are removed: they would pile up in the
        # storage and each initialization calls the init method of all of them
        # (e.g. the ahmia_filter plugin loads its blacklist, it is active with Tor).
        searx.plugins.STORAGE.plugin_list.clear()
        searx.plugins.initialize(searx.webapp.app)

        # pylint: disable=attribute-defined-outside-init
        self.app = searx.webapp.app
        self.client = self.app.test_client()


class SearxTorTestCase(SearxTestCase):
    """Test case with the profile :origin:`tests/unit/settings/test_tor.yml`
    (Tor circuits, Tor control port and an extra proxy timeout)."""

    TEST_SETTINGS = "test_tor.yml"
