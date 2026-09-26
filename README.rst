.. SPDX-License-Identifier: AGPL-3.0-or-later

======
TorXNG
======

TorXNG is a lightweight, hardened metasearch engine that sends **every**
request through the `Tor network`_.  It asks many search engines at once,
without tracking or profiling its users, and the search engines only ever see
Tor exit relays, never the server that runs TorXNG.

TorXNG is a fork of SearXNG_.

.. _Tor network: https://www.torproject.org/
.. _SearXNG: https://github.com/searxng/searxng
.. _torxng/README.md: torxng/README.md
.. _torxng/tests/README.md: torxng/tests/README.md
.. _SearXNG documentation: https://docs.searxng.org/admin/settings/index.html
.. _LICENSE: LICENSE


Based on SearXNG
================

TorXNG is based on SearXNG, upstream commit ``12f8b6515`` (September 2026), and
keeps its complete history and authors.  Since 2026-09-26 it has been modified
to run only through Tor, to be lighter and to be hardened.  The changes are
listed in section 12 of `torxng/README.md`_.  All credit for the metasearch
engine itself goes to the SearXNG contributors.


What is different
=================

- **Tor-only.**  TorXNG refuses to start without a Tor SOCKS proxy
  (``socks5h://``, default ``127.0.0.1:9050``, set another one with
  ``SEARXNG_TOR_PROXY``).  There is no setting to turn Tor off, and nothing can
  be sent before the network layer is set up.
- **Isolated circuits.**  Requests are spread over several Tor circuits with
  different exit relays; search ``circuit`` to see them.
- **Onion service.**  The Docker stack also publishes TorXNG as a Tor v3 onion
  service.
- **Hardened.**  Read-only, non-root containers without capabilities, a strict
  Content-Security-Policy, rate limits, and no search terms in the logs.
- **Light.**  About 160 MiB of memory for the whole stack including Tor, and a
  small set of search engines that work over Tor.


Quick start
===========

With Docker (recommended; see section 7 of `torxng/README.md`_ for the
secrets that have to be created first):

.. code:: sh

   cd torxng
   cp .env.example .env
   docker compose up -d --build --wait

Then open http://127.0.0.1:8080/ or the onion address shown by
``docker compose exec tor cat /var/lib/tor/searxng/hostname`` in Tor Browser.

Without Docker, ``make run`` needs a running Tor, either the Tor daemon on
``127.0.0.1:9050`` or Tor Browser:

.. code:: sh

   SEARXNG_TOR_PROXY=socks5h://127.0.0.1:9150 make run


Documentation
=============

- `torxng/README.md`_: architecture, the Tor-only guarantee, hardening,
  cryptographic background, measurements and limitations.
- `torxng/tests/README.md`_: the edge-case and security test suite.
- The `SearXNG documentation`_ remains the reference for general settings.


License
=======

TorXNG is licensed under the GNU Affero General Public License (AGPL-3.0), like
SearXNG; see LICENSE_.  If you run TorXNG as a service for other people, they
must be able to get the source code of the version you run.  The "Source code"
link in the footer of every page points to this repository.
