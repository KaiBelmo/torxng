.. _settings outgoing:

=============
``outgoing:``
=============

Communication with search engines.

.. important::

   This fork of SearXNG is **Tor-only**: all outgoing requests are sent over
   Tor, there is no way to run it without Tor.  ``using_tor_proxy`` can't be
   disabled and ``proxies`` has to be a ``socks5h://`` Tor proxy, see
   :ref:`settings outgoing tor-only`.

The values of the environment variables mentioned below (e.g.
``$SEARXNG_USING_TOR_PROXY``) take precedence over the values in the
:origin:`searx/settings.yml` file.

.. code:: yaml

   outgoing:
     request_timeout: 2.0       # default timeout in seconds, can be override by engine
     max_request_timeout: 10.0  # the maximum timeout in seconds
     useragent_suffix: ""       # information like an email address to the administrator
     pool_connections: 100      # Maximum number of concurrent connections (default: 100)
     enable_http2: true         # Enables the use of HTTP2
     # uncomment below section if you want to use a custom server certificate
     #  verify: ~/.mitmproxy/mitmproxy-ca-cert.cer
     #
     # Tor-only build: the SOCKS port of a local Tor daemon ($SEARXNG_TOR_PROXY)
     proxies:
       all://: socks5h://127.0.0.1:9050
     using_tor_proxy: true      # can't be false ($SEARXNG_USING_TOR_PROXY)
     #
     # Extra seconds to add in order to account for the time taken by the proxy
     #
     #  extra_proxy_timeout: 10.0
     #
     # Spread the requests over N Tor circuits
     #
     #  tor_circuits: 3
     #
     # Tor control port, used by the tor_circuit plugin
     #
     #  tor_control:
     #    host: 127.0.0.1
     #    port: 9051
     #    password: ""
     #
     # additional networks, see "networks" below
     #
     #  networks:
     #    my_network:
     #      proxies: socks5h://127.0.0.1:9050

``request_timeout`` :
  Global timeout of the requests made to others engines in seconds.  A bigger
  timeout will allow to wait for answers from slow engines, but in consequence
  will slow SearXNG reactivity (the result page may take the time specified in the
  timeout to load).  Can be override by ``timeout`` in the :ref:`settings engines`.

``max_request_timeout`` :
  The maximum timeout of a search request in seconds (default: no maximum).  The
  timeout of a search request is the largest timeout of the engines queried, the
  user can lower it with the ``timeout_limit`` argument of the query, but it can
  never exceed ``max_request_timeout``.

  When Tor is used, set it at least to ``request_timeout`` +
  ``extra_proxy_timeout``, otherwise the ``extra_proxy_timeout`` of the engines is
  cut off by this maximum.

``useragent_suffix`` :
  Suffix to add when an engine's User-Agent is set via searxng_useragent().
  Contact info here may be useful to avoid an engine blocking you.

.. _Pool limit configuration: https://curl-cffi.readthedocs.io/en/latest/api.html#sessions

``pool_connections`` :
  Maximum number of concurrent connections.  The default is 100.
  See ``max_clients`` `Pool limit configuration`_.

.. _curl_cffi proxies: https://curl-cffi.readthedocs.io/en/latest/quick_start.html

``proxies`` : ``$SEARXNG_TOR_PROXY``
  Define one or more proxies you wish to use, see `curl_cffi proxies`_.
  If there are more than one proxy for one protocol (http, https),
  requests to the engines are distributed in a round-robin fashion.

  Tor-only build: the default is ``{"all://": "socks5h://127.0.0.1:9050"}`` and
  only ``socks5h://`` proxies are accepted, so hostnames are resolved by Tor.
  ``$SEARXNG_TOR_PROXY`` (a single ``socks5h://host:port`` URL) replaces the
  proxies, see :ref:`settings outgoing tor-only`.

  When a proxy is configured, the environment variables ``no_proxy`` /
  ``NO_PROXY`` are ignored: the proxy is used for all hosts (libcurl would
  otherwise connect directly to the hosts listed there).

``source_ips`` :
  If you use multiple network interfaces, define from which IP the requests must
  be made. Example:

  * ``0.0.0.0`` any local IPv4 address.
  * ``::`` any local IPv6 address.
  * ``192.168.0.1``
  * ``[ 192.168.0.1, 192.168.0.2 ]`` these two specific IP addresses
  * ``fe80::60a2:1691:e5a2:ee1f``
  * ``fe80::60a2:1691:e5a2:ee1f/126`` all IP addresses in this network.
  * ``[ 192.168.0.1, fe80::/126 ]``

``retries`` :
  Number of retry in case of an HTTP error.  On each retry, SearXNG uses an
  different proxy and source ip.

``enable_http2`` :
  Enable by default (HTTP/2).  Set to ``false`` to force HTTP/1.1.
  HTTP/3 is opt-in per engine (``enable_http3``).

``verify``: : ``$SSL_CERT_FILE``, ``$SSL_CERT_DIR``
  HTTPS verification uses the OS's trust store by default.
  Set a path to use a custom CA file.

  In addition to ``verify``, SearXNG supports the ``$SSL_CERT_FILE`` (for a file) and
  ``$SSL_CERT_DIR`` (for a directory) OpenSSL variables.

``max_redirects`` :
  30 by default. Maximum redirect before it is an error.

``using_tor_proxy`` : ``$SEARXNG_USING_TOR_PROXY``
  Using tor proxy.  Tor-only build: the default is ``true`` and ``false`` is an
  error at startup, see :ref:`settings outgoing tor-only`.

  Every network uses Tor: the default network, the networks of all
  engines, the network of the ``/image_proxy`` endpoint and the networks defined
  in ``networks``.  At startup, each of these networks is verified against
  ``https://check.torproject.org/api/ip`` and SearXNG refuses to start when one
  of them does not use Tor.  A failed check is repeated two times (after 2 and 5
  seconds) before it counts as failed.  A client is only used when its proxies
  passed this check; a failed check at runtime is not cached, the next client
  with these proxies is checked again.

  The proxies of a network that uses Tor have to meet these requirements,
  otherwise SearXNG refuses to start:

  - All proxies are ``socks5h://`` URLs, so that the hostnames are resolved by
    Tor and not by the local DNS resolver.

  - There is a proxy for each scheme the network may use: an ``all://`` proxy,
    or a ``https://`` proxy and (if HTTP is enabled for the network, see
    ``enable_http`` in the :ref:`settings engines`) a ``http://`` proxy.
    Without such a proxy, the requests of this scheme would bypass Tor.

  An engine (or a network) cannot opt out of Tor (``using_tor_proxy: false`` in
  the :ref:`settings engines` is ignored).

``extra_proxy_timeout`` :
  Seconds (float or integer, default ``0``) added to the timeout of every engine
  that uses Tor, to account for the time taken by the Tor network.  The same
  extra time is added to the timeout of the autocompleter requests.  See also
  ``max_request_timeout``.

``tor_circuits`` : ``$SEARXNG_TOR_CIRCUITS``
  Number of Tor circuits the requests are spread over, an integer in the range
  ``0`` to ``32`` (default ``0``, values below ``2`` disable the feature, values
  outside of the range are an error at startup).  Requires ``using_tor_proxy:
  true`` and ``socks5h://`` proxies.

  Each ``socks5h://`` proxy URL without credentials is replaced by
  ``tor_circuits`` URLs with distinct SOCKS credentials
  (``socks5h://sxng-<i>:<salt>@host:port``) and the requests are distributed
  round-robin over them.  Tor isolates streams with different SOCKS credentials
  on different circuits, which requires the ``IsolateSOCKSAuth`` flag of the
  ``SocksPort`` (enabled by default in Tor).  The credentials are generated per
  process, a restart of SearXNG gets new circuits.  Proxy URLs that already have
  credentials are not changed.

``tor_control`` :
  Access to the control port of the Tor daemon, used by the "tor_circuit"
  plugin.

  .. code:: yaml

     tor_control:
       host: 127.0.0.1   # $SEARXNG_TOR_CONTROL_HOST, empty host disables the control port
       port: 9051        # $SEARXNG_TOR_CONTROL_PORT
       password: ""      # $SEARXNG_TOR_CONTROL_PASSWORD

  On the Tor side, the control port needs a ``ControlPort`` and a
  ``HashedControlPassword`` (``tor --hash-password <password>``).  Prefer the
  environment variable ``$SEARXNG_TOR_CONTROL_PASSWORD`` over a password in the
  settings file.

``networks`` :
  Additional named networks.  A network accepts the same options as the network
  settings of an engine (``enable_http``, ``verify``, ``enable_http2``,
  ``enable_http3``, ``max_connections``, ``proxies``, ``using_tor_proxy``,
  ``local_addresses``, ``retries``, ``retry_on_http_error``, ``max_redirects``),
  options that are not set get their defaults from this ``outgoing:`` section.
  An engine uses such a network by its name, see :ref:`network <engine network>`
  in the :ref:`settings engines`.

  .. code:: yaml

     outgoing:
       networks:
         my_proxy:
           proxies: socks5h://tor2:9050
           retries: 1

     engines:
       - name: wikipedia
         network: my_proxy

.. _settings outgoing tor-only:

Tor-only
========

SearXNG refuses to start (the web application, the test suite and the scripts
in :origin:`searxng_extra`) unless all requests are sent over Tor:

- ``outgoing.using_tor_proxy`` is ``true`` (the default).  A ``false`` in the
  settings or in ``$SEARXNG_USING_TOR_PROXY`` is an error::

    Tor-only build: outgoing.using_tor_proxy must be true

- ``outgoing.proxies`` is not empty and all of its URLs are ``socks5h://`` URLs
  (the default is ``socks5h://127.0.0.1:9050``, the SOCKS port of a local Tor
  daemon, the Tor Browser listens on port ``9150``).  Otherwise::

    Tor-only build: outgoing.proxies must be a socks5h:// Tor proxy (set SEARXNG_TOR_PROXY)

- The environment variable ``$SEARXNG_TOR_PROXY`` is a single
  ``socks5h://host:port`` URL (e.g. ``socks5h://tor:9050``), it replaces
  ``outgoing.proxies`` by ``{"all://": <URL>}``.  Any other value is an
  error, e.g.::

    Tor-only build: SEARXNG_TOR_PROXY must be a socks5h:// URL, not a socks5:// URL
    Tor-only build: SEARXNG_TOR_PROXY must be a socks5h://host:port URL, host or port is missing

- At startup, the networks are checked against
  ``https://check.torproject.org/api/ip`` (see ``using_tor_proxy`` above).  When
  Tor is not running or the requests do not arrive at the Tor network, the
  start fails (after two retries, about 7 seconds) with::

    RuntimeError: Invalid network configuration

There is no direct connection before the networks are initialized either: a
request sent before the initialization of the network (``searx.network.initialize()``)
fails with::

  RuntimeError: Tor-only build: the network is not initialized

With :ref:`use_default_settings <settings use_default_settings>`, the
``proxies`` of a user ``settings.yml`` are merged with the default ``all://``
proxy: use the ``all://`` key (or ``$SEARXNG_TOR_PROXY``) to replace it, an
``all://`` proxy takes precedence over ``http://`` and ``https://`` proxies.
