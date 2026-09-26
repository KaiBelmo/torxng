#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-or-later
"""This script saves `Ahmia's blacklist`_ for onion sites.

Output file: :origin:`searx/data/ahmia_blacklist.txt` (:origin:`CI Update data
...  <.github/workflows/data-update.yml>`).

.. _Ahmia's blacklist: https://ahmia.fi/blacklist/

"""

# pylint: disable=use-dict-literal

from searx import network
from searx.data import data_dir
from searx.utils import searxng_useragent

DATA_FILE = data_dir / 'ahmia_blacklist.txt'
URL = 'https://ahmia.fi/blacklist/banned/'


def fetch_ahmia_blacklist():
    # Tor-only build: searx.network sends the request over Tor
    resp = network.get(URL, timeout=30.0, headers={"User-Agent": searxng_useragent()})
    if resp.status_code != 200:
        # pylint: disable=broad-exception-raised
        raise Exception("Error fetching Ahmia blacklist, HTTP code " + str(resp.status_code))
    return resp.text.split()


def main():
    # Tor-only build: initialize the network (Tor) and check it
    network.initialize()
    network.check_network_configuration()
    blacklist = fetch_ahmia_blacklist()
    blacklist.sort()
    with DATA_FILE.open("w", encoding='utf-8') as f:
        f.write('\n'.join(blacklist))


if __name__ == '__main__':
    main()
