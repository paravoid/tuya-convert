#!/usr/bin/env python3
"""Configure Tuya devices via SmartConfig without the Tuya cloud or app.

The SmartConfig protocol encodes network information, such as the SSID and
password into broadcast and multicast UDP packets. It employspacket lengths and
multicast IP addresses, which are transmitted to the network. The ESP8266
firmware sniffs those and configures the network appropriately.
"""

# Copyright (c) 2019-2020 Colin Kuebler
# Copyright (c) 2020 Faidon Liambotis
# SPDX-License-Identifier: MIT

import argparse
import logging
import socket
import time
from typing import (
    List,
    Optional,
    Sequence,
    Tuple,
)

from . import broadcast, multicast

ATTEMPTS = 10
# time to sleep in-between packets, 5ms
GAP = 5 / 1000.0
MULTICAST_TTL = 1


logger = logging.getLogger("smarthack-smartconfig")  # pylint: disable=invalid-name


class SmartConfigSocket:
    """Hold a socket open, and send broadcast and multicast out of it."""

    def __init__(self, address: str, gap: float = GAP):
        """Initialize an instance: create a socket, setsockopt() and bind."""
        self._socket = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
        )
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL
        )
        self._socket.bind((address, 0))
        self._gap = gap

    def send_broadcast(self, data: List[int]) -> None:
        """Send broadcast packets for the given data.

        This encodes the data to the packet length.
        """
        for length in data:
            self._socket.sendto(b"\0" * length, ("255.255.255.255", 30011))
            time.sleep(self._gap)

    def send_multicast(self, data: List[str]) -> None:
        """Send multicast packets for the given data.

        The data is pre-encoded to multicast IPv4 addresses.
        """
        for ipaddr in data:
            self._socket.sendto(b"\0", (ipaddr, 30012))
            time.sleep(self._gap)


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    """Parse and return the parsed command line arguments."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--bind", dest="bind_address", default="127.0.0.1", help="Bind address",
    )
    parser.add_argument(
        "--ssid", dest="ssid", default="vtrust-flash", help="WiFi SSID",
    )
    parser.add_argument(
        "--password", dest="password", default="", help="Password for the network",
    )
    parser.add_argument(
        "--region", dest="region", default="US", help="WiFi Region",
    )
    parser.add_argument(
        "--token", dest="token", default="00000000", help="Token",
    )
    parser.add_argument(
        "--secret", dest="secret", default="0101", help="Secret",
    )

    return parser.parse_args(argv)


def smartconfig(bind_address: str, options: Tuple[str, ...]) -> None:
    """Attempt to SmartConfig.

    Sends both broadcast and multicast packets, multiple times.
    """
    password, ssid, region, token, secret = options

    sock = SmartConfigSocket(bind_address)
    token_group = region + token + secret
    broadcast_body = broadcast.encode_network(password, ssid, token_group)
    multicast_body = multicast.encode_network(password, ssid, token_group)

    for _ in range(40):  # originally 143, that's more than we really need
        sock.send_multicast(multicast.HEAD)
        sock.send_broadcast(broadcast.HEAD)

    for _ in range(10):  # originally 30, again, more than necessary
        sock.send_multicast(multicast.HEAD)
        sock.send_multicast(multicast_body)
        sock.send_broadcast(broadcast_body)


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Entry point for CLI users."""
    logging.basicConfig(
        format="%(asctime)-15s %(name)s %(levelname)-8s %(message)s",
        level=logging.INFO,
    )
    options = parse_args(argv)

    logger.info("Put the device in EZ config mode (LED should blink fast)")
    logger.info("Sending SSID       %s", options.ssid)
    logger.info("Sending Password   %s", options.password)
    logger.info("Sending Region     %s", options.region)
    logger.info("Sending Token      %s", options.token)
    logger.info("Sending Secret     %s", options.secret)

    for attempt in range(1, ATTEMPTS):
        logger.info("Attempting SmartConfig, attempt %d/%d", attempt, ATTEMPTS)
        smartconfig(
            options.bind_address,
            (
                options.password,
                options.ssid,
                options.region,
                options.token,
                options.secret,
            ),
        )
        logger.info("SmartConfig completed.")
        logger.info("Auto retry in 3s...")
        time.sleep(3)


if __name__ == "__main__":
    main()
