#!/usr/bin/env python3
"""Discover Tuya devices on the LAN via UDP broadcast."""

# Copyright (c) 2019-2020 Colin Kuebler
# Copyright (c) 2020 Faidon Liambotis
# SPDX-License-Identifier: MIT

import asyncio
import hashlib
import json
import logging
from typing import Tuple

from smarthack.util import decrypt

MAGIC_KEY = b"yGAdlopoPVldABfn"
PORT = 6666
ENC_PORT = 6667

logger = logging.getLogger("smarthack-discovery")  # pylint: disable=invalid-name


class TuyaDiscovery(asyncio.DatagramProtocol):
    """Receive and decode Tuya UDP broadcasts, and log about them."""

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):  # type: ignore
        """Receive a datagram and do all the work."""
        data = data[20:-8]  # remove message frame

        try:
            datadict = json.loads(data)
        except json.JSONDecodeError:
            logger.error("Device[%s]: could not parse %s", addr[0], data)
        except Exception:  # pylint: disable=broad-except
            logger.exception("Device[%s]: could not parse %s", addr[0], data)
        else:
            logger.info(
                "Device[%s]: broadcast; product key %s, version %s",
                addr[0],
                datadict["productKey"],
                datadict["version"],
            )
            for key, value in datadict.items():
                logger.debug("Device[%s]: %s=%s", addr[0], key, value)


class TuyaEncryptedDiscovery(TuyaDiscovery):
    """Receive and decode Tuya Encrypted UDP broadcasts, and log about them."""

    udpkey = hashlib.md5(MAGIC_KEY).digest()

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):  # type: ignore
        """Receive a datagram and do all the work."""
        head, body, tail = data[:20], data[20:-8], data[-8:]

        try:
            decrypted_body = decrypt(body, self.udpkey)
            logger.debug("Device[%s]: successfully decrypted data")
        except (ValueError, TypeError):
            logger.error("Device[%s]: could not decrypt %s", addr[0], body)
        except Exception:  # pylint: disable=broad-except
            logger.exception("Device[%s]: could not decrypt %s", addr[0], body)
        else:
            # readd head/tail and pass on to parent class
            data = head + decrypted_body + tail
            super().datagram_received(data, addr)


def main() -> None:
    """Entry point for CLI users."""
    logging.basicConfig(
        format="%(asctime)-15s %(name)s %(levelname)-8s %(message)s",
        level=logging.INFO,
    )

    loop = asyncio.get_event_loop()
    listener = loop.create_datagram_endpoint(
        TuyaDiscovery, local_addr=("0.0.0.0", PORT)
    )
    encrypted_listener = loop.create_datagram_endpoint(
        TuyaEncryptedDiscovery, local_addr=("0.0.0.0", ENC_PORT)
    )
    loop.run_until_complete(listener)
    logger.info("Listening for Tuya broadcast on UDP %s", PORT)
    loop.run_until_complete(encrypted_listener)
    logger.info("Listening for encrypted Tuya broadcast on UDP %s", ENC_PORT)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.stop()


if __name__ == "__main__":
    main()
