#!/usr/bin/env python3
"""Tuya MQTT wire protocol implementation."""

# Copyright (c) 2018 VTRUST
# Copyright (c) 2019-2020 Colin Kuebler
# Copyright (c) 2020 Faidon Liambotis
# SPDX-License-Identifier: MIT

import argparse
import base64
import binascii
import hashlib
import json
import logging
import time
from typing import (
    Optional,
    Sequence,
)

import paho.mqtt.publish as publish_mqtt  # type: ignore

from smarthack.util import decrypt, encrypt


logger = logging.getLogger("smarthack-mqtt")  # pylint: disable=invalid-name


def wire_format(data: bytes, key: bytes, protocol: str) -> bytes:
    """Encrypt data + checksum + timestamp using a per-protocol variant."""
    encrypted_data = encrypt(data, key)
    if protocol == "2.1":
        b64_data = base64.b64encode(encrypted_data)
        signature = b"data=" + b64_data + b"||pv=" + protocol.encode() + b"||" + key
        partial_hash = hashlib.md5(signature).hexdigest()[8:24]
        wire_data = protocol.encode() + partial_hash.encode() + b64_data
    else:
        timestamp = b"%08d" % ((int(time.time() * 100) % 100000000))
        timestamped_data = timestamp + encrypted_data
        crc = binascii.crc32(timestamped_data).to_bytes(4, byteorder="big")
        wire_data = protocol.encode() + crc + timestamped_data

    return wire_data


def wire_unformat(data: bytes, key: bytes) -> bytes:
    """Decrypt cleartext data from a per-protocol data string."""
    data_clear = decrypt(base64.b64decode(data[19:]), key)
    return data_clear


def prepare_message(device_id: str, key: str, protocol: str) -> bytes:
    """Prepare a wire protocol encrypted/hashed/checksumed JSON string."""
    message = {
        "data": {"gwId": device_id},
        "protocol": 15,
        "s": 1523715,
        "t": int(time.time()),
    }
    if protocol != "2.1":
        message["s"] = str(message["s"])
        message["t"] = str(message["t"])

    json_message = json.dumps(message, separators=(",", ":"))
    logger.debug("Message '%s' (protocol %s)", json_message, protocol)

    wire_message = wire_format(json_message.encode(), key.encode(), protocol)
    logger.debug("Wire-formatted as %s", wire_message)

    return wire_message


def publish_message(broker: str, device_id: str, message: bytes) -> None:
    """Publish a message for device_id to the MQTT broker."""
    topic = "smart/device/in/%s" % device_id
    logger.info("Publishing message to topic %s", topic)
    publish_mqtt.single(topic, message, hostname=broker)


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    """Parse and return the parsed command line arguments."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    def check_length_ten(value: str) -> str:
        if len(value) < 10:
            raise argparse.ArgumentTypeError("should be > 10 characters")
        return value

    parser.add_argument(
        "-i",
        "--deviceID",
        dest="device_id",
        required=True,
        type=check_length_ten,
        help="Device ID",
    )
    parser.add_argument(
        "-l",
        "--localKey",
        dest="local_key",
        default="0000000000000000",
        type=check_length_ten,
        help="Local key",
    )
    parser.add_argument(
        "-b",
        "--broker",
        dest="broker",
        default="127.0.0.1",
        help="Address of the MQTT broker",
    )
    parser.add_argument(
        "-p",
        "--protocol",
        dest="protocol",
        choices=("2.1", "2.2"),
        default="2.1",
        help="Protocol version",
    )

    return parser.parse_args(argv)


def send_message(broker: str, device_id: str, key: str, protocol: str) -> None:
    """Prepare and publish a message for a device to the MQTT broker.

    Main entry point for external users.
    """
    message = prepare_message(device_id, key, protocol)
    publish_message(broker, device_id, message)


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Entry point for CLI users."""
    logging.basicConfig(
        format="%(asctime)-15s %(name)s %(levelname)-8s %(message)s",
        level=logging.INFO,
    )
    options = parse_args(argv)
    send_message(options.broker, options.device_id, options.local_key, options.protocol)


if __name__ == "__main__":
    main()
