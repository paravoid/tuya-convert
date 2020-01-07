#!/usr/bin/env python3
"""Test the smarthack.discovery module."""

# Copyright (c) 2020 Faidon Liambotis
# SPDX-License-Identifier: MIT

import json
import logging
from typing import Any

from smarthack.discovery import TuyaDiscovery, TuyaEncryptedDiscovery

DUMMY_DATA = {
    "ip": "10.42.42.14",
    "gwId": "220388844c11ae0dd558",
    "active": 2,
    "ability": 0,
    "mode": 0,
    "encrypt": True,
    "productKey": "RN2FVAgXG6WfAktU",
    "version": "3.3",
}
DUMMY_JSON = json.dumps(DUMMY_DATA)
ENCRYPTED_DUMMY_JSON = bytes.fromhex(
    "415def5dd070e9aeb8e9e533e5375ffa4ba2680192d4"
    + "f6b381547fd0e3900b52148d7ecaa398b9298731deb8"
    + "e2ed33e612c45198dcd3c617a5271b12c588b66a98b5"
    + "a7135018ddfa3ca88c5b6c41188dd48182ba55c1c346"
    + "99c5942905fd52a0f24d14479cf7a3dd4cb43d0f842d"
    + "0ddc100f4624753c0f126f24c544414cae28f814bd80"
    + "77544a44fd89391ba4daed3d18febaf9be838a361895"
    + "d51d2451d6852dd3a795424f2879a4492a51a7d90f07"
)


def test_discovery_cleartext(caplog: Any) -> None:
    """Test the receipt of cleartext discovery packets."""
    caplog.set_level(logging.INFO)
    addr = ("127.0.0.1", 65535)
    packet = b"0" * 20 + DUMMY_JSON.encode() + b"0" * 8

    TuyaDiscovery().datagram_received(packet, addr)
    assert "product key RN2FVAgXG6WfAktU" in caplog.text


def test_discovery_encrypted(caplog: Any) -> None:
    """Test the receipt of encrypted discovery packets."""
    caplog.set_level(logging.INFO)
    addr = ("127.0.0.1", 65535)
    packet = b"0" * 20 + ENCRYPTED_DUMMY_JSON + b"0" * 8

    TuyaEncryptedDiscovery().datagram_received(packet, addr)
    assert "product key RN2FVAgXG6WfAktU" in caplog.text


def test_discovery_invalid(caplog: Any) -> None:
    """Test the receipt of invalid discovery packets."""
    caplog.set_level(logging.INFO)

    addr = ("127.0.0.1", 65535)
    for packet in [b"", b"\x80", b"0" * 28, b"0" * 20 + b"garbage" + b"0" * 8]:
        caplog.clear()
        TuyaDiscovery().datagram_received(packet, addr)
        assert "could not parse" in caplog.text
        caplog.clear()
        TuyaEncryptedDiscovery().datagram_received(packet, addr)
        assert "could not decrypt" in caplog.text
