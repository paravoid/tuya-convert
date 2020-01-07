#!/usr/bin/env python3
"""Test the smarthack.mqtt module."""

# Copyright (c) 2020 Faidon Liambotis
# SPDX-License-Identifier: MIT

import datetime
import time
from typing import Any

from smarthack.mqtt import prepare_message, wire_format, wire_unformat


FIXED_TIME = datetime.datetime(2020, 1, 1, 0, 0, 0, 0, datetime.timezone.utc)
KEY = b"k" * 16  # random key
PRECOMPUTED_21 = (
    (b"", b"2.1f60982e36ae45003ET+owGzMcMRnHMCdHyZ81Q=="),
    (b"foobar", b"2.14fe6da8264c3ffb2+C3QVjwIa4QPbzfpz7qFGw=="),
)
PRECOMPUTED_22 = (
    (b"", b"2.2\x8cH\xf6\xc983680000\x11?\xa8\xc0l\xccp\xc4g\x1c\xc0\x9d\x1f&|\xd5"),
    (b"foobar", b"2.2(\xb6hg83680000\xf8-\xd0V<\x08k\x84\x0fo7\xe9\xcf\xba\x85\x1b"),
)
# pylint: disable=bad-continuation
PRECOMPUTED_MESSAGE = {
    "2.1": b"2.1a41802d787391e8eMT2UIXuzcBLQqUSz7cH+YEh2N+GD8x4hS2lCWbUP1cruE"
    + b"lURyMXmlDLL+s6k3C2L9HUSfLcAzFe6ymn6Bos18E67cERGFvN3ZyOQAMPDFT0=",
    "2.2": b"2.2\xbd\xbc\x6e\xac\x38\x33\x36\x38\x30\x30\x30\x30\x31\x3d"
    + b"\x94\x21\x7b\xb3\x70\x12\xd0\xa9\x44\xb3\xed\xc1\xfe\x60\x48\x76"
    + b"\x37\xe1\x83\xf3\x1e\x21\x4b\x69\x42\x59\xb5\x0f\xd5\xca\xee\x12"
    + b"\x55\x11\xc8\xc5\xe6\x94\x32\xcb\xfa\xce\xa4\xdc\x2d\x8b\xff\xd8"
    + b"\x92\xa3\x41\x58\x22\x74\x1b\xbc\xe6\x81\x67\x0e\x99\x44\x29\xc7"
    + b"\xaa\xc9\x85\x3e\x40\xa6\x93\x28\x20\x2c\x84\x7f\xb1\xca",
}


def test_wire_format_v21() -> None:
    """Test the wire_format() method against a set of precomputed values (v2.1)."""
    for clear, encoded in PRECOMPUTED_21:
        assert wire_format(clear, KEY, "2.1") == encoded


def test_wire_format_v22(monkeypatch: Any) -> None:
    """Test the wire_format() method against a set of precomputed values (v2.2)."""
    with monkeypatch.context() as mpatch:
        mpatch.setattr(time, "time", FIXED_TIME.timestamp)
        for clear, encoded in PRECOMPUTED_22:
            assert wire_format(clear, KEY, "2.2") == encoded


def test_wire_unformat() -> None:
    """Test the wire_unformat() method against a set of precomputed values."""
    for clear, encoded in PRECOMPUTED_21:
        assert wire_unformat(encoded, KEY) == clear


def test_prepared_message(monkeypatch: Any) -> None:
    """Test the prepare_message() method against a set of precomputed values."""
    device_id = "0123456789"
    local_key = "abcdefghijklmnop"
    with monkeypatch.context() as mpatch:
        mpatch.setattr(time, "time", FIXED_TIME.timestamp)
        for protocol, message in PRECOMPUTED_MESSAGE.items():
            assert prepare_message(device_id, local_key, protocol) == message
