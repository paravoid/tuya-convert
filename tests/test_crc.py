#!/usr/bin/env python3
"""Test the CRC functions."""

# Copyright (c) 2020 Faidon Liambotis
# SPDX-License-Identifier: MIT

from binascii import crc32
from typing import (
    Sequence,
    Tuple,
)

from smarthack.util import crc8


PRECOMPUTED: Sequence[Tuple[bytes, int, str]] = [
    # (<data>, <crc8>, <crc32>)
    (b"", 0, "00000000"),
    (b"\x00", 0, "8def02d2"),
    (b"0", 190, "21dfdbf4"),
    (b"\x80", 140, "ad6cba3f"),
    (b"foobar", 53, "951ff69e"),
    (b"foobar" * 1024, 72, "e65db3fd"),
]


def test_crc8() -> None:
    """Test the CRC-8 method against a set of precomputed values."""
    for data, checksum8, _ in PRECOMPUTED:
        assert crc8(data) == checksum8


def test_crc32() -> None:
    """Test the CRC-32 method against a set of precomputed values."""
    for data, _, checksum32 in PRECOMPUTED:
        # this is a weird way of packing to little-endian, but this is how it's
        # currently being used in the callsites in the tree
        crc = [(crc32(data) >> i) & 255 for i in range(0, 32, 8)]
        assert bytearray(crc).hex() == checksum32
