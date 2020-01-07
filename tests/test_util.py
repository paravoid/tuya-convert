#!/usr/bin/env python3
"""Test the smarthack.util module."""

# Copyright (c) 2020 Faidon Liambotis
# SPDX-License-Identifier: MIT

from smarthack.util import decrypt, encrypt


KEY = bytearray(range(116, 116 + 16))  # random key
PRECOMPUTED = (
    (b"", "0b327b8802ae5d241f5f6b8d211430f5"),
    (b"0", "1f3ff4f95b04acd96d5c4723b4f0ebf0"),
    (b"\x80", "8e365eff349dd2e0b700d4291989005a"),
    (b"0" * 16, "1de2134cc4bdd1f8587c73c5631aaad40b327b8802ae5d241f5f6b8d211430f5"),
    (b"foobar", "d610f534b22fa8707ec1b86752e8ae96"),
)


def test_encrypt() -> None:
    """Test the encrypt() method against a set of precomputed keys."""
    for clear, encrypted in PRECOMPUTED:
        assert encrypt(clear, KEY).hex() == encrypted


def test_decrypt() -> None:
    """Test the decrypt() method against a set of precomputed keys."""
    for clear, encrypted in PRECOMPUTED:
        assert decrypt(bytes.fromhex(encrypted), KEY) == clear
