#!/usr/bin/env python3
"""Miscellaneous utilities functions used by other modules."""

# Copyright (c) 2019-2020 Colin Kuebler
# Copyright (c) 2020 Faidon Liambotis
# SPDX-License-Identifier: MIT

from Cryptodome.Cipher import AES


def pad(data: bytes) -> bytes:
    """Pad a string to 16 characters."""
    return data + (16 - len(data) % 16) * bytes([16 - len(data) % 16])


def unpad(data: bytes) -> bytes:
    """Unpad a previously padded string."""
    return data[: -ord(data[len(data) - 1 :])]


def encrypt(clear_data: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-ECB with the supplied key."""
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(clear_data)
    return cipher.encrypt(padded_data)


def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-ECB with the supplied key."""
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = cipher.decrypt(encrypted_data)
    return unpad(padded_data)


def crc8(data: bytes) -> int:
    """Calculate the CRC8 checksum for data.

    The inner loop calculates the CRC8 polynomial x⁸+x⁵+x⁴+1.
    """
    crc = 0
    for byte in data:
        for _ in range(8):
            if (crc ^ byte) & 0x01:
                crc = ((crc ^ 0x18) >> 1) | 0x80
            else:
                crc >>= 1
            byte >>= 1
    return crc
