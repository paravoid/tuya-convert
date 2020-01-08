#!/usr/bin/env python3
"""Encode data for Tuya smartconfig via multicast."""

# Created by kueblc on 2019-01-25.
# Multicast strategy reverse engineered by kueblc

# Copyright (c) 2019-2020 Colin Kuebler
# Copyright (c) 2020 Faidon Liambotis
# SPDX-License-Identifier: MIT

import binascii
from typing import List

from Cryptodome.Cipher import AES

MAGIC_AES_KEY = b"a3c6794oiu876t54"


def frame(data: bytes, encrypt: bool = False) -> bytearray:
    """Frame (and possibly encrypt) a payload; include a checksum."""
    output = bytearray()
    crc = binascii.crc32(data)

    # length, twice
    output.append(len(data))
    output.append(len(data))

    # CRC, as little-endian
    output.extend(crc.to_bytes(4, "little"))

    if not encrypt:
        # payload, plaintext
        output.extend(data)
    else:
        # payload, AES encrypted
        padded_data = data + b"\0" * ((16 - len(data)) % 16)
        cipher = AES.new(MAGIC_AES_KEY, AES.MODE_ECB)
        encrypted_pw = cipher.encrypt(padded_data)
        output.extend(encrypted_pw)
    return output


def bytes_to_ips(data: bytearray, sequence: int) -> List[str]:
    """Encode a little-endian bytearray into a list of multicast IPv4 addresses."""
    output = []
    if len(data) & 1:
        data.append(0)

    # split data into segments of 2-byte characters
    for i in range(0, len(data), 2):
        output.append(
            "226." + str(sequence) + "." + str(data[i + 1]) + "." + str(data[i])
        )
        sequence += 1

    return output


def encode_network(password: str, ssid: str, token_group: str) -> List[str]:
    """Encode data for the specified network, and return to a list of IPv4 addresses."""
    output = []

    ssid_encoded = frame(ssid.encode())
    output.extend(bytes_to_ips(ssid_encoded, 64))

    password_encoded = frame(password.encode(), encrypt=True)
    output.extend(bytes_to_ips(password_encoded, 0))

    token_group_encoded = frame(token_group.encode())
    output.extend(bytes_to_ips(token_group_encoded, 32))

    return output


HEAD = bytes_to_ips(bytearray(b"TYST01"), 120)
