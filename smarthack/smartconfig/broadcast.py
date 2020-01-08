#!/usr/bin/env python3
"""Encode data for Tuya smartconfig via broadcast."""

# Created by kueblc on 2019-01-25.
# Broadcast strategy ported from https://github.com/tuyapi/link

# Copyright (c) 2019-2020 Colin Kuebler
# Copyright (c) 2020 Faidon Liambotis
# SPDX-License-Identifier: MIT

from typing import List

from smarthack.util import crc8


def frame(data: bytes) -> List[int]:
    """Frame (and possibly encrypt a payload); include a checksum."""
    output = []

    length = len(data)
    output.append(length >> 4 | 16)
    output.append(length & 0xF | 32)

    length_crc = crc8(bytes([length % 256]))
    output.append(length_crc >> 4 | 48)
    output.append(length_crc & 0xF | 64)

    sequence = 0
    for i in range(0, length, 4):
        group = bytearray()
        group.append(sequence)
        group.extend(data[i : i + 4])
        group.extend([0] * (5 - len(group)))
        group_crc = crc8(group)

        output.append(group_crc & 0x7F | 128)
        output.append(sequence | 128)
        output.extend([b | 256 for b in data[i : i + 4]])
        sequence += 1
    output.extend([256] * (length - i))

    return output


def encode_network(password: str, ssid: str, token_group: str) -> List[int]:
    """Encode data for the specified network, and return to a list of gaps (ints)."""
    data = bytearray()

    data.append(len(password))
    data.extend(password.encode())

    data.append(len(token_group))
    data.extend(token_group.encode())

    data.extend(ssid.encode())

    return frame(data)


HEAD = [1, 3, 6, 10]
