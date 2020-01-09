#!/usr/bin/env python3
"""Simple TLS PSK proxy."""

# Copyright (c) 2019 Marty Tennison
# Copyright (c) 2019 Colin Kuebler
# Copyright (c) 2020 Faidon Liambotis
# SPDX-License-Identifier: MIT

import argparse
import hashlib
import logging
import select
import socket
import ssl
from typing import (
    List,
    Optional,
    Sequence,
    Tuple,
)

from Cryptodome.Cipher import AES

import sslpsk  # type: ignore


IDENTITY_PREFIX = b"BAohbmd6aG91IFR1"
DEFAULT_HINT = b"1dHRsc2NjbHltbGx3eWh5" b"0000000000000000"


logger = logging.getLogger("smarthack-pskproxy")  # pylint: disable=invalid-name


def gen_psk(identity: bytes, hint: bytes) -> bytes:
    """Generate a PSK for a given identity and hint.

    Called back from sslpsk.wrap_socket().
    """
    logger.info("Generating PSK for identity %s", identity.hex())
    identity = identity[1:]
    if identity[:16] != IDENTITY_PREFIX:
        logger.info("Non-standand identity %s", identity[:16].hex())

    key = hashlib.md5(hint[-16:]).digest()
    iv = hashlib.md5(identity).digest()  # pylint: disable=invalid-name

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        psk = cipher.encrypt(identity[:32])
    except ValueError as exc:
        logger.warning("Unable to generate PSK key: %s", exc)
        raise

    logger.info("Generated PSK %s", psk.hex())
    return psk


class PskProxy:
    """A SSL PSK server instance.

    Represents a socketpair of front (SSL PSK encrypted) and back (cleartext)
    sockets, to pass data from one to another.
    """

    def __init__(self, listen_host: str, listen_port: str, host: str, port: str):
        """Initialize the instance, and set up a listening socket."""
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.backend_host = host
        self.backend_port = int(port)

        self.hint = DEFAULT_HINT
        self.sessions: List[Tuple[socket.socket, socket.socket]] = []
        self.listen_for_connections()

    def listen_for_connections(self) -> None:
        """Set up a socket and listen for new connections."""
        logger.info(
            "[%s:%s] Listening for new connections to proxy to %s:%s",
            self.listen_host,
            self.listen_port,
            self.backend_host,
            self.backend_port,
        )

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.listen_host, self.listen_port))
        self.server_sock.listen(1)

    def new_client(self, client: socket.socket) -> None:
        """Handle a new client."""
        (client_host, client_port) = client.getpeername()
        logger.info(
            "[%s:%s] New connection from %s:%s",
            self.listen_host,
            self.listen_port,
            client_host,
            client_port,
        )
        try:
            # handshake SSL PSK with our client (i.e. front-facing socket)
            front = sslpsk.wrap_socket(
                client,
                server_side=True,
                ssl_version=ssl.PROTOCOL_TLSv1_2,
                ciphers="PSK-AES128-CBC-SHA256",
                psk=lambda identity: gen_psk(identity, self.hint),
                hint=self.hint,
            )
        except ssl.SSLError as exc:
            valid = ("NO_SHARED_CIPHER", "WRONG_VERSION_NUMBER", "WRONG_SSL_VERSION")
            if any([r in exc.reason for r in valid]):
                logger.info(
                    "[%s:%s] Unable to establish SSL PSK (probably your phone/PC)",
                    client_host,
                    client_port,
                )
                logger.debug("[%s:%s] Reason: %s", client_host, client_port, exc.reason)
            else:
                logger.warning(
                    "[%s:%s] Unable to establish SSL PSK: %s",
                    client_host,
                    client_port,
                    exc.reason,
                )
        # also catch SystemError, because sslpsk seems to be raising those instead...
        except SystemError as exc:
            logger.warning(
                "[%s:%s] Unable to establish SSL PSK, unknown error: %s",
                client_host,
                client_port,
                exc,
            )
        else:
            # connect to to the backend
            back = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            back.connect((self.backend_host, self.backend_port))

            # ...and append to a sessions array
            self.sessions.append((front, back))

    def readables(self) -> List[socket.socket]:
        """Return a list of readable fds for the instance.

        Each instance will have (n×2)+1 fds open: a listening socket for new
        connections, plus a front and back for each client.
        """
        readables = [self.server_sock]
        for front, back in self.sessions:
            readables.append(front)
            readables.append(back)
        return readables

    def data_ready_cb(self, sock: socket.socket) -> None:
        """Handle incoming data on a socket.

        Called from select() for every fd that is ready to be read. Gets called
        whether it's one of ours or not.
        """
        if sock == self.server_sock:
            # data on the main server socket
            client_conn, _ = sock.accept()
            self.new_client(client_conn)

        for (front, back) in self.sessions:
            if sock not in (front, back):
                # not us
                continue

            # data on either one of our front or back sockets
            other = front if sock == back else back
            # splice them together
            try:
                buf = sock.recv(4096)
                if len(buf) > 0:
                    other.send(buf)
                else:
                    front.shutdown(socket.SHUT_RDWR)
                    back.shutdown(socket.SHUT_RDWR)
                    self.sessions.remove((front, back))
            except socket.error:
                self.sessions.remove((front, back))


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    """Parse and return the parsed command line arguments."""
    parser = argparse.ArgumentParser()

    def listen_pair(string: str) -> Tuple[str, ...]:
        pair = string.split(":")
        if len(pair) != 4:
            raise argparse.ArgumentTypeError(f"{string} not a valid listen pair")
        return tuple(pair)

    parser.add_argument(
        "listen_pairs",
        help="Proxy instance to configure, format: listen_host:listen_port:host:port",
        type=listen_pair,
        nargs="+",
    )

    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Entry point for PSK proxy.

    Parses command-line arguments, sets up listening sockets
    and loops over incoming data on sockets using select().
    """
    logging.basicConfig(
        format="%(asctime)-15s %(name)s %(levelname)-8s %(message)s",
        level=logging.INFO,
    )
    options = parse_args(argv)
    proxies = [PskProxy(*pair) for pair in options.listen_pairs]

    while True:
        readables: List[socket.socket] = []
        for proxy in proxies:
            readables.extend(proxy.readables())

        rlist, _, _ = select.select(readables, [], [])
        for sock in rlist:
            for proxy in proxies:
                proxy.data_ready_cb(sock)


if __name__ == "__main__":
    main()
