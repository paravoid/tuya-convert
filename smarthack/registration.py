#!/usr/bin/env python3
"""Fake registration server for the Tuya API."""

# Copyright (c) 2018 VTRUST
# Copyright (c) 2019-2020 Colin Kuebler
# Copyright (c) 2020 Faidon Liambotis
# SPDX-License-Identifier: MIT


import argparse
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import time
from typing import (
    Any,
    Dict,
    Mapping,
    Optional,
    Sequence,
)

import tornado.web

from smarthack.util import decrypt, encrypt


logger = logging.getLogger("smarthack-registration")  # pylint: disable=invalid-name


UPGRADE_BIN_STATS = {}


def compact_json(obj: Any) -> str:
    """Encode into JSON, but in a more compacted form."""
    return json.dumps(obj, separators=(",", ":"))


def file_hash(filename: str, algorithm: str, key: Optional[str] = None) -> str:
    """Calculate the hash in a given algorithm for a given file.

    Return it in the format appropriate for the firmware (hex digest, when
    appropriate).

    Also handle the algorithm "len" for the file size.
    """
    contents = open(filename, "rb").read()
    if algorithm == "md5":
        return hashlib.md5(contents).hexdigest()
    if algorithm == "sha256":
        return hashlib.sha256(contents).hexdigest().upper()
    if algorithm == "hmac":
        if key is None:
            raise ValueError(f"Algorithm {algorithm} requires a key")
        return (
            hmac.new(key.encode(), file_hash(filename, "sha256").encode(), "sha256",)
            .hexdigest()
            .upper()
        )
    if algorithm == "len":
        # technically not a hash or an algorithm but... good enough
        return str(os.path.getsize(filename))

    raise ValueError("Unknown algorithm")


def update_file_stats(filename: str) -> None:
    """Update UPGRADE_BIN_STATS with algorithmic hashes etc. for upgrade.bin."""
    for algorithm in ("md5", "sha256", "hmac", "len"):
        key = "0000000000000000" if algorithm == "hmac" else None
        value = file_hash(filename, algorithm, key)
        UPGRADE_BIN_STATS[algorithm] = value


class FilesHandler(tornado.web.StaticFileHandler):
    """Handle the files/ path, serving static files."""

    # pylint: disable=abstract-method
    def parse_url_path(self, url_path: str) -> str:
        """Parse the URL path, adding an index page if necessary."""
        if not url_path or url_path.endswith("/"):
            url_path = url_path + str("index.html")
        return url_path


class MainHandler(tornado.web.RequestHandler):
    """Handle the / path, serving a dummy index page."""

    # pylint: disable=abstract-method
    def get(self) -> None:
        """Handle the GET method."""
        self.write("You are connected to the Tuya-convert webserver\n")


class JSONHandler(tornado.web.RequestHandler):
    """Handle the /gw.json path."""

    # pylint: disable=abstract-method
    activated_ids: Dict[str, bool] = {}

    def reply(self, result: Any = None, encrypted: bool = False) -> None:
        """JSON encode, sign and send a response to the client."""
        timestamp = int(time.time())
        key = self.settings["secKey"]

        if encrypted:
            answer = {"result": result, "t": timestamp, "success": True}
            answer_json = compact_json(answer)
            payload = base64.b64encode(
                encrypt(answer_json.encode(), key.encode())
            ).decode()
            signature = "result=%s||t=%d||%s" % (payload, timestamp, key)
            signature = hashlib.md5(signature.encode()).hexdigest()[8:24]
            answer = {"result": payload, "t": timestamp, "sign": signature}
        else:
            answer = {"t": timestamp, "e": False, "success": True}
            if result:
                answer["result"] = result

        answer_json = compact_json(answer)
        self.set_header("Content-Type", "application/json;charset=UTF-8")
        self.set_header("Content-Length", str(len(answer_json)))
        self.set_header("Content-Language", "zh-CN")

        self.write(answer_json)
        logger.debug("Response: %s", answer_json)

    def get(self) -> None:
        """Handle the GET method."""
        self.post()

    def post(self) -> None:
        """Handle the POST method."""
        # pylint: disable=too-many-branches,too-many-statements
        action = str(self.get_argument("a", "0"))
        encrypted = str(self.get_argument("et", "0")) == "1"
        gwId = str(self.get_argument("gwId", "0"))  # pylint: disable=invalid-name
        logger.debug("Action: %s, encrypted: %s, gwId: %s", action, encrypted, gwId)
        logger.debug(self.request.headers)

        key = self.settings["secKey"].encode()
        payload = self.request.body[5:]
        if payload:
            try:
                if b"{" not in payload:
                    # attempt to decrypt
                    decrypted_payload = binascii.unhexlify(payload)
                    decrypted_payload = decrypt(decrypted_payload, key)
                    payload = decrypted_payload
                json.loads(payload)
                logger.info("Payload (decrypted) is %s", payload)
            except binascii.Error:
                logger.info("Payload (unparseable-hex): %s", payload)
                logger.warning("Could not parse, neither JSON nor hex-encoded")
            except json.JSONDecodeError:
                logger.info("Payload (unparseable-json): %s", payload)
                logger.warning("Could not parse payload as JSON")
            except ValueError:
                logger.info("Payload (encrypted): %s", payload)
                logger.warning("Could not decrypt payload")

        if gwId == "0":
            logger.warning(
                "WARNING: it appears this device does not use an ESP82xx"
                " and therefore cannot install ESP based firmware"
            )

        # Activation endpoints
        if action == "s.gw.token.get":
            logger.info("Responding to s.gw.token.get")
            answer = {
                "gwApiUrl": "http://" + self.request.host + "/gw.json",
                "stdTimeZone": "-05:00",
                "mqttRanges": "",
                "timeZone": "-05:00",
                "httpsPSKUrl": "https://" + self.request.host + "/gw.json",
                "mediaMqttUrl": self.request.host,
                "gwMqttUrl": self.request.host,
                "dstIntervals": [],
            }
            if encrypted:
                answer["mqttsUrl"] = self.request.host
                answer["mqttsPSKUrl"] = self.request.host
                answer["mediaMqttsUrl"] = self.request.host
                answer["aispeech"] = self.request.host
            self.reply(answer)

            logger.info("Killing SmartConfig")
            os.system("pkill -f smarthack.smartconfig.smartconfig")

        elif ".active" in action:
            logger.info("Responding to s.gw.dev.pk.active")
            # first try extended schema, otherwise minimal schema
            schema_key_count = 1 if gwId in self.activated_ids else 20
            # record that this gwId has been seen
            self.activated_ids[gwId] = True
            schema = compact_json(
                [{"mode": "rw", "property": {"type": "bool"}, "id": 1, "type": "obj"}]
                * schema_key_count
            )
            answer = {
                "schema": schema,
                "uid": "00000000000000000000",
                "devEtag": "0000000000",
                "secKey": self.settings["secKey"],
                "schemaId": "0000000000",
                "localKey": "0000000000000000",
            }
            self.reply(answer)
            logger.warning("TRIGGERING UPGRADE IN 10 SECONDS")
            protocol = "2.2" if encrypted else "2.1"
            # very ugly and hopefully temporary hacks that I'm not proud for
            os.putenv("PYTHONPATH", os.path.dirname(os.path.abspath(__file__)) + "/..")
            os.system(
                "sleep 10 && python3 -m smarthack.mqtt -i %s -p %s &" % (gwId, protocol)
            )

        # Upgrade endpoints
        elif ".updatestatus" in action:
            logger.info("Responding to s.gw.upgrade.updatestatus")
            self.reply(None, encrypted)

        elif (".upgrade" in action) and encrypted:
            logger.info("Responding to s.gw.upgrade.get")
            answer = {
                "auto": 3,
                "size": UPGRADE_BIN_STATS["len"],
                "type": 0,
                "pskUrl": "http://" + self.request.host + "/files/upgrade.bin",
                "hmac": UPGRADE_BIN_STATS["hmac"],
                "version": "9.0.0",
            }
            self.reply(answer, encrypted)

        elif ".device.upgrade" in action:
            logger.info("Responding to tuya.device.upgrade.get")
            answer = {
                "auto": True,
                "type": 0,
                "size": UPGRADE_BIN_STATS["len"],
                "version": "9.0.0",
                "url": "http://" + self.request.host + "/files/upgrade.bin",
                "md5": UPGRADE_BIN_STATS["md5"],
            }
            self.reply(answer, encrypted)

        elif ".upgrade" in action:
            logger.info("Responding to s.gw.upgrade")
            answer = {
                "auto": 3,
                "fileSize": UPGRADE_BIN_STATS["len"],
                "etag": "0000000000",
                "version": "9.0.0",
                "url": "http://" + self.request.host + "/files/upgrade.bin",
                "md5": UPGRADE_BIN_STATS["md5"],
            }
            self.reply(answer, encrypted)

        # Misc endpoints
        elif ".log" in action:
            logger.info("Responding to atop.online.debug.log")
            answerb = True
            self.reply(answerb, encrypted)

        elif ".timer" in action:
            logger.info("Responding to s.gw.dev.timer.count")
            answer = {"devId": gwId, "count": 0, "lastFetchTime": 0}
            self.reply(answer, encrypted)

        elif ".config.get" in action:
            logger.info("Responding to tuya.device.dynamic.config.get")
            answer = {"validTime": 1800, "time": int(time.time()), "config": {}}
            self.reply(answer, encrypted)

        # Catch-all
        else:
            logger.info("Action %s unseen before; please file a bug report", action)
            self.reply(None, encrypted)


def make_app(settings: Mapping[str, Any]) -> tornado.web.Application:
    """Set up a Tornado web application with its handlers."""
    update_file_stats("files/upgrade.bin")
    return tornado.web.Application(
        [
            (r"/", MainHandler),
            (r"/gw.json", JSONHandler),
            (r"/d.json", JSONHandler),
            ("/files/(.*)", FilesHandler, {"path": "files/"}),
            (r".*", tornado.web.RedirectHandler, {"url": "/", "permanent": False},),
        ],
        **settings,
    )


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    """Parse and return the parsed command line arguments."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--address",
        "--addr",  # compatibility
        dest="address",
        default="127.0.0.1",
        help="Address to listen to",
    )
    parser.add_argument(
        "--port", dest="port", type=int, default=80, help="Port to listen to",
    )
    parser.add_argument(
        "--secKey",
        "--key",
        dest="secKey",
        default="0000000000000000",
        help="Key used for encrypted communication",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Debug mode: log to stdout and be more verbose",
    )

    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Entry point for CLI users."""
    logging.basicConfig(
        format="%(asctime)-15s %(name)-22s %(levelname)-8s %(message)s",
        level=logging.INFO,
    )
    options = parse_args(argv)

    app = make_app(vars(options))
    try:
        app.listen(options.port, options.address)
        logger.info("Listening on %s:%s", options.address, options.port)
        tornado.ioloop.IOLoop.current().start()
    except OSError as err:
        if err.errno == 98:  # EADDRINUSE
            logger.warning(
                "Could not start server on %s:%s: address in use",
                options.address,
                options.port,
            )
            logger.warning("Close the process on this port and try again")
        else:
            logger.warning(
                "Could not start server on %s:%s: %s",
                options.address,
                options.port,
                err,
            )
    except (SystemExit, KeyboardInterrupt):  # pragma: no cover
        logger.info("Shutting down")


if __name__ == "__main__":
    main()
