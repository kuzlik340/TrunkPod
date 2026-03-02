#!/usr/bin/env python3
"""
TrunkPod - Telnet Honeypot
Mimics a real Linux telnetd to capture attacker credentials and commands.
"""

import sys
import logging

from twisted.internet import reactor, protocol
from twisted.conch.telnet import TelnetProtocol, TelnetTransport
from json_formatter import JSONFormatter
import honeytokens

# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────

AUTH_DELAY_SECONDS = 4 # To make brute-foce for client slow as hell

# IAC negotiation bytes — sent in the same order as real Linux telnetd
# so nmap and other scanners fingerprint this as a genuine telnet service
IAC_HANDSHAKE = (
    b"\xff\xfb\x01"   # IAC WILL ECHO  — server controls echo
    b"\xff\xfb\x03"   # IAC WILL SGA   — suppress go-ahead
    b"\xff\xfd\x01"   # IAC DO ECHO    — ask client to echo
    b"\xff\xfd\x03"   # IAC DO SGA     — ask client to suppress go-ahead
)

BANNER = (
    b"\r\n"
    b"Debian GNU/Linux 11 ttyS0\r\n"
    b"\r\n"
    b"login: "
)

def build_logger(name: str, log_file: str, dst_ip: str, dst_port: int) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.FileHandler(log_file, mode="a")
    handler.setFormatter(JSONFormatter(dst_ip, dst_port, "TELNET"))
    logger.addHandler(handler)

    return logger


# ─────────────────────────────────────────────
#  Protocol
# ─────────────────────────────────────────────

class HoneypotProtocol(TelnetProtocol):
    """
    Fake telnet login shell.
    Captures username + password, always returns 'Login incorrect',
    then resets and waits for the next attempt.
    """

    def __init__(self, logger: logging.Logger):
        self.logger   = logger
        self.username = None
        self.password = None

    # ── connection lifecycle ──────────────────

    def connectionMade(self):
        peer = self.transport.getPeer()
        self.logger.warning("Connection opened", extra={
            "src_ip_addr": peer.host,
            "src_port"   : peer.port,
        })

        # Bypass TelnetTransport to write raw bytes — prevents double-escaping of 0xFF
        self._raw_write(IAC_HANDSHAKE + BANNER)

    def connectionLost(self, reason):
        peer = self.transport.getPeer()
        self.logger.warning("Connection closed", extra={
            "src_ip_addr": peer.host,
            "src_port"   : peer.port,
        })

    # ── data handling ─────────────────────────

    def dataReceived(self, data: bytes):
        data = self._strip_iac(data)
        text = data.strip().decode(errors="ignore")

        if not text:
            return

        peer = self.transport.getPeer()

        if self.username is None:
            self._handle_username(text, peer)

        elif self.password is None:
            self._handle_password(text, peer)

        else:
            self._handle_command(text, peer)

    def _handle_username(self, text: str, peer):
        self.username = text
        self._raw_write(b"\rPassword: ")

    def _handle_password(self, text: str, peer):
        self.password = text
        if honeytokens.is_honeytoken(self.username, self.password):
            key = honeytokens.get_fake_key(self.username, self.password)
            self.logger.critical(f"Found honeytoken. Some machine is compromised, key: {key}, user {self.username}, password {self.password}",
            extra={
                "src_ip_addr": peer.host,
                "src_port": peer.port,
            },)
        else:
            self.logger.warning(
                f"Login attempt: {self.username}:{self.password}",
                extra={
                    "src_ip_addr": peer.host,
                    "src_port": peer.port,
                },
            )

        reactor.callLater(AUTH_DELAY_SECONDS, self._finish_login)

    def _handle_command(self, text: str, peer):
        self.logger.warning(f"Command: {text}", extra={
            "src_ip_addr": peer.host,
            "src_port"   : peer.port,
        })
        self._raw_write(f"\r\n-bash: {text}: command not found\r\n$ ".encode())

    def _finish_login(self):
        self._raw_write(b"\rLogin incorrect\r\nlogin: ")
        self.username = None
        self.password = None

    # ── helpers ───────────────────────────────

    def _raw_write(self, data: bytes):
        """Write directly to the TCP socket, bypassing Twisted's telnet encoding."""
        self.transport.transport.write(data)

    @staticmethod
    def _strip_iac(data: bytes) -> bytes:
        """Strip IAC negotiation sequences returned by the client."""
        result = bytearray()
        i = 0
        while i < len(data):
            if data[i] == 0xFF:  # IAC byte
                i += 3 if (i + 2 < len(data)) else 1
            else:
                result.append(data[i])
                i += 1
        return bytes(result)


# ─────────────────────────────────────────────
#  Factory
# ─────────────────────────────────────────────

class HoneypotFactory(protocol.Factory):
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def buildProtocol(self, addr):
        return TelnetTransport(HoneypotProtocol, self.logger)


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────

def parse_args() -> tuple[int, str, str]:
    """Returns (port, name, dst_ip)."""
    if len(sys.argv) >= 4:
        return int(sys.argv[1]), sys.argv[2], sys.argv[3]
    return 23, "honeypot", "0.0.0.0"


def main():
    honeytokens.load("/honeytokens/tokens.json")
    port, name, dst_ip = parse_args()
    log_file = f"/log/telnet{port}.log"

    logger = build_logger(name, log_file, dst_ip, port)
    logger.info(f"Service TELNET running on port {port}, just an info message")

    factory = HoneypotFactory(logger)
    reactor.listenTCP(port, factory)

    print(f"Nothing to see here. All logs are accessible on host in /var/log/trunkpod, thank me later :)")

    reactor.run()


if __name__ == "__main__":
    main()