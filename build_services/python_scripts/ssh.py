import time
from twisted.conch import avatar, interfaces
from twisted.conch.ssh import factory, userauth, connection, keys, session, transport
from twisted.cred import portal, credentials, error
from twisted.internet import reactor, defer
from zope.interface import implementer
from twisted.python import log
from twisted.conch.ssh.transport import SSHServerTransport
import os
import sys
import struct
import logging

import honeytokens
from json_formatter import JSONFormatter

HOST_KEY_FILE = "/ssh/ssh_host_key"
AUTH_DELAY_SECONDS = 4   # To make brute-foce for client slow as hell 

# =========================
# Configuration
# =========================

def build_logger(name: str, log_file: str, dst_ip: str, dst_port: int) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.FileHandler(log_file, mode="a")
    handler.setFormatter(JSONFormatter(dst_ip, dst_port, "SSH"))
    logger.addHandler(handler)

    return logger

# =========================
# Generate host key once
# =========================
def generate_host_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(HOST_KEY_FILE, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

# =========================
# Fake Avatar
# =========================
@implementer(interfaces.IConchUser)
class FakeAvatar:
    def __init__(self, username):
        self.username = username
        self.channelLookup = {}
        self.subsystemLookup = {}

    def logout(self):
        pass

# =========================
# Realm
# =========================
class FakeRealm:
    def requestAvatar(self, avatarId, mind, *interfaces):
        return interfaces[0], FakeAvatar(avatarId), lambda: None


class LoggingSSHUserAuth(userauth.SSHUserAuthServer):

    def ssh_USERAUTH_REQUEST(self, packet):
        from twisted.conch.ssh.common import getNS

        user, rest = getNS(packet)
        service, rest = getNS(rest)
        method, rest = getNS(rest)

        if method == b"password":
            # skip "boolean change password"
            rest = rest[1:]
            password, _ = getNS(rest)
            username = user.decode(errors='ignore')
            user_password = password.decode(errors='ignore')
            peer = self.transport.transport.getPeer()
            if honeytokens.is_honeytoken(username, user_password):
                key = honeytokens.get_fake_key(username, user_password)
                logger.critical(f"Found honeytoken. Some machine is compromised, key: {key}, user {username}, password {password}",
                extra={
                    "src_ip_addr": peer.host,
                    "src_port": peer.port,
                },)
            else:
                logger.warning(
                    f"Login attempt: {username}:{user_password}",
                    extra={
                        "src_ip_addr": peer.host,
                        "src_port": peer.port,
                    },
            )

        return super().ssh_USERAUTH_REQUEST(packet)
# =========================
# Credential Checker
# =========================
@implementer(portal.ICredentialsChecker)
class RejectAllPasswords:
    credentialInterfaces = (credentials.IUsernamePassword,)

    def requestAvatarId(self, creds):
        d = defer.Deferred()
        reactor.callLater(AUTH_DELAY_SECONDS,
                          lambda: d.errback(error.UnauthorizedLogin("Invalid password")))
        return d

# =========================
# SSH Factory
# =========================
class LoggingSSHTransport(SSHServerTransport):
    def connectionMade(self):
        peer = self.transport.getPeer()
        self.peer = self.transport.getPeer()
        logger.warning(
            f"SSH connection connect",
            extra={
                "src_ip_addr": peer.host,
                "src_port": peer.port,
            }
        )
        self.ourVersionString = b"SSH-2.0-OpenSSH_8.9p1 Debian-1"
        super().connectionMade()


    def ssh_KEXINIT(self, packet):
        # packet format:
        # byte      SSH_MSG_KEXINIT (20)
        # byte[16]  cookie
        # then 10 name-lists
        peer = self.transport.getPeer()
        payload = packet
        pos = 16  # skip cookie

        def get_namelist():
            nonlocal pos
            length = struct.unpack(">I", payload[pos:pos+4])[0]
            pos += 4
            data = payload[pos:pos+length].decode(errors="ignore")
            pos += length
            return data

        kex = get_namelist()
        hostkey = get_namelist()
        c2s_enc = get_namelist()
        s2c_enc = get_namelist()
        c2s_mac = get_namelist()
        s2c_mac = get_namelist()
        c2s_comp = get_namelist()
        s2c_comp = get_namelist()
        c2s_lang = get_namelist()
        s2c_lang = get_namelist()

        
        logger.warning(
            "SSH Negotiation | "
            f"KEX: {kex} | "
            f"HostKey: {hostkey} | "
            f"C2S Enc: {c2s_enc} | "
            f"S2C Enc: {s2c_enc} | "
            f"C2S MAC: {c2s_mac} | "
            f"S2C MAC: {s2c_mac} | "
            f"Compression: {c2s_comp}",
            extra={
                   "src_ip_addr": peer.host,
                   "src_port" : peer.port,
            },
        )
        # Now let Twisted continue normally
        return super().ssh_KEXINIT(packet)
        

class FakeSSHFactory(factory.SSHFactory):
    protocol = LoggingSSHTransport
    services = {
        b'ssh-userauth': LoggingSSHUserAuth,
        b'ssh-connection': connection.SSHConnection,
    }
    def __init__(self):
        self.portal = portal.Portal(FakeRealm())
        self.portal.registerChecker(RejectAllPasswords())

    def getPublicKeys(self):
        key = keys.Key.fromFile(HOST_KEY_FILE)
        return {
            b"ssh-rsa": key.public(),
            b"rsa-sha2-256": key.public(),
            b"rsa-sha2-512": key.public(),
        }

    def getPrivateKeys(self):
        key = keys.Key.fromFile(HOST_KEY_FILE)
        return {
            b"ssh-rsa": key,
            b"rsa-sha2-256": key,
            b"rsa-sha2-512": key,
        }

def parse_args() -> tuple[int, str, str]:
    """Returns (port, name, dst_ip)."""
    if len(sys.argv) >= 4:
        return int(sys.argv[1]), sys.argv[2], sys.argv[3]
    return 22, "honeypot", "0.0.0.0"

def ensure_host_key():
    """Generate an RSA host key if one doesn't exist yet."""
    if os.path.exists(HOST_KEY_FILE):
        return

    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    logger.info("Generating SSH host key")
    print("[TrunkPod] Generating SSH host key...")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    os.makedirs(os.path.dirname(HOST_KEY_FILE), exist_ok=True)

    with open(HOST_KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

# =========================
# Start Server
# =========================

def main():
    honeytokens.load("/honeytokens/tokens.json")
    port, name, dst_ip = parse_args()

    log_file = f"/log/ssh{port}.log"
    global logger
    logger = build_logger(name, log_file, dst_ip, port) 
    ensure_host_key()   

    logger.info(f"Service SSH running on port {port}, just an info message")
    reactor.listenTCP(port, FakeSSHFactory())
    reactor.run()

if __name__ == "__main__":
    main()