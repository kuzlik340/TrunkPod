import time
from twisted.conch import avatar, interfaces
from twisted.conch.ssh import factory, userauth, connection, keys, session, transport
from twisted.cred import portal, credentials, error
from twisted.internet import reactor, defer
from zope.interface import implementer
from twisted.python import log
from datetime import datetime
import os
import sys


# =========================
# Configuration
# =========================
port = 22
name = "honeypot"
if len(sys.argv) >= 3:
    port = int(sys.argv[1])
    name = sys.argv[2]
AUTH_DELAY_SECONDS = 4   # artificial delay per attempt
SSH_PORT = port         
HOST_KEY_FILE = "/app/ssh_host_key"
os.makedirs("/app", exist_ok=True)
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

try:
    open(HOST_KEY_FILE)
except FileNotFoundError:
    print("[*] Generating SSH host key")
    generate_host_key()

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

# =========================
# Credential Checker
# =========================
@implementer(portal.ICredentialsChecker)
class RejectAllPasswords:
    credentialInterfaces = (credentials.IUsernamePassword,)

    def requestAvatarId(self, creds):
        username = creds.username.decode(errors="ignore")
        password = creds.password.decode(errors="ignore")
        message = (f"[!] Login attempt: {username} : {password}")
        print(f"[HoneyBridge][{name}][FAKE_SSH] Login attempt: {username} : {password}")


        d = defer.Deferred()

        # Delay AND reject correctly
        def reject():
            d.errback(error.UnauthorizedLogin("Invalid password"))

        reactor.callLater(4, reject)
        return d

# =========================
# SSH Factory
# =========================
# class LoggingSSHTransport(SSHServerTransport):
#     def connectionMade(self):
#         peer = self.transport.getPeer()

#         print(
#             f"[HoneyBridge][{name}][FAKE_SSH] SSH connection try from "
#             f"{peer.host}:{peer.port}"
#         )
#         self.ourVersionString = b"SSH-2.0-OpenSSH_8.9p1 Debian-1"
#         super().connectionMade()

#     def getService(self, service):
#         if service == b'ssh-userauth':
#             return LoggingSSHUserAuth
#         return super().getService(service)

class BannerOnlyTransport(transport.SSHServerTransport):
    def connectionMade(self):
        peer = self.transport.getPeer()
        print(
            f"[HoneyBridge][{name}][FAKE_SSH] SSH connection try from "
            f"{peer.host}:{peer.port}"
        )

        # Just send an OpenSSH-like banner, no immediate KEX
        self.ourVersionString = b"SSH-2.0-OpenSSH_8.9p1 Debian-1"
        self.transport.write(self.ourVersionString + b"\r\n")

        # Disable normal key exchange startup
        self.currentEncryptions = transport.SSHCiphers(
            b'none', b'none', b'none', b'none'
        )
        self.currentEncryptions.setKeys(b'', b'', b'', b'', b'', b'')

    def dataReceived(self, data):
        # Log any incoming data
        print(f"[HoneyBridge][{name}][FAKE_SSH] Manual connection (probably via nc): {data!r}")

        # Close with a proper SSH DISCONNECT message instead of crashing
        self.sendDisconnect(
            transport.DISCONNECT_PROTOCOL_ERROR,
            b"Invalid SSH identification string."
        )

class FakeSSHFactory(factory.SSHFactory):
    protocol = BannerOnlyTransport
    def __init__(self):
        self.portal = portal.Portal(FakeRealm())
        self.portal.registerChecker(RejectAllPasswords())

    def getPublicKeys(self):
        return {
            b"ssh-rsa": keys.Key.fromFile(HOST_KEY_FILE).public()
        }

    def getPrivateKeys(self):
        return {
            b"ssh-rsa": keys.Key.fromFile(HOST_KEY_FILE)
        }

# =========================
# Start Server
# =========================
print(f"[HoneyBridge][{name}][FAKE_SSH] Service running on port {SSH_PORT}, just an info message")
reactor.listenTCP(SSH_PORT, FakeSSHFactory())
reactor.run()
