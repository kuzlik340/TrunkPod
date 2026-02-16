import time
from twisted.conch import avatar, interfaces
from twisted.conch.ssh import factory, userauth, connection, keys, session, transport
from twisted.cred import portal, credentials, error
from twisted.internet import reactor, defer
from zope.interface import implementer
from twisted.python import log
from datetime import datetime
from twisted.conch.ssh.transport import SSHServerTransport
import os
import sys
import struct

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
class LoggingSSHTransport(SSHServerTransport):
    def connectionMade(self):
        peer = self.transport.getPeer()

        print(
            f"[HoneyBridge][{name}][FAKE_SSH] SSH connection try from "
            f"{peer.host}:{peer.port}"
        )
        self.ourVersionString = b"SSH-2.0-OpenSSH_8.9p1 Debian-1"
        super().connectionMade()

    def getService(self, service):
        if service == b'ssh-userauth':
            return LoggingSSHUserAuth
        return super().getService(service)

    def ssh_KEXINIT(self, packet):
        # packet format:
        # byte      SSH_MSG_KEXINIT (20)
        # byte[16]  cookie
        # then 10 name-lists

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

        print(f"[SSH] KEX: {kex}")
        print(f"[SSH] HostKey: {hostkey}")
        print(f"[SSH] C2S Enc: {c2s_enc}")
        print(f"[SSH] S2C Enc: {s2c_enc}")
        print(f"[SSH] C2S MAC: {c2s_mac}")
        print(f"[SSH] S2C MAC: {s2c_mac}")
        print(f"[SSH] Compression: {c2s_comp}")

        # Now let Twisted continue normally
        return super().ssh_KEXINIT(packet)
        

class FakeSSHFactory(factory.SSHFactory):
    protocol = LoggingSSHTransport
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


# =========================
# Start Server
# =========================
print(f"[HoneyBridge][{name}][FAKE_SSH] Service running on port {SSH_PORT}, just an info message")
reactor.listenTCP(SSH_PORT, FakeSSHFactory())
reactor.run()
