import time
from twisted.conch import avatar, interfaces
from twisted.conch.ssh import factory, userauth, connection, keys, session
from twisted.cred import portal, credentials, error
from twisted.internet import reactor, defer
from zope.interface import implementer
from twisted.conch.ssh.transport import SSHServerTransport
from twisted.python import log
from datetime import datetime
import os

LOG_DIR = "/var/log/honeypot_logs"
LOG_FILE = f"{LOG_DIR}/fake_ssh_logs"

os.makedirs(LOG_DIR, exist_ok=True)
log.startLogging(open(LOG_FILE, "a"))
# =========================
# Configuration
# =========================
AUTH_DELAY_SECONDS = 4   # artificial delay per attempt
SSH_PORT = 22         
HOST_KEY_FILE = "ssh_host_key"

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
        timestamp = datetime.utcnow().isoformat()
        log.msg(f"[{timestamp}] Login attempt: {username} : {password}")


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
        timestamp = datetime.utcnow().isoformat()

        log.msg(
            f"[{timestamp}] SSH connection started from "
            f"{peer.host}:{peer.port}"
        )

        super().connectionMade()

    def getService(self, service):
        if service == b'ssh-userauth':
            return LoggingSSHUserAuth
        return super().getService(service)


class FakeSSHFactory(factory.SSHFactory):
    protocol = LoggingSSHTransport
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
print(f"[+] Fake SSH server listening on port {SSH_PORT}")
reactor.listenTCP(SSH_PORT, FakeSSHFactory())
reactor.run()
