from twisted.internet import reactor, protocol
from twisted.conch.telnet import TelnetProtocol, TelnetTransport
import sys
import logging
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "service": "HoneyBridge",
            "component": "FAKE_TELNET",
            "message": record.getMessage(),
        }

        # Add optional fields if present
        if hasattr(record, "src_ip_addr"):
            log_record["src_ip_addr"] = record.src_ip_addr
        if hasattr(record, "src_port"):
            log_record["src_port"] = record.src_port
        return json.dumps(log_record)
        

class HoneypotProtocol(TelnetProtocol):
    def connectionMade(self):
        peer = self.transport.getPeer()
        self.attacker_ip = peer.host
        self.attacker_port = peer.port
        logger.warning("TELNET connection connect", extra={
                "src_ip_addr": peer.host,
                "src_port": peer.port,
        })
        self.transport.write(b"login: ")

    def dataReceived(self, data):
        text = data.strip().decode(errors="ignore")
        peer = self.transport.getPeer()
        self.attacker_ip = peer.host
        self.attacker_port = peer.port

        if not hasattr(self, "username"):
            self.username = text
            self.transport.write(b"Password: ")
        elif not hasattr(self, "password"):
            self.password = text
            logger.warning(f"Login attempt: {self.username}:{self.password}", 
            extra={
                "src_ip_addr": peer.host,
                "src_port": peer.port,
            })
            
            self.transport.write(b"Login incorrect\nlogin: ")
            del self.username
            del self.password
        else:
            logger.warning(f"Command tried: {text}", 
            extra={
                "src_ip_addr": peer.host,
                "src_port": peer.port,
            })
            self.transport.write(b"sh: command not found\n$ ")

class HoneypotFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return TelnetTransport(HoneypotProtocol)

port = 23
name = "honeypot"
if len(sys.argv) >= 3:
    port = int(sys.argv[1])
    name = sys.argv[2]
LOG_FILE = f"/log/fake_telnet{port}.log"

handler = logging.FileHandler(LOG_FILE, mode='a')
handler.setFormatter(JSONFormatter())
logger = logging.getLogger(name)
logger.setLevel(logging.INFO)
logger.addHandler(handler)
logger.propagate = False

reactor.listenTCP(port, HoneypotFactory())
logger.info(f"Service running on port {port}, just an info message")
reactor.run()