from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
import os
import time
from datetime import datetime
import logging
import json

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Login Required</title>
    <style>
        body { font-family: Arial; background:#f2f2f2; }
        .box {
            margin: 100px auto;
            width: 300px; padding: 20px;
            background: white; border-radius: 8px;
            box-shadow: 0px 0px 10px rgba(0,0,0,0.1);
            box-sizing: border-box;
        }
        input { width: 100%; padding: 10px; margin-top: 10px; }
        button { width: 100%; padding: 10px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>Login</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""
name = "honeypot"
port = 9000

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "service": "HoneyBridge",
            "component": "FAKE_SSH",
            "message": record.getMessage(),
        }

        # Add optional fields if present
        if hasattr(record, "client_ip"):
            log_record["client_ip"] = record.client_ip
        if hasattr(record, "client_port"):
            log_record["client_port"] = record.client_port

        return json.dumps(log_record)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        attacker_ip = self.client_address[0]
        logger.info(f"GET request from IP: {attacker_ip}")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(HTML_PAGE.encode())

    def do_POST(self):
        attacker_ip = self.client_address[0]

        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length).decode()
        logger.info(f"crdential captured from {attacker_ip} -> {data}")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        self.wfile.write(b"<h2>Invalid credentials</h2>")

def run():
    global port, name
    if len(sys.argv) >= 3:
        port = int(sys.argv[1])
        name = sys.argv[2]
    LOG_FILE = f"/log/login_server{port}.log"
    global logger
    handler = logging.FileHandler(LOG_FILE, mode='a')
    handler.setFormatter(JSONFormatter())

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False
    server = HTTPServer(("0.0.0.0", port), Handler)
    logger.info(f"Service running on port {port}, just an info message")
    server.serve_forever()

if __name__ == "__main__":
    run()
