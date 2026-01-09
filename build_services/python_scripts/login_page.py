from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
import os
import time
from datetime import datetime


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
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        attacker_ip = self.client_address[0]
        msg = f"[HoneyBridge][{name}][LOGIN_PAGE] GET request from IP: {attacker_ip}"
        print(msg)

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(HTML_PAGE.encode())

    def do_POST(self):
        attacker_ip = self.client_address[0]

        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length).decode()
        msg = f"[HoneyBridge][{name}][LOGIN_PAGE] crdential captured from {attacker_ip} -> {data}"
        print(msg)

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        self.wfile.write(b"<h2>Invalid credentials</h2>")

def run():
    global port, name
    if len(sys.argv) >= 3:
        port = int(sys.argv[1])
        name = sys.argv[2]
    server = HTTPServer(("0.0.0.0", port), Handler)
    msg = f"[HoneyBridge][{name}][LOGIN_PAGE] Honeypot running, just an info message"
    print(msg)
    server.serve_forever()

if __name__ == "__main__":
    run()
