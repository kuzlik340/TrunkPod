from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
import os
import time
import logging
from json_formatter import JSONFormatter

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

def build_logger(name: str, log_file: str, dst_ip: str, dst_port: int) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.FileHandler(log_file, mode="a")
    handler.setFormatter(JSONFormatter(dst_ip, dst_port, "HTTP"))
    logger.addHandler(handler)

    return logger

class Handler(BaseHTTPRequestHandler):
    html_dir = None  # class-level variable set during run()

    def do_GET(self):
        attacker_ip = self.client_address[0]
        attacker_port = self.client_address[1]
        logger.warning("GET request",
            extra={"src_ip_addr": attacker_ip, "src_port": attacker_port})

        # Serve CSS files if requested
        if self.path.endswith(".css") and self.html_dir:
            css_path = os.path.join(self.html_dir, os.path.basename(self.path))
            if os.path.exists(css_path):
                self.send_response(200)
                self.send_header("Content-type", "text/css")
                self.end_headers()
                with open(css_path, "rb") as f:
                    self.wfile.write(f.read())
                return

        # Serve main HTML page
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        if self.html_dir:
            html_path = os.path.join(self.html_dir, "index.html")
            with open(html_path, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.wfile.write(HTML_PAGE.encode())
    
    def do_POST(self):
        attacker_ip = self.client_address[0]
        attacker_port = self.client_address[1]
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length).decode()
        logger.warning(f"crdential captured {data}",
        extra={
            "src_ip_addr": attacker_ip,
            "src_port" : attacker_port,
        },)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h2>Invalid credentials</h2>")

def parse_args() -> tuple[int, str, str]:
    """Returns (port, name, dst_ip)."""
    if len(sys.argv) >= 4:
        return int(sys.argv[1]), sys.argv[2], sys.argv[3]
    return 80, "honeypot", "0.0.0.0"

def run():
    port, name, dst_ip = parse_args()
    log_file = f"/log/http_server{port}.log"
    global logger
    logger = build_logger(name, log_file, dst_ip, port)

    if len(sys.argv) >= 5:
        html_dir = sys.argv[4]
        if not os.path.isdir(html_dir):
            print(f"Error: {html_dir} is not a valid directory")
            sys.exit(1)
        Handler.html_dir = html_dir

    server = HTTPServer(("0.0.0.0", port), Handler)
    logger.info(f"Service HTTP running on port {port}, just an info message")
    server.serve_forever()

if __name__ == "__main__":
    run()
