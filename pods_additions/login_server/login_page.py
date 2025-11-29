from http.server import BaseHTTPRequestHandler, HTTPServer
import sys

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

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(HTML_PAGE.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length"))
        data = self.rfile.read(length).decode()

        # Log credentials
        print("[CREDENTIAL CAPTURED] →", data)

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        self.wfile.write(b"<h2>Invalid credentials</h2>")

def run():
    port = 8000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    server = HTTPServer(("0.0.0.0", port), Handler)
    print("Honeypot running on http://0.0.0.0:8000")
    server.serve_forever()

if __name__ == "__main__":
    run()
