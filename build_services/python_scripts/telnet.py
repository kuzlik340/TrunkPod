import socket

HOST = "0.0.0.0"
PORT = 23
PASSWORD = "secret123"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(5)

print("Fake Telnet server running...")

while True:
    conn, addr = s.accept()
    conn.send(b"Welcome to Secure Telnet Service\n")
    conn.send(b"Password: ")
    pw = conn.recv(1024).strip()

    if pw.decode() == PASSWORD:
        conn.send(b"Access granted!\n")
    else:
        conn.send(b"Access denied!\n")

    conn.close()
