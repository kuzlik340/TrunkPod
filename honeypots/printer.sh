import logging
from pkipplib import pkipplib
from gevent.server import StreamServer

logger = logging.getLogger(__name__)

class PrintServer(object):

    def handle(self, sock, address):
        print("Connection from:", address)
        data = sock.recv(8192)
        print("Raw data:", repr(data))

        try:
            body = data.split(b"\r\n\r\n", 1)[1]
        except IndexError:
            body = data

        request = pkipplib.IPPRequest(body)
        request.parse()
        print("Parsed request:", request)

        response = pkipplib.IPPRequest(operation_id=pkipplib.CUPS_GET_DEFAULT)
        response.operation["attributes-charset"] = ("charset", "utf-8")
        response.operation["attributes-natural-language"] = ("naturalLanguage", "en-us")

        sock.send(response.dump())

    def get_server(self, host, port):
        connection = (host, port)
        server = StreamServer(connection, self.handle)
        logger.info(f"LPR honeypot started on {connection}")
        return server

if __name__ == "__main__":
    ps = PrintServer()
    print_server = ps.get_server("0.0.0.0", 9100)  # <-- IMPORTANT
    print_server.serve_forever()