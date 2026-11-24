"""Only serves requests from the disposable network-namespace lab."""

import ipaddress
import socket
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CHUNK = bytes(256 * 1024)
SAMPLE_SIZE = 64 * 1024 * 1024


class Origin(BaseHTTPRequestHandler):
    def send_body(self, body):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/throughput":
            self.send_response(200)
            self.send_header("Content-Length", str(SAMPLE_SIZE))
            self.end_headers()
            for _ in range(SAMPLE_SIZE // len(CHUNK)):
                self.wfile.write(CHUNK)
        else:
            self.send_body((self.client_address[0] + "\n").encode("ascii"))

    def do_PUT(self):
        if self.path != "/throughput" or self.headers.get("Content-Length") != str(SAMPLE_SIZE):
            self.send_error(400)
            return
        remaining = SAMPLE_SIZE
        while remaining:
            received = self.rfile.read(min(remaining, len(CHUNK)))
            if not received:
                return
            remaining -= len(received)
        self.send_body(b"ok\n")

    def log_message(self, _format, *_args):
        pass


class IPv6Origin(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class DnsOrigin(socketserver.BaseRequestHandler):
    def handle(self):
        query, transport = self.request
        question = b"\x06egress\x04test\x00\x00\x01\x00\x01"
        if len(query) < 12 or not query[12:].lower().startswith(question):
            return
        header = query[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0)
        address = ipaddress.IPv4Address("198.18.47.2").packed
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, len(address)) + address
        transport.sendto(header + question + answer, self.client_address)


if __name__ == "__main__":
    servers = [
        ThreadingHTTPServer(("198.18.47.2", 8081), Origin),
        IPv6Origin(("2001:db8:47::2", 8081), Origin),
        socketserver.UDPServer(("198.18.47.2", 53), DnsOrigin),
    ]
    for server in servers[:-1]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    servers[-1].serve_forever()
