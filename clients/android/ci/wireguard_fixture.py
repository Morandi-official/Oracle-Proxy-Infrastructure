"""Run on the disposable Linux emulator runner. Keep fixture keys off disk."""

import base64
import http.server
import ipaddress
import re
import socket
import subprocess
import threading

INTERFACE = "wg-proxy-ci"
CLIENT_IPV4 = "10.77.0.2"
CLIENT_IPV6 = "fd77:4242:77::2"
SERVER_IPV4 = "10.77.0.1"
SERVER_IPV6 = "fd77:4242:77::1"
PORT = 51820


def command(*args, input_text=None):
    return subprocess.run(args, input=input_text, text=True, check=True, capture_output=True).stdout.strip()


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_text(self, status, body=""):
        encoded = body.encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class Control(QuietHandler):
    def do_GET(self):
        if self.path == "/key":
            self.send_text(200, self.server.public_key)
        else:
            self.send_text(404)

    def do_POST(self):
        if self.path != "/register" or self.headers.get("Content-Length") != "44":
            self.send_text(400)
            return
        key = self.rfile.read(44).decode("ascii", errors="replace")
        if re.fullmatch(r"[A-Za-z0-9+/]{43}=", key) is None or len(base64.b64decode(key)) != 32:
            self.send_text(400)
            return
        command("wg", "set", INTERFACE, "peer", key, "allowed-ips", f"{CLIENT_IPV4}/32,{CLIENT_IPV6}/128")
        self.send_text(204)


class ExitProof(QuietHandler):
    def do_GET(self):
        source = ipaddress.ip_address(self.client_address[0])
        if self.path != "/exit" or str(source) not in {CLIENT_IPV4, CLIENT_IPV6}:
            self.send_text(403)
            return
        self.send_text(200, self.server.server_address[0] + "\n")


class IPv6Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


def main():
    try:
        command("ip", "link", "add", INTERFACE, "type", "wireguard")
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"Cannot start Linux WireGuard fixture: {error.stderr}") from None
    try:
        private_key = command("wg", "genkey")
        public_key = command("wg", "pubkey", input_text=private_key + "\n")
        command("wg", "set", INTERFACE, "listen-port", str(PORT), "private-key", "/dev/stdin",
                input_text=private_key + "\n")
        command("ip", "addr", "add", SERVER_IPV4 + "/24", "dev", INTERFACE)
        command("ip", "-6", "addr", "add", SERVER_IPV6 + "/64", "dev", INTERFACE, "nodad")
        command("ip", "link", "set", INTERFACE, "up")
        exits = [http.server.ThreadingHTTPServer((SERVER_IPV4, 18080), ExitProof),
                 IPv6Server((SERVER_IPV6, 18080), ExitProof)]
        for server in exits:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with http.server.ThreadingHTTPServer(("127.0.0.1", 18081), Control) as control:
            control.public_key = public_key
            control.serve_forever()
    finally:
        subprocess.run(("ip", "link", "del", INTERFACE), check=False, capture_output=True)


if __name__ == "__main__":
    main()
