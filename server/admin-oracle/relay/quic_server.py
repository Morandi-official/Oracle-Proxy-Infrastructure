"""Authenticated QUIC datagrams carrying only WireGuard to the local wg0 socket."""
import asyncio
import hashlib
import re
import signal

from aiohttp import ClientSession, ClientTimeout, web
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, DatagramFrameReceived, StreamDataReceived

from .fragments import Reassembly, fragment
from .server import PacketQueue, Rate, authenticate, wireguard_packet

ALPN = 'oracle-wireguard-quic-v1'


class RelayState:
    def __init__(self, session, auth=authenticate, target=('127.0.0.1', 51820), refresh=5):
        self.session, self.auth, self.target, self.refresh = session, auth, target, refresh
        self.active = set()
        self.pending = 0
        self.attempts = Rate(128)
        self.rate = Rate(16 * 1024 * 1024)


class RelayProtocol(QuicConnectionProtocol):
    def __init__(self, *args, state, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = state
        self.header = bytearray()
        self.started = False
        self.identity = None
        self.udp = None
        self.tasks = []
        self.fragments = Reassembly()
        self.number = 0
        self.rate = Rate(4 * 1024 * 1024)
        self.auth_slot = False
        self.deadline = asyncio.get_running_loop().call_later(5, self.reject)

    def reject(self):
        self.cleanup()
        self.close(error_code=0x100, reason_phrase='RELAY_CLOSED')

    def cleanup(self):
        self.deadline.cancel()
        for task in self.tasks: task.cancel()
        self.tasks.clear()
        if self.udp is not None: self.udp.close(); self.udp = None
        if self.identity is not None: self.state.active.discard(self.identity); self.identity = None
        if self.auth_slot: self.state.pending -= 1; self.auth_slot = False
        self.fragments.pending.clear()
        self.header.clear()

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self.cleanup()
        elif isinstance(event, StreamDataReceived):
            if event.stream_id != 0 or self.started or len(self.header) + len(event.data) > 44:
                self.reject(); return
            self.header.extend(event.data)
            if event.end_stream:
                if not re.fullmatch(rb'[A-Za-z0-9_-]{43}\n', self.header): self.reject(); return
                if self.state.pending >= 16 or len(self.state.active) >= 32 or not self.state.attempts.accept(1):
                    self.reject(); return
                self.started = True
                self.auth_slot = True
                self.state.pending += 1
                token = self.header[:-1].decode('ascii')
                self.header.clear()
                self.tasks.append(asyncio.create_task(self.authorize(token)))
        elif isinstance(event, DatagramFrameReceived):
            if self.udp is None: self.reject(); return
            # Charge every authenticated fragment, including malformed or
            # incomplete ones, before reassembly work or forwarding.
            if not self.accept(len(event.data)): self.reject(); return
            packet = self.fragments.receive(event.data)
            if packet is not None:
                if not wireguard_packet(packet): self.reject(); return
                self.udp.sendto(packet)

    def accept(self, size):
        return self.rate.accept(size) and self.state.rate.accept(size)

    async def authorize(self, token):
        try:
            if not await self.state.auth(self.state.session, token): self.reject(); return
            identity = hashlib.sha256(token.encode()).digest()
            if identity in self.state.active or len(self.state.active) >= 32: self.reject(); return
            self.identity = identity
            self.state.active.add(identity)
            queue = PacketQueue()
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: queue, remote_addr=self.state.target)
            # A timeout or peer close can occur during the awaited socket creation.
            if self.identity is None: transport.close(); return
            self.udp = transport
            self.deadline.cancel()
            self._quic.send_stream_data(0, b'OK\n', end_stream=True)
            self.transmit()
            self.tasks.extend([asyncio.create_task(self.outbound(queue)), asyncio.create_task(self.policy(token)),
                               asyncio.create_task(self.watch_failure(queue))])
        except asyncio.CancelledError:
            return
        except Exception:
            self.reject()  # no exception, bearer or packet logging
        finally:
            if self.auth_slot: self.state.pending -= 1; self.auth_slot = False

    async def outbound(self, queue):
        try:
            while True:
                packet = await queue.queue.get()
                if not self.accept(len(packet)): self.reject(); return
                self.number = (self.number + 1) & 0xffffffff
                for part in fragment(packet, self.number): self._quic.send_datagram_frame(part)
                self.transmit()
        except asyncio.CancelledError: return
        except Exception: self.reject()

    async def policy(self, token):
        try:
            while True:
                await asyncio.sleep(self.state.refresh)
                if not await self.state.auth(self.state.session, token): self.reject(); return
        except asyncio.CancelledError: return
        except Exception: self.reject()

    async def watch_failure(self, queue):
        try: await queue.failed.wait(); self.reject()
        except asyncio.CancelledError: return


async def run():
    config = QuicConfiguration(is_client=False, alpn_protocols=[ALPN], max_datagram_frame_size=1200,
                               idle_timeout=45, max_data=4096, max_stream_data=64)
    config.load_cert_chain('/etc/oracle-proxy-quic/certificate.pem', '/etc/oracle-proxy-quic/private.pem')
    async with ClientSession(timeout=ClientTimeout(total=3), trust_env=False) as session:
        state = RelayState(session)
        server = await serve('0.0.0.0', 8443, configuration=config, retry=True,
                             create_protocol=lambda *args, **kwargs: RelayProtocol(*args, state=state, **kwargs))
        app = web.Application()
        async def health(request): return web.json_response({'ready': True})
        app.router.add_get('/health', health)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, '127.0.0.1', 8789).start()
        stopped = asyncio.Event()
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM): loop.add_signal_handler(signum, stopped.set)
        try: await stopped.wait()
        finally: server.close(); await runner.cleanup()


if __name__ == '__main__': asyncio.run(run())
