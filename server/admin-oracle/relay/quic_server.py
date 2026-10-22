"""Authenticated QUIC datagrams carrying only WireGuard to the local wg0 socket."""
import asyncio
import hashlib
import re
import signal

from aiohttp import ClientSession, ClientTimeout, web
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, DatagramFrameReceived, StreamDataReceived, ProtocolNegotiated

from .fragments import Reassembly, fragment
from .capsules import Capsules, encode as capsule
from .server import PacketQueue, Rate, authenticate, wireguard_packet

from aioquic.h3.connection import H3Connection, Setting
from aioquic.h3.events import HeadersReceived, DataReceived, DatagramReceived

ALPN = 'oracle-wireguard-quic-v1'  # rc6–rc8 compatibility
H3_ALPN = 'h3'
CONNECT_PATH = '/.well-known/masque/udp/127.0.0.1/51820/'


class DatagramH3(H3Connection):
    def _get_local_settings(self):
        settings=super()._get_local_settings()
        settings[Setting.H3_DATAGRAM]=1
        return settings


class RelayState:
    def __init__(self, session, auth=authenticate, target=('127.0.0.1', 51820), refresh=5):
        self.session, self.auth, self.target, self.refresh = session, auth, target, refresh
        self.active = {}
        self.pending = 0
        self.attempts = Rate(128)
        self.rate = Rate(16 * 1024 * 1024)


class RelayProtocol(QuicConnectionProtocol):
    def __init__(self, *args, state, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = state
        self.header = bytearray()
        self.started = False
        self.http = None
        self.http_stream = None
        self.identity = None
        self.udp = None
        self.tasks = []
        self.fragments = Reassembly()
        self.capsules = Capsules()
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
        if self.identity is not None:
            if self.state.active.get(self.identity) is self: self.state.active.pop(self.identity,None)
            self.identity = None
        if self.auth_slot: self.state.pending -= 1; self.auth_slot = False
        self.fragments.pending.clear();self.capsules.pending.clear()
        self.header.clear()

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated) and event.alpn_protocol == H3_ALPN:
            self.http = DatagramH3(self._quic)
        if isinstance(event, ConnectionTerminated):
            self.cleanup()
            return
        if self.http is not None:
            for item in self.http.handle_event(event): self.http_event(item)
            return
        if isinstance(event, StreamDataReceived):
            if event.stream_id != 0 or self.started or len(self.header) + len(event.data) > 44:
                self.reject(); return
            self.header.extend(event.data)
            if event.end_stream:
                if not re.fullmatch(rb'[A-Za-z0-9_-]{43}\n', self.header): self.reject(); return
                if self.state.pending >= 16 or not self.state.attempts.accept(1):
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

    def http_event(self, event):
        if isinstance(event, HeadersReceived):
            if len(event.headers)>16 or sum(len(k)+len(v) for k,v in event.headers)>2048:
                self.reject(); return
            headers=dict(event.headers)
            if len(headers)!=len(event.headers): self.reject(); return
            if headers.get(b':method')==b'GET' and headers.get(b':path')==b'/health' and not self.started:
                self.http.send_headers(event.stream_id,[(b':status',b'200'),(b'content-type',b'application/json')])
                self.http.send_data(event.stream_id,b'{"ready":true}',end_stream=True);self.transmit(); return
            if (event.stream_id!=0 or self.started or event.stream_ended or
                headers.get(b':method')!=b'CONNECT' or headers.get(b':protocol')!=b'connect-udp' or
                headers.get(b':scheme')!=b'https' or headers.get(b':authority')!=b'vpn-admin.morandi.dpdns.org' or
                headers.get(b':path')!=CONNECT_PATH.encode() or
                headers.get(b'capsule-protocol')!=b'?1'):
                self.reject(); return
            bearer=headers.get(b'authorization',b'')
            if not re.fullmatch(rb'Bearer [A-Za-z0-9_-]{43}',bearer): self.reject(); return
            if self.state.pending>=16 or not self.state.attempts.accept(1):
                self.reject(); return
            self.started=True;self.http_stream=event.stream_id;self.auth_slot=True;self.state.pending+=1
            self.tasks.append(asyncio.create_task(self.authorize(bearer[7:].decode('ascii'))))
        elif isinstance(event, DataReceived):
            if event.stream_id!=self.http_stream or self.udp is None or event.stream_ended or not self.accept(len(event.data)):
                self.reject();return
            try:
                for packet in self.capsules.receive(event.data):
                    if not wireguard_packet(packet): self.reject();return
                    self.udp.sendto(packet)
            except ValueError:self.reject()
        elif isinstance(event, DatagramReceived):
            if event.stream_id!=self.http_stream or self.udp is None or not event.data or event.data[0]!=0:
                self.reject();return
            if not self.accept(len(event.data)): self.reject();return
            packet=event.data[1:]
            if not wireguard_packet(packet): self.reject();return
            self.udp.sendto(packet)

    def accept(self, size):
        return self.rate.accept(size) and self.state.rate.accept(size)

    async def authorize(self, token):
        try:
            if not await self.state.auth(self.state.session, token): self.reject(); return
            identity = hashlib.sha256(token.encode()).digest()
            previous=self.state.active.get(identity)
            if previous is None and len(self.state.active)>=32: self.reject(); return
            # Authenticate first, then replace the old owner synchronously.
            # A dead UDP client cannot send CONNECTION_CLOSE; refusing the same
            # token until the 45s idle timeout breaks normal crash recovery.
            if previous is not None: previous.reject()
            self.identity = identity
            self.state.active[identity]=self
            queue = PacketQueue()
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: queue, remote_addr=self.state.target)
            # A timeout or peer close can occur during the awaited socket creation.
            if self.identity is None: transport.close(); return
            self.udp = transport
            self.deadline.cancel()
            if self.http is None: self._quic.send_stream_data(0, b'OK\n', end_stream=True)
            else: self.http.send_headers(self.http_stream,[(b':status',b'200'),(b'capsule-protocol',b'?1')])
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
                if self.http is None:
                    for part in fragment(packet,self.number):self._quic.send_datagram_frame(part)
                elif len(packet)<=1000:self.http.send_datagram(self.http_stream,b"\0"+packet)
                else:
                    stream=self._quic._streams.get(self.http_stream)
                    if stream is None:self.reject();return
                    # Bound queued reliable fallback while allowing normal TCP
                    # receive windows. Backpressure rather than closing a
                    # healthy tunnel after a small burst of large UDP frames.
                    while len(stream.sender._buffer)>256*1024:
                        await asyncio.sleep(0.01)
                    self.http.send_data(self.http_stream,capsule(packet),end_stream=False)
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
    config = QuicConfiguration(is_client=False, alpn_protocols=[H3_ALPN, ALPN], max_datagram_frame_size=1200,
                               idle_timeout=45, max_data=16384, max_stream_data=4096)
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
