"""Unprivileged loopback WebSocket relay; only Caddy exposes its fixed route.

WireGuard authentication/encryption and root-controlled quotas remain in wg0.
No SSH key, admin cookie, host credential, arbitrary destination or shell API.
"""
import asyncio
import hashlib
import re
import time

from aiohttp import ClientSession, ClientTimeout, WSMsgType, web

HOST = 'vpn-admin.morandi.dpdns.org'
PATH = '/api/client/relay'
MAX_PACKET = 4096
AUTH_SESSION = web.AppKey('auth_session', ClientSession)


def wireguard_packet(data):
    if not isinstance(data, bytes) or not 4 <= len(data) <= MAX_PACKET or data[1:4] != b'\0\0\0': return False
    kind = data[0]
    return ((kind == 1 and len(data) == 148) or (kind == 2 and len(data) == 92) or
            (kind == 3 and len(data) == 64) or (kind == 4 and len(data) >= 32))


async def authenticate(session, token):
    try:
        async with session.get('http://127.0.0.1:8787/api/client/state', headers={
            'Host': HOST, 'X-Forwarded-Proto': 'https', 'Authorization': 'Bearer ' + token},
            allow_redirects=False) as response:
            if response.status != 200: return False
            body = bytearray()
            async for part in response.content.iter_chunked(4096):
                body.extend(part)
                if len(body) > 32768: return False
            import json
            value = json.loads(body)
            return (value.get('account', {}).get('status') == 'active' and
                    type(value.get('observed_at')) is int and abs(time.time() - value['observed_at']) <= 20)
    except (OSError, ValueError, TypeError, AttributeError, asyncio.TimeoutError):
        return False


class PacketQueue(asyncio.DatagramProtocol):
    def __init__(self):
        self.queue = asyncio.Queue(64)
        self.failed = asyncio.Event()

    def datagram_received(self, data, addr):
        if not wireguard_packet(data): return
        try: self.queue.put_nowait(data)
        except asyncio.QueueFull: self.failed.set()

    def error_received(self, error): self.failed.set()
    def connection_lost(self, error): self.failed.set()


class Rate:
    def __init__(self, maximum): self.maximum, self.at, self.used = maximum, time.monotonic(), 0
    def accept(self, size):
        now = time.monotonic()
        if now - self.at >= 1: self.at, self.used = now, 0
        self.used += size
        return self.used <= self.maximum


def application(auth=authenticate, udp_target=('127.0.0.1', 51820), refresh=5):
    app = web.Application(client_max_size=1024)
    active = set()
    slots = asyncio.Semaphore(16)
    global_rate = Rate(16 * 1024 * 1024)
    attempts = Rate(128)  # bounded auth attempts/second before an HTTP call

    async def lifecycle(app):
        async with ClientSession(timeout=ClientTimeout(total=3), trust_env=False) as session:
            app[AUTH_SESSION] = session
            yield
    app.cleanup_ctx.append(lifecycle)

    async def health(request): return web.json_response({'ready': True})

    async def relay(request):
        if request.query_string or request.headers.get('Origin') or request.headers.get('Cookie'):
            raise web.HTTPForbidden()
        header = request.headers.get('Authorization', '')
        if not re.fullmatch(r'Bearer [A-Za-z0-9_-]{43}', header): raise web.HTTPUnauthorized()
        token = header[7:]
        identity = hashlib.sha256(token.encode()).digest()
        if len(active) >= 32 or identity in active or slots.locked() or not attempts.accept(1):
            raise web.HTTPTooManyRequests()
        async with slots:
            if not await auth(app[AUTH_SESSION], token): raise web.HTTPUnauthorized()
        # Recheck after the awaited auth call so concurrent opens cannot exceed
        # the cap or register the same bearer twice.
        if len(active) >= 32 or identity in active: raise web.HTTPTooManyRequests()
        ws = web.WebSocketResponse(max_msg_size=MAX_PACKET, compress=False, heartbeat=15,
                                   receive_timeout=45, protocols=('oracle-wireguard-v1',))
        if not ws.can_prepare(request).ok: raise web.HTTPBadRequest()
        active.add(identity)
        transport = None
        tasks = []
        rate = Rate(4 * 1024 * 1024)
        try:
            await ws.prepare(request)
            protocol = PacketQueue()
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: protocol, remote_addr=udp_target)

            async def inbound():
                async for message in ws:
                    if message.type != WSMsgType.BINARY or not wireguard_packet(message.data): return
                    if not rate.accept(len(message.data)) or not global_rate.accept(len(message.data)): return
                    transport.sendto(message.data)

            async def outbound():
                while True:
                    packet = await protocol.queue.get()
                    if not rate.accept(len(packet)) or not global_rate.accept(len(packet)): return
                    await asyncio.wait_for(ws.send_bytes(packet), 3)

            async def policy():
                while True:
                    await asyncio.sleep(refresh)
                    if not await auth(app[AUTH_SESSION], token): return

            tasks = [asyncio.create_task(fn()) for fn in (inbound, outbound, policy, protocol.failed.wait)]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (Exception, asyncio.CancelledError):
            pass  # never echo exceptions, tokens or frame contents
        finally:
            for task in tasks: task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if transport is not None: transport.close()
            active.discard(identity)
            await ws.close(code=1008, message=b'RELAY_CLOSED')
        return ws

    app.router.add_get('/health', health)
    app.router.add_get(PATH, relay)
    return app


if __name__ == '__main__':
    web.run_app(application(), host='127.0.0.1', port=8788, access_log=None, print=None,
                shutdown_timeout=5, handler_cancellation=True)
