import asyncio
import unittest

from aiohttp import WSMsgType, WSServerHandshakeError
from aiohttp.test_utils import TestClient, TestServer

from relay.server import PATH, PacketQueue, Rate, application, wireguard_packet

TOKEN = 'A' * 43
PACKET = bytes([1, 0, 0, 0]) + b'x' * 144


class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, data, addr): self.transport.sendto(data, addr)


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.allowed = True
        self.checked = 0
        async def auth(session, token):
            self.checked += 1
            return self.allowed and token == TOKEN
        self.udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(Echo, local_addr=('127.0.0.1', 0))
        self.client = TestClient(TestServer(application(auth, self.udp.get_extra_info('sockname'), refresh=0.04)))
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        self.udp.close()

    async def connect(self, **kwargs):
        return await self.client.ws_connect(PATH, headers={'Authorization': 'Bearer ' + TOKEN, **kwargs},
                                            protocols=('oracle-wireguard-v1',))

    async def test_fixed_udp_roundtrip_and_revocation(self):
        ws = await self.connect()
        await ws.send_bytes(PACKET)
        message = await ws.receive(timeout=1)
        self.assertEqual((message.type, message.data), (WSMsgType.BINARY, PACKET))
        self.allowed = False
        message = await ws.receive(timeout=1)
        self.assertIn(message.type, (WSMsgType.CLOSE, WSMsgType.CLOSED))
        self.assertGreaterEqual(self.checked, 2)

    async def test_no_browser_credentials_or_query_destination(self):
        for headers in ({}, {'Authorization': 'Bearer wrong'}, {'Authorization': 'Bearer ' + TOKEN, 'Origin': 'https://evil.invalid'},
                        {'Authorization': 'Bearer ' + TOKEN, 'Cookie': 'sessionid=ambient'}):
            response = await self.client.get(PATH, headers=headers)
            self.assertIn(response.status, (401, 403))
        response = await self.client.get(PATH + '?destination=example.com', headers={'Authorization': 'Bearer ' + TOKEN})
        self.assertEqual(response.status, 403)
        self.assertEqual(self.checked, 0)

    async def test_duplicate_token_and_invalid_frames_refused(self):
        ws = await self.connect()
        with self.assertRaises(WSServerHandshakeError) as error: await self.connect()
        self.assertEqual(error.exception.status, 429)
        await ws.send_str('arbitrary command')
        self.assertIn((await ws.receive(timeout=1)).type, (WSMsgType.CLOSE, WSMsgType.CLOSED))
        await ws.close()
        await asyncio.sleep(0.02)
        ws = await self.connect()
        await ws.send_bytes(b'not wireguard')
        self.assertIn((await ws.receive(timeout=1)).type, (WSMsgType.CLOSE, WSMsgType.CLOSED))

    async def test_denied_policy_never_opens_relay(self):
        self.allowed = False
        with self.assertRaises(WSServerHandshakeError) as error: await self.connect()
        self.assertEqual(error.exception.status, 401)


class BoundsTests(unittest.TestCase):
    def test_packet_shapes_and_bounded_queue(self):
        self.assertTrue(wireguard_packet(PACKET))
        for value in (b'', b'\x01\0\0\0', b'\x04\0\0\0' + b'x' * 5000, b'\x04\0\0\0' + b'x' * 10,
                      b'\x01\1\0\0' + b'x' * 144): self.assertFalse(wireguard_packet(value))
        queue = PacketQueue()
        for _ in range(65): queue.datagram_received(PACKET, ('127.0.0.1', 51820))
        self.assertEqual(queue.queue.qsize(), 64)
        self.assertTrue(queue.failed.is_set())
        rate = Rate(10)
        self.assertTrue(rate.accept(10))
        self.assertFalse(rate.accept(1))


if __name__ == '__main__': unittest.main()

class DeviceEnrollmentAuthorization(unittest.IsolatedAsyncioTestCase):
    async def test_pending_or_missing_device_confirmation_cannot_authorize_relay(self):
        import json,time
        from relay.server import authenticate
        class Content:
            def __init__(self,value):self.value=value
            async def iter_chunked(self,size):yield json.dumps(self.value).encode()
        class Reply:
            status=200
            def __init__(self,value):self.content=Content(value)
            async def __aenter__(self):return self
            async def __aexit__(self,*args):pass
        class Session:
            def __init__(self,value):self.value=value
            def get(self,*args,**kwargs):return Reply(self.value)
        for registered,expected in ((None,False),(False,False),(True,True)):
            data={'account':{'status':'active'},'observed_at':int(time.time())}
            if registered is not None:data['device']={'registered':registered}
            self.assertEqual(await authenticate(Session(data),TOKEN),expected)
