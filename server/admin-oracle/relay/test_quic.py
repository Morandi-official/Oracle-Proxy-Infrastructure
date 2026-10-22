import asyncio
import contextlib
import os
import ssl
import tempfile
import unittest
from pathlib import Path

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import DatagramFrameReceived
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from relay.fragments import CHUNK, Reassembly, fragment
from relay.quic_keys import HOST, certificate
from relay.quic_server import ALPN, H3_ALPN, CONNECT_PATH, RelayProtocol, RelayState
from relay.server import Rate

TOKEN = 'a' * 43
PACKET = b'\x04\0\0\0' + bytes(range(256))*5


class Framing(unittest.TestCase):
    def test_out_of_order_round_trip_and_bounded_invalid_input(self):
        for size in (1, 92, 148, CHUNK, CHUNK+1, 1380, 4096):
            data = os.urandom(size); receiver = Reassembly(); result = None
            for part in reversed(fragment(data, 42)): result = receiver.receive(part)
            self.assertEqual(result, data)
            self.assertEqual(receiver.pending, {})
        receiver = Reassembly()
        for number in range(1000):
            self.assertIsNone(receiver.receive(fragment(b'a'*1380,number)[0]))
        self.assertEqual(len(receiver.pending),64)
        for data in (b'',b'x'*1009,b'\0'*8,b'\0'*1008): self.assertIsNone(receiver.receive(data))
        for size in (0,4097):
            with self.assertRaises(ValueError): fragment(b'x'*size,1)


class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport): self.transport=transport
    def datagram_received(self, data, addr): self.transport.sendto(data,addr)


class Client(QuicConnectionProtocol):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.received=asyncio.Queue();self.parts=Reassembly()
    def quic_event_received(self,event):
        if isinstance(event,DatagramFrameReceived):
            packet=self.parts.receive(event.data)
            if packet is not None: self.received.put_nowait(packet)
        else: super().quic_event_received(event)
    async def auth(self,token=TOKEN):
        reader,writer=await self.create_stream()
        writer.write(token.encode()+b'\n');writer.write_eof()
        return await asyncio.wait_for(reader.read(16),2)
    def send(self,packet):
        for piece in fragment(packet,1): self._quic.send_datagram_frame(piece)
        self.transmit()


class QuicTLS(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory=tempfile.TemporaryDirectory();root=Path(self.directory.name)
        key=ec.generate_private_key(ec.SECP256R1());cert=certificate(key)
        (root/'cert').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root/'key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        server=QuicConfiguration(is_client=False,alpn_protocols=[H3_ALPN,ALPN],max_datagram_frame_size=1200)
        server.load_cert_chain(str(root/'cert'),str(root/'key'))
        self.client=QuicConfiguration(is_client=True,alpn_protocols=[ALPN],server_name=HOST,max_datagram_frame_size=1200)
        self.client.load_verify_locations(cafile=str(root/'cert'))
        self.allowed=True
        async def auth(session,token): return self.allowed and token==TOKEN
        self.udp,_=await asyncio.get_running_loop().create_datagram_endpoint(Echo,local_addr=('127.0.0.1',0))
        self.state=RelayState(None,auth=auth,target=self.udp.get_extra_info('sockname'),refresh=0.05)
        self.server=await serve('127.0.0.1',0,configuration=server,retry=True,
            create_protocol=lambda *args,**kwargs: RelayProtocol(*args,state=self.state,**kwargs))
        self.port=self.server._transport.get_extra_info('sockname')[1]
    async def asyncTearDown(self):
        self.server.close();self.udp.close();await asyncio.sleep(0.02);self.directory.cleanup()
    def connection(self): return connect('127.0.0.1',self.port,configuration=self.client,create_protocol=Client)
    async def test_real_tls_fragmented_datagram_and_revocation(self):
        async with self.connection() as client:
            self.assertEqual(await client.auth(),b'OK\n')
            client.send(PACKET)
            self.assertEqual(await asyncio.wait_for(client.received.get(),2),PACKET)
            self.allowed=False
            await asyncio.wait_for(client.wait_closed(),2)
            self.assertFalse(self.state.active)
    async def test_unauthenticated_data_rejected(self):
        async with self.connection() as client:
            client.send(PACKET)
            await asyncio.wait_for(client.wait_closed(),2)
            self.assertFalse(self.state.active)
    async def test_authenticated_new_session_replaces_stale_owner(self):
        async with self.connection() as first:
            self.assertEqual(await first.auth(),b'OK\n')
            async with self.connection() as second:
                self.assertEqual(await second.auth(),b'OK\n')
                await asyncio.wait_for(first.wait_closed(),2)
                self.assertEqual(len(self.state.active),1)
                second.send(PACKET);self.assertEqual(await asyncio.wait_for(second.received.get(),2),PACKET)
    async def test_denied_new_session_cannot_displace_existing_owner(self):
        async with self.connection() as first:
            self.assertEqual(await first.auth(),b'OK\n')
            async with self.connection() as second:
                with contextlib.suppress(ConnectionError,asyncio.TimeoutError):await second.auth(token='b'*43)
                await asyncio.wait_for(second.wait_closed(),2)
                self.assertEqual(len(self.state.active),1)
                first.send(PACKET);self.assertEqual(await asyncio.wait_for(first.received.get(),2),PACKET)
    async def test_incomplete_fragments_cannot_bypass_rate_limit(self):
        async with self.connection() as client:
            self.assertEqual(await client.auth(),b'OK\n')
            self.state.rate = Rate(10)
            first = fragment(PACKET,123)[0]
            client._quic.send_datagram_frame(first)
            client.transmit()
            await asyncio.wait_for(client.wait_closed(),2)
            self.assertFalse(self.state.active)
    async def test_untrusted_certificate_rejected(self):
        self.client=QuicConfiguration(is_client=True,alpn_protocols=[ALPN],server_name=HOST,max_datagram_frame_size=1200)
        with self.assertRaises(ConnectionError):
            async with self.connection(): self.fail('untrusted connection accepted')


from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DatagramReceived, DataReceived
from relay.capsules import Capsules, encode as capsule

class H3Client(QuicConnectionProtocol):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.http=H3Connection(self._quic);self.status=asyncio.Queue();self.received=asyncio.Queue();self.capsules=Capsules()
    def quic_event_received(self,event):
        for item in self.http.handle_event(event):
            if isinstance(item,HeadersReceived):self.status.put_nowait(dict(item.headers).get(b':status'))
            elif isinstance(item,DatagramReceived) and item.data[:1]==b'\0':
                self.received.put_nowait(item.data[1:])
            elif isinstance(item,DataReceived):
                for packet in self.capsules.receive(item.data):self.received.put_nowait(packet)
    async def auth(self,token=TOKEN,path=CONNECT_PATH):
        self.http.send_headers(0,[(b':method',b'CONNECT'),(b':protocol',b'connect-udp'),(b':scheme',b'https'),(b':authority',HOST.encode()),(b':path',path.encode()),(b'capsule-protocol',b'?1'),(b'authorization',b'Bearer '+token.encode())]);self.transmit()
        return await asyncio.wait_for(self.status.get(),2)
    def send(self,packet):
        if len(packet)<=1000:self.http.send_datagram(0,b'\0'+packet)
        else:self.http.send_data(0,capsule(packet),end_stream=False)
        self.transmit()

class Http3TLS(QuicTLS):
    async def test_large_udp_burst_respects_flow_control_without_session_loss(self):
        async with self.connection() as client:
            self.assertEqual(await client.auth(),b'200')
            packets=[b'\x04\0\0\0'+bytes([i])*1376 for i in range(48)]
            for packet in packets:client.send(packet)
            received=[await asyncio.wait_for(client.received.get(),3) for _ in packets]
            self.assertEqual(received,packets);self.assertEqual(len(self.state.active),1)

    async def test_unauthenticated_data_rejected(self):
        async with self.connection() as client:
            client.send(b'\x04\0\0\0'+bytes(28))
            await asyncio.wait_for(client.wait_closed(),2);self.assertFalse(self.state.active)

    async def asyncSetUp(self):
        await super().asyncSetUp();self.client.alpn_protocols=[H3_ALPN]
    def connection(self):return connect('127.0.0.1',self.port,configuration=self.client,create_protocol=H3Client)
    async def test_real_tls_fragmented_datagram_and_revocation(self):
        async with self.connection() as client:
            self.assertEqual(await client.auth(),b'200');client.send(PACKET)
            self.assertEqual(await asyncio.wait_for(client.received.get(),2),PACKET)
            self.allowed=False;await asyncio.wait_for(client.wait_closed(),2);self.assertFalse(self.state.active)
    async def test_authenticated_new_session_replaces_stale_owner(self):
        async with self.connection() as first:
            self.assertEqual(await first.auth(),b'200')
            async with self.connection() as second:
                self.assertEqual(await second.auth(),b'200')
                await asyncio.wait_for(first.wait_closed(),2);self.assertEqual(len(self.state.active),1)
                second.send(PACKET);self.assertEqual(await asyncio.wait_for(second.received.get(),2),PACKET)
    async def test_denied_new_session_cannot_displace_existing_owner(self):
        async with self.connection() as first:
            self.assertEqual(await first.auth(),b'200')
            async with self.connection() as second:
                with contextlib.suppress(ConnectionError,asyncio.TimeoutError):await second.auth(token='b'*43)
                await asyncio.wait_for(second.wait_closed(),2);self.assertEqual(len(self.state.active),1)
                first.send(PACKET);self.assertEqual(await asyncio.wait_for(first.received.get(),2),PACKET)
    async def test_incomplete_fragments_cannot_bypass_rate_limit(self):
        async with self.connection() as client:
            self.assertEqual(await client.auth(),b'200');self.state.rate=Rate(10)
            client.http.send_datagram(0,b'\0'+fragment(PACKET,123)[0]);client.transmit()
            await asyncio.wait_for(client.wait_closed(),2);self.assertFalse(self.state.active)
    async def test_cannot_choose_a_general_udp_destination(self):
        async with self.connection() as client:
            with contextlib.suppress(ConnectionError,asyncio.TimeoutError):await client.auth(path='/.well-known/masque/udp/8.8.8.8/53/')
            await asyncio.wait_for(client.wait_closed(),2);self.assertFalse(self.state.active)

class CapsuleBounds(unittest.TestCase):
    def test_split_capsule_and_invalid_context_or_size(self):
        data=capsule(PACKET);parser=Capsules();self.assertEqual(parser.receive(data[:3]),[]);self.assertEqual(parser.receive(data[3:]),[PACKET])
        for data in (b'\0\x40\0',b'\0\x40\x01\x01',b'\0\xff'+b'\xff'*7):
            with self.assertRaises(ValueError):Capsules().receive(data)
