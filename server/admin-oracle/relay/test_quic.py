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
from relay.quic_server import ALPN, RelayProtocol, RelayState

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
        server=QuicConfiguration(is_client=False,alpn_protocols=[ALPN],max_datagram_frame_size=1200)
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
    async def test_duplicate_token_cannot_open_second_session(self):
        async with self.connection() as first:
            self.assertEqual(await first.auth(),b'OK\n')
            async with self.connection() as second:
                with contextlib.suppress(ConnectionError,asyncio.TimeoutError): await second.auth()
                await asyncio.wait_for(second.wait_closed(),2)
                self.assertEqual(len(self.state.active),1)
            first.send(PACKET)
            self.assertEqual(await asyncio.wait_for(first.received.get(),2),PACKET)
    async def test_untrusted_certificate_rejected(self):
        self.client=QuicConfiguration(is_client=True,alpn_protocols=[ALPN],server_name=HOST,max_datagram_frame_size=1200)
        with self.assertRaises(ConnectionError):
            async with self.connection(): self.fail('untrusted connection accepted')
