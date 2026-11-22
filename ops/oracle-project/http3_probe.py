"""TLS-verified HTTP/3 controls for the public administration website."""
import asyncio
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived

HOST = 'vpn-admin.morandi.dpdns.org'


class Http3Probe(QuicConnectionProtocol):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.http=H3Connection(self._quic);self.status=asyncio.Queue()
    def quic_event_received(self,event):
        for item in self.http.handle_event(event):
            if isinstance(item,HeadersReceived):self.status.put_nowait(dict(item.headers).get(b':status'))
