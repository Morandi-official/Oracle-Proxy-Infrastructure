"""Disposable Windows acceptance relay for the project's TLS origin only."""

import asyncio
import ipaddress
import os
import sys
from pathlib import Path


ORIGIN = b"vpn-admin.morandi.dpdns.org:443"


async def copy(reader, writer):
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()


async def handle(client, response, address):
    upstream = None
    try:
        header = await asyncio.wait_for(client.readuntil(b"\r\n\r\n"), 5)
        request = header.split(b"\r\n", 1)[0].split()
        if len(request) != 3 or request[0] != b"CONNECT" or request[1].lower() != ORIGIN:
            response.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            await response.drain()
            return
        reader, upstream = await asyncio.wait_for(asyncio.open_connection(address, 443), 8)
        response.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await response.drain()
        tasks = [asyncio.create_task(copy(client, upstream)), asyncio.create_task(copy(reader, response))]
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        pass
    finally:
        if upstream is not None:
            upstream.close()
        response.close()


async def main(address, ready):
    socket = await asyncio.start_server(
        lambda client, response: handle(client, response, address),
        "127.0.0.1", 0, limit=8192,
    )
    async with socket:
        pending = ready.with_suffix(".tmp")
        pending.write_text(str(socket.sockets[0].getsockname()[1]), encoding="ascii")
        pending.replace(ready)
        await socket.serve_forever()


if __name__ == "__main__":
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("GITHUB_REF") != "refs/heads/main"):
        raise SystemExit("A disposable main-branch acceptance runner is required")
    asyncio.run(main(str(ipaddress.IPv4Address(sys.argv[1])), Path(sys.argv[2])))
