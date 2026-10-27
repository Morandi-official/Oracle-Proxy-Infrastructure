# rc21 performance audit

Checked 2026-10-27. This is a code-path and local allocation review, not a new
China-to-Oracle speed test. Existing cloud/hardware acceptance must still pass
before a new binary is offered to users.

## Instance allocation and physical limits

The existing read-only instance snapshot in `work/rc16-server-preflight.json`
identifies `VM.Standard.A1.Flex`, `uk-london-1`, 2 OCPUs, 12 GiB and
`networkingBandwidthInGbps: 2`. It is historical evidence, not a new live query.
Oracle's [Compute Shapes](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm)
reference specifies 1 Gbps per A1 OCPU and describes VM network bandwidth in the
VCN context. A 2 Gbps allocation is not guaranteed Internet throughput between
China Mobile and London, nor evidence of a per-direction Internet guarantee.
The E2.1.Micro 50 Mbps rule does not describe this A1 instance. Monthly free
outbound allowance and network bandwidth are separate limits.

Previous owner results already rule out a universal 3 Mbps upload ceiling:
Speedtestworld reported about 38–40 Mbps upload while native UDP was connected,
whereas several Ookla UK targets reported about 2–4 Mbps. Different endpoints,
concurrency and methodology prevent treating those as equivalent controls.
Native download results varied roughly 150–250 Mbps. No new speed guarantee is
inferred from those observations.

The Oracle region remains London. Client code can reduce processing/queuing
cost but cannot eliminate intercontinental propagation and upstream routing.
Changing the server's kernel TCP congestion control does not tune TCP sessions
terminated by the client's userspace WireGuard stack.

## Existing optimizations retained

- Native WireGuard UDP stays the primary transport; known working UDP8443 and
  transport-address hints remain intact. QUIC is a backup and HTTPS is fallback.
- Native sockets already request 7 MiB receive/send buffers; actual accepted
  buffer sizes remain visible in redacted diagnostics.
- Native receive payloads already use a bounded frame pool with ownership
  transfer; frames are not reused while queued.
- The userspace WireGuard TCP policy already uses CUBIC. That patch retains
  upstream window/buffer limits and is checked against pinned upstream source.
- The owned Oracle physical queue already has an FQ-CoDel apply/rollback path.
- Dual-stack MTU remains 1280, preserving IPv6's minimum packet size and the
  previously accepted low-MTU/outer-fragment handling. No speculative MTU,
  global buffer, firewall, route, quota or UU changes are introduced here.

## Native receive allocation change

`nativeConn.Read` previously created a cancellable context and cancellation
closure for every received packet, even when no read deadline was installed.
The ordinary WireGuard receive loop does not install a per-packet deadline.
The new native-only path waits directly on the bounded incoming channel, the
connection-close channel and a read-deadline-change channel. It creates a timer
only for an actual nonzero deadline. Changing/clearing an absolute deadline
wakes a pending read; expiry remains effective until explicitly changed.
Expiry decisions recheck the current deadline generation under the same lock,
so an old ready timer cannot override a concurrent extension or clear.
Read/write deadline independence and connection-close wake-up are preserved.
The shared HTTPS/QUIC deadline implementation is unchanged.

On the same Linux executor, Go 1.27.1, deterministic 1232-byte packet producer,
three repetitions of `BenchmarkNativeReceive` measured:

| Version | Allocation/packet | Time/packet |
|---|---:|---:|
| Before | 256 B, 5 allocations | 1469–1527 ns |
| After | 0 B, 0 allocations | 1378–1726 ns |

The timing ranges overlap and the new range is noisy: this is an allocation
improvement, not demonstrated throughput or RTT improvement. At a hypothetical
20,000 packets/s, eliminating 256 B/packet avoids about 5.12 MB/s of allocation;
that arithmetic is not a measured WAN traffic rate. The generated-packet
benchmark includes payload copying/checking and does not exercise a Windows
NIC, TUN, encryption, Oracle or a mobile network.

Local checks: receive-queue frame integrity/short reads and dynamic deadline
change/clear/expiry/close tests pass under the Go race detector. Windows x64
native transport tests cross-compile using a temporary module file; the real
repository's dependency files are untouched. This sandbox rejects real UDP
socket creation (`operation not permitted`), so real loopback UDP tests and
all-carrier Oracle acceptance belong to the existing Windows cloud workflow.

## QUIC throughput limitation retained explicitly

The current HTTP/3 CONNECT-UDP carrier sends WireGuard frames up to 1000 bytes
in HTTP datagrams. Larger frames use reliable DATAGRAM capsules on the request
stream. This is a conservative compatibility policy for QUIC's minimum-sized
path, not an arbitrary network speed cap. A typical full 1280-byte inner packet
produces a WireGuard frame larger than 1000 bytes; high-volume traffic can
therefore encounter stream head-of-line blocking when packets are lost.

Blindly raising that threshold can exceed the negotiated/path datagram budget.
Blindly reducing dual-stack inner MTU below 1280 breaks the IPv6 policy.
A real unreliable large-packet improvement needs bounded reassembly plus an
explicitly negotiated client/server extension and mixed-version, packet-loss,
quota/revocation and low-MTU acceptance. This audit does not silently introduce
such a protocol change or claim QUIC now matches native UDP throughput.
