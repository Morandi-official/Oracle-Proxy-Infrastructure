# Native WireGuard UDP8443 path

MetaWise's paired attempt received response-shaped packets at Oracle's physical
interface on51820 and443, while the client exported no receive events. This is
not proof of carrier blocking. Add a fixed native8443 path to test a port already
used by the QUIC backup, without changing the normal native port order.

At UDP8443, redirect only the existing four-byte WireGuard type signatures to
the existing51820 listener. QUIC remains on8443. There is no generic forwarding
API, extra server key, duplicate concurrent same-key client, or new OCI rule.
The kernel reverses the port translation for replies. Advertise8443 only in the
authenticated native-port metadata when the WG listen port is51820. Existing
clients continue to choose51820/443.

Validate actual request/reply port translation and preservation of non-WG QUIC
traffic in disposable namespaces on443 and8443, plus current public QUIC health
after deployment. Count native header shapes on8443 separately from other QUIC
traffic. Neither these tests nor aggregate counts prove MetaWise connectivity;
a client must verify an actual Oracle exit before reporting native success.
