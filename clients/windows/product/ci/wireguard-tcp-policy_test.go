//go:build with_gvisor

// Compiled against the actual vendored endpoint in disposable CI; not a binary payload.
package wireguard

import (
 "testing"
 "github.com/sagernet/gvisor/pkg/tcpip"
 "github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
)

func TestOracleActualWireGuardTCPPolicy(t *testing.T) {
 d,err:=newStackDevice(DeviceOptions{MTU:1200})
 if err!=nil {t.Fatal(err)}
 defer d.stack.Close()
 var cc tcpip.CongestionControlOption
 if err:=d.stack.TransportProtocolOption(tcp.ProtocolNumber,&cc);err!=nil||cc!="cubic" {t.Fatal("CUBIC policy not applied to actual WireGuard stack",err,cc)}
 var receive tcpip.TCPReceiveBufferSizeRangeOption
 var send tcpip.TCPSendBufferSizeRangeOption
 if err:=d.stack.TransportProtocolOption(tcp.ProtocolNumber,&receive);err!=nil{t.Fatal(err)}
 if err:=d.stack.TransportProtocolOption(tcp.ProtocolNumber,&send);err!=nil{t.Fatal(err)}
 if receive.Default!=1<<20||receive.Max!=8<<20||send.Default!=1<<20||send.Max!=6<<20{t.Fatal("unexpected desktop TCP buffers",receive,send)}
 if d.mtu!=1200{t.Fatal("MTU changed")}
 t.Log("ACTUAL_WIREGUARD_CUBIC_DESKTOP_BUFFERS_AND_MTU=PASS")
}
