package perf
import("context";"fmt";"io";"sync";"sync/atomic";"testing";"time"
"github.com/sagernet/gvisor/pkg/tcpip"
"github.com/sagernet/gvisor/pkg/buffer"
"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
"github.com/sagernet/gvisor/pkg/tcpip/header"
"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
"github.com/sagernet/gvisor/pkg/tcpip/stack"
"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp")
func node(last byte,cc string)(*stack.Stack,*channel.Endpoint){
 s:=stack.New(stack.Options{NetworkProtocols:[]stack.NetworkProtocolFactory{ipv4.NewProtocol},TransportProtocols:[]stack.TransportProtocolFactory{tcp.NewProtocol}})
 e:=channel.New(4096,1200,"");if err:=s.CreateNIC(1,e);err!=nil{panic(err)}
 addr:=tcpip.AddrFrom4([4]byte{10,0,0,last})
 if err:=s.AddProtocolAddress(1,tcpip.ProtocolAddress{Protocol:ipv4.ProtocolNumber,AddressWithPrefix:tcpip.AddressWithPrefix{Address:addr,PrefixLen:24}},stack.AddressProperties{});err!=nil{panic(err)}
 s.SetRouteTable([]tcpip.Route{{Destination:header.IPv4EmptySubnet,NIC:1}})
 v:=tcpip.CongestionControlOption(cc);if err:=s.SetTransportProtocolOption(tcp.ProtocolNumber,&v);err!=nil{panic(err)}
 sack:=tcpip.TCPSACKEnabled(true);s.SetTransportProtocolOption(tcp.ProtocolNumber,&sack)
 moderate:=tcpip.TCPModerateReceiveBufferOption(true);s.SetTransportProtocolOption(tcp.ProtocolNumber,&moderate)
 return s,e
}
func trial(cc string,dropEvery int) int64 {
 a,x:=node(1,cc);b,y:=node(2,"cubic");defer a.Close();defer b.Close()
 ctx,cancel:=context.WithCancel(context.Background());defer cancel();var workers sync.WaitGroup
 type scheduled struct{pkt *stack.PacketBuffer;at time.Time}
 wire:=func(src,dst *channel.Endpoint){defer workers.Done();queue:=make(chan scheduled,4096);var feeder sync.WaitGroup;feeder.Add(1)
 go func(){defer feeder.Done();defer close(queue);n:=0;for{pkt:=src.ReadContext(ctx);if pkt==nil{return};n++;if dropEvery>0&&n>20&&n%dropEvery==0&&pkt.Size()>100{pkt.DecRef();continue};select{case queue<-scheduled{pkt,time.Now().Add(100*time.Millisecond)}:case <-ctx.Done():pkt.DecRef();return}}}()
 for item:=range queue{wait:=time.NewTimer(time.Until(item.at));select{case <-ctx.Done():wait.Stop();case <-wait.C:incoming:=stack.NewPacketBuffer(stack.PacketBufferOptions{Payload:buffer.MakeWithView(item.pkt.ToView())});dst.InjectInbound(ipv4.ProtocolNumber,incoming);incoming.DecRef()};item.pkt.DecRef()};feeder.Wait()}
 workers.Add(2);go wire(x,y);go wire(y,x)
 listener,err:=gonet.ListenTCP(b,tcpip.FullAddress{NIC:1,Addr:tcpip.AddrFrom4([4]byte{10,0,0,2}),Port:8000},ipv4.ProtocolNumber);if err!=nil{panic(err)};defer listener.Close()
 var received atomic.Int64
 go func(){c,err:=listener.Accept();if err!=nil{return};defer c.Close();buf:=make([]byte,65536);for{n,e:=c.Read(buf);received.Add(int64(n));if e!=nil{return}}}()
 dialCtx,dialCancel:=context.WithTimeout(ctx,3*time.Second);defer dialCancel();client,err:=gonet.DialTCPWithBind(dialCtx,a,tcpip.FullAddress{},tcpip.FullAddress{NIC:1,Addr:tcpip.AddrFrom4([4]byte{10,0,0,2}),Port:8000},ipv4.ProtocolNumber);if err!=nil{panic(err)}
 go func(){client.SetWriteDeadline(time.Now().Add(8*time.Second));io.Copy(client,zeroReader{})}()
 time.Sleep(2*time.Second);start:=received.Load();time.Sleep(6*time.Second);result:=received.Load()-start
 client.Close();cancel();listener.Close();workers.Wait();return result
}
type zeroReader struct{}
func(zeroReader)Read(b []byte)(int,error){clear(b);return len(b),nil}
func TestControlledHighLatencyCongestion(t *testing.T){for _,loss:=range []int{0,120,600}{for _,cc:=range []string{"reno","cubic"}{n:=trial(cc,loss);fmt.Printf("CONTROLLED_RTT200MS_LOSS_EVERY%d_%s_MBPS=%.3f\n",loss,cc,float64(n)*8/6e6);if n==0{t.Fatal("no bytes delivered")}}}}
