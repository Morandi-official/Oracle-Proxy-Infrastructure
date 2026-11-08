using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
namespace OracleProxy.Product;

// Resolves only the fixed management hostname through the physical NIC's DNS.
// DNS never authenticates a server: HTTPS still verifies the fixed hostname.
internal static class PhysicalDns
{
    private static byte[] Query(ushort id,string hostname)
    {
        using var stream=new MemoryStream();var header=new byte[12];BinaryPrimitives.WriteUInt16BigEndian(header,id);header[2]=1;header[5]=1;stream.Write(header);
        foreach(string label in hostname.Split('.')){var bytes=Encoding.ASCII.GetBytes(label);stream.WriteByte((byte)bytes.Length);stream.Write(bytes);}
        stream.Write([0,0,1,0,1]);return stream.ToArray();
    }
    private static int NameEnd(byte[] value,int offset)
    {
        for(int n=0;n<128;n++){
            if(offset>=value.Length)throw new IOException("DNS_RESPONSE_REJECTED");int size=value[offset++];
            if(size==0)return offset;
            if((size&0xc0)==0xc0){if(offset>=value.Length)throw new IOException("DNS_RESPONSE_REJECTED");return offset+1;}
            if(size>63 || offset+size>value.Length)throw new IOException("DNS_RESPONSE_REJECTED");offset+=size;
        }
        throw new IOException("DNS_RESPONSE_REJECTED");
    }
    internal static string[] Parse(byte[] value,byte[] query)
    {
        if(value.Length<query.Length || value.Length>4096 || value[0]!=query[0] || value[1]!=query[1] || (value[2]&0x82)!=0x80 || (value[3]&15)!=0 || value[4]!=0 || value[5]!=1 || !value.AsSpan(12,query.Length-12).SequenceEqual(query.AsSpan(12)))throw new IOException("DNS_RESPONSE_REJECTED");
        int count=BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(6)),offset=query.Length;
        if(count>32)throw new IOException("DNS_RESPONSE_REJECTED");var result=new List<string>();
        for(int n=0;n<count;n++){
            offset=NameEnd(value,offset);if(offset+10>value.Length)throw new IOException("DNS_RESPONSE_REJECTED");
            int type=BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(offset)),cls=BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(offset+2)),length=BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(offset+8));offset+=10;
            if(offset+length>value.Length)throw new IOException("DNS_RESPONSE_REJECTED");
            if(type==1 && cls==1 && length==4){try{result.Add(EndpointCatalog.Public(new IPAddress(value.AsSpan(offset,4)).ToString()));}catch(IOException){}}
            offset+=length;
        }
        return result.Distinct().Take(4).ToArray();
    }
    internal static async Task<string[]> Resolve(uint index,CancellationToken cancel)
    {
        var nic=NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n=>n.GetIPProperties().GetIPv4Properties()?.Index==(int)index);
        var servers=nic?.GetIPProperties().DnsAddresses.Where(a=>a.AddressFamily==AddressFamily.InterNetwork && !IPAddress.IsLoopback(a)).Take(2).ToArray() ?? [];
        foreach(var server in servers){
            try{
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancel);timeout.CancelAfter(TimeSpan.FromSeconds(1));
                using var socket=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);
                socket.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder((int)index));
                await socket.ConnectAsync(new IPEndPoint(server,53),timeout.Token);
                byte[] request=Query((ushort)RandomNumberGenerator.GetInt32(65536),AccountApi.Base.Host);
                await socket.SendAsync(request,SocketFlags.None,timeout.Token);var buffer=new byte[4096];int count=await socket.ReceiveAsync(buffer,SocketFlags.None,timeout.Token);
                var result=Parse(buffer.AsSpan(0,count).ToArray(),request);if(result.Length>0)return result;
            }catch(Exception e) when(e is SocketException or IOException or OperationCanceledException){cancel.ThrowIfCancellationRequested();}
        }
        return [];
    }
}
