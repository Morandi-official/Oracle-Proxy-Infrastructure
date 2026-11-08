using System.Text.Json.Nodes;
namespace OracleProxy.Product;

// A port preference is a performance hint, never permission to use an
// arbitrary destination or to bypass WireGuard authentication.
internal static class NativeUdpPortPolicy
{
    internal static bool Upgrade(DurableState secret)
    {
        if(secret.NativeUdpPortPolicyVersion>=1)return false;
        secret.NativeUdpPortPolicyVersion=1;
        secret.NativeUdpAdaptive=true;
        secret.CarrierHintUntil=0; // Reassess a fallback learned by the old pinned plan.
        // Older ordinary UI selections persisted a hard 8443 pin. Migrate it
        // once; a later explicit single-port diagnostic remains explicit.
        if(secret.NativeUdpPortPreference==8443)secret.NativeUdpPortPreference=0;
        return true;
    }

    internal static int[] Select(JsonObject state,DurableState secret,int endpointPort)
    {
        if(secret.NativeUdpPortPreference is not (0 or 443 or 8443 or 51820))throw new IOException("INVALID_NATIVE_PORT_PREFERENCE");
        if(secret.NativeUdpPortPreference>0){
            if(state["tunnel"]?["native_udp_ports"] is not JsonArray available || !available.Any(p=>p?.GetValue<int>()==secret.NativeUdpPortPreference))throw new IOException("NATIVE_UDP_PORT_NOT_AVAILABLE");
            return [secret.NativeUdpPortPreference];
        }
        bool available443=state["tunnel"]?["native_udp_ports"] is JsonArray ports && ports.Any(n=>n?.GetValue<int>()==443);
        if(endpointPort!=51820 || !available443)return [endpointPort];
        bool cached=secret.CarrierHint=="wireguard-udp" && secret.CarrierHintUntil>DateTimeOffset.UtcNow.ToUnixTimeSeconds() && secret.CarrierNetworkHash==CarrierMemory.NetworkHash(state);
        if(secret.NativeUdpAdaptive && TransportPolicy.Native8443Available(state))return cached && secret.NativeUdpPortHint==8443?[8443,443]:[443,8443];
        return cached && secret.NativeUdpPortHint==443?[443,51820]:[51820,443];
    }
}
