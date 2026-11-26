package org.morandi.proxy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.wireguard.config.Config;
import com.wireguard.crypto.Key;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;

@RunWith(AndroidJUnit4.class)
public final class TunnelProfileTest {
    private static final String PRIMARY = "152.67.156.100";
    private static final String BACKUP = "150.230.113.158";

    @Test public void endpointOrderAndKeysFollowAccountPolicy() throws Exception {
        String primaryKey = TunnelEngine.publicKey(TunnelEngine.generatePrivateKey());
        String backupKey = TunnelEngine.publicKey(TunnelEngine.generatePrivateKey());
        JSONObject tunnel = tunnel(primaryKey);
        tunnel.put("backup_address", BACKUP);
        tunnel.put("server_public_keys", new JSONObject().put(PRIMARY, primaryKey).put(BACKUP, backupKey));
        tunnel.put("egress_ipv4_candidates", new JSONArray().put(PRIMARY).put(BACKUP));

        TunnelProfile profile = read(tunnel, 8443);
        assertEquals(6, profile.candidates.size());
        assertEquals(PRIMARY + ":8443", profile.candidates.get(0).endpoint());
        assertEquals(PRIMARY + ":443", profile.candidates.get(1).endpoint());
        assertEquals(PRIMARY + ":51820", profile.candidates.get(2).endpoint());
        assertEquals(BACKUP + ":8443", profile.candidates.get(3).endpoint());
        assertEquals(primaryKey, profile.candidates.get(0).key.toBase64());
        assertEquals(backupKey, profile.candidates.get(3).key.toBase64());
        assertEquals(PRIMARY, profile.candidates.get(0).exit);
        assertEquals(BACKUP, profile.candidates.get(3).exit);
    }

    @Test public void onlyUsesAdvertisedEndpointsAndPorts() throws Exception {
        String key = TunnelEngine.publicKey(TunnelEngine.generatePrivateKey());
        JSONObject tunnel = tunnel(key);
        TunnelProfile profile = read(tunnel, 123);
        assertEquals(3, profile.candidates.size());
        assertTrue(profile.candidates.stream().allMatch(
                candidate -> PRIMARY.equals(candidate.address) && candidate.port != 123));

        tunnel.put("backup_address", BACKUP);
        assertThrows(IOException.class, () -> read(tunnel, 0));
        tunnel.put("server_public_keys", new JSONObject().put(PRIMARY, key));
        assertThrows(IOException.class, () -> read(tunnel, 0));
    }

    @Test public void permitsExactlyTheRequestedDefaultRoutesAndFamilies() throws Exception {
        Key privateKey = Key.fromBase64(TunnelEngine.generatePrivateKey());
        JSONObject tunnel = tunnel(TunnelEngine.publicKey(privateKey.toBase64()));
        TunnelProfile blocked = read(tunnel, 0);
        Config blockedConfig = blocked.wireGuardConfig(blocked.candidates.get(0), privateKey);
        assertEquals(1, blockedConfig.getInterface().getAddresses().size());
        assertEquals(1, blockedConfig.getPeers().get(0).getAllowedIps().size());
        assertTrue(blocked.ipv6Exit.isEmpty());
        assertEquals(1200, blockedConfig.getInterface().getMtu().get().intValue());
        assertEquals(privateKey, blockedConfig.getInterface().getKeyPair().getPrivateKey());
        assertEquals("1.1.1.1", blockedConfig.getInterface().getDnsServers().iterator()
                .next().getHostAddress());

        tunnel.put("ipv6_policy", "tunnel");
        tunnel.put("ipv6_egress", "2603:c020:c015:8100::10");
        tunnel.getJSONArray("addresses").put("fd77:4242:77::2/128");
        tunnel.getJSONArray("allowed_ips").put("::/0");
        TunnelProfile dual = read(tunnel, 0);
        Config dualConfig = dual.wireGuardConfig(dual.candidates.get(0), privateKey);
        assertEquals(2, dualConfig.getInterface().getAddresses().size());
        assertEquals(2, dualConfig.getPeers().get(0).getAllowedIps().size());

        assertEquals(1280, dualConfig.getInterface().getMtu().get().intValue());
        assertEquals(PRIMARY + ":443", dualConfig.getPeers().get(0).getEndpoint().get().toString());
        assertEquals(dual.candidates.get(0).key, dualConfig.getPeers().get(0).getPublicKey());
        assertEquals(25, dualConfig.getPeers().get(0).getPersistentKeepalive().get().intValue());

        tunnel.put("allowed_ips", new JSONArray().put("10.77.0.0/24").put("::/0"));
        assertThrows(IOException.class, () -> read(tunnel, 0));
    }

    @Test public void rejectsInternalEndpointsAndMalformedProfilesInProduction() throws Exception {
        String key = TunnelEngine.publicKey(TunnelEngine.generatePrivateKey());
        JSONObject tunnel = tunnel(key);
        tunnel.put("transport_address", "10.0.2.2");
        assertThrows(IOException.class, () -> read(tunnel, 0));
        tunnel.put("transport_address", PRIMARY);
        tunnel.getJSONArray("addresses").put("0.0.0.0/32");
        assertThrows(IOException.class, () -> read(tunnel, 0));
    }

    private static JSONObject tunnel(String key) throws Exception {
        return new JSONObject()
                .put("transport_address", PRIMARY)
                .put("server_public_key", key)
                .put("addresses", new JSONArray().put("10.77.0.2/32"))
                .put("allowed_ips", new JSONArray().put("0.0.0.0/0"))
                .put("dns", new JSONArray().put("1.1.1.1"))
                .put("ipv6_policy", "block")
                .put("native_udp_ports", new JSONArray().put(51820).put(443).put(8443));
    }

    private static TunnelProfile read(JSONObject tunnel, int port) throws Exception {
        return TunnelProfile.read(new JSONObject().put("tunnel", tunnel), port, false);
    }
}
