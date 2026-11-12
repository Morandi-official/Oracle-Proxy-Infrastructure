package dev.oracleproxy.client;

import com.wireguard.config.Config;
import com.wireguard.config.Interface;
import com.wireguard.config.Peer;
import com.wireguard.crypto.KeyPair;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Real library parser/builders, all test identities generated in process.
 * No fixed keys, live endpoints, credentials, or Android VPN access.
 */
public final class ConfigSafetyTests {
    private static Config fixture(boolean hasAddress, boolean hasDns,
                                  boolean hasIpv6Route, boolean hasEndpoint,
                                  boolean bypass, int peerCount) throws Exception {
        final Interface.Builder iface = new Interface.Builder()
            .setKeyPair(new KeyPair());
        if (hasAddress) iface.parseAddresses("10.77.0.50/32");
        if (hasDns) iface.parseDnsServers("198.51.100.53");
        if (bypass) iface.excludeApplication("dev.example.bypass");

        final Config.Builder config = new Config.Builder().setInterface(iface.build());
        for (int i = 0; i < peerCount; ++i) {
            final Peer.Builder peer = new Peer.Builder()
                .setPublicKey(new KeyPair().getPublicKey());
            peer.parseAllowedIPs(hasIpv6Route ? "0.0.0.0/0, ::/0" : "0.0.0.0/0");
            if (hasEndpoint) peer.parseEndpoint("198.51.100.42:443");
            config.addPeer(peer.build());
        }
        return config.build();
    }

    @Test public void strictFullTunnelAccepted() throws Exception {
        assertNull(ConfigSafety.rejectReason(fixture(true, true, true, true, false, 1)));
    }

    @Test public void noDnsRejected() throws Exception {
        assertNotNull(ConfigSafety.rejectReason(fixture(true, false, true, true, false, 1)));
    }

    @Test public void noIpv6RouteRejected() throws Exception {
        assertNotNull(ConfigSafety.rejectReason(fixture(true, true, false, true, false, 1)));
    }

    @Test public void missingInterfaceAddressRejected() throws Exception {
        assertNotNull(ConfigSafety.rejectReason(fixture(false, true, true, true, false, 1)));
    }

    @Test public void endpointMissingRejected() throws Exception {
        assertNotNull(ConfigSafety.rejectReason(fixture(true, true, true, false, false, 1)));
    }

    @Test public void bypassWithoutReviewRejected() throws Exception {
        assertNotNull(ConfigSafety.rejectReason(fixture(true, true, true, true, true, 1)));
    }

    @Test public void multiplePeersRejected() throws Exception {
        assertNotNull(ConfigSafety.rejectReason(fixture(true, true, true, true, false, 2)));
    }

    @Test public void zeroPeersRejected() throws Exception {
        assertNotNull(ConfigSafety.rejectReason(fixture(true, true, true, false, false, 0)));
    }
}
