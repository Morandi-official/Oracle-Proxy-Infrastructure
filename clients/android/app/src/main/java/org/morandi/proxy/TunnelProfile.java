package org.morandi.proxy;

import android.net.InetAddresses;

import com.wireguard.config.BadConfigException;
import com.wireguard.config.Config;
import com.wireguard.config.Interface;
import com.wireguard.config.Peer;
import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;
import com.wireguard.crypto.KeyPair;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class TunnelProfile {
    static final class Candidate {
        final String address;
        final int port;
        final Key key;
        final String exit;

        Candidate(String address, int port, Key key, String exit) {
            this.address = address;
            this.port = port;
            this.key = key;
            this.exit = exit;
        }

        String endpoint() {
            return address + ":" + port;
        }
    }

    final Set<InetAddress> interfaceAddresses;
    final List<Candidate> candidates;
    final String ipv6Exit;
    private final List<String> addresses;
    private final List<InetAddress> dns;
    private final boolean dualStack;

    private TunnelProfile(List<String> addresses, Set<InetAddress> interfaceAddresses,
                          List<InetAddress> dns, List<Candidate> candidates, boolean dualStack,
                          String ipv6Exit) {
        this.addresses = addresses;
        this.interfaceAddresses = interfaceAddresses;
        this.dns = dns;
        this.candidates = candidates;
        this.dualStack = dualStack;
        this.ipv6Exit = ipv6Exit;
    }

    static TunnelProfile read(JSONObject payload, int preferredPort, boolean allowPrivate)
            throws IOException {
        try {
            JSONObject tunnel = payload.getJSONObject("tunnel");
            String ipv6Policy = tunnel.getString("ipv6_policy");
            boolean dualStack = "tunnel".equals(ipv6Policy);
            require(dualStack || "block".equals(ipv6Policy));
            String ipv6Exit = dualStack
                    ? numeric(tunnel.getString("ipv6_egress"), true, !allowPrivate).getHostAddress()
                    : "";
            List<String> addresses = stringList(tunnel.getJSONArray("addresses"), dualStack ? 2 : 1);
            require(addresses.size() == (dualStack ? 2 : 1));
            Set<InetAddress> interfaceAddresses = new HashSet<>();
            Set<Integer> families = new HashSet<>();
            for (String cidr : addresses) {
                int separator = cidr.lastIndexOf('/');
                require(separator > 0);
                String address = cidr.substring(0, separator);
                boolean ipv6 = address.indexOf(':') >= 0;
                require((dualStack || !ipv6) && cidr.substring(separator + 1)
                        .equals(ipv6 ? "128" : "32"));
                InetAddress parsed = numeric(address, ipv6, false);
                require(!parsed.isLoopbackAddress() && !parsed.isAnyLocalAddress()
                        && !parsed.isMulticastAddress() && !parsed.isLinkLocalAddress());
                require(families.add(ipv6 ? 6 : 4));
                interfaceAddresses.add(parsed);
            }
            require(families.contains(4));
            Set<String> allowed = new HashSet<>(stringList(
                    tunnel.getJSONArray("allowed_ips"), dualStack ? 2 : 1));
            require(allowed.size() == (dualStack ? 2 : 1) && allowed.contains("0.0.0.0/0")
                    && (!dualStack || allowed.contains("::/0")));
            List<InetAddress> dns = new ArrayList<>();
            for (String address : stringList(tunnel.getJSONArray("dns"), 4)) {
                boolean ipv6 = address.indexOf(':') >= 0;
                require(dualStack || !ipv6);
                InetAddress parsed = numeric(address, ipv6, false);
                require(!parsed.isLoopbackAddress() && !parsed.isAnyLocalAddress()
                        && !parsed.isMulticastAddress() && !parsed.isLinkLocalAddress());
                dns.add(parsed);
            }
            require(!dns.isEmpty());

            String primary = numeric(tunnel.getString("transport_address"), false, !allowPrivate)
                    .getHostAddress();
            List<String> endpoints = new ArrayList<>();
            endpoints.add(primary);
            if (tunnel.has("backup_address") && !tunnel.isNull("backup_address")) {
                String backup = numeric(tunnel.getString("backup_address"), false, !allowPrivate)
                        .getHostAddress();
                require(!backup.equals(primary));
                endpoints.add(backup);
            }
            List<String> egress = new ArrayList<>();
            JSONArray candidateIps = tunnel.optJSONArray("egress_ipv4_candidates");
            if (candidateIps != null) {
                for (String address : stringList(candidateIps, 2)) {
                    egress.add(numeric(address, false, !allowPrivate).getHostAddress());
                }
                require(!egress.isEmpty() && new HashSet<>(egress).size() == egress.size());
                if (egress.size() > 1) {
                    require(egress.containsAll(endpoints));
                }
            }
            JSONObject endpointKeys = tunnel.optJSONObject("server_public_keys");
            require(endpointKeys != null || endpoints.size() == 1);
            List<Integer> ports = orderedPorts(tunnel.getJSONArray("native_udp_ports"), preferredPort);
            List<Candidate> candidates = new ArrayList<>();
            for (String address : endpoints) {
                Key key = Key.fromBase64(endpointKeys == null
                        ? tunnel.getString("server_public_key")
                        : endpointKeys.getString(address));
                require(!"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".equals(key.toBase64()));
                String exit = egress.size() == 1 ? egress.get(0) : address;
                for (int port : ports) {
                    candidates.add(new Candidate(address, port, key, exit));
                }
            }
            return new TunnelProfile(addresses, Collections.unmodifiableSet(interfaceAddresses),
                    dns, Collections.unmodifiableList(candidates), dualStack, ipv6Exit);
        } catch (JSONException | KeyFormatException | IllegalArgumentException error) {
            throw new IOException("INVALID_TUNNEL_PROFILE");
        }
    }

    private static List<Integer> orderedPorts(JSONArray values, int preferred) throws JSONException {
        require(values.length() > 0 && values.length() <= 3);
        Set<Integer> advertised = new LinkedHashSet<>();
        for (int i = 0; i < values.length(); i++) {
            Object value = values.get(i);
            require(value instanceof Integer || value instanceof Long);
            long port = ((Number) value).longValue();
            require(port >= 1 && port <= 65535 && advertised.add((int) port));
        }
        List<Integer> ports = new ArrayList<>();
        if (advertised.remove(preferred)) {
            ports.add(preferred);
        }
        if (advertised.remove(443)) {
            ports.add(443);
        }
        ports.addAll(advertised);
        return ports;
    }

    Config wireGuardConfig(Candidate candidate, Key key) throws IOException {
        try {
            Interface network = new Interface.Builder()
                    .setKeyPair(new KeyPair(key))
                    .parseAddresses(String.join(", ", addresses))
                    .addDnsServers(dns)
                    .setMtu(dualStack ? 1280 : 1200)
                    .build();
            Peer peer = new Peer.Builder()
                    .setPublicKey(candidate.key)
                    .parseAllowedIPs(dualStack ? "0.0.0.0/0, ::/0" : "0.0.0.0/0")
                    .parseEndpoint(candidate.endpoint())
                    .setPersistentKeepalive(25)
                    .build();
            return new Config.Builder().setInterface(network).addPeer(peer).build();
        } catch (BadConfigException error) {
            throw new IOException("INVALID_TUNNEL_PROFILE");
        }
    }

    private static List<String> stringList(JSONArray values, int maximum) throws JSONException {
        require(values.length() <= maximum);
        List<String> entries = new ArrayList<>();
        for (int i = 0; i < values.length(); i++) {
            Object value = values.get(i);
            require(value instanceof String && ((String) value).length() <= 64);
            entries.add((String) value);
        }
        return entries;
    }

    static InetAddress numeric(String value, boolean ipv6, boolean publicOnly) {
        require(value != null && !value.isEmpty() && value.length() <= 47
                && value.matches(ipv6 ? "[0-9A-Fa-f:.]+" : "[0-9.]+"));
        InetAddress address = InetAddresses.parseNumericAddress(value);
        require(ipv6 ? address instanceof Inet6Address : address instanceof Inet4Address);
        if (!ipv6) {
            require(value.equals(address.getHostAddress()));
        }
        if (publicOnly) {
            require(!address.isAnyLocalAddress() && !address.isLoopbackAddress()
                    && !address.isLinkLocalAddress() && !address.isSiteLocalAddress()
                    && !address.isMulticastAddress());
            byte[] bytes = address.getAddress();
            int first = bytes[0] & 255;
            int second = bytes[1] & 255;
            int third = bytes[2] & 255;
            if (ipv6) {
                require((first & 0xe0) == 0x20 && !(first == 0x20 && second == 1
                        && third == 0x0d && (bytes[3] & 255) == 0xb8));
            } else {
                require(first > 0 && first < 224 && !(first == 100 && second >= 64 && second <= 127)
                        && !(first == 192 && second == 0 && (third == 0 || third == 2))
                        && !(first == 198 && (second == 18 || second == 19
                        || (second == 51 && third == 100)))
                        && !(first == 203 && second == 0 && third == 113));
            }
        }
        return address;
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new IllegalArgumentException("INVALID_TUNNEL_PROFILE");
        }
    }
}
