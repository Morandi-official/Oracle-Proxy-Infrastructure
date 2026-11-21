package org.morandi.proxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.SystemClock;

import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Statistics;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.config.Config;
import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;
import com.wireguard.crypto.KeyPair;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

public final class TunnelEngine {
    private static final long VERIFY_DEADLINE_MS = 4_500;
    private static final long VPN_NETWORK_WAIT_MS = 1_500;
    private static final long CONNECT_DEADLINE_MS = 38_000;
    private static final int MAX_TRACE_BYTES = 8_192;
    private static final String TRACE4 = "https://1.1.1.1/cdn-cgi/trace";
    private static final String TRACE6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace";

    public interface Callback {
        void trying(String endpoint);
        boolean cancelled();
    }

    interface Probe {
        String verify(Network vpn, String expected, boolean ipv6, long timeoutMs) throws IOException;
    }

    public static final class Result {
        public final String endpoint;
        public final String ipv4;
        public final String ipv6;

        Result(String endpoint, String ipv4, String ipv6) {
            this.endpoint = endpoint;
            this.ipv4 = ipv4;
            this.ipv6 = ipv6;
        }
    }

    private final Context context;
    private final ConnectivityManager connectivity;
    private final Probe probe;
    private final boolean allowPrivateTestAddresses;
    private volatile boolean up;
    private volatile boolean expectedDown;
    private volatile Runnable onRevocation;
    private GoBackend backend;
    private TunnelProfile profile;
    private TunnelProfile.Candidate connected;
    private final Tunnel tunnel = new Tunnel() {
        @Override public String getName() {
            return "Proxy";
        }

        @Override public void onStateChange(State state) {
            boolean wasUp = up;
            up = state == State.UP;
            Runnable listener = onRevocation;
            if (wasUp && !up && !expectedDown && listener != null) {
                listener.run();
            }
        }
    };

    public TunnelEngine(Context context) {
        this(context, TunnelEngine::verifyCloudflare, false);
    }

    TunnelEngine(Context context, Probe probe, boolean allowPrivateTestAddresses) {
        this.context = context.getApplicationContext();
        this.connectivity = this.context.getSystemService(ConnectivityManager.class);
        this.probe = probe;
        this.allowPrivateTestAddresses = allowPrivateTestAddresses;
    }

    public static String generatePrivateKey() {
        return new KeyPair().getPrivateKey().toBase64();
    }

    public static String publicKey(String privateKey) {
        return new KeyPair(parsePrivateKey(privateKey)).getPublicKey().toBase64();
    }

    private static Key parsePrivateKey(String encoded) {
        try {
            return Key.fromBase64(encoded);
        } catch (KeyFormatException error) {
            throw new IllegalArgumentException("INVALID_PRIVATE_KEY");
        }
    }

    public void setRevocationListener(Runnable listener) {
        onRevocation = listener;
    }

    public boolean isUp() {
        return up;
    }

    public synchronized Result connect(JSONObject payload, String privateKey, int preferredPort,
                                       Callback callback) throws IOException {
        if (VpnService.prepare(context) != null) {
            throw new IOException("VPN_PERMISSION_REQUIRED");
        }
        TunnelProfile target = TunnelProfile.read(payload, preferredPort, allowPrivateTestAddresses);
        Key key = parsePrivateKey(privateKey);
        disconnect();
        if (backend == null) {
            try {
                backend = new GoBackend(context);
            } catch (RuntimeException | LinkageError error) {
                throw new IOException("WIREGUARD_UNAVAILABLE");
            }
        }
        long deadline = SystemClock.elapsedRealtime() + CONNECT_DEADLINE_MS;
        for (TunnelProfile.Candidate candidate : target.candidates) {
            if (callback.cancelled()) {
                throw new IOException("VPN_CONNECT_CANCELLED");
            }
            if (SystemClock.elapsedRealtime() >= deadline) {
                break;
            }
            callback.trying(candidate.endpoint());
            // There is no client-side traffic bypass while a full-route TUN is up.
            // Android can restore normal routes between attempts when a TUN is torn down.
            Config config = target.wireGuardConfig(candidate, key);
            try {
                ProxyVpnService.start(context, callback);
                if (backend.setState(tunnel, Tunnel.State.UP, config) != Tunnel.State.UP) {
                    throw new IOException("VPN_START_FAILED");
                }
                Result result = verify(target, candidate, deadline, callback);
                if (result != null && up && !callback.cancelled()) {
                    profile = target;
                    connected = candidate;
                    return result;
                }
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                disconnect();
                throw new IOException("VPN_CONNECT_CANCELLED");
            } catch (Exception error) {
                // Native or configuration exceptions can contain internal arguments.
                // Return only this allowlisted status to the controller.
                disconnect();
                if (error instanceof IOException &&
                        "VPN_SERVICE_START_FAILED".equals(error.getMessage())) {
                    throw new IOException("VPN_SERVICE_START_FAILED");
                }
                continue;
            }
            disconnect();
        }
        throw new IOException(callback.cancelled() ? "VPN_CONNECT_CANCELLED"
                : "VPN_EXIT_NOT_VERIFIED");
    }

    public synchronized boolean verifyConnected() {
        if (!up || profile == null || connected == null) {
            return false;
        }
        try {
            return verify(profile, connected, SystemClock.elapsedRealtime() + VERIFY_DEADLINE_MS,
                    null) != null && up;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    public synchronized void disconnect() throws IOException {
        profile = null;
        connected = null;
        expectedDown = true;
        boolean down;
        boolean serviceStopped;
        try {
            down = backend == null
                    || backend.setState(tunnel, Tunnel.State.DOWN, null) == Tunnel.State.DOWN;
        } catch (Exception error) {
            down = false;
        } finally {
            try {
                serviceStopped = ProxyVpnService.stop(context);
            } catch (RuntimeException error) {
                serviceStopped = false;
            } finally {
                expectedDown = false;
            }
        }
        if (!down || !serviceStopped || up) {
            throw new IOException("VPN_STOP_FAILED");
        }
    }

    private Result verify(TunnelProfile target, TunnelProfile.Candidate candidate, long deadline,
                          Callback callback) throws InterruptedException {
        long probeDeadline = Math.min(deadline, SystemClock.elapsedRealtime() + VERIFY_DEADLINE_MS);
        Network vpn = awaitNetwork(target, Math.min(probeDeadline,
                SystemClock.elapsedRealtime() + VPN_NETWORK_WAIT_MS), callback);
        if (vpn == null || cancelled(callback)) {
            return null;
        }
        long remaining = probeDeadline - SystemClock.elapsedRealtime();
        if (remaining <= 0) {
            return null;
        }
        ExecutorService executor = Executors.newFixedThreadPool(target.ipv6Exit.isEmpty() ? 1 : 2);
        Future<String> v4 = executor.submit(() -> checkAddress(vpn, candidate.exit, false, remaining));
        Future<String> v6 = target.ipv6Exit.isEmpty() ? null : executor.submit(
                () -> checkAddress(vpn, target.ipv6Exit, true, remaining));
        try {
            while (up && !cancelled(callback) && SystemClock.elapsedRealtime() < probeDeadline) {
                if (v4.isDone() && (v6 == null || v6.isDone())) {
                    String ipv4;
                    String ipv6;
                    try {
                        ipv4 = v4.get();
                        ipv6 = v6 == null ? "" : v6.get();
                    } catch (ExecutionException error) {
                        return null;
                    }
                    Statistics.PeerStats stats = backend.getStatistics(tunnel).peer(candidate.key);
                    return stats != null && stats.latestHandshakeEpochMillis() > 0
                            ? new Result(candidate.endpoint(), ipv4, ipv6) : null;
                }
                Thread.sleep(30);
            }
            return null;
        } finally {
            v4.cancel(true);
            if (v6 != null) {
                v6.cancel(true);
            }
            executor.shutdownNow();
        }
    }

    private String checkAddress(Network vpn, String expected, boolean ipv6, long timeoutMs)
            throws IOException {
        String address = probe.verify(vpn, expected, ipv6, timeoutMs);
        InetAddress actual = TunnelProfile.numeric(address, ipv6, !allowPrivateTestAddresses);
        if (!actual.equals(TunnelProfile.numeric(expected, ipv6, !allowPrivateTestAddresses))) {
            throw new IOException("VPN_EXIT_MISMATCH");
        }
        return actual.getHostAddress();
    }

    private Network awaitNetwork(TunnelProfile target, long deadline, Callback callback)
            throws InterruptedException {
        do {
            if (!up || cancelled(callback)) {
                return null;
            }
            // Use the network owned by this VPN and this exact profile, not the underlying
            // Android default selected before VpnService finished installing routes.
            Network network = connectivity.getActiveNetwork();
            if (network != null && matches(network, target.interfaceAddresses)) {
                return network;
            }
            for (Network candidate : connectivity.getAllNetworks()) {
                if (matches(candidate, target.interfaceAddresses)) {
                    return candidate;
                }
            }
            Thread.sleep(30);
        } while (SystemClock.elapsedRealtime() < deadline);
        return null;
    }

    private boolean matches(Network network, Set<InetAddress> addresses) {
        NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
        LinkProperties links = connectivity.getLinkProperties(network);
        if (capabilities == null || !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                || links == null) {
            return false;
        }
        Set<InetAddress> found = new HashSet<>();
        for (LinkAddress address : links.getLinkAddresses()) {
            found.add(address.getAddress());
        }
        return found.containsAll(addresses);
    }

    private static boolean cancelled(Callback callback) {
        return callback != null && callback.cancelled();
    }

    private static String verifyCloudflare(Network vpn, String expected, boolean ipv6, long timeoutMs)
            throws IOException {
        HttpsURLConnection connection = (HttpsURLConnection) vpn.openConnection(
                new URL(ipv6 ? TRACE6 : TRACE4), Proxy.NO_PROXY);
        try {
            int timeout = (int) Math.max(1, Math.min(timeoutMs, VERIFY_DEADLINE_MS));
            connection.setConnectTimeout(timeout);
            connection.setReadTimeout(timeout);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestProperty("Connection", "close");
            if (connection.getResponseCode() != 200) {
                throw new IOException("VPN_EXIT_PROBE_HTTP_FAILED");
            }
            try (InputStream stream = connection.getInputStream();
                 ByteArrayOutputStream data = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[1024];
                int count;
                while ((count = stream.read(buffer)) != -1) {
                    if (data.size() + count > MAX_TRACE_BYTES) {
                        throw new IOException("VPN_EXIT_PROBE_INVALID");
                    }
                    data.write(buffer, 0, count);
                }
                String match = null;
                for (String line : new String(data.toByteArray(), StandardCharsets.US_ASCII)
                        .split("\\r?\\n")) {
                    if (line.startsWith("ip=")) {
                        if (match != null) {
                            throw new IOException("VPN_EXIT_PROBE_INVALID");
                        }
                        match = line.substring(3);
                    }
                }
                if (match != null) {
                    return match;
                }
                throw new IOException("VPN_EXIT_PROBE_INVALID");
            }
        } finally {
            connection.disconnect();
        }
    }
}
