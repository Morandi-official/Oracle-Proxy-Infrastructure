package org.morandi.proxy.tailscale;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.InetAddresses;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.SystemClock;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

final class ExitCheck {
    static final URI V4 = URI.create("https://1.1.1.1/cdn-cgi/trace");
    static final URI V6 = URI.create("https://[2606:4700:4700::1111]/cdn-cgi/trace");
    private static final long MAX_PROOF_AGE_MS = 2_500;
    private final Context context;
    private final ConnectivityManager networks;

    ExitCheck(Context context) {
        this.context = context;
        networks = context.getSystemService(ConnectivityManager.class);
    }

    Proof verify(LocalControl control, AccountClient.Profile profile, long start, BooleanSupplier cancelled) throws Exception {
        long verificationStarted = SystemClock.elapsedRealtime();
        long deadline = verificationStarted + 10_000;
        var workers = Executors.newFixedThreadPool(2);
        var changed = new Semaphore(0);
        var listener = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) { changed.release(); }
            @Override public void onLost(Network network) { changed.release(); }
            @Override public void onLinkPropertiesChanged(Network network, android.net.LinkProperties properties) {
                changed.release();
            }
        };
        Network probing = null;
        Network triedQuic = null;
        long routeReady = -1;
        FamilyProof ipv4Verified = null;
        FamilyProof ipv6Verified = null;
        String expectedExit = Long.toString(profile.exitId());
        boolean registered = false;
        try {
            networks.registerNetworkCallback(new NetworkRequest.Builder()
                    .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .addTransportType(NetworkCapabilities.TRANSPORT_VPN).build(), listener);
            registered = true;
            while (SystemClock.elapsedRealtime() < deadline && !cancelled.getAsBoolean()) {
                var state = control.readState();
                var vpn = "Running".equals(state.state()) && expectedExit.equals(state.exitId())
                        ? vpnFor(state.addresses()) : null;
                if (probing == null || !probing.equals(vpn)) {
                    probing = vpn;
                    routeReady = vpn == null ? -1 : SystemClock.elapsedRealtime() - start;
                    ipv4Verified = null;
                    ipv6Verified = null;
                }
                if (vpn != null) {
                    long elapsed = SystemClock.elapsedRealtime() - start;
                    var first = !fresh(ipv4Verified, elapsed)
                            ? workers.submit(() -> proofTime(vpn, V4, profile.ipv4(), start)) : null;
                    var second = !fresh(ipv6Verified, elapsed)
                            ? workers.submit(() -> proofTime(vpn, V6, profile.ipv6(), start)) : null;
                    long batchDeadline = Math.min(deadline, SystemClock.elapsedRealtime() + 3_500);
                    boolean tryQuic = !vpn.equals(triedQuic);
                    if (tryQuic) triedQuic = vpn;
                    BooleanSupplier abort = () -> cancelled.getAsBoolean() || !vpn.equals(networks.getActiveNetwork());
                    try (var quic4 = tryQuic && first != null
                            ? ExitQuicProbe.start(context, vpn, V4, profile.ipv4(), start) : null;
                         var quic6 = tryQuic && second != null
                            ? ExitQuicProbe.start(context, vpn, V6, profile.ipv6(), start) : null) {
                        if (first != null) ipv4Verified = awaitProof(first, quic4, batchDeadline, abort);
                        if (second != null) ipv6Verified = awaitProof(second, quic6, batchDeadline, abort);
                    } finally {
                        if (first != null && !first.isDone()) first.cancel(true);
                        if (second != null && !second.isDone()) second.cancel(true);
                    }
                    long verifiedAt = SystemClock.elapsedRealtime() - start;
                    if (fresh(ipv4Verified, verifiedAt) && fresh(ipv6Verified, verifiedAt) && !abort.getAsBoolean()) {
                        var current = control.readState();
                        long currentAt = SystemClock.elapsedRealtime() - start;
                        if ("Running".equals(current.state()) && expectedExit.equals(current.exitId())
                                && vpn.equals(vpnFor(current.addresses()))
                                && fresh(ipv4Verified, currentAt) && fresh(ipv6Verified, currentAt)
                                && !cancelled.getAsBoolean()) {
                            return new Proof(vpn, routeReady, ipv4Verified.at(), ipv6Verified.at(),
                                    ipv4Verified.transport(), ipv6Verified.transport());
                        }
                    }
                }
                long elapsed = SystemClock.elapsedRealtime() - verificationStarted;
                changed.tryAcquire(elapsed < 800 ? 35 : 125, TimeUnit.MILLISECONDS);
                changed.drainPermits();
            }
            throw new IOException(cancelled.getAsBoolean() ? "CONNECTION_CANCELLED" : "EXIT_NOT_VERIFIED");
        } finally {
            workers.shutdownNow();
            if (registered) networks.unregisterNetworkCallback(listener);
        }
    }

    record Proof(Network network, long routeReadyMs, long ipv4VerifiedMs, long ipv6VerifiedMs,
                 String ipv4Transport, String ipv6Transport) { }

    private record FamilyProof(long at, String transport) { }

    private static boolean fresh(FamilyProof proof, long now) {
        return proof != null && now - proof.at() <= MAX_PROOF_AGE_MS;
    }

    private static FamilyProof awaitProof(Future<Long> tcp, ExitQuicProbe quic, long deadline,
                                          BooleanSupplier abort) throws Exception {
        var http3 = quic == null ? null : quic.result();
        while (!abort.getAsBoolean()) {
            boolean tcpDone = tcp.isDone();
            boolean http3Done = http3 == null || http3.isDone();
            long tcpAt = tcpDone ? tcp.get() : -1;
            Long http3At = http3 != null && http3Done ? http3.get() : null;
            if (http3At != null && (tcpAt < 0 || http3At <= tcpAt)) return new FamilyProof(http3At, "h3");
            if (tcpAt >= 0) return new FamilyProof(tcpAt, "tcp-tls");
            long remaining = deadline - SystemClock.elapsedRealtime();
            if ((tcpDone && http3Done) || remaining <= 0) return null;
            try {
                var pending = tcpDone ? http3 : tcp;
                pending.get(Math.min(remaining, 15), TimeUnit.MILLISECONDS);
            } catch (TimeoutException pending) {
                // Either transport can complete first. Both share the same deadline.
            }
        }
        return null;
    }

    private static long proofTime(Network network, URI target, String expected, long start) {
        return matches(network, target, expected) ? SystemClock.elapsedRealtime() - start : -1;
    }

    private Network vpnFor(List<String> addresses) {
        if (addresses.isEmpty()) return null;
        var active = networks.getActiveNetwork();
        var details = active == null ? null : networks.getNetworkCapabilities(active);
        if (details == null || !details.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null;
        var link = networks.getLinkProperties(active);
        if (link == null) return null;
        for (String address : addresses) {
            var expected = InetAddresses.parseNumericAddress(address);
            for (var local : link.getLinkAddresses()) {
                if (expected.equals(local.getAddress())) return active;
            }
        }
        return null;
    }

    private static boolean matches(Network network, URI target, String expected) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) network.openConnection(target.toURL(), Proxy.NO_PROXY);
            connection.setConnectTimeout(1_500);
            connection.setReadTimeout(1_500);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestProperty("Connection", "close");
            if (connection.getResponseCode() != 200) return false;
            try (var reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                return containsExitAddress(reader, expected);
            }
        } catch (IOException | IllegalArgumentException failure) {
            return false;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    static boolean containsExitAddress(BufferedReader reader, String expected) throws IOException {
        for (int index = 0; index < 40; index++) {
            String line = reader.readLine();
            if (line == null || line.length() > 512) break;
            if (line.startsWith("ip=")) {
                return InetAddresses.parseNumericAddress(expected)
                        .equals(InetAddresses.parseNumericAddress(line.substring(3)));
            }
        }
        return false;
    }
}
