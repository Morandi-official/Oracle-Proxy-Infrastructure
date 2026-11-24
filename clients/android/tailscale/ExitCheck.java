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
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

final class ExitCheck {
    private static final URI V4 = URI.create("https://1.1.1.1/cdn-cgi/trace");
    private static final URI V6 = URI.create("https://[2606:4700:4700::1111]/cdn-cgi/trace");
    private static final long MAX_PROOF_AGE_MS = 2_500;
    private final ConnectivityManager networks;

    ExitCheck(Context context) {
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
        long routeReady = -1;
        long ipv4Verified = -1;
        long ipv6Verified = -1;
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
                    ipv4Verified = -1;
                    ipv6Verified = -1;
                }
                if (vpn != null) {
                    long elapsed = SystemClock.elapsedRealtime() - start;
                    var first = ipv4Verified < 0 || elapsed - ipv4Verified > MAX_PROOF_AGE_MS
                            ? workers.submit(() -> proofTime(vpn, V4, profile.ipv4(), start)) : null;
                    var second = ipv6Verified < 0 || elapsed - ipv6Verified > MAX_PROOF_AGE_MS
                            ? workers.submit(() -> proofTime(vpn, V6, profile.ipv6(), start)) : null;
                    if (first != null) ipv4Verified = first.get(4, TimeUnit.SECONDS);
                    if (second != null) ipv6Verified = second.get(4, TimeUnit.SECONDS);
                    long verifiedAt = SystemClock.elapsedRealtime() - start;
                    if (ipv4Verified >= 0 && verifiedAt - ipv4Verified <= MAX_PROOF_AGE_MS
                            && ipv6Verified >= 0 && verifiedAt - ipv6Verified <= MAX_PROOF_AGE_MS
                            && vpn.equals(vpnFor(state.addresses()))
                            && !cancelled.getAsBoolean()) {
                        return new Proof(vpn, routeReady, ipv4Verified, ipv6Verified);
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

    record Proof(Network network, long routeReadyMs, long ipv4VerifiedMs, long ipv6VerifiedMs) { }

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
            connection.setRequestProperty("Connection", "close");
            if (connection.getResponseCode() != 200) return false;
            try (var reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                for (int index = 0; index < 40; index++) {
                    String line = reader.readLine();
                    if (line == null || line.length() > 512) break;
                    if (line.startsWith("ip=")) {
                        return InetAddresses.parseNumericAddress(expected)
                                .equals(InetAddresses.parseNumericAddress(line.substring(3)));
                    }
                }
            }
        } catch (IOException | IllegalArgumentException failure) {
            return false;
        } finally {
            if (connection != null) connection.disconnect();
        }
        return false;
    }
}
