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
import java.util.concurrent.atomic.AtomicReference;
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
        var earlyWorkers = Executors.newFixedThreadPool(2);
        var changed = new Semaphore(0);
        var availableVpn = new AtomicReference<Network>();
        var listener = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) {
                availableVpn.set(network);
                changed.release();
            }
            @Override public void onLost(Network network) {
                var prior = availableVpn.get();
                if (network.equals(prior)) availableVpn.compareAndSet(prior, null);
                changed.release();
            }
            @Override public void onLinkPropertiesChanged(Network network, android.net.LinkProperties properties) {
                changed.release();
            }
        };
        Network probing = null;
        Network triedEarly = null;
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
                var active = networks.getActiveNetwork();
                boolean selected = "Running".equals(state.state()) && expectedExit.equals(state.exitId());
                var announced = availableVpn.get();
                var vpn = !selected ? null : ownsVpn(active, state.addresses()) ? active
                        : ownsVpn(announced, state.addresses()) ? announced : null;
                if (probing == null || !probing.equals(vpn)) {
                    probing = vpn;
                    routeReady = vpn == null ? -1 : SystemClock.elapsedRealtime() - start;
                    ipv4Verified = -1;
                    ipv6Verified = -1;
                }
                boolean isDefault = vpn != null && vpn.equals(active);
                if (vpn != null && (isDefault || !vpn.equals(triedEarly))) {
                    // A visible VPN can carry bound sockets before it becomes the Android default.
                    // Give that attempt a separate pool so it cannot delay a ready default path.
                    if (!isDefault) triedEarly = vpn;
                    var pool = isDefault ? workers : earlyWorkers;
                    int socketTimeoutMs = isDefault ? 1_500 : 450;
                    long batchDeadline = Math.min(deadline, SystemClock.elapsedRealtime() + (isDefault ? 3_500 : 650));
                    BooleanSupplier abort = isDefault ? cancelled
                            : () -> cancelled.getAsBoolean() || vpn.equals(networks.getActiveNetwork());
                    long elapsed = SystemClock.elapsedRealtime() - start;
                    var first = ipv4Verified < 0 || elapsed - ipv4Verified > MAX_PROOF_AGE_MS
                            ? pool.submit(() -> proofTime(vpn, V4, profile.ipv4(), start, socketTimeoutMs)) : null;
                    var second = ipv6Verified < 0 || elapsed - ipv6Verified > MAX_PROOF_AGE_MS
                            ? pool.submit(() -> proofTime(vpn, V6, profile.ipv6(), start, socketTimeoutMs)) : null;
                    try {
                        if (first != null) ipv4Verified = awaitProof(first, batchDeadline, abort);
                        if (second != null) ipv6Verified = awaitProof(second, batchDeadline, abort);
                    } finally {
                        if (first != null && !first.isDone()) first.cancel(true);
                        if (second != null && !second.isDone()) second.cancel(true);
                    }
                    long verifiedAt = SystemClock.elapsedRealtime() - start;
                    if (ipv4Verified >= 0 && verifiedAt - ipv4Verified <= MAX_PROOF_AGE_MS
                            && ipv6Verified >= 0 && verifiedAt - ipv6Verified <= MAX_PROOF_AGE_MS
                            && vpn.equals(networks.getActiveNetwork()) && ownsVpn(vpn, state.addresses())
                            && !cancelled.getAsBoolean()) {
                        var current = control.readState();
                        long currentAt = SystemClock.elapsedRealtime() - start;
                        if ("Running".equals(current.state()) && expectedExit.equals(current.exitId())
                                && vpn.equals(networks.getActiveNetwork()) && ownsVpn(vpn, current.addresses())
                                && currentAt - ipv4Verified <= MAX_PROOF_AGE_MS
                                && currentAt - ipv6Verified <= MAX_PROOF_AGE_MS
                                && !cancelled.getAsBoolean()) {
                            return new Proof(vpn, routeReady, ipv4Verified, ipv6Verified);
                        }
                    }
                    if (!isDefault && vpn.equals(networks.getActiveNetwork())) continue;
                }
                long elapsed = SystemClock.elapsedRealtime() - verificationStarted;
                changed.tryAcquire(elapsed < 800 ? 35 : 125, TimeUnit.MILLISECONDS);
                changed.drainPermits();
            }
            throw new IOException(cancelled.getAsBoolean() ? "CONNECTION_CANCELLED" : "EXIT_NOT_VERIFIED");
        } finally {
            earlyWorkers.shutdownNow();
            workers.shutdownNow();
            if (registered) networks.unregisterNetworkCallback(listener);
        }
    }

    record Proof(Network network, long routeReadyMs, long ipv4VerifiedMs, long ipv6VerifiedMs) { }

    private static long awaitProof(Future<Long> proof, long deadline, BooleanSupplier abort) throws Exception {
        while (!proof.isDone() && !abort.getAsBoolean()) {
            long remaining = deadline - SystemClock.elapsedRealtime();
            if (remaining <= 0) break;
            try {
                return proof.get(Math.min(remaining, 25), TimeUnit.MILLISECONDS);
            } catch (TimeoutException pending) {
                // Check the current default route and connection generation before waiting again.
            }
        }
        return proof.isDone() ? proof.get() : -1;
    }

    private static long proofTime(Network network, URI target, String expected, long start, int timeoutMs) {
        return matches(network, target, expected, timeoutMs) ? SystemClock.elapsedRealtime() - start : -1;
    }

    private boolean ownsVpn(Network network, List<String> addresses) {
        if (network == null || addresses.isEmpty()) return false;
        var details = networks.getNetworkCapabilities(network);
        if (details == null || !details.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return false;
        var link = networks.getLinkProperties(network);
        if (link == null) return false;
        for (String address : addresses) {
            var expected = InetAddresses.parseNumericAddress(address);
            for (var local : link.getLinkAddresses()) {
                if (expected.equals(local.getAddress())) return true;
            }
        }
        return false;
    }

    private static boolean matches(Network network, URI target, String expected, int timeoutMs) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) network.openConnection(target.toURL(), Proxy.NO_PROXY);
            connection.setConnectTimeout(timeoutMs);
            connection.setReadTimeout(timeoutMs);
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
