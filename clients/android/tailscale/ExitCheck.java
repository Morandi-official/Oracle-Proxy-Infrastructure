package org.morandi.proxy.tailscale;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.InetAddresses;
import android.net.Network;
import android.net.NetworkCapabilities;
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
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

final class ExitCheck {
    private static final URI V4 = URI.create("https://1.1.1.1/cdn-cgi/trace");
    private static final URI V6 = URI.create("https://[2606:4700:4700::1111]/cdn-cgi/trace");
    private final ConnectivityManager networks;

    ExitCheck(Context context) {
        networks = context.getSystemService(ConnectivityManager.class);
    }

    void verify(LocalControl control, AccountClient.Profile profile, BooleanSupplier cancelled) throws Exception {
        long deadline = SystemClock.elapsedRealtime() + 10_000;
        var workers = Executors.newFixedThreadPool(2);
        try {
            while (SystemClock.elapsedRealtime() < deadline && !cancelled.getAsBoolean()) {
                var state = control.readState();
                var vpn = vpnFor(state.addresses());
                if ("Running".equals(state.state()) && Long.toString(profile.exitId()).equals(state.exitId()) && vpn != null) {
                    var first = workers.submit(() -> matches(vpn, V4, profile.ipv4()));
                    var second = workers.submit(() -> matches(vpn, V6, profile.ipv6()));
                    boolean v4 = first.get(4, TimeUnit.SECONDS);
                    boolean v6 = second.get(4, TimeUnit.SECONDS);
                    if (v4 && v6 && vpn.equals(vpnFor(state.addresses())) && !cancelled.getAsBoolean()) return;
                }
                Thread.sleep(125);
            }
            throw new IOException(cancelled.getAsBoolean() ? "CONNECTION_CANCELLED" : "EXIT_NOT_VERIFIED");
        } finally {
            workers.shutdownNow();
        }
    }

    private Network vpnFor(List<String> addresses) {
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
