package org.morandi.proxy.tailscale;

import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Base64;
import android.widget.EditText;
import android.widget.TextView;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.By;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.Until;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/** Exercises the normal production UI with the exact signed APK queued for publication. */
@RunWith(AndroidJUnit4.class)
public final class ProductionAcceptanceTest {
    private static final String DIRECT = "已断开 · 当前直连";
    private static final String CONNECTED = "已连接 · ";
    private static final int DOWNLOAD_BYTES = 8 * 1024 * 1024;
    private static final int UPLOAD_BYTES = 4 * 1024 * 1024;
    private static final int STREAMS = 4;
    private final Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
    private final Context context = instrumentation.getTargetContext();
    private final ConnectivityManager networks = context.getSystemService(ConnectivityManager.class);

    @Test
    public void signedClientThroughOracleExit() throws Exception {
        var arguments = InstrumentationRegistry.getArguments();
        assertEquals("Production mode must be explicit", "1", arguments.getString("proxyProduction"));
        boolean latencyOnly = "1".equals(arguments.getString("proxyLatencyOnly"));
        assertTrue("Fresh installation must have no login", EngineHost.from(context).decryptFromPref("client-session").isEmpty());
        var loginUser = credential(arguments, "proxyUser");
        var loginPassword = credential(arguments, "proxyPass");
        var activity = (MainActivity) instrumentation.startActivitySync(
                new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        var report = new JSONObject();
        try {
            await("Internet access before VPN", () -> networks.getActiveNetwork() != null && !hasVpn());
            if (latencyOnly) {
                report.put("latency_only", true);
                assertTrue("Direct HTTPS before VPN", probeLatency() > 0);
            } else {
                report.put("baseline", measurePath(false));
            }

            await("Login controls are available", () -> enabled(activity, R.id.login));
            instrumentation.runOnMainSync(() -> {
                activity.<EditText>findViewById(R.id.username).setText(loginUser);
                activity.<EditText>findViewById(R.id.password).setText(loginPassword);
                activity.findViewById(R.id.login).performClick();
            });
            await("Production account login via HTTPS", () -> enabled(activity, R.id.connect));
            click(activity, R.id.connect);
            var consent = UiDevice.getInstance(instrumentation).wait(
                    Until.findObject(By.res("android", "button1")), 10_000);
            assertNotNull("Android VPN consent appeared on clean install", consent);
            consent.click();
            report.put("first_connect_to_verified_ms", awaitVerified(activity));
            report.put("first_connect_stages_ms", connectionStages(activity));
            var vpn = networks.getActiveNetwork();
            assertTrue("Android default network is the verified VPN", isVpn(vpn));
            assertTrue("DNS resolves over the VPN network", vpn.getAllByName("speed.cloudflare.com").length > 0);
            if (!latencyOnly) report.put("vpn", measurePath(true));
            var control = new LocalControl(EngineHost.from(context).engine());
            report.put("exit_transport", control.exitPath());

            for (int probe = 0; probe < 10; probe++) {
                assertEquals("VPN remains the default route while connected", vpn, networks.getActiveNetwork());
                probeLatency();
                if (probe != 9) SystemClock.sleep(2_000);
            }
            report.put("continuous_egress_probes", 10);

            var reconnect = new ArrayList<Long>();
            var disconnect = new ArrayList<Long>();
            var reconnectStages = new JSONArray();
            for (int attempt = 0; attempt < 3; attempt++) {
                disconnect.add(disconnect(activity));
                click(activity, R.id.connect);
                reconnect.add(awaitVerified(activity));
                reconnectStages.put(connectionStages(activity));
            }
            disconnect.add(disconnect(activity));
            assertTrue("Direct HTTPS after tunnel shutdown", probeLatency() > 0);
            report.put("reconnect_to_verified_ms", new JSONArray(reconnect));
            report.put("reconnect_stages_ms", reconnectStages);
            report.put("disconnect_to_direct_ms", new JSONArray(disconnect));
        } finally {
            instrumentation.runOnMainSync(activity::finish);
            await("Android cleared the acceptance VPN", () -> !hasVpn());
            releaseOwnDevice();
        }

        var result = new Bundle();
        result.putString("proxyMetrics", report.toString());
        instrumentation.sendStatus(0, result);
    }

    private void releaseOwnDevice() throws Exception {
        String saved = EngineHost.from(context).decryptFromPref("client-session");
        if (saved.isEmpty()) return;
        String session = new JSONObject(saved).getString("token");
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                new AccountClient().release(session);
                return;
            } catch (Exception failure) {
                if (attempt == 2) throw new AssertionError("Acceptance device cleanup was not confirmed");
                SystemClock.sleep(500);
            }
        }
    }

    private long disconnect(MainActivity activity) {
        long started = SystemClock.elapsedRealtime();
        click(activity, R.id.disconnect);
        await("User disconnection removed the Android tunnel", () -> !hasVpn() && status(activity).equals(DIRECT));
        return SystemClock.elapsedRealtime() - started;
    }

    private long awaitVerified(MainActivity activity) {
        await("Production authenticated WireGuard egress on IPv4 and IPv6", () -> status(activity).startsWith(CONNECTED));
        return Long.parseLong(status(activity).substring(CONNECTED.length()).replace(" ms", ""));
    }

    private void click(MainActivity activity, int id) {
        instrumentation.runOnMainSync(() -> {
            var button = activity.findViewById(id);
            assertTrue("User action is enabled", button.isEnabled() && button.performClick());
        });
    }

    private boolean enabled(MainActivity activity, int id) {
        var value = new AtomicReference<Boolean>();
        instrumentation.runOnMainSync(() -> value.set(activity.findViewById(id).isEnabled()));
        return value.get();
    }

    private String status(MainActivity activity) {
        var value = new AtomicReference<String>();
        instrumentation.runOnMainSync(() -> value.set(activity.<TextView>findViewById(R.id.status).getText().toString()));
        return value.get();
    }

    private JSONObject connectionStages(MainActivity activity) throws Exception {
        var value = new AtomicReference<MainActivity.ConnectTiming>();
        instrumentation.runOnMainSync(() -> value.set(activity.lastConnectionTiming()));
        var timing = value.get();
        assertNotNull("Completed connection timing is present", timing);
        return new JSONObject().put("account_profile_ready", timing.profileReadyMs())
                .put("native_engine_ready", timing.engineReadyMs())
                .put("device_enrollment_ready", timing.enrollmentReadyMs())
                .put("exit_route_requested", timing.routeRequestedMs())
                .put("android_vpn_ready", timing.routeReadyMs())
                .put("ipv4_exit_verified", timing.ipv4VerifiedMs())
                .put("ipv6_exit_verified", timing.ipv6VerifiedMs())
                .put("ipv4_exit_transport", timing.ipv4Transport())
                .put("ipv6_exit_transport", timing.ipv6Transport())
                .put("exit_peer_mapped_ms", timing.exitPeerMappedMs())
                .put("exit_peer_probe_started_ms", timing.peerProbeStartedMs())
                .put("exit_peer_probe_reply_ms", timing.peerProbeReplyMs());
    }

    private boolean hasVpn() {
        for (Network network : networks.getAllNetworks()) if (isVpn(network)) return true;
        return false;
    }

    private boolean isVpn(Network network) {
        var capabilities = network == null ? null : networks.getNetworkCapabilities(network);
        return capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }

    private static void await(String stage, BooleanSupplier condition) {
        long end = SystemClock.elapsedRealtime() + 50_000;
        while (!condition.getAsBoolean() && SystemClock.elapsedRealtime() < end) SystemClock.sleep(50);
        assertTrue(stage, condition.getAsBoolean());
    }

    private static String credential(Bundle arguments, String name) {
        try {
            var value = new String(Base64.decode(arguments.getString(name, ""), Base64.DEFAULT), StandardCharsets.UTF_8);
            assertTrue("A CI acceptance credential is required", !value.isEmpty());
            return value;
        } catch (IllegalArgumentException failure) {
            throw new AssertionError("Invalid CI credential encoding");
        }
    }

    private JSONObject measurePath(boolean throughVpn) throws Exception {
        var latencies = new ArrayList<Long>();
        var download = new ArrayList<Double>();
        var upload = new ArrayList<Double>();
        for (int sample = 0; sample < 7; sample++) {
            assertEquals("Metric sampled on the expected route", throughVpn, isVpn(networks.getActiveNetwork()));
            latencies.add(probeLatency());
        }
        for (int sample = 0; sample < 3; sample++) {
            assertEquals("Throughput sampled on the expected route", throughVpn, isVpn(networks.getActiveNetwork()));
            download.add(singleTransfer(false));
            upload.add(singleTransfer(true));
        }
        assertEquals("Parallel download sampled on the expected route", throughVpn, isVpn(networks.getActiveNetwork()));
        double parallelDownload = parallelTransfer(false);
        assertEquals("Parallel upload sampled on the expected route", throughVpn, isVpn(networks.getActiveNetwork()));
        double parallelUpload = parallelTransfer(true);
        assertEquals("Throughput run retained the expected route", throughVpn, isVpn(networks.getActiveNetwork()));
        return new JSONObject().put("https_p50_ms", percentile(latencies, .50))
                .put("https_p95_ms", percentile(latencies, .95))
                .put("down_mbps_median", percentile(download, .50))
                .put("up_mbps_median", percentile(upload, .50))
                .put("down_mbps_four_stream", parallelDownload)
                .put("up_mbps_four_stream", parallelUpload);
    }

    private static <T extends Comparable<T>> T percentile(List<T> values, double quantile) {
        Collections.sort(values);
        return values.get((int) Math.ceil(values.size() * quantile) - 1);
    }

    private static HttpURLConnection open(String path) throws IOException {
        var connection = (HttpURLConnection) URI.create("https://speed.cloudflare.com" + path).toURL()
                .openConnection(Proxy.NO_PROXY);
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(8_000);
        connection.setReadTimeout(15_000);
        connection.setRequestProperty("Connection", "close");
        connection.setRequestProperty("Cache-Control", "no-cache");
        return connection;
    }

    private static long probeLatency() throws IOException {
        var connection = open("/__down?bytes=0&sample=" + System.nanoTime());
        try {
            long started = SystemClock.elapsedRealtime();
            requireOk(connection);
            return SystemClock.elapsedRealtime() - started;
        } finally {
            connection.disconnect();
        }
    }

    private static double singleTransfer(boolean upload) throws IOException {
        long started = SystemClock.elapsedRealtimeNanos();
        transfer(upload, null);
        return rate(upload ? UPLOAD_BYTES : DOWNLOAD_BYTES, started);
    }

    private static double parallelTransfer(boolean upload) throws Exception {
        var workers = Executors.newFixedThreadPool(STREAMS);
        var start = new CountDownLatch(1);
        var connections = new ConcurrentLinkedQueue<HttpURLConnection>();
        var tasks = new ArrayList<Future<Void>>(STREAMS);
        try {
            for (int stream = 0; stream < STREAMS; stream++) {
                tasks.add(workers.submit(() -> {
                    start.await();
                    transfer(upload, connections);
                    return null;
                }));
            }
            long started = SystemClock.elapsedRealtimeNanos();
            long deadline = started + TimeUnit.SECONDS.toNanos(45);
            start.countDown();
            for (var task : tasks) {
                task.get(Math.max(1, deadline - SystemClock.elapsedRealtimeNanos()), TimeUnit.NANOSECONDS);
            }
            return rate(STREAMS * (upload ? UPLOAD_BYTES : DOWNLOAD_BYTES), started);
        } finally {
            workers.shutdownNow();
            for (var connection : connections) connection.disconnect();
        }
    }

    private static double rate(int bytes, long started) {
        double elapsed = (SystemClock.elapsedRealtimeNanos() - started) / 1e9;
        return Math.round(bytes * 8 / elapsed / 10_000) / 100.0;
    }

    private static void transfer(boolean upload, ConcurrentLinkedQueue<HttpURLConnection> connections) throws IOException {
        int expected = upload ? UPLOAD_BYTES : DOWNLOAD_BYTES;
        var connection = open(upload ? "/__up" : "/__down?bytes=" + expected + "&sample=" + System.nanoTime());
        if (connections != null) connections.add(connection);
        byte[] chunk = new byte[32 * 1024];
        try {
            if (upload) {
                connection.setRequestMethod("POST");
                connection.setDoOutput(true);
                connection.setFixedLengthStreamingMode(expected);
                connection.setRequestProperty("Content-Type", "application/octet-stream");
                try (var output = connection.getOutputStream()) {
                    for (int sent = 0; sent < expected; sent += chunk.length) output.write(chunk);
                }
                requireOk(connection);
            } else {
                requireOk(connection);
                try (var input = connection.getInputStream()) {
                    int total = 0;
                    for (int read; (read = input.read(chunk)) != -1; ) {
                        total += read;
                        if (total > expected) throw new IOException("DOWNLOAD_SIZE_MISMATCH");
                    }
                    if (total != expected) throw new IOException("DOWNLOAD_SIZE_MISMATCH");
                }
            }
        } finally {
            if (connections != null) connections.remove(connection);
            connection.disconnect();
        }
    }

    private static void requireOk(HttpURLConnection connection) throws IOException {
        int status = connection.getResponseCode();
        if (status < 200 || status >= 300) throw new IOException("PERFORMANCE_ENDPOINT_HTTP_" + status);
    }
}
