package org.morandi.proxy;

import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Base64;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.By;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject2;
import androidx.test.uiautomator.Until;

import org.json.JSONObject;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Predicate;

import javax.net.ssl.HttpsURLConnection;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/** Trusted release job only. Uses the production client, TLS and exit probes. */
@RunWith(AndroidJUnit4.class)
public final class ProductionLifecycleTest {
    @Test
    public void signedAppAgainstProduction() throws Exception {
        Bundle arguments = InstrumentationRegistry.getArguments();
        Assume.assumeTrue("Dedicated release job only", "1".equals(arguments.getString("proxyProduction")));
        String username = decode(arguments, "proxyUser");
        String password = decode(arguments, "proxyPass");
        String run = arguments.getString("proxyRun", "");
        assertTrue("Dedicated release run ID required", run.matches("[0-9]{1,20}"));

        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context context = instrumentation.getTargetContext();
        AcceptanceApi api = new AcceptanceApi(context);
        AppController enrollment = new AppController(context, api, new TunnelEngine(context));
        AppController.installForTest(enrollment);
        AppController active = enrollment;
        MainActivity activity = null;
        try {
            try (StateTiming fresh = new StateTiming(enrollment, ProductionLifecycleTest::signedIn)) {
                fresh.start();
                enrollment.login(username, password, true);
                fresh.report("LOGIN_FRESH");
            }
            assertFalse("Release test requires a fresh emulator identity", enrollment.snapshot().registered);
            enrollment.confirmDevice("Android CI " + run);
            await("Production device enrollment", () -> enrollment.snapshot().registered
                    && !enrollment.snapshot().busy);
            String device = enrollment.snapshot().deviceId;

            long restoreStarted = SystemClock.elapsedRealtimeNanos();
            TunnelEngine engine = new TunnelEngine(context);
            AppController controller = new AppController(context, api, engine);
            AppController.installForTest(controller);
            active = controller;
            Predicate<AppController.State> sameDevice = state -> signedIn(state)
                    && state.registered && device.equals(state.deviceId);
            try (StateTiming restore = new StateTiming(controller, sameDevice, restoreStarted)) {
                restore.report("LOGIN_SAVED_CONTROLLER");
            }
            controller.logout();
            await("Log out before measuring known-device credential sign-in",
                    () -> !controller.snapshot().signedIn && !controller.snapshot().busy);
            try (StateTiming warm = new StateTiming(controller, sameDevice)) {
                warm.start();
                controller.login(username, password, false);
                warm.report("LOGIN_WARM");
            }

            MainActivity screen = (MainActivity) instrumentation.startActivitySync(
                    new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            activity = screen;
            ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
            Network direct = manager.getActiveNetwork();
            assertNotNull("Direct baseline network is installed", direct);
            NetworkCapabilities directCapabilities = manager.getNetworkCapabilities(direct);
            assertNotNull("Direct baseline network capabilities available", directCapabilities);
            assertFalse("Direct baseline must precede activation of any VPN",
                    directCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
            HttpsLatencyTestProbe latency = new HttpsLatencyTestProbe(direct);
            latency.sample(direct, "DIRECT", "");
            sampleDownload(direct, "DIRECT");

            Predicate<AppController.State> verified = state -> "connected".equals(state.mode)
                    && !state.verifiedIpv4.isEmpty() && (!api.dualStack || !state.verifiedIpv6.isEmpty());
            try (StateTiming firstClick = new StateTiming(controller, verified);
                 StateTiming afterConsent = new StateTiming(controller, verified)) {
                tapConnect(instrumentation, screen, firstClick);
                UiDevice ui = UiDevice.getInstance(instrumentation);
                UiObject2 allow = ui.wait(Until.findObject(By.res("android", "button1")), 8_000);
                assertNotNull("Android VPN consent appeared on fresh installation", allow);
                afterConsent.start();
                allow.click();
                firstClick.report("CONNECT_FIRST_CLICK");
                afterConsent.report("CONNECT_AFTER_CONSENT");
            }
            android.util.Log.i("ProxySpeedAcceptance", "ANDROID_PERF_VERIFIED_FAMILIES="
                    + (api.dualStack ? 2 : 1));
            reportProofProtocol(controller, "FIRST");
            Network vpn = vpnNetwork(context);
            assertNotNull("Production VPN network is installed", vpn);
            assertTrue("DNS resolves over the VPN network", vpn.getAllByName("www.cloudflare.com").length > 0);
            latency.sample(vpn, "WIREGUARD_UDP", controller.snapshot().verifiedIpv4);
            sampleDownload(vpn, "WIREGUARD_UDP");

            controller.disconnect();
            await("Production VPN route removed", () -> "disconnected".equals(controller.snapshot().mode)
                    && !engine.isUp() && vpnNetwork(context) == null);
            try (StateTiming reconnect = new StateTiming(controller, verified)) {
                tapConnect(instrumentation, screen, reconnect);
                reconnect.report("CONNECT_RECONNECT_CLICK");
            }
            reportProofProtocol(controller, "RECONNECT");
            controller.disconnect();
            await("Production VPN route removed after reconnect",
                    () -> "disconnected".equals(controller.snapshot().mode) && !engine.isUp()
                            && vpnNetwork(context) == null);
            controller.removeDevice(controller.snapshot().deviceId);
            await("Dedicated test device removed and signed out", () -> !controller.snapshot().signedIn);
        } finally {
            active.disconnect();
            if (activity != null) {
                instrumentation.runOnMainSync(activity::finish);
            }
            api.cleanUp(username, password);
        }
    }

    private static boolean signedIn(AppController.State state) {
        return state.signedIn && !state.busy;
    }

    private static void reportProofProtocol(AppController controller, String label) {
        AppController.ConnectionTiming timing = controller.lastConnectTiming();
        assertNotNull("Verified connection records its actual proof protocols", timing);
        assertTrue(timing.ipv4ProofProtocol.equals("h3") || timing.ipv4ProofProtocol.equals("https"));
        assertTrue(timing.ipv6ProofProtocol.isEmpty() || timing.ipv6ProofProtocol.equals("h3")
                || timing.ipv6ProofProtocol.equals("https"));
        android.util.Log.i("ProxySpeedAcceptance", "ANDROID_PERF_EXIT_PROOF_" + label
                + "=IPV4:" + timing.ipv4ProofProtocol + ";IPV6:"
                + (timing.ipv6ProofProtocol.isEmpty() ? "blocked" : timing.ipv6ProofProtocol)
                + ";H3_CANDIDATE=" + (BuildConfig.H3_EXIT_PROOF_ENABLED ? 1 : 0));
        android.util.Log.i("ProxySpeedAcceptance", "ANDROID_PERF_CONNECT_PHASES_" + label
                + "=TOTAL_MS:" + timing.totalMs + ";POLICY_MS:" + timing.policyMs
                + ";SERVICE_WAIT_MS:" + timing.serviceWaitMs + ";NATIVE_START_MS:" + timing.nativeStartMs
                + ";NETWORK_WAIT_MS:" + timing.networkWaitMs + ";EXIT_PROOF_MS:" + timing.exitProofMs
                + ";ATTEMPTS:" + timing.attempts);
    }

    private static void tapConnect(Instrumentation instrumentation, MainActivity screen, StateTiming timing) {
        instrumentation.waitForIdleSync();
        instrumentation.runOnMainSync(() -> {
            android.view.View connect = screen.findViewById(R.id.connect);
            assertNotNull("Connect action is present", connect);
            assertTrue("Connect action is enabled", connect.isEnabled());
            timing.start();
            assertTrue("Connect action was accepted", connect.performClick());
        });
    }

    private static final class StateTiming implements AutoCloseable {
        private static final long TARGET_NANOS = TimeUnit.SECONDS.toNanos(1);
        private final AppController controller;
        private final AppController.Listener observer;
        private final CountDownLatch finished = new CountDownLatch(1);
        private volatile long startedAt;
        private long duration;

        StateTiming(AppController controller, Predicate<AppController.State> ready) {
            this(controller, ready, 0);
        }

        StateTiming(AppController controller, Predicate<AppController.State> ready, long startedAt) {
            this.controller = controller;
            this.startedAt = startedAt;
            observer = state -> {
                long start = this.startedAt;
                if (start != 0 && finished.getCount() != 0 && ready.test(state)) {
                    duration = SystemClock.elapsedRealtimeNanos() - start;
                    finished.countDown();
                }
            };
            controller.observe(observer);
        }

        void start() {
            startedAt = SystemClock.elapsedRealtimeNanos();
        }

        void report(String name) throws InterruptedException {
            assertTrue(name + " reached verified state", finished.await(65, TimeUnit.SECONDS));
            android.util.Log.i("ProxySpeedAcceptance", "ANDROID_PERF_" + name + "_MS="
                    + TimeUnit.NANOSECONDS.toMillis(duration) + ";TARGET_MS=1000;UNDER_TARGET="
                    + (duration < TARGET_NANOS ? 1 : 0));
        }

        @Override public void close() {
            controller.removeObserver(observer);
        }
    }

    private static void sampleDownload(Network network, String route) throws IOException {
        int limit = 2 * 1024 * 1024;
        long start = SystemClock.elapsedRealtime();
        HttpsURLConnection connection = null;
        try {
            if (network == null) {
                throw new IOException();
            }
            connection = (HttpsURLConnection) network.openConnection(
                    new URL("https://speed.cloudflare.com/__down?bytes=" + limit), Proxy.NO_PROXY);
            connection.setConnectTimeout(5_000);
            connection.setReadTimeout(5_000);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestProperty("Accept-Encoding", "identity");
            int total = 0;
            try (InputStream input = connection.getInputStream()) {
                byte[] buffer = new byte[32768];
                while (total <= limit && SystemClock.elapsedRealtime() - start < 12_000) {
                    int read = input.read(buffer, 0, Math.min(buffer.length, limit + 1 - total));
                    if (read == -1) {
                        break;
                    }
                    total += read;
                }
            }
            if (total != limit) {
                throw new IOException();
            }
            android.util.Log.i("ProxySpeedAcceptance", "ANDROID_DOWNLOAD_" + route + "_BYTES=" + total
                    + ";ELAPSED_MS=" + (SystemClock.elapsedRealtime() - start));
        } catch (IOException failure) {
            throw new IOException("ANDROID_DOWNLOAD_" + route + "_FAILED", failure);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static String decode(Bundle arguments, String key) {
        try {
            String value = new String(Base64.decode(arguments.getString(key, ""), Base64.DEFAULT),
                    StandardCharsets.UTF_8);
            assertTrue("Dedicated test credential present", !value.isEmpty());
            return value;
        } catch (IllegalArgumentException error) {
            throw new AssertionError("Dedicated test credential invalid");
        }
    }

    private static Network vpnNetwork(Context context) {
        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
            if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                return network;
            }
        }
        return null;
    }

    private static void await(String stage, BooleanSupplier condition) {
        long end = SystemClock.elapsedRealtime() + 65_000;
        while (!condition.getAsBoolean() && SystemClock.elapsedRealtime() < end) {
            SystemClock.sleep(100);
        }
        assertTrue(stage, condition.getAsBoolean());
    }

    private static final class AcceptanceApi extends ClientApi {
        private volatile String token = "";
        private volatile String newDevice = "";
        private String authenticationKey;
        private String authenticationDeviceName;
        private String authenticationClientVersion;
        private volatile boolean enrollmentAttempted;
        private volatile boolean removed;
        private volatile boolean dualStack;

        AcceptanceApi(Context context) {
            super(context);
        }

        @Override
        JSONObject call(String action, String credential, JSONObject body) throws Exception {
            if ("enroll".equals(action) && !newDevice.isEmpty()) {
                enrollmentAttempted = true;
            }
            if ("authenticate".equals(action) && authenticationKey == null) {
                authenticationKey = body.getString("public_key");
                authenticationDeviceName = body.getString("device_name");
                authenticationClientVersion = body.getString("client_version");
            }
            JSONObject response = super.call(action, credential, body);
            if ("authenticate".equals(action)) {
                JSONObject registration = response.getJSONObject("registration");
                String issuedDevice = registration.optString("device_id");
                if (newDevice.isEmpty() && "pending".equals(registration.optString("status"))) {
                    newDevice = issuedDevice;
                }
                if (newDevice.isEmpty() || newDevice.equals(issuedDevice)) {
                    token = response.getString("token");
                }
            } else if ("logout".equals(action) && token.equals(credential)) {
                token = "";
            }
            JSONObject tunnel = response.optJSONObject("tunnel");
            if (tunnel != null) {
                dualStack = "tunnel".equals(tunnel.optString("ipv6_policy"));
            }
            if ("device-delete".equals(action) && newDevice.equals(response.optString("removed"))
                    && response.optBoolean("current")) {
                removed = true;
            }
            return response;
        }

        void cleanUp(String username, String password) throws Exception {
            if (removed) {
                return;
            }
            if (enrollmentAttempted && newDevice.matches("[a-f0-9]{12}")) {
                for (int attempt = 0; attempt < 3; attempt++) {
                    try {
                        if (token.isEmpty()) {
                            restoreCleanupToken(username, password);
                        }
                        JSONObject response = super.call("device-delete", token,
                                new JSONObject().put("device_id", newDevice));
                        assertTrue("Teardown removed exactly the acceptance device",
                                response.optBoolean("current") && newDevice.equals(response.optString("removed")));
                        return;
                    } catch (ClientApi.ApiError failure) {
                        if ("DEVICE_NOT_FOUND".equals(failure.code)) {
                            break;
                        }
                        if ("LOGIN_REQUIRED".equals(failure.code)) {
                            token = "";
                        }
                        if (attempt == 2) {
                            throw new AssertionError("Acceptance device cleanup requires review");
                        }
                    } catch (Exception failure) {
                        if (attempt == 2) {
                            throw new AssertionError("Acceptance device cleanup requires review");
                        }
                    }
                    SystemClock.sleep(800);
                }
            }
            if (token.isEmpty()) {
                return;
            }
            try {
                super.call("logout", token, new JSONObject());
            } catch (ClientApi.ApiError failure) {
                if (!"LOGIN_REQUIRED".equals(failure.code)) {
                    throw new AssertionError("Acceptance session cleanup requires review");
                }
            }
        }

        private void restoreCleanupToken(String username, String password) throws Exception {
            // Warm sign-in intentionally revokes the old session. Recover only the
            // original device for cleanup if that sign-in failed before issuing a token.
            JSONObject request = new JSONObject()
                    .put("username", username)
                    .put("password", password)
                    .put("public_key", authenticationKey)
                    .put("device_name", authenticationDeviceName)
                    .put("client_version", authenticationClientVersion);
            try {
                JSONObject response = super.call("authenticate", "", request);
                String issued = response.getString("token");
                if (!newDevice.equals(response.getJSONObject("registration").optString("device_id"))) {
                    super.call("logout", issued, new JSONObject());
                    throw new IOException("ANDROID_ACCEPTANCE_DEVICE_CHANGED");
                }
                token = issued;
            } finally {
                request.remove("password");
            }
        }
    }
}
