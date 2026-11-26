package org.morandi.proxy;

import android.app.ActivityManager;
import android.app.Instrumentation;
import android.content.ComponentName;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.SystemClock;
import android.view.View;
import android.widget.EditText;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.By;
import androidx.test.uiautomator.UiDevice;
import androidx.test.uiautomator.UiObject2;
import androidx.test.uiautomator.Until;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(AndroidJUnit4.class)
public final class AndroidLifecycleTest {
    private static final String TEST_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String HOST = "10.0.2.2";
    private static final String V4 = "10.77.0.1";
    private static final String V6 = "fd77:4242:77::1";
    private static final String DEVICE_NAME = "Android 验收设备";

    @Test
    public void foregroundSignInOffersOneAnonymousRequestAndSubmissionCancelsQueuedWork() {
        ClientApi api = new ClientApi();
        ClientApi.LoginWarmup stoppedScreen = api.offerLoginWarmup();
        ClientApi.LoginWarmup submitted = api.offerLoginWarmup();
        assertFalse(stoppedScreen.begin());
        api.cancelPendingLoginWarmup();
        assertFalse(submitted.begin());

        ClientApi.LoginWarmup typing = api.offerLoginWarmup();
        assertTrue(typing.begin());
        assertFalse(typing.begin());
        api.cancelPendingLoginWarmup();
        assertFalse(typing.begin());
    }

    @Test
    public void stoppingPreparationWaitsForTheSubmittedServiceStart() throws Exception {
        Context app = InstrumentationRegistry.getInstrumentation().getTargetContext();
        CountDownLatch startEntered = new CountDownLatch(1);
        CountDownLatch allowStartReturn = new CountDownLatch(1);
        AtomicBoolean startReturned = new AtomicBoolean();
        CountDownLatch stopIssued = new CountDownLatch(1);
        AtomicBoolean stoppedAfterStart = new AtomicBoolean();
        Context delayedService = new ContextWrapper(app) {
            @Override public Context getApplicationContext() { return this; }

            @Override public ComponentName startService(Intent intent) {
                startEntered.countDown();
                try {
                    if (!allowStartReturn.await(8, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("fixture start timed out");
                    }
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(error);
                }
                startReturned.set(true);
                return intent.getComponent();
            }

            @Override public boolean stopService(Intent intent) {
                stoppedAfterStart.set(startReturned.get());
                stopIssued.countDown();
                return true;
            }
        };
        TunnelEngine engine = new TunnelEngine(delayedService, null, true);
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            Future<?> prepare = worker.submit(() -> engine.prepareConnection(true));
            assertTrue(startEntered.await(5, TimeUnit.SECONDS));
            prepare.get(2, TimeUnit.SECONDS);
            CountDownLatch stopping = new CountDownLatch(1);
            Future<?> teardown = worker.submit(() -> {
                stopping.countDown();
                engine.disconnect();
                return null;
            });
            assertTrue(stopping.await(2, TimeUnit.SECONDS));
            assertFalse("No stop may overtake an in-flight start", stopIssued.await(150, TimeUnit.MILLISECONDS));
            allowStartReturn.countDown();
            teardown.get(5, TimeUnit.SECONDS);
            assertTrue("The start transaction must finish before stopService", stoppedAfterStart.get());
            assertFalse(engine.isUp());
        } finally {
            allowStartReturn.countDown();
            worker.shutdownNow();
        }
    }

    @Test
    public void loginEnrollConsentConnectDisconnectAndLogout() throws Exception {
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context context = instrumentation.getTargetContext();
        AtomicReference<Network> proved4 = new AtomicReference<>();
        AtomicReference<Network> proved6 = new AtomicReference<>();
        AtomicInteger verified4 = new AtomicInteger();
        AtomicInteger verified6 = new AtomicInteger();
        AtomicBoolean injectFirstIpv6Failure = new AtomicBoolean(true);
        FixtureApi api = new FixtureApi();
        TunnelEngine engine = new TunnelEngine(context, (network, expected, ipv6, timeout) -> {
            try {
                String observed = http(network, expected, 18080, "GET", "/exit", "", timeout);
                if (ipv6 && injectFirstIpv6Failure.compareAndSet(true, false)) {
                    throw new IOException("FIXTURE_IPV6_RETRY");
                }
                (ipv6 ? proved6 : proved4).set(network);
                (ipv6 ? verified6 : verified4).incrementAndGet();
                return observed;
            } catch (IOException error) {
                android.util.Log.d("ProxyTunnel", "Isolated IPv" + (ipv6 ? 6 : 4) + " fixture: " + error);
                throw error;
            }
        }, true);
        AppController controller = new AppController(context, api, engine);
        AppController.installForTest(controller);
        AtomicBoolean attemptedClosedPort = new AtomicBoolean();
        AtomicReference<AppController.State> trying = new AtomicReference<>();
        AppController.Listener observer = state -> {
            if ((HOST + ":443").equals(state.endpoint)) {
                attemptedClosedPort.set(true);
                trying.set(state);
            }
        };
        controller.observe(observer);
        MainActivity activity = (MainActivity) instrumentation.startActivitySync(
                new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        try {
            UiDevice ui = UiDevice.getInstance(instrumentation);
            enter(instrumentation, activity, R.id.username, "fixture");
            enter(instrumentation, activity, R.id.password, "fixture-only");
            try (VisibleConnectionTiming login = new VisibleConnectionTiming("FIXTURE_LOGIN", instrumentation,
                    activity, controller, state -> state.signedIn && !state.busy && !state.registered,
                    R.id.device_confirm, "确认登记")) {
                login.tapButton(R.id.login);
                login.await("Fixture sign-in");
            }
            assertFalse(controller.snapshot().registered);
            assertEquals("A new device can claim the local foreground preparation",
                    AppController.IdentitySource.NEW_FOREGROUND, controller.lastLoginTiming().identitySource());

            enter(instrumentation, activity, R.id.device_name, DEVICE_NAME);
            tap(instrumentation, activity, R.id.device_confirm);
            await("enrollment", controller, () -> controller.snapshot().registered && !controller.snapshot().busy);
            assertEquals("0123456789ab", controller.snapshot().deviceId);
            AtomicReference<View> connectionButton = new AtomicReference<>();
            instrumentation.runOnMainSync(() -> connectionButton.set(activity.findViewById(R.id.connect)));
            assertNotNull(connectionButton.get());

            assertNotNull("A newly installed app asks for VPN consent", VpnService.prepare(context));
            PolicyGate deniedPolicy = new PolicyGate();
            api.policyGate.set(deniedPolicy);
            try {
                tap(instrumentation, activity, R.id.connect);
                assertNotNull("The Android VPN consent dialog was shown",
                        ui.wait(Until.findObject(By.res("android", "button1")), 7_000));
                assertTrue("The explicit tap can read policy while awaiting consent",
                        deniedPolicy.requested.await(7, TimeUnit.SECONDS));
                ActivityManager.RunningServiceInfo warming = ownVpnService(context);
                if (warming != null) {
                    assertFalse("Consent prebinding must not start the service", warming.started);
                    assertFalse("Consent prebinding must not promote a foreground service", warming.foreground);
                }
                assertFalse("Consent is required before installing a VPN route", hasVpnRoute(context));
                UiObject2 deny = ui.wait(Until.findObject(By.res("android", "button2")), 7_000);
                assertNotNull("The Android VPN consent dialog has a cancel button", deny);
                deny.click();
                await("consent cancellation", controller,
                        () -> controller.snapshot().message.contains("系统未授权 VPN"));
                assertFalse(engine.isUp());
                await("Cancelled consent releases the bound-only service", controller,
                        () -> ownVpnService(context) == null);
            } finally {
                api.policyGate.compareAndSet(deniedPolicy, null);
                deniedPolicy.respond.countDown();
            }

            PolicyGate pendingPrefetch = new PolicyGate();
            PolicyGate approvedPolicy = new PolicyGate();
            api.policyGate.set(pendingPrefetch);
            try {
                tap(instrumentation, activity, R.id.connect);
                UiObject2 allow = ui.wait(Until.findObject(By.res("android", "button1")), 7_000);
                assertNotNull("The user can reopen VPN consent", allow);
                assertTrue("The next tap requests its own policy",
                        pendingPrefetch.requested.await(7, TimeUnit.SECONDS));
                api.policyGate.set(approvedPolicy);
                allow.click();
                assertTrue("An incomplete prefetch never delays the approved attempt's own policy request",
                        approvedPolicy.requested.await(7, TimeUnit.SECONDS));
                assertFalse("A pending account response cannot activate the tunnel", engine.isUp());
                assertFalse("A pending account response cannot install a VPN route", hasVpnRoute(context));
            } finally {
                api.policyGate.set(null);
                pendingPrefetch.respond.countDown();
                approvedPolicy.respond.countDown();
            }
            await("verified connection", controller, () -> "connected".equals(controller.snapshot().mode));
            AppController.State connected = controller.snapshot();
            AppController.ConnectionTiming firstTiming = controller.lastConnectTiming();
            assertNotNull(firstTiming);
            assertTrue(engine.isUp());
            assertTrue(hasVpnRoute(context));
            assertTrue("The closed UDP port was tried before connecting", attemptedClosedPort.get());
            assertSame("Progress and verification share the same account snapshot", trying.get().devices, connected.devices);
            assertSame(trying.get().ports, connected.ports);
            instrumentation.runOnMainSync(() -> assertSame("One connection action retains focus",
                    connectionButton.get(), activity.findViewById(R.id.disconnect)));
            assertEquals(HOST + ":51820", connected.endpoint);
            assertEquals(InetAddress.getByName(V4), InetAddress.getByName(connected.verifiedIpv4));
            assertEquals(InetAddress.getByName(V6), InetAddress.getByName(connected.verifiedIpv6));
            assertEquals("A valid IPv4 proof is kept during the IPv6 retry", 1, verified4.get());
            assertTrue(verified6.get() > 0);
            Network firstNetwork = proved4.get();
            assertNotNull(firstNetwork);
            assertEquals("Both exit families were proven on this activation's VPN", firstNetwork, proved6.get());
            assertTrue("IPv6 was freshly proven after its retry",
                    firstTiming.ipv6ProofAttempts > 1);
            await("connected presence", controller, () -> api.events.contains("presence:connected"));

            tap(instrumentation, activity, R.id.disconnect);
            await("disconnect", controller, () -> !engine.isUp() && !hasVpnRoute(context));
            await("disconnected presence", controller, () -> api.events.contains("presence:disconnected"));
            assertEquals(200, request(null, HOST, 18081, "GET", "/key", "", 2_000).status());

            int previousV4Proofs = verified4.get();
            int previousV6Proofs = verified6.get();
            instrumentation.waitForIdleSync();
            tap(instrumentation, activity, R.id.connect);
            await("verified reconnect", controller, () -> "connected".equals(controller.snapshot().mode));
            assertEquals(HOST + ":51820", controller.snapshot().endpoint);
            AppController.ConnectionTiming reconnectTiming = controller.lastConnectTiming();
            assertNotNull(reconnectTiming);
            if (firstTiming.verifiedUnderlay != null
                    && firstTiming.verifiedUnderlay.equals(reconnectTiming.orderingUnderlay)) {
                assertEquals("A same-network reconnect tries the verified port first",
                        51820, reconnectTiming.firstAttemptedPort);
            }
            assertTrue("Reconnect needs a new IPv4 proof", verified4.get() > previousV4Proofs);
            assertTrue("Reconnect needs a new IPv6 proof", verified6.get() > previousV6Proofs);
            assertFalse("Reconnect must not reuse the previous VPN network for proof",
                    firstNetwork.equals(proved4.get()));
            assertEquals("Reconnect proves both families on its own VPN", proved4.get(), proved6.get());
            tap(instrumentation, activity, R.id.disconnect);
            await("reconnect disconnect", controller, () -> "disconnected".equals(controller.snapshot().mode)
                    && !engine.isUp() && !hasVpnRoute(context));

            api.policyDisabled = true;
            tap(instrumentation, activity, R.id.connect);
            await("fresh policy denies connection", controller, () -> "disconnected".equals(controller.snapshot().mode)
                    && controller.snapshot().message.contains("账号当前不可用"));
            assertFalse("Service preparation must never activate a tunnel before policy", engine.isUp());
            assertFalse(hasVpnRoute(context));

            tap(instrumentation, activity, R.id.nav_account);
            tap(instrumentation, activity, R.id.logout);
            UiObject2 confirmLogout = ui.wait(Until.findObject(By.res("android", "button1")), 7_000);
            assertNotNull("Logout confirmation was shown", confirmLogout);
            confirmLogout.click();
            await("logout", controller, () -> !controller.snapshot().signedIn && !controller.snapshot().busy);
            assertTrue(controller.snapshot().devices.isEmpty());
            assertTrue(controller.snapshot().ports.isEmpty());
            assertTrue(controller.snapshot().deviceId.isEmpty());
            assertTrue(api.events.contains("logout"));
            assertFalse(engine.isUp());
            String priorKey = api.clientPublicKey;
            enter(instrumentation, activity, R.id.username, "fixture");
            enter(instrumentation, activity, R.id.password, "fixture-only");
            tap(instrumentation, activity, R.id.login);
            await("known-device login", controller, () -> controller.snapshot().signedIn && !controller.snapshot().busy);
            assertEquals("A prepared candidate cannot replace an enrolled key", priorKey, api.clientPublicKey);
            assertEquals(AppController.IdentitySource.STORED, controller.lastLoginTiming().identitySource());
            controller.logout();
            await("known-device logout", controller, () -> !controller.snapshot().signedIn && !controller.snapshot().busy);
        } finally {
            controller.removeObserver(observer);
            controller.disconnect();
            instrumentation.runOnMainSync(activity::finish);
        }
    }

    private static boolean hasVpnRoute(Context context) {
        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
            if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                return true;
            }
        }
        return false;
    }

    private static void enter(Instrumentation instrumentation, MainActivity activity, int id, String value) {
        long deadline = SystemClock.elapsedRealtime() + 5_000;
        AtomicBoolean entered = new AtomicBoolean();
        do {
            instrumentation.runOnMainSync(() -> {
                EditText field = activity.findViewById(id);
                if (field != null && field.isShown()) {
                    field.setText(value);
                    entered.set(true);
                }
            });
            if (entered.get()) {
                return;
            }
            // The controller publishes before the Activity handles the update.
            SystemClock.sleep(25);
        } while (SystemClock.elapsedRealtime() < deadline);
        fail("Expected visible field " + activity.getResources().getResourceEntryName(id));
    }

    private static void tap(Instrumentation instrumentation, MainActivity activity, int id) {
        instrumentation.waitForIdleSync();
        instrumentation.runOnMainSync(() -> {
            View view = activity.findViewById(id);
            assertNotNull("Expected control " + activity.getResources().getResourceEntryName(id), view);
            assertTrue("Control must be enabled", view.isEnabled());
            assertTrue(view.performClick());
        });
    }

    @SuppressWarnings("deprecation")
    private static ActivityManager.RunningServiceInfo ownVpnService(Context context) {
        ActivityManager manager = context.getSystemService(ActivityManager.class);
        for (ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
            if (ProxyVpnService.class.getName().equals(service.service.getClassName())) return service;
        }
        return null;
    }

    private static void await(String stage, AppController controller, BooleanSupplier predicate) {
        long end = SystemClock.elapsedRealtime() + 45_000;
        while (SystemClock.elapsedRealtime() < end && !predicate.getAsBoolean()) {
            SystemClock.sleep(60);
        }
        AppController.State state = controller.snapshot();
        assertTrue(stage + " mode=" + state.mode + " message=" + state.message, predicate.getAsBoolean());
    }

    private static String http(Network network, String host, int port, String method, String path,
                               String body, long timeout) throws IOException {
        FixtureHttpResponse response = request(network, host, port, method, path, body, timeout);
        if (response.status() != 200 && response.status() != 204) {
            throw new IOException("Fixture HTTP status " + response.status());
        }
        return response.body().trim();
    }

    private static FixtureHttpResponse request(Network network, String host, int port, String method,
                                               String path, String body, long timeout) throws IOException {
        // A local fixture exchange needs its own attempt budget. A single lost request
        // must not exhaust the real engine's shared 6.5 s deadline for all family retries.
        int timeoutMs = (int) Math.max(1, Math.min(network == null ? 6_000 : 1_500, timeout));
        long deadline = SystemClock.elapsedRealtime() + timeoutMs;
        try (Socket socket = network == null ? new Socket() : network.getSocketFactory().createSocket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout((int) Math.max(1, deadline - SystemClock.elapsedRealtime()));
            String request = method + " " + path + " HTTP/1.0\r\nHost: fixture\r\nContent-Length: "
                    + body.length() + "\r\n\r\n" + body;
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            return FixtureHttpResponse.read(socket.getInputStream());
        }
    }

    private static final class PolicyGate {
        final CountDownLatch requested = new CountDownLatch(1);
        final CountDownLatch respond = new CountDownLatch(1);
    }

    private static final class FixtureApi extends ClientApi {
        private final List<String> events = Collections.synchronizedList(new ArrayList<>());
        private final AtomicReference<PolicyGate> policyGate = new AtomicReference<>();
        private volatile boolean policyDisabled;
        private boolean registered;
        private String clientPublicKey;
        private final String serverPublicKey;

        FixtureApi() throws IOException {
            serverPublicKey = http(null, HOST, 18081, "GET", "/key", "", 3_000);
        }

        @Override
        JSONObject call(String action, String token, JSONObject body) throws Exception {
            if (!"authenticate".equals(action)) {
                assertEquals(TEST_TOKEN, token);
            }
            switch (action) {
                case "authenticate":
                    assertEquals("fixture", body.getString("username"));
                    assertEquals("fixture-only", body.getString("password"));
                    assertEquals(5, body.length());
                    clientPublicKey = body.getString("public_key");
                    assertEquals(44, clientPublicKey.length());
                    Context app = InstrumentationRegistry.getInstrumentation().getTargetContext();
                    String stored = new PrivateStore(app).read(PrivateStore.accountSlot("fixture"));
                    assertFalse("The device key is durable before authentication", stored.isEmpty());
                    assertEquals(TunnelEngine.publicKey(stored), clientPublicKey);
                    return state().put("token", TEST_TOKEN)
                            .put("token_expires_at", System.currentTimeMillis() / 1000 + 900);
                case "enroll":
                    assertTrue(body.getBoolean("confirm"));
                    assertEquals(DEVICE_NAME, body.getString("device_name"));
                    http(null, HOST, 18081, "POST", "/register", clientPublicKey, 3_000);
                    registered = true;
                    return state();
                case "presence":
                    events.add("presence:" + body.getString("mode"));
                    return state();
                case "logout":
                    events.add("logout");
                    return new JSONObject().put("ok", true);
                case "state":
                    PolicyGate gate = policyGate.getAndSet(null);
                    if (gate != null) {
                        gate.requested.countDown();
                        gate.respond.await();
                    }
                    return state();
                default:
                    throw new AssertionError("Unexpected account API operation: " + action);
            }
        }

        private JSONObject state() throws Exception {
            JSONObject device = new JSONObject().put("id", "0123456789ab").put("name", DEVICE_NAME)
                    .put("current", true);
            JSONObject tunnel = new JSONObject().put("transport_address", HOST)
                    .put("endpoint", HOST + ":51820").put("ipv6_policy", "tunnel")
                    .put("ipv6_egress", V6).put("server_public_key", serverPublicKey)
                    .put("native_udp_ports", new JSONArray().put(443).put(51820))
                    .put("addresses", new JSONArray().put("10.77.0.2/32").put("fd77:4242:77::2/128"))
                    .put("allowed_ips", new JSONArray().put("0.0.0.0/0").put("::/0"))
                    .put("dns", new JSONArray().put(V4))
                    .put("egress_ipv4_candidates", new JSONArray().put(V4));
            return new JSONObject().put("ok", true).put("schema", 1)
                    .put("observed_at", System.currentTimeMillis() / 1000)
                    .put("account", new JSONObject().put("status", policyDisabled ? "disabled" : "active")
                            .put("username", "fixture"))
                    .put("device", device)
                    .put("devices", new JSONArray().put(device))
                    .put("registration", new JSONObject().put("status", registered ? "registered" : "confirmation_required")
                            .put("device_id", registered ? "0123456789ab" : ""))
                    .put("tunnel", registered ? tunnel : JSONObject.NULL);
        }
    }
}
