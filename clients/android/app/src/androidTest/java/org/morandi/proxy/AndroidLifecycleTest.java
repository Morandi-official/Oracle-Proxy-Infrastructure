package org.morandi.proxy;

import android.app.Instrumentation;
import android.content.Context;
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public final class AndroidLifecycleTest {
    private static final String TEST_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String HOST = "10.0.2.2";
    private static final String V4 = "10.77.0.1";
    private static final String V6 = "fd77:4242:77::1";
    private static final String DEVICE_NAME = "Android 验收设备";

    @Test
    public void loginEnrollConsentConnectDisconnectAndLogout() throws Exception {
        Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context context = instrumentation.getTargetContext();
        AtomicInteger verified4 = new AtomicInteger();
        AtomicInteger verified6 = new AtomicInteger();
        FixtureApi api = new FixtureApi();
        TunnelEngine engine = new TunnelEngine(context, (network, expected, ipv6, timeout) -> {
            String observed = http(network, expected, 18080, "GET", "/exit", "", timeout);
            (ipv6 ? verified6 : verified4).incrementAndGet();
            return observed;
        }, true);
        AppController controller = new AppController(context, api, engine);
        AppController.installForTest(controller);
        AtomicBoolean attemptedClosedPort = new AtomicBoolean();
        AppController.Listener observer = state -> {
            if ((HOST + ":443").equals(state.endpoint)) {
                attemptedClosedPort.set(true);
            }
        };
        controller.observe(observer);
        MainActivity activity = (MainActivity) instrumentation.startActivitySync(
                new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        try {
            UiDevice ui = UiDevice.getInstance(instrumentation);
            enter(instrumentation, activity, R.id.username, "fixture");
            enter(instrumentation, activity, R.id.password, "fixture-only");
            tap(instrumentation, activity, R.id.login);
            await("sign-in", controller, () -> controller.snapshot().signedIn && !controller.snapshot().busy);
            assertFalse(controller.snapshot().registered);

            enter(instrumentation, activity, R.id.device_name, DEVICE_NAME);
            tap(instrumentation, activity, R.id.device_confirm);
            await("enrollment", controller, () -> controller.snapshot().registered && !controller.snapshot().busy);
            assertEquals("0123456789ab", controller.snapshot().deviceId);

            assertNotNull("A newly installed app asks for VPN consent", VpnService.prepare(context));
            tap(instrumentation, activity, R.id.connect);
            UiObject2 allow = ui.wait(Until.findObject(By.res("android", "button1")), 7_000);
            assertNotNull("The Android VPN consent dialog was shown", allow);
            UiObject2 deny = ui.wait(Until.findObject(By.res("android", "button2")), 7_000);
            assertNotNull("The Android VPN consent dialog has a cancel button", deny);
            deny.click();
            await("consent cancellation", controller, () -> controller.snapshot().message.contains("系统未授权 VPN"));
            assertFalse(engine.isUp());

            tap(instrumentation, activity, R.id.connect);
            allow = ui.wait(Until.findObject(By.res("android", "button1")), 7_000);
            assertNotNull("The user can reopen VPN consent", allow);
            allow.click();
            await("verified connection", controller, () -> "connected".equals(controller.snapshot().mode));
            AppController.State connected = controller.snapshot();
            assertTrue(engine.isUp());
            assertTrue(hasVpnRoute(context));
            assertTrue("The closed UDP port was tried before connecting", attemptedClosedPort.get());
            assertEquals(HOST + ":51820", connected.endpoint);
            assertEquals(InetAddress.getByName(V4), InetAddress.getByName(connected.verifiedIpv4));
            assertEquals(InetAddress.getByName(V6), InetAddress.getByName(connected.verifiedIpv6));
            assertTrue(verified4.get() > 0);
            assertTrue(verified6.get() > 0);
            await("connected presence", controller, () -> api.events.contains("presence:connected"));

            tap(instrumentation, activity, R.id.disconnect);
            await("disconnect", controller, () -> !engine.isUp() && !hasVpnRoute(context));
            await("disconnected presence", controller, () -> api.events.contains("presence:disconnected"));
            assertEquals(200, Integer.parseInt(httpStatus(null, HOST, 18081, "GET", "/key", "", 2_000)));

            tap(instrumentation, activity, R.id.nav_account);
            tap(instrumentation, activity, R.id.logout);
            UiObject2 confirmLogout = ui.wait(Until.findObject(By.res("android", "button1")), 7_000);
            assertNotNull("Logout confirmation was shown", confirmLogout);
            confirmLogout.click();
            await("logout", controller, () -> !controller.snapshot().signedIn && !controller.snapshot().busy);
            assertTrue(api.events.contains("logout"));
            assertFalse(engine.isUp());
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
        instrumentation.runOnMainSync(() -> {
            EditText view = activity.findViewById(id);
            assertNotNull(view);
            view.setText(value);
        });
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
        String response = request(network, host, port, method, path, body, timeout);
        String status = response.substring(0, response.indexOf("\r\n"));
        if (!status.startsWith("HTTP/1.0 200") && !status.startsWith("HTTP/1.0 204")) {
            throw new IOException("Fixture HTTP request was rejected");
        }
        return response.substring(response.indexOf("\r\n\r\n") + 4).trim();
    }

    private static String httpStatus(Network network, String host, int port, String method, String path,
                                     String body, long timeout) throws IOException {
        return request(network, host, port, method, path, body, timeout).split(" ", 3)[1];
    }

    private static String request(Network network, String host, int port, String method, String path,
                                  String body, long timeout) throws IOException {
        int timeoutMs = (int) Math.max(250, Math.min(6_000, timeout));
        try (Socket socket = network == null ? new Socket() : network.getSocketFactory().createSocket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            String request = method + " " + path + " HTTP/1.0\r\nHost: fixture\r\nContent-Length: "
                    + body.length() + "\r\n\r\n" + body;
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            try (InputStream stream = socket.getInputStream()) {
                ByteArrayOutputStream data = new ByteArrayOutputStream();
                byte[] block = new byte[512];
                for (int read; (read = stream.read(block)) != -1; ) {
                    if (data.size() + read > 8_192) {
                        throw new IOException("Fixture response exceeded limit");
                    }
                    data.write(block, 0, read);
                }
                return data.toString(StandardCharsets.US_ASCII.name());
            }
        }
    }

    private static final class FixtureApi extends ClientApi {
        private final List<String> events = Collections.synchronizedList(new ArrayList<>());
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
                    .put("account", new JSONObject().put("status", "active").put("username", "fixture"))
                    .put("device", device)
                    .put("devices", new JSONArray().put(device))
                    .put("registration", new JSONObject().put("status", registered ? "registered" : "confirmation_required")
                            .put("device_id", registered ? "0123456789ab" : ""))
                    .put("tunnel", registered ? tunnel : JSONObject.NULL);
        }
    }
}
