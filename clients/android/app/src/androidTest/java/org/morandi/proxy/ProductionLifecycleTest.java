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

import java.nio.charset.StandardCharsets;
import java.util.function.BooleanSupplier;

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
        TunnelEngine engine = new TunnelEngine(context);
        AcceptanceApi api = new AcceptanceApi(context);
        AppController controller = new AppController(context, api, engine);
        AppController.installForTest(controller);
        MainActivity activity = (MainActivity) instrumentation.startActivitySync(
                new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        try {
            controller.login(username, password, false);
            await("Production TLS authentication", () -> controller.snapshot().signedIn
                    && !controller.snapshot().busy);
            assertFalse("Release test requires a fresh emulator identity", controller.snapshot().registered);
            controller.confirmDevice("Android CI " + run);
            await("Production device enrollment", () -> controller.snapshot().registered
                    && !controller.snapshot().busy);

            instrumentation.waitForIdleSync();
            instrumentation.runOnMainSync(() -> {
                android.view.View connect = activity.findViewById(R.id.connect);
                assertNotNull("Connect action is present", connect);
                assertTrue("Connect action was accepted", connect.performClick());
            });
            UiDevice ui = UiDevice.getInstance(instrumentation);
            UiObject2 allow = ui.wait(Until.findObject(By.res("android", "button1")), 8_000);
            assertNotNull("Android VPN consent appeared on fresh installation", allow);
            allow.click();
            await("Production authenticated UDP and verified exit", () -> "connected".equals(controller.snapshot().mode));
            assertTrue("Verified production IPv4 egress", !controller.snapshot().verifiedIpv4.isEmpty());
            if (api.dualStack) {
                assertTrue("Verified production IPv6 egress", !controller.snapshot().verifiedIpv6.isEmpty());
            }
            Network vpn = vpnNetwork(context);
            assertNotNull("Production VPN network is installed", vpn);
            assertTrue("DNS resolves over the VPN network", vpn.getAllByName("www.cloudflare.com").length > 0);
            controller.disconnect();
            await("Production VPN route removed", () -> !engine.isUp() && vpnNetwork(context) == null);
            controller.removeDevice(controller.snapshot().deviceId);
            await("Dedicated test device removed and signed out", () -> !controller.snapshot().signedIn);
        } finally {
            controller.disconnect();
            instrumentation.runOnMainSync(activity::finish);
            api.cleanUp();
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
            JSONObject response = super.call(action, credential, body);
            if ("authenticate".equals(action)) {
                token = response.getString("token");
                JSONObject registration = response.getJSONObject("registration");
                if ("pending".equals(registration.optString("status"))) {
                    newDevice = registration.optString("device_id");
                }
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

        void cleanUp() throws Exception {
            if (removed || token.isEmpty()) {
                return;
            }
            if (enrollmentAttempted && newDevice.matches("[a-f0-9]{12}")) {
                for (int attempt = 0; attempt < 3; attempt++) {
                    try {
                        JSONObject response = super.call("device-delete", token,
                                new JSONObject().put("device_id", newDevice));
                        assertTrue("Teardown removed exactly the acceptance device",
                                response.optBoolean("current") && newDevice.equals(response.optString("removed")));
                        return;
                    } catch (ClientApi.ApiError failure) {
                        if ("DEVICE_NOT_FOUND".equals(failure.code)) {
                            break;
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
            try {
                super.call("logout", token, new JSONObject());
            } catch (ClientApi.ApiError failure) {
                if (!"LOGIN_REQUIRED".equals(failure.code)) {
                    throw new AssertionError("Acceptance session cleanup requires review");
                }
            }
        }
    }
}
