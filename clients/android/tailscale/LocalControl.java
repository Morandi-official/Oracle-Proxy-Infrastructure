package org.morandi.proxy.tailscale;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import libtailscale.Application;
import libtailscale.InputStream;
import libtailscale.LocalAPIResponse;
import org.json.JSONException;
import org.json.JSONObject;

/** Controls the daemon directly through its JNI binding on a worker thread. */
public final class LocalControl {
    private static final String API = "/localapi/v0/";
    private static final int MAX_STATUS_BYTES = 65_536;
    private static final Pattern ENROLLMENT_KEY =
            Pattern.compile("hskey-auth-[A-Za-z0-9_-]{12}-[A-Za-z0-9_-]{64}");
    private final Application application;

    public LocalControl(Application application) {
        this.application = Objects.requireNonNull(application);
    }

    public DaemonState readState() throws IOException {
        try {
            byte[] bytes = request("GET", "status?peers=false", null);
            if (bytes == null || bytes.length > MAX_STATUS_BYTES) {
                throw new IOException("INVALID_TAILSCALE_STATUS");
            }
            JSONObject state = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
            var addresses = new ArrayList<String>();
            var raw = state.optJSONArray("TailscaleIPs");
            if (raw != null) {
                for (int index = 0; index < raw.length(); index++) addresses.add(raw.getString(index));
            }
            var exit = state.optJSONObject("ExitNodeStatus");
            return new DaemonState(state.getString("BackendState"), state.optBoolean("HaveNodeKey"),
                    exit == null ? "" : exit.optString("ID"), Collections.unmodifiableList(addresses));
        } catch (JSONException error) {
            throw new IOException("INVALID_TAILSCALE_STATUS");
        }
    }

    public void enroll(URI coordinator, String credential) throws IOException {
        String path = coordinator.getRawPath();
        String host = coordinator.getHost();
        if (!"https".equalsIgnoreCase(coordinator.getScheme()) || host == null ||
                !host.matches("(?i)[a-z0-9-]+(?:\\.[a-z0-9-]+)+") || host.matches("[0-9.]+") ||
                (coordinator.getPort() != -1 && coordinator.getPort() != 443) ||
                coordinator.getRawUserInfo() != null || (!path.isEmpty() && !path.equals("/")) ||
                coordinator.getRawQuery() != null || coordinator.getRawFragment() != null) {
            throw new IllegalArgumentException("INVALID_TAILSCALE_COORDINATOR");
        }
        if (!ENROLLMENT_KEY.matcher(credential).matches()) {
            throw new IllegalArgumentException("INVALID_TAILSCALE_ENROLLMENT");
        }
        if (readState().hasNodeKey()) {
            throw new IOException("TAILSCALE_DEVICE_ALREADY_REGISTERED");
        }
        try {
            JSONObject preferences = new JSONObject()
                    .put("ControlURL", "https://" + host)
                    .put("WantRunning", true)
                    .put("ShieldsUp", true)
                    .put("CorpDNS", true)
                    .put("RouteAll", false);
            request("POST", "start", new JSONObject().put("AuthKey", credential).put("UpdatePrefs", preferences));
            request("POST", "login-interactive", null);
        } catch (JSONException error) {
            throw new IOException("INVALID_TAILSCALE_ENROLLMENT");
        }
    }

    public void selectExitNode(long nodeId) throws IOException {
        if (nodeId <= 0) {
            throw new IllegalArgumentException("INVALID_TAILSCALE_EXIT_NODE");
        }
        try {
            request("PATCH", "prefs", new JSONObject()
                    .put("ExitNodeID", Long.toString(nodeId))
                    .put("ExitNodeIDSet", true)
                    .put("ExitNodeIPSet", true)
                    .put("ExitNodeAllowLANAccess", false)
                    .put("ExitNodeAllowLANAccessSet", true)
                    .put("WantRunning", true)
                    .put("WantRunningSet", true));
        } catch (JSONException error) {
            throw new IOException("INVALID_TAILSCALE_EXIT_NODE");
        }
    }

    public void stop() throws IOException {
        try {
            request("PATCH", "prefs", new JSONObject().put("WantRunning", false).put("WantRunningSet", true));
        } catch (JSONException error) {
            throw new IOException("INVALID_TAILSCALE_PREFERENCES");
        }
    }

    private byte[] request(String method, String endpoint, JSONObject value) throws IOException {
        try {
            InputStream body = value == null ? null : new RequestBody(value.toString().getBytes(StandardCharsets.UTF_8));
            LocalAPIResponse response = application.callLocalAPI(3_000, method, API + endpoint, body);
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IOException("TAILSCALE_LOCAL_CONTROL_REJECTED");
            }
            return response.bodyBytes();
        } catch (Exception error) {
            // Native errors may include URLs so the caller receives a fixed code.
            throw new IOException("TAILSCALE_LOCAL_CONTROL_UNAVAILABLE");
        }
    }

    private static final class RequestBody implements InputStream {
        private byte[] bytes;

        RequestBody(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public byte[] read() {
            byte[] result = bytes;
            close();
            return result;
        }

        @Override
        public void close() {
            bytes = null;
        }
    }

    public record DaemonState(String state, boolean hasNodeKey, String exitId, List<String> addresses) {}
}
