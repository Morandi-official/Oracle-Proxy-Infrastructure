package org.morandi.proxy.tailscale;

import android.net.InetAddresses;
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
                    exit == null ? "" : exit.optString("ID"), Collections.unmodifiableList(addresses),
                    selectedExitIpv4(exit));
        } catch (JSONException error) {
            throw new IOException("INVALID_TAILSCALE_STATUS");
        }
    }

    private static String selectedExitIpv4(JSONObject exit) {
        var prefixes = exit == null ? null : exit.optJSONArray("TailscaleIPs");
        if (prefixes == null) return "";
        for (int index = 0; index < prefixes.length(); index++) {
            String prefix = prefixes.optString(index);
            if (!prefix.endsWith("/32")) continue;
            try {
                var address = InetAddresses.parseNumericAddress(prefix.substring(0, prefix.length() - 3));
                byte[] octets = address.getAddress();
                if (octets.length == 4 && octets[0] == 100 && (octets[1] & 0xc0) == 64) {
                    return address.getHostAddress();
                }
            } catch (IllegalArgumentException invalid) {
                // Skip malformed or non-tailnet peer addresses.
            }
        }
        return "";
    }

    boolean primeExitPeer(String address) {
        try {
            var value = request("POST", "ping?type=TSMP&ip=" + address, null, 500);
            if (value == null || value.length > MAX_STATUS_BYTES) return false;
            var reply = new JSONObject(new String(value, StandardCharsets.UTF_8));
            return reply.optString("Err").isEmpty() && address.equals(reply.optString("NodeIP"));
        } catch (IOException | JSONException failure) {
            return false;
        }
    }

    String exitPath() throws IOException {
        try {
            byte[] bytes = request("GET", "status", null);
            if (bytes == null || bytes.length > MAX_STATUS_BYTES) throw new IOException("INVALID_TAILSCALE_STATUS");
            var status = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
            var exit = status.optJSONObject("ExitNodeStatus");
            var peers = status.optJSONObject("Peer");
            if (exit != null && peers != null) {
                String id = exit.getString("ID");
                for (var iterator = peers.keys(); iterator.hasNext();) {
                    var peer = peers.getJSONObject(iterator.next());
                    if (!id.equals(peer.optString("ID"))) continue;
                    if (!peer.optString("CurAddr").isEmpty()) return "direct";
                    if (!peer.optString("PeerRelay").isEmpty()) return "peer-relay";
                    if (!peer.optString("Relay").isEmpty()) return "derp";
                }
            }
            return "unobserved";
        } catch (JSONException failure) {
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
        return request(method, endpoint, value, 3_000);
    }

    private byte[] request(String method, String endpoint, JSONObject value, int timeoutMs) throws IOException {
        try {
            InputStream body = value == null ? null : new RequestBody(value.toString().getBytes(StandardCharsets.UTF_8));
            LocalAPIResponse response = application.callLocalAPI(timeoutMs, method, API + endpoint, body);
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

    public record DaemonState(String state, boolean hasNodeKey, String exitId, List<String> addresses,
                              String exitPeerIpv4) {}
}
