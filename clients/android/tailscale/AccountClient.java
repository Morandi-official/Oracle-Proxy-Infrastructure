package org.morandi.proxy.tailscale;

import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONException;
import org.json.JSONObject;

final class AccountClient {
    private static final URI BASE = URI.create("https://vpn-admin.morandi.dpdns.org/api/tailscale/v1/");
    private static final int MAX_RESPONSE_BYTES = 16_384;
    private final AtomicReference<HttpURLConnection> request = new AtomicReference<>();
    private final ConnectivityManager networks;
    // Account requests are serialized by the client action worker.
    private Network directPool;

    AccountClient() {
        this(null);
    }

    AccountClient(ConnectivityManager networks) {
        this.networks = networks;
    }

    String login(String username, String password, String device) throws IOException, JSONException {
        var body = new JSONObject().put("username", username).put("password", password).put("device", device);
        return post("login", null, body).getString("token");
    }

    Profile profile(String token, boolean confirm) throws IOException, JSONException {
        var value = post(confirm ? "confirm" : "profile", token, new JSONObject());
        return new Profile(URI.create(value.getString("coordinator")), Long.parseLong(value.getString("exit_node_id")),
                value.getString("ipv4"), value.getString("ipv6"),
                value.isNull("enrollment_key") ? null : value.getString("enrollment_key"));
    }

    void release(String token) throws IOException, JSONException {
        if (!post("release", token, new JSONObject()).optBoolean("released")) {
            throw new IOException("DEVICE_RELEASE_UNCONFIRMED");
        }
    }

    void cancelCurrentRequest() {
        var current = request.get();
        if (current != null) current.disconnect();
    }

    private HttpURLConnection open(URL url) throws IOException {
        if (networks != null) {
            var active = networks.getActiveNetwork();
            var scope = active == null ? null : networks.getNetworkCapabilities(active);
            if (scope != null && scope.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    && !scope.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    && networks.getBoundNetworkForProcess() == null) {
                // Android owns a pool per Network object. Reuse it only when its network is the current default.
                if (!active.equals(directPool)) directPool = active;
                var connection = (HttpURLConnection) directPool.openConnection(url, Proxy.NO_PROXY);
                if (active.equals(networks.getActiveNetwork())) return connection;
                connection.disconnect();
            }
        }
        return (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
    }

    private JSONObject post(String action, String token, JSONObject body) throws IOException, JSONException {
        HttpURLConnection connection = open(BASE.resolve(action).toURL());
        request.set(connection);
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setConnectTimeout(5_000);
            connection.setReadTimeout(12_000);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            if (token != null) connection.setRequestProperty("Authorization", "Bearer " + token);
            byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(bytes.length);
            connection.setDoOutput(true);
            try (var output = connection.getOutputStream()) { output.write(bytes); }
            int status = connection.getResponseCode();
            var source = status == 200 ? connection.getInputStream() : connection.getErrorStream();
            if (source == null) throw new IOException("ACCOUNT_SERVICE_UNAVAILABLE");
            try (source; var output = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                for (int count; (count = source.read(buffer)) != -1; ) {
                    if (output.size() + count > MAX_RESPONSE_BYTES) throw new IOException("ACCOUNT_RESPONSE_INVALID");
                    output.write(buffer, 0, count);
                }
                var value = new JSONObject(new String(output.toByteArray(), StandardCharsets.UTF_8));
                if (status != 200) {
                    String code = value.optString("error");
                    throw new IOException(code.matches("[A-Z_]{1,80}") ? code : "ACCOUNT_SERVICE_UNAVAILABLE");
                }
                return value;
            }
        } finally {
            request.compareAndSet(connection, null);
            connection.disconnect();
        }
    }

    record Profile(URI coordinator, long exitId, String ipv4, String ipv6, String key) { }
}
