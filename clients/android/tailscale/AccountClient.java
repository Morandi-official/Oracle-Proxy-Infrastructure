package org.morandi.proxy.tailscale;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.json.JSONException;
import org.json.JSONObject;

final class AccountClient {
    private static final URI BASE = URI.create("https://vpn-admin.morandi.dpdns.org/api/tailscale/v1/");
    private static final int MAX_RESPONSE_BYTES = 16_384;

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

    private JSONObject post(String action, String token, JSONObject body) throws IOException, JSONException {
        HttpURLConnection connection = (HttpURLConnection) BASE.resolve(action).toURL().openConnection(Proxy.NO_PROXY);
        try {
            connection.setInstanceFollowRedirects(false);
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
            connection.disconnect();
        }
    }

    record Profile(URI coordinator, long exitId, String ipv4, String ipv6, String key) { }
}
