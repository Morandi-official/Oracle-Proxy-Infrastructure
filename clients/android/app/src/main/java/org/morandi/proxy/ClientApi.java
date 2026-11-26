package org.morandi.proxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.SystemClock;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import javax.net.ssl.HttpsURLConnection;

class ClientApi {
    private static final String ORIGIN = "https://vpn-admin.morandi.dpdns.org";
    private static final String LOGIN_WARMUP_PATH = "/api/client/quic-certificate";
    private static final List<String> ACTIONS = Arrays.asList(
            "authenticate", "enroll", "state", "presence", "logout", "device-delete");
    private static final int RESPONSE_LIMIT = 65_536;

    private final ConnectivityManager connectivity;
    private Network reusablePhysicalNetwork;
    private volatile PasswordTiming lastPasswordTiming;

    record PasswordTiming(long streamOpenMs, long uploadMs, long responseHeadersMs,
                          long responseBodyMs) {}

    PasswordTiming lastPasswordTiming() {
        return lastPasswordTiming;
    }

    ClientApi() {
        connectivity = null;
    }

    ClientApi(Context context) {
        connectivity = context.getSystemService(ConnectivityManager.class);
    }

    JSONObject call(String action, String token, JSONObject body) throws Exception {
        if (!ACTIONS.contains(action) || ("state".equals(action) != (body == null))) {
            throw new IllegalArgumentException("INVALID_CLIENT_REQUEST");
        }
        if (!token.isEmpty() && !validToken(token)) {
            throw new ApiError("LOGIN_REQUIRED");
        }

        boolean passwordRequest = "authenticate".equals(action);
        long started = passwordRequest ? SystemClock.elapsedRealtime() : 0;
        long streamOpened = 0;
        long requestWritten = 0;
        if (passwordRequest) {
            lastPasswordTiming = null;
        }
        URL url = new URL(ORIGIN + "/api/client/" + action);
        Network controlNetwork = controlNetwork();
        HttpsURLConnection connection = (HttpsURLConnection) (controlNetwork == null
                ? url.openConnection(Proxy.NO_PROXY)
                : controlNetwork.openConnection(url, Proxy.NO_PROXY));
        boolean responseConsumed = false;
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setConnectTimeout(6_000);
            connection.setReadTimeout(6_000);
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("X-Oracle-Client-Capabilities", "dual-stack-v1");
            if (!token.isEmpty()) {
                connection.setRequestProperty("Authorization", "Bearer " + token);
            }
            connection.setRequestMethod(body == null ? "GET" : "POST");
            if (body != null) {
                byte[] request = body.toString().getBytes(StandardCharsets.UTF_8);
                if (request.length > 4_096) {
                    throw new ApiError("INVALID_REQUEST");
                }
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setFixedLengthStreamingMode(request.length);
                connection.setDoOutput(true);
                try (var output = connection.getOutputStream()) {
                    if (passwordRequest) {
                        streamOpened = SystemClock.elapsedRealtime();
                    }
                    output.write(request);
                } finally {
                    java.util.Arrays.fill(request, (byte) 0);
                }
                if (passwordRequest) {
                    requestWritten = SystemClock.elapsedRealtime();
                }
            }
            int status = connection.getResponseCode();
            long headersReceived = passwordRequest ? SystemClock.elapsedRealtime() : 0;
            if (status >= 300 && status < 400) {
                throw new ApiError("API_UNAVAILABLE");
            }
            boolean success = status >= 200 && status < 300;
            InputStream responseStream = success ? connection.getInputStream() : connection.getErrorStream();
            JSONObject response;
            try (InputStream stream = responseStream) {
                response = readObject(stream);
            }
            // Closing the drained body returns the connection to Android's pool.
            responseConsumed = responseStream != null;
            if (!success) {
                String code = response.optString("error");
                if (!code.matches("[A-Z][A-Z0-9_]{1,63}")) {
                    code = status == 401 ? "LOGIN_REQUIRED" : "API_UNAVAILABLE";
                }
                throw new ApiError(code);
            }
            if (passwordRequest) {
                lastPasswordTiming = new PasswordTiming(streamOpened - started,
                        requestWritten - streamOpened, headersReceived - requestWritten,
                        SystemClock.elapsedRealtime() - headersReceived);
            }
            return response;
        } finally {
            if (!responseConsumed) {
                connection.disconnect();
            }
        }
    }

    void warmLoginConnection() {
        HttpsURLConnection connection = null;
        boolean responseConsumed = false;
        try {
            Network network = controlNetwork();
            if (network == null) {
                return;
            }
            connection = (HttpsURLConnection) network.openConnection(
                    new URL(ORIGIN + LOGIN_WARMUP_PATH), Proxy.NO_PROXY);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setConnectTimeout(1_500);
            connection.setReadTimeout(1_500);
            if (connection.getResponseCode() == 200) {
                try (InputStream response = connection.getInputStream()) {
                    readObject(response);
                }
                responseConsumed = true;
            }
        } catch (Exception ignored) {
            // Login does not wait for this anonymous request and sends credentials only once.
        } finally {
            if (connection != null && !responseConsumed) {
                connection.disconnect();
            }
        }
    }

    static boolean validToken(String token) {
        return token.matches("[A-Za-z0-9_-]{43}");
    }

    private synchronized Network controlNetwork() {
        Network selected = physicalNetwork();
        // Android's HTTP connection pool belongs to the Network instance, not its netId.
        // Retain that instance only while ConnectivityManager still selects this network.
        if (!Objects.equals(reusablePhysicalNetwork, selected)) {
            reusablePhysicalNetwork = selected;
        }
        return reusablePhysicalNetwork;
    }

    private Network physicalNetwork() {
        if (connectivity == null) {
            return null;
        }
        Network active = connectivity.getActiveNetwork();
        if (eligible(active, false)) {
            return active;
        }
        // The control plane may share the public address of the tunnel. Use the
        // underlying network only for this one TLS-authenticated API origin.
        for (Network network : connectivity.getAllNetworks()) {
            if (eligible(network, true)) {
                return network;
            }
        }
        return null;
    }

    private boolean eligible(Network network, boolean validated) {
        if (network == null) {
            return false;
        }
        NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
        return capabilities != null
                && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                && (!validated || capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED));
    }

    private static JSONObject readObject(InputStream stream) throws Exception {
        if (stream == null) {
            return new JSONObject();
        }
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = stream.read(buffer)) != -1) {
            if (data.size() + count > RESPONSE_LIMIT) {
                throw new IOException("API_RESPONSE_TOO_LARGE");
            }
            data.write(buffer, 0, count);
        }
        return new JSONObject(data.toString(StandardCharsets.UTF_8.name()));
    }

    static final class ApiError extends IOException {
        final String code;

        ApiError(String code) {
            super(code);
            this.code = code;
        }
    }
}
