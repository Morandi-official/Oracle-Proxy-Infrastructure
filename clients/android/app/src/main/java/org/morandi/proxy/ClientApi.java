package org.morandi.proxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.SystemClock;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.EventListener;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okio.BufferedSink;

class ClientApi {
    private static final String HOST = "vpn-admin.morandi.dpdns.org";
    private static final String ORIGIN = "https://" + HOST;
    private static final byte[] BOOTSTRAP_IPV4 = {(byte) 152, 67, (byte) 156, 100};
    private static final List<String> ACTIONS = Arrays.asList(
            "authenticate", "enroll", "state", "presence", "logout", "device-delete");
    private static final int RESPONSE_LIMIT = 65_536;
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final long FOREGROUND_TIMEOUT_MS = 42_000;
    private static final long BACKGROUND_TIMEOUT_MS = 12_000;
    private static final long VERIFY_TIMEOUT_MS = 18_000;

    private static final class Http {
        static final OkHttpClient CLIENT = new OkHttpClient.Builder()
                .proxy(Proxy.NO_PROXY)
                .followRedirects(false)
                .followSslRedirects(false)
                .retryOnConnectionFailure(false)
                .connectTimeout(VERIFY_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .readTimeout(24, TimeUnit.SECONDS)
                .callTimeout(VERIFY_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .eventListenerFactory(call -> {
                    PasswordMetrics metrics = call.request().tag(PasswordMetrics.class);
                    return metrics == null ? EventListener.NONE : metrics;
                })
                .build();
    }

    private final ConnectivityManager connectivity;
    private Routes reusableRoutes;
    private volatile PasswordTiming lastPasswordTiming;
    private enum Warmup { NONE, RUNNING, READY, UNAVAILABLE }
    private final AtomicReference<LoginWarmup> loginWarmup = new AtomicReference<>();

    // One offer per visible sign-in screen. The click can cancel a queued GET
    // even while it is selecting a Network. Only the GET worker owns its socket.
    static final class LoginWarmup {
        private volatile Warmup state = Warmup.NONE;
        private boolean pending = true;

        synchronized boolean begin() {
            if (!pending) return false;
            pending = false;
            state = Warmup.RUNNING;
            return true;
        }

        synchronized void cancelPending() { pending = false; }

        private synchronized void finish(boolean reusable) {
            if (pending || state == Warmup.RUNNING) {
                pending = false;
                state = reusable ? Warmup.READY : Warmup.UNAVAILABLE;
            }
        }
    }

    LoginWarmup offerLoginWarmup() {
        LoginWarmup offer = new LoginWarmup();
        LoginWarmup previous = loginWarmup.getAndSet(offer);
        if (previous != null) previous.cancelPending();
        return offer;
    }

    void cancelPendingLoginWarmup() {
        LoginWarmup offer = loginWarmup.get();
        if (offer != null) offer.cancelPending();
    }

    record PasswordTiming(long streamOpenMs, long uploadMs, long responseHeadersMs,
                          long responseBodyMs, long networkSelectMs, long configureMs, long outputOpenMs,
                          String warmupAtStart, String warmupAtOutput) {}

    private static final class PasswordMetrics extends EventListener {
        final LoginWarmup warmup;
        long streamOpened, requestWritten, headersReceived;
        Warmup warmupAtOutput;

        PasswordMetrics(LoginWarmup warmup) { this.warmup = warmup; }

        @Override public void requestBodyStart(Call call) {
            streamOpened = SystemClock.elapsedRealtime();
            warmupAtOutput = warmup == null ? Warmup.NONE : warmup.state;
        }

        @Override public void requestBodyEnd(Call call, long byteCount) {
            requestWritten = SystemClock.elapsedRealtime();
        }

        @Override public void responseHeadersEnd(Call call, Response response) {
            headersReceived = SystemClock.elapsedRealtime();
        }
    }

    private static final class SinglePost extends RequestBody {
        private final byte[] data;

        SinglePost(byte[] data) { this.data = data; }
        @Override public MediaType contentType() { return JSON; }
        @Override public long contentLength() { return data.length; }
        @Override public boolean isOneShot() { return true; }
        @Override public void writeTo(BufferedSink sink) throws IOException { sink.write(data); }
    }

    PasswordTiming lastPasswordTiming() {
        return lastPasswordTiming;
    }

    ClientApi() {
        connectivity = null;
    }

    ClientApi(Context context) {
        connectivity = context.getSystemService(ConnectivityManager.class);
    }

    ClientApi(OkHttpClient ordinary, OkHttpClient bootstrap) {
        connectivity = null;
        reusableRoutes = new Routes(null, ordinary, bootstrap);
    }

    JSONObject call(String action, String token, JSONObject body) throws Exception {
        if (!ACTIONS.contains(action) || ("state".equals(action) != (body == null))) {
            throw new IllegalArgumentException("INVALID_CLIENT_REQUEST");
        }
        if (!token.isEmpty() && !validToken(token)) {
            throw new ApiError("LOGIN_REQUIRED");
        }

        boolean passwordRequest = "authenticate".equals(action);
        long started = SystemClock.elapsedRealtime();
        long deadline = started + (passwordRequest || "enroll".equals(action)
                ? FOREGROUND_TIMEOUT_MS : BACKGROUND_TIMEOUT_MS);
        LoginWarmup offered = loginWarmup.get();
        Warmup warmupAtStart = offered == null ? Warmup.NONE : offered.state;
        if (passwordRequest) {
            lastPasswordTiming = null;
        }
        Routes routes = controlRoutes();
        long networkSelected = SystemClock.elapsedRealtime();
        CompletableFuture<OkHttpClient> verification = routes.verified();
        OkHttpClient client;
        try {
            client = verification.get(remaining(deadline), TimeUnit.MILLISECONDS);
        } catch (ExecutionException failure) {
            throw accountError(failure.getCause());
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw accountError(failure);
        } catch (TimeoutException failure) {
            throw accountError(failure);
        }

        Request.Builder request = request(action);
        if (!token.isEmpty()) request.header("Authorization", "Bearer " + token);
        byte[] data = body == null ? null : body.toString().getBytes(StandardCharsets.UTF_8);
        PasswordMetrics metrics = passwordRequest ? new PasswordMetrics(offered) : null;
        try {
            if (data != null) {
                if (data.length > 4_096) throw new ApiError("INVALID_REQUEST");
                request.post(new SinglePost(data));
            }
            if (metrics != null) request.tag(PasswordMetrics.class, metrics);
            Call call = client.newCall(request.build());
            call.timeout().timeout(remaining(deadline), TimeUnit.MILLISECONDS);
            long outputRequested = SystemClock.elapsedRealtime();
            try (Response exchange = call.execute()) {
                if (exchange.isRedirect()) throw new ApiError("API_UNAVAILABLE");
                JSONObject response = readObject(exchange, RESPONSE_LIMIT);
                if (!exchange.isSuccessful()) {
                    String code = response.optString("error");
                    if (!code.matches("[A-Z][A-Z0-9_]{1,63}")) {
                        code = exchange.code() == 401 ? "LOGIN_REQUIRED" : "API_UNAVAILABLE";
                    }
                    throw new ApiError(code);
                }
                if (metrics != null && metrics.warmupAtOutput != null) {
                    lastPasswordTiming = new PasswordTiming(metrics.streamOpened - started,
                            metrics.requestWritten - metrics.streamOpened,
                            metrics.headersReceived - metrics.requestWritten,
                            SystemClock.elapsedRealtime() - metrics.headersReceived, networkSelected - started,
                            outputRequested - networkSelected, metrics.streamOpened - outputRequested,
                            warmupAtStart.name(), metrics.warmupAtOutput.name());
                }
                return response;
            }
        } catch (ApiError failure) {
            if ("API_UNAVAILABLE".equals(failure.code)) routes.invalidate(verification);
            throw failure;
        } catch (IOException failure) {
            routes.invalidate(verification);
            throw accountError(failure);
        } finally {
            if (data != null) Arrays.fill(data, (byte) 0);
        }
    }

    void warmLoginConnection(LoginWarmup offer) {
        if (connectivity == null || !offer.begin()) return;
        controlRoutes().verified().whenComplete((route, failure) -> offer.finish(failure == null));
    }

    static boolean validToken(String token) {
        return token.matches("[A-Za-z0-9_-]{43}");
    }

    private synchronized Routes controlRoutes() {
        Network selected = physicalNetwork();
        if (reusableRoutes == null || !Objects.equals(reusableRoutes.network, selected)) {
            reusableRoutes = new Routes(selected);
        }
        return reusableRoutes;
    }

    private static OkHttpClient boundClient(Network network, boolean bootstrap) {
        OkHttpClient.Builder builder = Http.CLIENT.newBuilder();
        if (network != null) builder.socketFactory(network.getSocketFactory());
        if (bootstrap) {
            // Keep the URL, SNI and Android certificate verification on HOST.
            builder.dns(host -> {
                if (!HOST.equals(host)) throw new UnknownHostException();
                return List.of(InetAddress.getByAddress(BOOTSTRAP_IPV4));
            });
        } else if (network != null) {
            builder.dns(host -> Arrays.asList(network.getAllByName(host)));
        }
        return builder.build();
    }

    private static final class Routes {
        final Network network;
        private final OkHttpClient ordinary, bootstrap;
        private CompletableFuture<OkHttpClient> verification;

        Routes(Network network) {
            this(network, boundClient(network, false), boundClient(network, true));
        }

        Routes(Network network, OkHttpClient ordinary, OkHttpClient bootstrap) {
            this.network = network;
            this.ordinary = ordinary;
            this.bootstrap = bootstrap;
        }

        synchronized CompletableFuture<OkHttpClient> verified() {
            if (verification == null || verification.isCompletedExceptionally()) {
                // This exact POST receives INVALID_REQUEST before account/session work.
                // Race only the two anonymous probes. Credentials are sent over the winner once.
                Request probe = request("authenticate").post(new SinglePost(new byte[]{'{', '}'})).build();
                Call ordinaryCall = ordinary.newCall(probe);
                Call bootstrapCall = bootstrap.newCall(probe);
                var result = new CompletableFuture<OkHttpClient>();
                verification = result;
                var waiting = new AtomicInteger(2);
                var failure = new AtomicReference<IOException>();
                prove(ordinary, ordinaryCall, bootstrapCall, result, waiting, failure);
                prove(bootstrap, bootstrapCall, ordinaryCall, result, waiting, failure);
            }
            return verification;
        }

        synchronized void invalidate(CompletableFuture<OkHttpClient> used) {
            if (verification == used) verification = null;
        }

        private static void prove(OkHttpClient client, Call probe, Call other,
                                  CompletableFuture<OkHttpClient> result, AtomicInteger waiting,
                                  AtomicReference<IOException> failure) {
            probe.enqueue(new Callback() {
                @Override public void onResponse(Call call, Response exchange) {
                    try (Response accepted = exchange) {
                        if (accepted.code() != 400 || !"INVALID_REQUEST".equals(
                                readObject(accepted, 1024).optString("error"))) {
                            throw new ApiError("API_UNAVAILABLE");
                        }
                    } catch (IOException error) {
                        onFailure(call, error);
                        return;
                    }
                    if (result.complete(client)) other.cancel();
                }

                @Override public void onFailure(Call call, IOException error) {
                    failure.accumulateAndGet(error, (previous, current) -> {
                        if (previous instanceof SSLException || current instanceof SSLException) {
                            return previous instanceof SSLException ? previous : current;
                        }
                        return previous == null || current instanceof ApiError ? current : previous;
                    });
                    if (waiting.decrementAndGet() == 0) result.completeExceptionally(failure.get());
                }
            });
        }
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

    private static Request.Builder request(String action) {
        return new Request.Builder().url(ORIGIN + "/api/client/" + action)
                .header("Accept", "application/json")
                .header("X-Oracle-Client-Capabilities", "dual-stack-v1");
    }

    private static long remaining(long deadline) throws ApiError {
        long timeLeft = deadline - SystemClock.elapsedRealtime();
        if (timeLeft <= 0) throw new ApiError("ACCOUNT_API_UNREACHABLE");
        return timeLeft;
    }

    private static ApiError accountError(Throwable failure) {
        if (failure instanceof ApiError apiError) return apiError;
        return new ApiError(failure instanceof SSLException ? "ACCOUNT_API_TLS_FAILED" : "ACCOUNT_API_UNREACHABLE", failure);
    }

    private static JSONObject readObject(Response response, int limit) throws IOException {
        if (response.body() == null) return new JSONObject();
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        InputStream stream = response.body().byteStream();
        while ((count = stream.read(buffer)) != -1) {
            if (data.size() + count > limit) {
                throw new ApiError("API_UNAVAILABLE");
            }
            data.write(buffer, 0, count);
        }
        try {
            return new JSONObject(data.toString(StandardCharsets.UTF_8.name()));
        } catch (JSONException failure) {
            throw new ApiError("API_UNAVAILABLE", failure);
        }
    }

    static final class ApiError extends IOException {
        final String code;

        ApiError(String code) {
            this(code, null);
        }

        ApiError(String code, Throwable cause) {
            super(code, cause);
            this.code = code;
        }
    }
}
