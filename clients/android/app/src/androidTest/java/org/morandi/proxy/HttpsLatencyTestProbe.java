package org.morandi.proxy;

import android.net.InetAddresses;
import android.net.Network;
import android.os.SystemClock;
import android.util.Log;

import okhttp3.Call;
import okhttp3.Connection;
import okhttp3.ConnectionPool;
import okhttp3.EventListener;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.StringJoiner;
import java.util.concurrent.TimeUnit;

final class HttpsLatencyTestProbe {
    private static final String HOST = "www.cloudflare.com";
    private static final String PATH = "/cdn-cgi/trace";
    private static final int SAMPLES = 20;
    private static final int RESPONSE_LIMIT = 8_192;
    private static final long TARGET_NANOS = TimeUnit.MILLISECONDS.toNanos(500);

    private final Inet4Address endpoint;

    HttpsLatencyTestProbe(Network direct) throws IOException {
        if (direct != null) {
            for (InetAddress candidate : direct.getAllByName(HOST)) {
                if (candidate instanceof Inet4Address ipv4) {
                    endpoint = ipv4;
                    return;
                }
            }
        }
        throw new IOException("ANDROID_HTTPS_NO_IPV4_PROBE_ADDRESS");
    }

    void sample(Network network, String route, String expectedExit) throws IOException {
        if (network == null) {
            throw new IOException("ANDROID_HTTPS_NETWORK_UNAVAILABLE");
        }
        for (boolean reuse : new boolean[]{false, true}) {
            measure(network, route, expectedExit, reuse);
        }
    }

    private void measure(Network network, String route, String expectedExit, boolean reuse)
            throws IOException {
        ConnectionObservation observed = new ConnectionObservation();
        ConnectionPool pool = new ConnectionPool(reuse ? 1 : 0, 1, TimeUnit.MINUTES);
        OkHttpClient client = new OkHttpClient.Builder()
                .dns(hostname -> {
                    if (!HOST.equals(hostname)) {
                        throw new UnknownHostException();
                    }
                    return Collections.singletonList(endpoint);
                })
                .socketFactory(network.getSocketFactory())
                .protocols(Collections.singletonList(Protocol.HTTP_1_1))
                .proxy(Proxy.NO_PROXY)
                .followRedirects(false)
                .followSslRedirects(false)
                .retryOnConnectionFailure(false)
                .callTimeout(6, TimeUnit.SECONDS)
                .connectionPool(pool)
                .eventListener(observed)
                .build();
        Request.Builder request = new Request.Builder().url("https://" + HOST + PATH)
                .header("Accept-Encoding", "identity").header("Cache-Control", "no-cache");
        if (!reuse) {
            request.header("Connection", "close");
        }
        Request planned = request.build();
        long[] durations = new long[SAMPLES];
        Connection previous = null;
        try {
            if (reuse) {
                requestProof(client, planned, expectedExit);
                previous = observed.connection;
                if (previous == null) {
                    throw new IOException("ANDROID_HTTPS_WARMUP_CONNECTION_NOT_OBSERVED");
                }
            }
            for (int index = 0; index < SAMPLES; index++) {
                observed.connection = null;
                durations[index] = requestProof(client, planned, expectedExit);
                if (observed.connection == null
                        || (reuse ? observed.connection != previous : observed.connection == previous)) {
                    throw new IOException("ANDROID_HTTPS_CONNECTION_REUSE_NOT_VERIFIED");
                }
                previous = observed.connection;
            }
        } finally {
            pool.evictAll();
            client.dispatcher().executorService().shutdown();
        }
        StringJoiner milliseconds = new StringJoiner(",");
        int underTarget = 0;
        for (long duration : durations) {
            milliseconds.add(Long.toString(TimeUnit.NANOSECONDS.toMillis(duration)));
            if (duration < TARGET_NANOS) {
                underTarget++;
            }
        }
        Arrays.sort(durations);
        long median = (durations[SAMPLES / 2 - 1] + durations[SAMPLES / 2]) / 2;
        long percentile95 = durations[(95 * SAMPLES + 99) / 100 - 1];
        Log.i("ProxySpeedAcceptance", "ANDROID_PERF_HTTPS_" + route + (reuse ? "_REUSED" : "_FRESH")
                + "_SAMPLES_MS=" + milliseconds + ";N=" + SAMPLES
                + ";MEDIAN_MS=" + TimeUnit.NANOSECONDS.toMillis(median)
                + ";P95_MS=" + TimeUnit.NANOSECONDS.toMillis(percentile95)
                + ";UNDER_500MS=" + underTarget + ";HOST=" + HOST + ";PATH=" + PATH
                + ";ENDPOINT=" + endpoint.getHostAddress()
                + ";ADDRESS_FAMILY=IPv4;PROTOCOL=HTTP_1_1");
    }

    private static long requestProof(OkHttpClient client, Request request, String expectedExit)
            throws IOException {
        long start = SystemClock.elapsedRealtimeNanos();
        try (Response response = client.newCall(request).execute()) {
            ResponseBody body = response.body();
            if (response.code() != 200 || response.handshake() == null
                    || response.protocol() != Protocol.HTTP_1_1 || body == null) {
                throw new IOException("ANDROID_HTTPS_UNEXPECTED_RESPONSE");
            }
            try (InputStream input = body.byteStream()) {
                int first = input.read();
                long elapsed = SystemClock.elapsedRealtimeNanos() - start;
                if (first == -1) {
                    throw new IOException("ANDROID_HTTPS_EMPTY_TRACE");
                }
                ByteArrayOutputStream trace = new ByteArrayOutputStream();
                trace.write(first);
                byte[] block = new byte[1024];
                for (int count; (count = input.read(block)) != -1; ) {
                    if (trace.size() + count > RESPONSE_LIMIT) {
                        throw new IOException("ANDROID_HTTPS_TRACE_SIZE");
                    }
                    trace.write(block, 0, count);
                }
                assertTraceExit(trace.toString(StandardCharsets.US_ASCII.name()), expectedExit);
                return elapsed;
            }
        }
    }

    private static void assertTraceExit(String trace, String expected) throws IOException {
        InetAddress observed = null;
        try {
            for (String line : trace.split("\\r?\\n")) {
                if (line.startsWith("ip=")) {
                    if (observed != null) {
                        throw new IOException("ANDROID_HTTPS_DUPLICATE_EXIT");
                    }
                    observed = InetAddresses.parseNumericAddress(line.substring(3));
                }
            }
            if (!(observed instanceof Inet4Address)
                    || (!expected.isEmpty() && !observed.equals(InetAddresses.parseNumericAddress(expected)))) {
                throw new IOException("ANDROID_HTTPS_EXIT_MISMATCH");
            }
        } catch (IllegalArgumentException failure) {
            throw new IOException("ANDROID_HTTPS_INVALID_EXIT");
        }
    }

    private static final class ConnectionObservation extends EventListener {
        Connection connection;

        @Override public void connectionAcquired(Call call, Connection acquired) {
            connection = acquired;
        }
    }
}
