package org.morandi.proxy;

import android.annotation.SuppressLint;
import android.content.Context;
import android.net.Network;
import android.net.http.HttpEngine;
import android.net.http.HttpException;
import android.net.http.UrlRequest;
import android.net.http.UrlResponseInfo;
import android.os.Build;
import android.os.SystemClock;
import android.os.ext.SdkExtensions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

final class CloudflareExitProbe {
    private static final String ORIGIN4 = "1.1.1.1";
    private static final String ORIGIN6 = "[2606:4700:4700::1111]";
    private static final int MAX_TRACE_BYTES = 8_192;
    private static final long HTTPS_HEDGE_MS = 100;

    static final class Proof {
        final String address;
        final String protocol;

        Proof(String address, String protocol) {
            this.address = address;
            this.protocol = protocol;
        }
    }

    private CloudflareExitProbe() { }

    static void prepare(Context context) {
        if (BuildConfig.H3_EXIT_PROOF_ENABLED && platformSupported()) {
            PlatformHttp3.prepareEngine(context);
        }
    }

    static Proof verify(Context context, Network vpn, String expected, boolean ipv6, long timeoutMs)
            throws IOException {
        long deadline = SystemClock.elapsedRealtime() + timeoutMs;
        String url = "https://" + (ipv6 ? ORIGIN6 : ORIGIN4) + "/cdn-cgi/trace";
        HttpsTrial https = new HttpsTrial(vpn, url, expected, ipv6);
        if (!BuildConfig.H3_EXIT_PROOF_ENABLED || !platformSupported()) {
            return https.run(deadline);
        }
        // Give QUIC a short head start so dual-stack probes do not launch four
        // handshakes at once. An early QUIC failure starts HTTPS immediately.
        return PlatformHttp3.hedge(context, vpn, url, expected, ipv6, deadline, https);
    }

    private static boolean platformSupported() {
        int sdk = Build.VERSION.SDK_INT;
        return sdk >= 34 || (sdk >= 31 && ExtensionS.hasHttpEngine());
    }

    private static final class ExtensionS {
        @SuppressLint("NewApi")
        private static boolean hasHttpEngine() {
            return SdkExtensions.getExtensionVersion(Build.VERSION_CODES.S) >= 7;
        }
    }

    private static long remaining(long deadline) throws IOException {
        long timeout = deadline - SystemClock.elapsedRealtime();
        if (timeout <= 0) {
            throw new IOException("VPN_EXIT_PROBE_TIMEOUT");
        }
        return timeout;
    }

    static Proof readTrace(byte[] body, String expected, boolean ipv6, String protocol)
            throws IOException {
        if (body.length > MAX_TRACE_BYTES) {
            throw new IOException("VPN_EXIT_PROBE_INVALID");
        }
        String address = null;
        for (String line : new String(body, StandardCharsets.US_ASCII).split("\\r?\\n")) {
            if (line.startsWith("ip=")) {
                if (address != null) {
                    throw new IOException("VPN_EXIT_PROBE_INVALID");
                }
                address = line.substring(3);
            }
            if ("h3".equals(protocol) && line.startsWith("http=") && !line.equals("http=http/3")) {
                throw new IOException("VPN_EXIT_PROBE_PROTOCOL_MISMATCH");
            }
        }
        try {
            InetAddress actual = TunnelProfile.numeric(address, ipv6, true);
            if (actual.equals(TunnelProfile.numeric(expected, ipv6, true))) {
                return new Proof(actual.getHostAddress(), protocol);
            }
        } catch (IllegalArgumentException error) {
            throw new IOException("VPN_EXIT_PROBE_INVALID");
        }
        throw new IOException("VPN_EXIT_MISMATCH");
    }

    private static final class HttpsTrial {
        private final Network vpn;
        private final String url;
        private final String expected;
        private final boolean ipv6;
        private boolean cancelled;
        private HttpsURLConnection connection;

        HttpsTrial(Network vpn, String url, String expected, boolean ipv6) {
            this.vpn = vpn;
            this.url = url;
            this.expected = expected;
            this.ipv6 = ipv6;
        }

        Proof run(long deadline) throws IOException {
            HttpsURLConnection current = (HttpsURLConnection) vpn.openConnection(new URL(url), Proxy.NO_PROXY);
            try {
                synchronized (this) {
                    if (cancelled) {
                        throw new IOException("VPN_EXIT_PROBE_CANCELLED");
                    }
                    connection = current;
                }
                int timeout = (int) remaining(deadline);
                current.setConnectTimeout(timeout);
                current.setReadTimeout(timeout);
                current.setInstanceFollowRedirects(false);
                current.setUseCaches(false);
                current.setRequestProperty("Connection", "close");
                if (current.getResponseCode() != 200) {
                    throw new IOException("VPN_EXIT_PROBE_HTTP_FAILED");
                }
                try (InputStream stream = current.getInputStream();
                     ByteArrayOutputStream data = new ByteArrayOutputStream()) {
                    byte[] buffer = new byte[1024];
                    int count;
                    while ((count = stream.read(buffer)) != -1) {
                        if (data.size() + count > MAX_TRACE_BYTES) {
                            throw new IOException("VPN_EXIT_PROBE_INVALID");
                        }
                        remaining(deadline);
                        data.write(buffer, 0, count);
                    }
                    return readTrace(data.toByteArray(), expected, ipv6, "https");
                }
            } finally {
                synchronized (this) {
                    connection = null;
                }
                current.disconnect();
            }
        }

        void cancel() {
            HttpsURLConnection current;
            synchronized (this) {
                cancelled = true;
                current = connection;
            }
            if (current != null) {
                current.disconnect();
            }
        }
    }

    // Loaded only after the documented API/extension check. Bound UrlRequests
    // use only their explicitly supplied Network and fail if that VPN disappears.
    @SuppressLint("NewApi")
    private static final class PlatformHttp3 {
        private static final ExecutorService CALLBACKS = Executors.newSingleThreadExecutor();
        private static volatile HttpEngine engine;
        private static CompletableFuture<HttpEngine> initialization;

        private static synchronized CompletableFuture<HttpEngine> prepareEngine(Context context) {
            if (initialization != null) {
                return initialization;
            }
            CompletableFuture<HttpEngine> result = new CompletableFuture<>();
            initialization = result;
            try {
                new Thread(() -> {
                    try {
                        HttpEngine built = new HttpEngine.Builder(context.getApplicationContext())
                                .setEnableQuic(true)
                                .setEnableHttpCache(HttpEngine.Builder.HTTP_CACHE_DISABLED, 0)
                                .addQuicHint(ORIGIN4, 443, 443)
                                .addQuicHint(ORIGIN6, 443, 443)
                                .build();
                        engine = built;
                        result.complete(built);
                    } catch (RuntimeException | LinkageError error) {
                        failedInitialization(result, error);
                    }
                }, "ProxyHttp3Preparation").start();
            } catch (RuntimeException error) {
                failedInitialization(result, error);
            }
            return result;
        }

        private static void failedInitialization(CompletableFuture<HttpEngine> result, Throwable error) {
            synchronized (PlatformHttp3.class) {
                if (initialization == result) {
                    initialization = null;
                }
            }
            result.completeExceptionally(error);
        }

        private static final class H3Trial {
            private UrlRequest request;
            private boolean cancelled;

            void start(HttpEngine available, Network vpn, String url, String expected, boolean ipv6,
                       long deadline, CompletableFuture<Proof> result) {
                try {
                    remaining(deadline);
                    UrlRequest built = available.newUrlRequestBuilder(url, CALLBACKS,
                            callback(expected, ipv6, result))
                            .bindToNetwork(vpn)
                            .setCacheDisabled(true)
                            .addHeader("Cache-Control", "no-cache, no-store")
                            .build();
                    synchronized (this) {
                        if (cancelled) {
                            return;
                        }
                        remaining(deadline);
                        request = built;
                        request.start();
                    }
                } catch (IOException | RuntimeException | LinkageError error) {
                    result.completeExceptionally(new IOException("VPN_EXIT_PROBE_HTTP3_FAILED"));
                }
            }

            void cancel() {
                UrlRequest current;
                synchronized (this) {
                    cancelled = true;
                    current = request;
                }
                if (current != null) {
                    current.cancel();
                }
            }
        }

        static Proof hedge(Context context, Network vpn, String url, String expected, boolean ipv6,
                           long deadline, HttpsTrial https) throws IOException {
            HttpEngine prepared = engine;
            // HttpEngine is already asynchronous. Let its callback deliver the result
            // directly to the family verifier, and create a worker only for a TLS hedge.
            BlockingQueue<Future<Proof>> finished = new LinkedBlockingQueue<>();
            CompletableFuture<Proof> h3 = new CompletableFuture<>();
            h3.whenComplete((value, failure) -> finished.add(h3));
            H3Trial quic = new H3Trial();
            CompletableFuture<?> pendingStart = null;
            ExecutorService worker = null;
            Future<Proof> fallback = null;
            try {
                if (prepared == null) {
                    // Start HTTPS immediately while the shared engine loads. A working
                    // HTTP/3 route can still win even if TCP is stalled on this VPN.
                    pendingStart = prepareEngine(context).whenComplete((available, error) -> {
                        if (error == null) {
                            quic.start(available, vpn, url, expected, ipv6, deadline, h3);
                        } else {
                            h3.completeExceptionally(error);
                        }
                    });
                } else {
                    quic.start(prepared, vpn, url, expected, ipv6, deadline, h3);
                }
                long headStart = prepared == null ? 0 : HTTPS_HEDGE_MS;
                Future<Proof> first = finished.poll(
                        Math.min(headStart, remaining(deadline)), TimeUnit.MILLISECONDS);
                if (first != null) {
                    try {
                        return first.get();
                    } catch (ExecutionException ignored) {
                        // An unavailable or failed HTTP/3 request needs no hedge delay.
                    }
                }
                worker = Executors.newSingleThreadExecutor();
                ExecutorCompletionService<Proof> tls = new ExecutorCompletionService<>(worker, finished);
                fallback = tls.submit(() -> https.run(deadline));
                int outstanding = first == null ? 2 : 1;
                IOException failure = null;
                while (outstanding-- > 0) {
                    Future<Proof> next = finished.poll(remaining(deadline), TimeUnit.MILLISECONDS);
                    if (next == null) {
                        throw new IOException("VPN_EXIT_PROBE_TIMEOUT");
                    }
                    try {
                        return next.get();
                    } catch (ExecutionException error) {
                        if (next == fallback && error.getCause() instanceof IOException) {
                            failure = (IOException) error.getCause();
                        }
                    }
                }
                throw failure == null ? new IOException("VPN_EXIT_PROBE_HTTP_FAILED") : failure;
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new IOException("VPN_EXIT_PROBE_CANCELLED");
            } finally {
                quic.cancel();
                if (pendingStart != null) {
                    pendingStart.cancel(false);
                }
                https.cancel();
                if (fallback != null) {
                    fallback.cancel(true);
                }
                if (worker != null) {
                    worker.shutdownNow();
                }
            }
        }

        private static UrlRequest.Callback callback(String expected, boolean ipv6,
                                                    CompletableFuture<Proof> completion) {
            return new UrlRequest.Callback() {
                private final ByteArrayOutputStream body = new ByteArrayOutputStream();

                private void reject(UrlRequest request) {
                    completion.completeExceptionally(new IOException("VPN_EXIT_PROBE_HTTP3_FAILED"));
                    request.cancel();
                }

                @Override public void onRedirectReceived(UrlRequest request, UrlResponseInfo info,
                                                         String newLocationUrl) {
                    reject(request);
                }

                @Override public void onResponseStarted(UrlRequest request, UrlResponseInfo info) {
                    if (info.getHttpStatusCode() != 200 || info.wasCached()
                            || !"h3".equals(info.getNegotiatedProtocol())) {
                        reject(request);
                        return;
                    }
                    request.read(ByteBuffer.allocateDirect(1024));
                }

                @Override public void onReadCompleted(UrlRequest request, UrlResponseInfo info,
                                                      ByteBuffer buffer) {
                    buffer.flip();
                    if (body.size() + buffer.remaining() > MAX_TRACE_BYTES) {
                        reject(request);
                        return;
                    }
                    byte[] bytes = new byte[buffer.remaining()];
                    buffer.get(bytes);
                    body.write(bytes, 0, bytes.length);
                    buffer.clear();
                    request.read(buffer);
                }

                @Override public void onSucceeded(UrlRequest request, UrlResponseInfo info) {
                    try {
                        completion.complete(readTrace(body.toByteArray(), expected, ipv6,
                                info.getNegotiatedProtocol()));
                    } catch (IOException error) {
                        completion.completeExceptionally(error);
                    }
                }

                @Override public void onFailed(UrlRequest request, UrlResponseInfo info, HttpException error) {
                    completion.completeExceptionally(new IOException("VPN_EXIT_PROBE_HTTP3_FAILED"));
                }

                @Override public void onCanceled(UrlRequest request, UrlResponseInfo info) {
                    completion.completeExceptionally(new IOException("VPN_EXIT_PROBE_CANCELLED"));
                }
            };
        }
    }
}
