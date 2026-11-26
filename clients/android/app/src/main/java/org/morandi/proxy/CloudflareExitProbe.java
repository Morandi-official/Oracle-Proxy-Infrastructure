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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.HttpsURLConnection;

final class CloudflareExitProbe {
    private static final String ORIGIN4 = "1.1.1.1";
    private static final String ORIGIN6 = "[2606:4700:4700::1111]";
    private static final int MAX_TRACE_BYTES = 8_192;
    private static final long HTTPS_HEDGE_MS = 100;
    private static final long FIRST_HTTPS_HEDGE_MS = 50;
    private static volatile String lastHttp3Exit4 = "";
    private static volatile String lastHttp3Exit6 = "";

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

    static void rememberVerifiedProtocols(Proof ipv4, Proof ipv6) {
        lastHttp3Exit4 = "h3".equals(ipv4.protocol) ? ipv4.address : "";
        lastHttp3Exit6 = ipv6 != null && "h3".equals(ipv6.protocol) ? ipv6.address : "";
    }

    static Proof verify(Context context, Network vpn, String expected, boolean ipv6, long timeoutMs)
            throws IOException {
        long deadline = SystemClock.elapsedRealtime() + timeoutMs;
        String url = "https://" + (ipv6 ? ORIGIN6 : ORIGIN4) + "/cdn-cgi/trace";
        HttpsTrial https = new HttpsTrial(vpn, url, expected, ipv6);
        if (!BuildConfig.H3_EXIT_PROOF_ENABLED || !platformSupported()) {
            return https.run(deadline);
        }
        // Give QUIC a short head start so the first dual-stack probe does
        // not launch four handshakes at once. An early QUIC failure starts
        // HTTPS immediately. A previously verified QUIC path gets longer.
        String verifiedHttp3 = ipv6 ? lastHttp3Exit6 : lastHttp3Exit4;
        long hedgeDelay = expected.equals(verifiedHttp3)
                ? HTTPS_HEDGE_MS : FIRST_HTTPS_HEDGE_MS;
        return PlatformHttp3.hedge(context, vpn, url, expected, ipv6, deadline, hedgeDelay, https);
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
        private static final AtomicBoolean PREPARING = new AtomicBoolean();
        private static volatile HttpEngine engine;

        static void prepareEngine(Context context) {
            if (engine != null || !PREPARING.compareAndSet(false, true)) {
                return;
            }
            try {
                new Thread(() -> {
                    try {
                        engine(context);
                    } catch (RuntimeException | LinkageError ignored) {
                        // A later probe keeps its existing HTTPS fallback.
                    } finally {
                        PREPARING.set(false);
                    }
                }, "ProxyHttp3Preparation").start();
            } catch (RuntimeException ignored) {
                PREPARING.set(false);
            }
        }

        private static synchronized HttpEngine engine(Context context) {
            if (engine == null) {
                engine = new HttpEngine.Builder(context.getApplicationContext())
                        .setEnableQuic(true)
                        .setEnableHttpCache(HttpEngine.Builder.HTTP_CACHE_DISABLED, 0)
                        .addQuicHint(ORIGIN4, 443, 443)
                        .addQuicHint(ORIGIN6, 443, 443)
                        .build();
            }
            return engine;
        }

        static Proof hedge(Context context, Network vpn, String url, String expected, boolean ipv6,
                           long deadline, long hedgeDelay, HttpsTrial https) throws IOException {
            ExecutorService worker = Executors.newFixedThreadPool(2);
            ExecutorCompletionService<Proof> completed = new ExecutorCompletionService<>(worker);
            H3Trial quic = new H3Trial();
            Future<Proof> fast = completed.submit(() -> quic.run(context, vpn, url, expected, ipv6, deadline));
            Future<Proof> fallback = null;
            try {
                Future<Proof> first = hedgeDelay == 0 ? null
                        : completed.poll(Math.min(hedgeDelay, remaining(deadline)), TimeUnit.MILLISECONDS);
                if (first != null) {
                    try {
                        return first.get();
                    } catch (ExecutionException error) {
                        // The explicit Network-bound HTTPS proof can still succeed.
                    }
                }
                fallback = completed.submit(() -> https.run(deadline));
                int outstanding = first == null ? 2 : 1;
                IOException failure = null;
                while (outstanding-- > 0) {
                    Future<Proof> finished = completed.poll(remaining(deadline), TimeUnit.MILLISECONDS);
                    if (finished == null) {
                        throw new IOException("VPN_EXIT_PROBE_TIMEOUT");
                    }
                    try {
                        return finished.get();
                    } catch (ExecutionException error) {
                        if (finished == fallback && error.getCause() instanceof IOException) {
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
                https.cancel();
                fast.cancel(true);
                if (fallback != null) {
                    fallback.cancel(true);
                }
                worker.shutdownNow();
            }
        }

        private static final class H3Trial {
            private boolean cancelled;
            private UrlRequest request;

            Proof run(Context context, Network vpn, String url, String expected, boolean ipv6, long deadline)
                    throws IOException, InterruptedException {
                CompletableFuture<Proof> completion = new CompletableFuture<>();
                UrlRequest current = engine(context).newUrlRequestBuilder(url, CALLBACKS,
                        callback(expected, ipv6, completion))
                        .bindToNetwork(vpn)
                        .setCacheDisabled(true)
                        .addHeader("Cache-Control", "no-cache, no-store")
                        .build();
                try {
                    synchronized (this) {
                        if (cancelled) {
                            throw new IOException("VPN_EXIT_PROBE_CANCELLED");
                        }
                        remaining(deadline);
                        request = current;
                        current.start();
                    }
                    return completion.get(remaining(deadline), TimeUnit.MILLISECONDS);
                } catch (ExecutionException error) {
                    throw new IOException("VPN_EXIT_PROBE_HTTP3_FAILED");
                } catch (TimeoutException error) {
                    throw new IOException("VPN_EXIT_PROBE_TIMEOUT");
                } finally {
                    current.cancel();
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
