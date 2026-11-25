package org.morandi.proxy.tailscale;

import android.annotation.TargetApi;
import android.content.Context;
import android.net.Network;
import android.net.http.HttpEngine;
import android.net.http.HttpException;
import android.net.http.UrlRequest;
import android.net.http.UrlResponseInfo;
import android.os.Build;
import android.os.SystemClock;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Optional HTTPS exit proof on the same Android VPN network as the TCP probe. */
final class ExitQuicProbe implements AutoCloseable {
    private final CompletableFuture<Long> result = new CompletableFuture<>();
    private Runnable cancel;

    static void prepare(Context context) {
        if (Build.VERSION.SDK_INT < 34) return;
        try {
            Platform.prepare(context.getApplicationContext());
        } catch (RuntimeException | LinkageError unavailable) {
            // The TCP proof remains available.
        }
    }

    static ExitQuicProbe start(Context context, Network network, URI target, String expected, long start) {
        if (Build.VERSION.SDK_INT < 34) return null;
        var probe = new ExitQuicProbe();
        try {
            Platform.start(probe, context, network, target, expected, start);
        } catch (RuntimeException | LinkageError unavailable) {
            return null;
        }
        return probe;
    }

    Future<Long> result() {
        return result;
    }

    private synchronized void launch(Runnable start, Runnable cancelRequest) {
        if (result.isDone()) return;
        cancel = cancelRequest;
        start.run();
    }

    @Override public synchronized void close() {
        try {
            if (result.complete(null) && cancel != null) cancel.run();
        } catch (RuntimeException | LinkageError unavailable) {
            // The optional HTTP engine cannot prevent the TCP proof from completing.
        } finally {
            cancel = null;
        }
    }

    // Keep Android 14 HTTP types out of the API 29 class initialization path.
    @TargetApi(34)
    private static final class Platform {
        private static final int MAX_BODY_BYTES = 4_096;
        private static final Executor WORKER = Executors.newSingleThreadExecutor();
        private static HttpEngine engine;

        private static HttpEngine engine(Context application) {
            if (engine == null) {
                engine = new HttpEngine.Builder(application).setEnableQuic(true)
                        .addQuicHint(ExitCheck.V4.getHost(), 443, 443)
                        .addQuicHint(ExitCheck.V6.getHost(), 443, 443).build();
            }
            return engine;
        }

        static void prepare(Context application) {
            WORKER.execute(() -> {
                try { engine(application); }
                catch (RuntimeException | LinkageError unavailable) { }
            });
        }

        static void start(ExitQuicProbe probe, Context context, Network network, URI target, String expected, long start) {
            var application = context.getApplicationContext();
            WORKER.execute(() -> {
                if (probe.result.isDone()) return;
                try {
                    var request = engine(application).newUrlRequestBuilder(target.toASCIIString(), WORKER,
                                    callback(probe, expected, start))
                            .bindToNetwork(network).setCacheDisabled(true).build();
                    probe.launch(request::start, request::cancel);
                } catch (RuntimeException | LinkageError unavailable) {
                    probe.close();
                }
            });
        }

        private static UrlRequest.Callback callback(ExitQuicProbe probe, String expected, long start) {
            return new UrlRequest.Callback() {
                private final ByteArrayOutputStream data = new ByteArrayOutputStream();

                @Override public void onRedirectReceived(UrlRequest request, UrlResponseInfo info, String target) {
                    probe.close();
                }

                @Override public void onResponseStarted(UrlRequest request, UrlResponseInfo info) {
                    if (info.getHttpStatusCode() != 200 || info.wasCached() || !"h3".equals(info.getNegotiatedProtocol())) {
                        probe.close();
                    } else if (!probe.result.isDone()) {
                        request.read(ByteBuffer.allocateDirect(1_024));
                    }
                }

                @Override public void onReadCompleted(UrlRequest request, UrlResponseInfo info, ByteBuffer buffer) {
                    if (probe.result.isDone()) return;
                    buffer.flip();
                    if (data.size() + buffer.remaining() > MAX_BODY_BYTES) {
                        probe.close();
                        return;
                    }
                    byte[] chunk = new byte[buffer.remaining()];
                    buffer.get(chunk);
                    data.write(chunk, 0, chunk.length);
                    buffer.clear();
                    request.read(buffer);
                }

                @Override public void onSucceeded(UrlRequest request, UrlResponseInfo info) {
                    var body = new String(data.toByteArray(), StandardCharsets.UTF_8);
                    try (var reader = new BufferedReader(new StringReader(body))) {
                        boolean verified = ExitCheck.containsExitAddress(reader, expected);
                        probe.result.complete(verified ? SystemClock.elapsedRealtime() - start : null);
                    } catch (IOException | IllegalArgumentException invalid) {
                        probe.result.complete(null);
                    }
                }

                @Override public void onFailed(UrlRequest request, UrlResponseInfo info, HttpException error) {
                    probe.result.complete(null);
                }

                @Override public void onCanceled(UrlRequest request, UrlResponseInfo info) {
                    probe.result.complete(null);
                }
            };
        }
    }
}
