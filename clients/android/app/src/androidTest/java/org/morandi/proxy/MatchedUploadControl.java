package org.morandi.proxy;

import android.net.Network;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.SocketAddress;
import java.net.URL;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;

/** Optional same-origin upload controls after all timing and loaded RTT measurements. */
final class MatchedUploadControl {
    private static final int TRIALS = 2;
    private static final int BYTES = 2 * 1024 * 1024;
    private static final String ORIGIN = "speed.cloudflare.com";
    private final byte[] body = new byte[32 * 1024];
    private static final boolean HAS_TCP_INFO = loadTcpInfo();
    private Thread worker;
    private volatile HttpsURLConnection active;

    MatchedUploadControl() {
        new SecureRandom().nextBytes(body);
    }

    record Sample(long ackMs, InetAddress peer, String pop, String protocol, String cipher,
                  long retrans, long segsOut) {
        static final Sample UNKNOWN = new Sample(-1, null, null, null, null, -1, -1);

        String numbers() {
            return ackMs + ";RETRANS:" + retrans + ";SEGS_OUT:" + segsOut;
        }
    }

    Sample[] measure(Network network) throws InterruptedException {
        Sample[] results = {Sample.UNKNOWN, Sample.UNKNOWN};
        if (network == null || (worker != null && worker.isAlive())) return results;
        for (int i = 0; i < TRIALS; i++) {
            final Sample[] trial = {Sample.UNKNOWN};
            worker = new Thread(() -> {
                try {
                    trial[0] = upload(network);
                } catch (IOException | RuntimeException ignored) {
                    // An unacknowledged trial is never recorded as zero retransmits.
                }
            }, "Matched Android upload control");
            worker.setDaemon(true);
            worker.start();
            worker.join(12_000);
            if (worker.isAlive()) {
                worker.interrupt();
                HttpsURLConnection connection = active;
                if (connection != null) {
                    Thread stop = new Thread(connection::disconnect, "Cancel Android upload control");
                    stop.setDaemon(true);
                    stop.start();
                }
                break;
            }
            results[i] = trial[0];
        }
        return results;
    }

    void compareWithDirect(Sample[] vpn, Network direct) throws InterruptedException {
        Sample[] plain = measure(direct);
        for (int i = 0; i < TRIALS; i++) {
            Sample a = vpn[i], b = plain[i];
            Log.i("ProxySpeedAcceptance", "ANDROID_PERF_UPLOAD_CONTROL_" + (i + 1)
                    + "=SAME_IP:" + same(a.peer, b.peer) + ";SAME_POP:" + same(a.pop, b.pop)
                    + ";SAME_PROTOCOL:" + same(a.protocol, b.protocol)
                    + ";SAME_CIPHER:" + same(a.cipher, b.cipher)
                    + ";VPN_ACK_MS:" + a.numbers() + ";DIRECT_ACK_MS:" + b.numbers());
        }
    }

    private static int same(Object a, Object b) {
        if (a == null || b == null) return -1;
        return a.equals(b) ? 1 : 0;
    }

    private Sample upload(Network network) throws IOException {
        Set<InetAddress> candidates = new HashSet<>(Arrays.asList(network.getAllByName(ORIGIN)));
        if (Thread.currentThread().isInterrupted()) return Sample.UNKNOWN;
        HttpsURLConnection connection = (HttpsURLConnection) network.openConnection(
                new URL("https://" + ORIGIN + "/__up"), Proxy.NO_PROXY);
        active = connection;
        List<Flow> flows = new ArrayList<>();
        try {
            if (Thread.currentThread().isInterrupted()) return Sample.UNKNOWN;
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestProperty("Accept-Encoding", "identity");
            connection.setRequestProperty("Content-Type", "application/octet-stream");
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setFixedLengthStreamingMode(BYTES);
            long start;
            try (OutputStream out = connection.getOutputStream()) {
                snapshot(candidates, flows);
                start = SystemClock.elapsedRealtimeNanos();
                for (int sent = 0; sent < BYTES; sent += body.length) {
                    if (Thread.currentThread().isInterrupted()) return Sample.UNKNOWN;
                    out.write(body);
                }
            }
            int status = connection.getResponseCode();
            long ackMs = TimeUnit.NANOSECONDS.toMillis(SystemClock.elapsedRealtimeNanos() - start);
            if (status < 200 || status >= 300) return Sample.UNKNOWN;
            String ray = connection.getHeaderField("CF-Ray");
            String pop = ray != null && ray.matches("(?i)[0-9a-f]+-[a-z]{3}")
                    ? ray.substring(ray.length() - 3) : null;
            String protocol = connection.getHeaderField("X-Android-Selected-Protocol");
            Sample result = new Sample(ackMs, null, pop, protocol, connection.getCipherSuite(), -1, -1);
            Sample attributed = null;
            for (Flow flow : flows) {
                long[] end = tcpInfo(flow.socket);
                if (end == null) continue;
                long acknowledged = end[0] - flow.before[0];
                // Count only an entire acknowledged body with a bounded allowance for TLS framing.
                if (acknowledged < BYTES || acknowledged > BYTES + 128 * 1024
                        || end[1] < flow.before[1] || end[2] < flow.before[2]) continue;
                if (attributed != null) return result;
                attributed = new Sample(ackMs, flow.peer, pop, protocol, result.cipher,
                        end[1] - flow.before[1], end[2] - flow.before[2]);
            }
            return attributed == null ? result : attributed;
        } finally {
            for (Flow flow : flows) close(flow.socket);
            connection.disconnect();
            active = null;
        }
    }

    private record Flow(ParcelFileDescriptor socket, InetAddress peer, long[] before) {}

    private static boolean loadTcpInfo() {
        try {
            System.loadLibrary("proxy_upload_test");
            return true;
        } catch (UnsatisfiedLinkError unavailable) {
            return false;
        }
    }

    private static native long[] readTcpInfo(int fd);

    private static long[] tcpInfo(ParcelFileDescriptor socket) {
        return HAS_TCP_INFO ? readTcpInfo(socket.getFd()) : null;
    }

    private static void snapshot(Set<InetAddress> allowed, List<Flow> flows) {
        if (!HAS_TCP_INFO) return;
        File[] entries;
        try {
            entries = new File("/proc/self/fd").listFiles();
        } catch (SecurityException unavailable) {
            return;
        }
        if (entries == null) return;
        Set<Long> seen = new HashSet<>();
        for (File entry : entries) {
            ParcelFileDescriptor copy = null;
            try {
                if (!Os.readlink(entry.getPath()).startsWith("socket:[")) continue;
                copy = ParcelFileDescriptor.fromFd(Integer.parseInt(entry.getName()));
                SocketAddress address = Os.getpeername(copy.getFileDescriptor());
                if (!(address instanceof InetSocketAddress peer) || peer.getPort() != 443
                        || !allowed.contains(peer.getAddress())) continue;
                long[] before = tcpInfo(copy);
                if (before == null || !seen.add(Os.fstat(copy.getFileDescriptor()).st_ino)) continue;
                flows.add(new Flow(copy, peer.getAddress(), before));
                copy = null; // Ownership transferred to upload() until the HTTP response.
            } catch (ErrnoException | IOException | NumberFormatException ignored) {
                // Descriptors can close between listing and duplication.
            } finally {
                if (copy != null) {
                    close(copy);
                }
            }
        }
    }

    private static void close(ParcelFileDescriptor handle) {
        try {
            handle.close();
        } catch (IOException ignored) {
            // The duplicate holds no user-visible state.
        }
    }
}
