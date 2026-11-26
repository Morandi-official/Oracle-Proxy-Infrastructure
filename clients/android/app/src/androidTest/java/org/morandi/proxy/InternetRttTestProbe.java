package org.morandi.proxy;

import android.net.InetAddresses;
import android.net.Network;
import android.os.SystemClock;
import android.util.Log;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.PortUnreachableException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.StringJoiner;
import java.util.concurrent.TimeUnit;

/** Measures idle UDP round trips without including DNS, TCP, TLS or VPN establishment. */
final class InternetRttTestProbe {
    private static final int SAMPLES = 12;
    private static final int REPLY_TIMEOUT_MS = 1_200;
    private static final int SAMPLE_GAP_MS = 80;
    private static final int COOKIE = 0x2112A442;
    private static final int HEADER_BYTES = 20;

    private final Target[] targets;
    private final SecureRandom random = new SecureRandom();

    InternetRttTestProbe(Network direct) {
        targets = new Target[]{
                resolve(direct, "stun.cloudflare.com", 3478),
                resolve(direct, "stun.l.google.com", 19302)
        };
    }

    private static Target resolve(Network direct, String host, int port) {
        try {
            for (InetAddress candidate : direct.getAllByName(host)) {
                if (candidate instanceof Inet4Address ipv4) {
                    return new Target(host, port, ipv4, "");
                }
            }
            return new Target(host, port, null, "NO_IPV4_ADDRESS");
        } catch (UnknownHostException failure) {
            return new Target(host, port, null, "DNS_UNAVAILABLE");
        }
    }

    void sampleDirect(Network direct) throws IOException {
        sample(direct, "DIRECT", null);
    }

    void sampleTunnel(Network vpn, String expectedExit) throws IOException {
        InetAddress expected = InetAddresses.parseNumericAddress(expectedExit);
        if (!(expected instanceof Inet4Address)) {
            throw new IOException("ANDROID_UDP_STUN_EXPECTED_IPV4");
        }
        sample(vpn, "WIREGUARD_UDP", expected);
    }

    private void sample(Network network, String route, InetAddress expected) throws IOException {
        for (Target target : targets) {
            if (target.address == null) {
                Log.i("ProxySpeedAcceptance", "ANDROID_PERF_UDP_STUN_" + route
                        + "_STATUS=" + target.unavailableReason + ";HOST=" + target.host + ";PORT=" + target.port);
                continue;
            }
            sampleTarget(network, route, target, expected);
        }
    }

    private void sampleTarget(Network network, String route, Target target, InetAddress expected)
            throws IOException {
        long[] roundTrips = new long[SAMPLES];
        byte[] response = new byte[512];
        try (DatagramSocket socket = new DatagramSocket(null)) {
            // The explicit binding must precede connect() so Android cannot choose
            // an underlying network for a VPN test or a VPN for the direct test.
            network.bindSocket(socket);
            socket.connect(target.address, target.port);
            for (int index = 0; index < SAMPLES; index++) {
                byte[] transaction = new byte[12];
                random.nextBytes(transaction);
                byte[] request = ByteBuffer.allocate(HEADER_BYTES)
                        .putShort((short) 0x0001)
                        .putShort((short) 0)
                        .putInt(COOKIE)
                        .put(transaction)
                        .array();
                roundTrips[index] = roundTrip(socket, request, transaction, response, expected);
                if (index + 1 < SAMPLES) {
                    SystemClock.sleep(SAMPLE_GAP_MS);
                }
            }
        }
        report(route, target, roundTrips, expected != null);
    }

    private static long roundTrip(DatagramSocket socket, byte[] request, byte[] transaction,
                                  byte[] response, InetAddress expected) throws IOException {
        DatagramPacket outbound = new DatagramPacket(request, request.length);
        DatagramPacket inbound = new DatagramPacket(response, response.length);
        long started = SystemClock.elapsedRealtimeNanos();
        long deadline = started + TimeUnit.MILLISECONDS.toNanos(REPLY_TIMEOUT_MS);
        try {
            socket.send(outbound);
            while (true) {
                long remaining = deadline - SystemClock.elapsedRealtimeNanos();
                if (remaining <= 0) {
                    return -1;
                }
                socket.setSoTimeout((int) (TimeUnit.NANOSECONDS.toMillis(remaining) + 1));
                inbound.setLength(response.length);
                socket.receive(inbound);
                long received = SystemClock.elapsedRealtimeNanos();
                InetAddress mapped = mappedAddress(response, inbound.getLength(), transaction);
                if (mapped == null) {
                    continue;
                }
                if (expected != null && !expected.equals(mapped)) {
                    throw new IOException("ANDROID_UDP_STUN_EXIT_MISMATCH");
                }
                return received <= deadline ? received - started : -1;
            }
        } catch (SocketTimeoutException | PortUnreachableException unanswered) {
            return -1;
        }
    }

    private static InetAddress mappedAddress(byte[] bytes, int length, byte[] transaction)
            throws IOException {
        if (length < HEADER_BYTES) {
            return null;
        }
        ByteBuffer packet = ByteBuffer.wrap(bytes, 0, length);
        if (packet.getShort() != 0x0101) {
            return null;
        }
        int bodyLength = packet.getShort() & 0xffff;
        if ((bodyLength & 3) != 0 || bodyLength != length - HEADER_BYTES || packet.getInt() != COOKIE) {
            return null;
        }
        for (byte value : transaction) {
            if (packet.get() != value) {
                return null;
            }
        }
        InetAddress mapped = null;
        while (packet.remaining() >= 4) {
            int type = packet.getShort() & 0xffff;
            int size = packet.getShort() & 0xffff;
            int padded = (size + 3) & ~3;
            if (padded > packet.remaining()) {
                return null;
            }
            int next = packet.position() + padded;
            if (type == 0x0020) {
                if (mapped != null || size != 8 || packet.get() != 0 || packet.get() != 1) {
                    return null;
                }
                int port = (packet.getShort() & 0xffff) ^ (COOKIE >>> 16);
                if (port == 0) {
                    return null;
                }
                int address = packet.getInt() ^ COOKIE;
                mapped = InetAddress.getByAddress(ByteBuffer.allocate(4).putInt(address).array());
            }
            packet.position(next);
        }
        return packet.hasRemaining() ? null : mapped;
    }

    private static void report(String route, Target target, long[] roundTrips, boolean verifyExit) {
        StringJoiner detail = new StringJoiner(",");
        long[] successful = new long[SAMPLES];
        int replies = 0;
        int adjacentPairs = 0;
        long variationSum = 0;
        long previous = -1;
        for (long result : roundTrips) {
            detail.add(milliseconds(result));
            if (result >= 0) {
                successful[replies++] = result;
                if (previous >= 0) {
                    variationSum += Math.abs(previous - result);
                    adjacentPairs++;
                }
            }
            previous = result;
        }
        Arrays.sort(successful, 0, replies);
        long median = replies == 0 ? -1
                : (successful[(replies - 1) / 2] + successful[replies / 2]) / 2;
        long percentile95 = replies == 0 ? -1 : successful[(95 * replies + 99) / 100 - 1];
        long jitter = adjacentPairs == 0 ? -1 : variationSum / adjacentPairs;
        int unanswered = SAMPLES - replies;
        Log.i("ProxySpeedAcceptance", "ANDROID_PERF_UDP_STUN_" + route + "_RTT_MS=" + detail
                + ";N=" + SAMPLES + ";REPLIES=" + replies + ";UNANSWERED=" + unanswered
                + ";PROBE_LOSS_PERCENT=" + String.format(Locale.ROOT, "%.3f", 100.0 * unanswered / SAMPLES)
                + ";MEDIAN_MS=" + milliseconds(median) + ";P95_MS=" + milliseconds(percentile95)
                + ";MEAN_ADJACENT_RTT_CHANGE_MS=" + milliseconds(jitter) + ";HOST=" + target.host
                + ";ENDPOINT=" + target.address.getHostAddress() + ";PORT=" + target.port
                + ";TIMEOUT_MS=" + REPLY_TIMEOUT_MS
                + ";VPN_EXIT_VERIFIED=" + (verifyExit && replies > 0 ? 1 : 0));
    }

    private static String milliseconds(long nanos) {
        return nanos < 0 ? "-1" : String.format(Locale.ROOT, "%.3f", nanos / 1_000_000.0);
    }

    private record Target(String host, int port, Inet4Address address, String unavailableReason) {}
}
