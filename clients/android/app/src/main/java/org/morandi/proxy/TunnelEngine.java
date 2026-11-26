package org.morandi.proxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.SystemClock;

import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Statistics;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.config.Config;
import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;
import com.wireguard.crypto.KeyPair;

import org.json.JSONObject;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

public final class TunnelEngine {
    private static final long VERIFY_DEADLINE_MS = 6_500;
    private static final long VPN_NETWORK_WAIT_MS = 1_500;
    private static final long CONNECT_DEADLINE_MS = 48_000;
    private static final long PORT_HINT_LIFETIME_MS = 10 * 60_000;
    private static final long CANCELLATION_CHECK_MS = 80;

    public interface Callback {
        void trying(String endpoint);
        boolean cancelled();
    }

    interface Probe {
        String verify(Network vpn, String expected, boolean ipv6, long timeoutMs) throws IOException;
    }

    public static final class Result {
        public final String endpoint;
        public final String ipv4;
        public final String ipv6;
        final AttemptTiming timing;

        Result(String endpoint, String ipv4, String ipv6, AttemptTiming timing) {
            this.endpoint = endpoint;
            this.ipv4 = ipv4;
            this.ipv6 = ipv6;
            this.timing = timing;
        }
    }

    static final class AttemptTiming {
        final int attempts;
        long serviceWaitMs;
        long nativeStartMs;
        long networkWaitMs;
        long exitProofMs;
        String ipv4ProofProtocol = "";
        String ipv6ProofProtocol = "";

        AttemptTiming(int attempts) {
            this.attempts = attempts;
        }
    }

    private final Context context;
    private final ConnectivityManager connectivity;
    private final Probe probe;
    private final boolean allowPrivateTestAddresses;
    private volatile boolean up;
    private volatile boolean expectedDown;
    private volatile Runnable onRevocation;
    private GoBackend backend;
    private TunnelProfile profile;
    private TunnelProfile.Candidate connected;
    private Network lastProbeNetwork;
    private long preparedServiceDeadline;
    private Network lastVerifiedUnderlay;
    private TunnelProfile.Candidate lastVerifiedCandidate;
    private long lastVerifiedAt;
    private final Tunnel tunnel = new Tunnel() {
        @Override public String getName() {
            return "Proxy";
        }

        @Override public void onStateChange(State state) {
            boolean wasUp = up;
            up = state == State.UP;
            Runnable listener = onRevocation;
            if (wasUp && !up && !expectedDown && listener != null) {
                listener.run();
            }
        }
    };

    public TunnelEngine(Context context) {
        this(context, null, false);
    }

    TunnelEngine(Context context, Probe probe, boolean allowPrivateTestAddresses) {
        this.context = context.getApplicationContext();
        this.connectivity = this.context.getSystemService(ConnectivityManager.class);
        this.probe = probe;
        this.allowPrivateTestAddresses = allowPrivateTestAddresses;
    }

    public static String generatePrivateKey() {
        return new KeyPair().getPrivateKey().toBase64();
    }

    public static String publicKey(String privateKey) {
        return new KeyPair(parsePrivateKey(privateKey)).getPublicKey().toBase64();
    }

    private static Key parsePrivateKey(String encoded) {
        try {
            return Key.fromBase64(encoded);
        } catch (KeyFormatException error) {
            throw new IllegalArgumentException("INVALID_PRIVATE_KEY");
        }
    }

    public void setRevocationListener(Runnable listener) {
        onRevocation = listener;
    }

    public boolean isUp() {
        return up;
    }

    synchronized void prepareConnection() {
        if (up || preparedServiceDeadline != 0 || VpnService.prepare(context) != null) {
            return;
        }
        try {
            // Starting the notification-bearing service does not install a
            // TUN, load a server profile or send WireGuard traffic.
            preparedServiceDeadline = ProxyVpnService.requestPreparation(context);
        } catch (IOException ignored) {
            // Connect can start the service normally after policy is available.
        }
    }

    public synchronized Result connect(JSONObject payload, String privateKey, int preferredPort,
                                       Callback callback) throws IOException {
        if (VpnService.prepare(context) != null) {
            throw new IOException("VPN_PERMISSION_REQUIRED");
        }
        TunnelProfile target = TunnelProfile.read(payload, preferredPort, allowPrivateTestAddresses);
        Key key = parsePrivateKey(privateKey);
        long serviceDeadline = preparedServiceDeadline;
        preparedServiceDeadline = 0;
        if (serviceDeadline == 0 || up) {
            disconnect();
            serviceDeadline = 0;
        }
        if (backend == null) {
            try {
                backend = new GoBackend(context);
            } catch (RuntimeException | LinkageError error) {
                throw new IOException("WIREGUARD_UNAVAILABLE");
            }
        }
        long deadline = SystemClock.elapsedRealtime() + CONNECT_DEADLINE_MS;
        Network underlay = currentUnderlay();
        int attempts = 0;
        for (TunnelProfile.Candidate candidate : orderedCandidates(target, preferredPort, underlay)) {
            if (callback.cancelled()) {
                throw new IOException("VPN_CONNECT_CANCELLED");
            }
            if (SystemClock.elapsedRealtime() >= deadline) {
                break;
            }
            callback.trying(candidate.endpoint());
            trace("attempt UDP " + candidate.port);
            // There is no client-side traffic bypass while a full-route TUN is up.
            // Android can restore normal routes between attempts when a TUN is torn down.
            Config config = target.wireGuardConfig(candidate, key);
            AttemptTiming timing = new AttemptTiming(++attempts);
            try {
                long serviceStarted = SystemClock.elapsedRealtime();
                boolean overlappedStart = serviceDeadline != 0;
                if (!overlappedStart) {
                    serviceDeadline = ProxyVpnService.requestStart(context);
                }
                try {
                    ProxyVpnService.awaitStart(serviceDeadline, callback);
                } catch (IOException error) {
                    if (!overlappedStart || callback.cancelled()) {
                        throw error;
                    }
                    // If Android rejected the early launch, use the normal
                    // foreground-service start after authorization has completed.
                    disconnect();
                    ProxyVpnService.awaitStart(ProxyVpnService.requestStart(context), callback);
                }
                serviceDeadline = 0;
                long nativeStarted = SystemClock.elapsedRealtime();
                timing.serviceWaitMs = nativeStarted - serviceStarted;
                if (backend.setState(tunnel, Tunnel.State.UP, config) != Tunnel.State.UP) {
                    throw new IOException("VPN_START_FAILED");
                }
                timing.nativeStartMs = SystemClock.elapsedRealtime() - nativeStarted;
                trace("native tunnel started");
                Network previousNetwork = lastProbeNetwork;
                Result result = verify(target, candidate, deadline, callback, previousNetwork, timing);
                if (result != null && up && !callback.cancelled()) {
                    profile = target;
                    connected = candidate;
                    lastVerifiedCandidate = candidate;
                    lastVerifiedUnderlay = underlay;
                    lastVerifiedAt = SystemClock.elapsedRealtime();
                    return result;
                }
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                disconnect();
                throw new IOException("VPN_CONNECT_CANCELLED");
            } catch (Exception error) {
                // Native or configuration exceptions can contain internal arguments.
                // Return only this allowlisted status to the controller.
                trace("candidate error " + error.getClass().getSimpleName());
                disconnect();
                serviceDeadline = 0;
                if (error instanceof IOException &&
                        "VPN_SERVICE_START_FAILED".equals(error.getMessage())) {
                    throw new IOException("VPN_SERVICE_START_FAILED");
                }
                continue;
            }
            disconnect();
        }
        throw new IOException(callback.cancelled() ? "VPN_CONNECT_CANCELLED"
                : "VPN_EXIT_NOT_VERIFIED");
    }

    private Network currentUnderlay() {
        Network active = connectivity.getActiveNetwork();
        NetworkCapabilities capabilities = active == null ? null : connectivity.getNetworkCapabilities(active);
        return capabilities != null && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                ? active : null;
    }

    private List<TunnelProfile.Candidate> orderedCandidates(TunnelProfile target, int preferredPort,
                                                             Network underlay) {
        TunnelProfile.Candidate hint = lastVerifiedCandidate;
        if (preferredPort != 0 || underlay == null || !underlay.equals(lastVerifiedUnderlay)
                || hint == null || SystemClock.elapsedRealtime() - lastVerifiedAt >= PORT_HINT_LIFETIME_MS) {
            return target.candidates;
        }
        int firstForAddress = -1;
        for (int i = 0; i < target.candidates.size(); i++) {
            TunnelProfile.Candidate candidate = target.candidates.get(i);
            if (!hint.address.equals(candidate.address)) {
                continue;
            }
            if (firstForAddress == -1) {
                firstForAddress = i;
            }
            if (i > firstForAddress && hint.port == candidate.port && hint.key.equals(candidate.key)) {
                // The hint changes only port order within the same authorized
                // address and is never accepted as proof for a new tunnel.
                List<TunnelProfile.Candidate> reordered = new ArrayList<>(target.candidates);
                reordered.add(firstForAddress, reordered.remove(i));
                return reordered;
            }
        }
        return target.candidates;
    }

    public synchronized boolean verifyConnected() {
        if (!up || profile == null || connected == null) {
            return false;
        }
        try {
            return verify(profile, connected, SystemClock.elapsedRealtime() + VERIFY_DEADLINE_MS,
                    null, null, new AttemptTiming(0)) != null && up;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    public synchronized void disconnect() throws IOException {
        preparedServiceDeadline = 0;
        profile = null;
        connected = null;
        expectedDown = true;
        boolean down;
        boolean serviceStopped;
        try {
            down = backend == null
                    || backend.setState(tunnel, Tunnel.State.DOWN, null) == Tunnel.State.DOWN;
        } catch (Exception error) {
            down = false;
        } finally {
            try {
                serviceStopped = ProxyVpnService.stop(context);
            } catch (RuntimeException error) {
                serviceStopped = false;
            } finally {
                expectedDown = false;
            }
        }
        if (!down || !serviceStopped || up) {
            throw new IOException("VPN_STOP_FAILED");
        }
    }

    private Result verify(TunnelProfile target, TunnelProfile.Candidate candidate, long deadline,
                          Callback callback, Network previousNetwork, AttemptTiming timing) throws InterruptedException {
        long detectionStarted = SystemClock.elapsedRealtime();
        long probeDeadline = Math.min(deadline, SystemClock.elapsedRealtime() + VERIFY_DEADLINE_MS);
        Network vpn = awaitNetwork(target, Math.min(probeDeadline,
                SystemClock.elapsedRealtime() + VPN_NETWORK_WAIT_MS), callback, previousNetwork);
        if (vpn == null || cancelled(callback)) {
            trace("compatible Android VPN network unavailable");
            return null;
        }
        // Android can publish this Network before netd permits its explicit
        // socket binding. Confirm that the same VPN accepts a socket without
        // sending traffic, and leave the original proof deadline in effect.
        if (!awaitProbeBinding(vpn, probeDeadline, callback)) {
            return null;
        }
        long proofStarted = SystemClock.elapsedRealtime();
        timing.networkWaitMs = proofStarted - detectionStarted;
        lastProbeNetwork = vpn;
        trace("Android VPN network ready");
        // An Android network agent is visible slightly before all its routes
        // are ready. Retry early socket failures on the same VPN within the
        // original deadline, keeping both address-family checks mandatory.
        for (int attempt = 0; attempt < 3 && up && !cancelled(callback)
                && SystemClock.elapsedRealtime() < probeDeadline; attempt++) {
            Result result = verifyOnce(target, candidate, vpn, probeDeadline, callback, timing);
            if (result != null) {
                timing.exitProofMs = SystemClock.elapsedRealtime() - proofStarted;
                return result;
            }
            if (probeDeadline - SystemClock.elapsedRealtime() < 500) {
                break;
            }
            Thread.sleep(160);
        }
        return null;
    }

    private boolean awaitProbeBinding(Network vpn, long deadline, Callback callback)
            throws InterruptedException {
        boolean waiting = false;
        while (up && !cancelled(callback)) {
            long remaining = deadline - SystemClock.elapsedRealtime();
            if (remaining <= 0) {
                break;
            }
            try (Socket socket = new Socket()) {
                vpn.bindSocket(socket);
                return up && !cancelled(callback);
            } catch (IOException error) {
                if (!waiting) {
                    trace("Android VPN socket binding not ready");
                    waiting = true;
                }
                Thread.sleep(Math.min(CANCELLATION_CHECK_MS, remaining));
            }
        }
        trace("compatible Android VPN socket binding unavailable");
        return false;
    }

    private Result verifyOnce(TunnelProfile target, TunnelProfile.Candidate candidate, Network vpn,
                              long probeDeadline, Callback callback, AttemptTiming timing)
            throws InterruptedException {
        long remaining = probeDeadline - SystemClock.elapsedRealtime();
        if (remaining <= 0) {
            return null;
        }
        ExecutorService executor = Executors.newFixedThreadPool(target.ipv6Exit.isEmpty() ? 1 : 2);
        ExecutorCompletionService<CloudflareExitProbe.Proof> completed = new ExecutorCompletionService<>(executor);
        Future<CloudflareExitProbe.Proof> v4 = completed.submit(
                () -> checkAddress(vpn, candidate.exit, false, remaining));
        Future<CloudflareExitProbe.Proof> v6 = target.ipv6Exit.isEmpty() ? null : completed.submit(
                () -> checkAddress(vpn, target.ipv6Exit, true, remaining));
        try {
            int outstanding = v6 == null ? 1 : 2;
            while (up && !cancelled(callback) && SystemClock.elapsedRealtime() < probeDeadline) {
                long wait = Math.min(CANCELLATION_CHECK_MS, probeDeadline - SystemClock.elapsedRealtime());
                if (wait > 0 && completed.poll(wait, TimeUnit.MILLISECONDS) != null
                        && --outstanding == 0 && up && !cancelled(callback)) {
                    CloudflareExitProbe.Proof ipv4;
                    CloudflareExitProbe.Proof ipv6;
                    try {
                        ipv4 = v4.get();
                        ipv6 = v6 == null ? null : v6.get();
                    } catch (ExecutionException error) {
                        Throwable cause = error.getCause();
                        trace("exit probe error " + (cause == null ? "unknown" : cause.getClass().getSimpleName())
                                + ", handshake=" + hasHandshake(candidate));
                        return null;
                    }
                    if (!hasHandshake(candidate)) {
                        return null;
                    }
                    timing.ipv4ProofProtocol = ipv4.protocol;
                    timing.ipv6ProofProtocol = ipv6 == null ? "" : ipv6.protocol;
                    return new Result(candidate.endpoint(), ipv4.address,
                            ipv6 == null ? "" : ipv6.address, timing);
                }
            }
            trace("exit proof deadline, handshake=" + hasHandshake(candidate));
            return null;
        } finally {
            v4.cancel(true);
            if (v6 != null) {
                v6.cancel(true);
            }
            executor.shutdownNow();
        }
    }

    private boolean hasHandshake(TunnelProfile.Candidate candidate) {
        Statistics.PeerStats stats = backend.getStatistics(tunnel).peer(candidate.key);
        return stats != null && stats.latestHandshakeEpochMillis() > 0;
    }

    private static void trace(String stage) {
        if (BuildConfig.DEBUG) {
            android.util.Log.d("ProxyTunnel", stage);
        }
    }

    private CloudflareExitProbe.Proof checkAddress(Network vpn, String expected, boolean ipv6, long timeoutMs)
            throws IOException {
        if (probe == null) {
            return CloudflareExitProbe.verify(context, vpn, expected, ipv6, timeoutMs);
        }
        String address = probe.verify(vpn, expected, ipv6, timeoutMs);
        InetAddress actual = TunnelProfile.numeric(address, ipv6, !allowPrivateTestAddresses);
        if (!actual.equals(TunnelProfile.numeric(expected, ipv6, !allowPrivateTestAddresses))) {
            throw new IOException("VPN_EXIT_MISMATCH");
        }
        return new CloudflareExitProbe.Proof(actual.getHostAddress(), "fixture");
    }

    private Network awaitNetwork(TunnelProfile target, long deadline, Callback callback, Network previousNetwork)
            throws InterruptedException {
        Network ready = findNetwork(target, previousNetwork);
        if (ready != null) {
            return ready;
        }
        Semaphore changes = new Semaphore(0);
        ConnectivityManager.NetworkCallback wake = new ConnectivityManager.NetworkCallback() {
            private void signal() {
                if (changes.availablePermits() == 0) {
                    changes.release();
                }
            }
            @Override public void onAvailable(Network network) {
                signal();
            }
            @Override public void onLinkPropertiesChanged(Network network, LinkProperties links) {
                signal();
            }
            @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
                signal();
            }
        };
        boolean watching;
        try {
            connectivity.registerNetworkCallback(new NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                    .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
                    .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
                    .build(), wake);
            watching = true;
        } catch (RuntimeException error) {
            watching = false;
        }
        try {
            while (up && !cancelled(callback)) {
                ready = findNetwork(target, previousNetwork);
                if (ready != null) {
                    return ready;
                }
                long remaining = deadline - SystemClock.elapsedRealtime();
                if (remaining <= 0) {
                    break;
                }
                changes.tryAcquire(Math.min(remaining, watching ? CANCELLATION_CHECK_MS : 30),
                        TimeUnit.MILLISECONDS);
            }
            return null;
        } finally {
            if (watching) {
                connectivity.unregisterNetworkCallback(wake);
            }
        }
    }

    private Network findNetwork(TunnelProfile target, Network previousNetwork) {
        // Use this VPN's new network and profile, not the underlying Android default.
        Network active = connectivity.getActiveNetwork();
        if (active != null && !active.equals(previousNetwork) && matches(active, target.interfaceAddresses)) {
            return active;
        }
        for (Network candidate : connectivity.getAllNetworks()) {
            if (!candidate.equals(previousNetwork) && matches(candidate, target.interfaceAddresses)) {
                return candidate;
            }
        }
        return null;
    }

    private boolean matches(Network network, Set<InetAddress> addresses) {
        NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
        LinkProperties links = connectivity.getLinkProperties(network);
        if (capabilities == null || !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                || links == null) {
            return false;
        }
        Set<InetAddress> found = new HashSet<>();
        for (LinkAddress address : links.getLinkAddresses()) {
            found.add(address.getAddress());
        }
        return found.containsAll(addresses);
    }

    private static boolean cancelled(Callback callback) {
        return callback != null && callback.cancelled();
    }
}
