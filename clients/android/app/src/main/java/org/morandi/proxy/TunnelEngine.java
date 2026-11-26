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
import java.util.concurrent.FutureTask;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class TunnelEngine {
    private static final long VERIFY_DEADLINE_MS = 6_500;
    private static final long VPN_NETWORK_WAIT_MS = 1_500;
    private static final long CONNECT_DEADLINE_MS = 48_000;
    private static final long PORT_HINT_LIFETIME_MS = 10 * 60_000;
    private static final long CANCELLATION_CHECK_MS = 80;
    private static final long FAST_BIND_WINDOW_MS = 800;
    private static final long FAST_BIND_RETRY_MS = 25;
    private static final long EXIT_RETRY_BACKOFF_MS = 160;
    private static final long MIN_EXIT_RETRY_BUDGET_MS = 500;
    private static final int MAX_EXIT_PROBE_ATTEMPTS = 3;

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
        int firstAttemptedPort;
        Network orderingUnderlay;
        Network verifiedUnderlay;
        long backendWaitMs;
        long serviceWaitMs;
        long nativeStartMs;
        long networkWaitMs;
        long networkDiscoveryMs;
        long networkBindingMs;
        long exitProofMs;
        long ipv4ProofMs;
        long ipv6ProofMs;
        int ipv4ProofAttempts;
        int ipv6ProofAttempts;
        long handshakeMs = -1;
        long nativeActivationWallMs;
        long nativeActivationElapsedMs;
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
    private FutureTask<GoBackend> preparedBackend;
    private TunnelProfile profile;
    private TunnelProfile.Candidate connected;
    private Network lastProbeNetwork;
    private long preparedServiceDeadline;
    private Network preparedUnderlay;
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
        preparedUnderlay = currentUnderlay(connectivity, null);
        prepareLocalComponents();
        try {
            // Starting the notification-bearing service does not install a
            // TUN, load a server profile or send WireGuard traffic.
            preparedServiceDeadline = ProxyVpnService.requestPreparation(context);
        } catch (IOException ignored) {
            // Connect can start the service normally after policy is available.
        }
    }

    synchronized void prepareLocalComponents() {
        // Safe during system consent. Neither component starts a service,
        // attaches a TUN or makes an exit request.
        prepareBackend();
        CloudflareExitProbe.prepare(context);
    }

    private void prepareBackend() {
        if (backend == null && preparedBackend == null) {
            // Library loading can run with the policy request. A GoBackend
            // constructor has no profile and cannot install a VPN or send packets.
            FutureTask<GoBackend> loading = new FutureTask<>(() -> new GoBackend(context));
            try {
                new Thread(loading, "ProxyWireGuardPreparation").start();
                preparedBackend = loading;
            } catch (RuntimeException ignored) {
                // The authorized connection path can load the backend normally.
            }
        }
    }

    public synchronized Result connect(JSONObject payload, String privateKey, int preferredPort,
                                       Callback callback) throws IOException {
        if (VpnService.prepare(context) != null) {
            throw new IOException("VPN_PERMISSION_REQUIRED");
        }
        TunnelProfile target = TunnelProfile.read(payload, preferredPort, allowPrivateTestAddresses);
        Key key = parsePrivateKey(privateKey);
        Network beforeService = preparedUnderlay;
        preparedUnderlay = null;
        long serviceDeadline = preparedServiceDeadline;
        preparedServiceDeadline = 0;
        if (serviceDeadline == 0 || up) {
            disconnect();
            serviceDeadline = 0;
        }
        long backendStarted = SystemClock.elapsedRealtime();
        long deadline = backendStarted + CONNECT_DEADLINE_MS;
        loadBackend(deadline, callback);
        long backendWaitMs = SystemClock.elapsedRealtime() - backendStarted;
        Network underlay = currentUnderlay(connectivity, beforeService);
        Network attemptUnderlay = underlay;
        int firstAttemptedPort = 0;
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
            if (firstAttemptedPort == 0) {
                firstAttemptedPort = candidate.port;
            }
            if (attempts != 0) {
                Network replacement = currentUnderlay(connectivity, attemptUnderlay);
                if (replacement != null || !isPhysical(capabilities(connectivity, attemptUnderlay))) {
                    attemptUnderlay = replacement;
                }
            }
            // There is no client-side traffic bypass while a full-route TUN is up.
            // Android can restore normal routes between attempts when a TUN is torn down.
            Config config = target.wireGuardConfig(candidate, key);
            AttemptTiming timing = new AttemptTiming(++attempts);
            timing.firstAttemptedPort = firstAttemptedPort;
            timing.orderingUnderlay = underlay;
            timing.backendWaitMs = backendWaitMs;
            try (NetworkChanges changes = new NetworkChanges()) {
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
                timing.nativeActivationElapsedMs = nativeStarted;
                timing.nativeActivationWallMs = System.currentTimeMillis();
                if (backend.setState(tunnel, Tunnel.State.UP, config) != Tunnel.State.UP) {
                    throw new IOException("VPN_START_FAILED");
                }
                timing.nativeStartMs = SystemClock.elapsedRealtime() - nativeStarted;
                trace("native tunnel started");
                Network previousNetwork = lastProbeNetwork;
                Result result = verify(target, candidate, deadline, callback, previousNetwork, timing, changes);
                if (result != null && up && !callback.cancelled()) {
                    profile = target;
                    connected = candidate;
                    lastVerifiedCandidate = candidate;
                    lastVerifiedUnderlay = attemptUnderlay;
                    timing.verifiedUnderlay = attemptUnderlay;
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

    private void loadBackend(long deadline, Callback callback) throws IOException {
        if (backend != null) {
            return;
        }
        prepareBackend();
        try {
            if (preparedBackend == null) {
                backend = new GoBackend(context);
                return;
            }
            while (!callback.cancelled()) {
                long remaining = deadline - SystemClock.elapsedRealtime();
                if (remaining <= 0) {
                    throw new IOException("WIREGUARD_UNAVAILABLE");
                }
                try {
                    backend = preparedBackend.get(Math.min(remaining, CANCELLATION_CHECK_MS),
                            TimeUnit.MILLISECONDS);
                    preparedBackend = null;
                    return;
                } catch (TimeoutException ignored) {
                    // Recheck cancellation within the existing connect deadline.
                }
            }
            // A later connection can reuse the single loader if it is still in progress.
            throw new IOException("VPN_CONNECT_CANCELLED");
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException("VPN_CONNECT_CANCELLED");
        } catch (ExecutionException | RuntimeException | LinkageError error) {
            preparedBackend = null;
            throw new IOException("WIREGUARD_UNAVAILABLE");
        }
    }

    private static Network currentUnderlay(ConnectivityManager connectivity, Network earlier) {
        Network active = connectivity.getActiveNetwork();
        if (isPhysical(capabilities(connectivity, active))) {
            return active;
        }
        // On disconnect, Android can briefly report its old VPN or no
        // default. Revalidate the observed pre-service physical network
        // first. These identities only influence port ordering.
        if (isValidatedInternet(capabilities(connectivity, earlier))) {
            return earlier;
        }
        Network physical = null;
        for (Network network : connectivity.getAllNetworks()) {
            if (!isValidatedInternet(capabilities(connectivity, network))) {
                continue;
            }
            if (physical != null) {
                return null;
            }
            physical = network;
        }
        return physical;
    }

    private static NetworkCapabilities capabilities(ConnectivityManager connectivity, Network network) {
        return network == null ? null : connectivity.getNetworkCapabilities(network);
    }

    private static boolean isPhysical(NetworkCapabilities capabilities) {
        return capabilities != null && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }

    private static boolean isValidatedInternet(NetworkCapabilities capabilities) {
        return isPhysical(capabilities)
                && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
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
        try (NetworkChanges changes = new NetworkChanges()) {
            return verify(profile, connected, SystemClock.elapsedRealtime() + VERIFY_DEADLINE_MS,
                    null, null, new AttemptTiming(0), changes) != null && up;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    public synchronized void disconnect() throws IOException {
        preparedServiceDeadline = 0;
        preparedUnderlay = null;
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
                          Callback callback, Network previousNetwork, AttemptTiming timing,
                          NetworkChanges changes) throws InterruptedException {
        long detectionStarted = SystemClock.elapsedRealtime();
        long probeDeadline = Math.min(deadline, detectionStarted + VERIFY_DEADLINE_MS);
        Network vpn = awaitNetwork(target, Math.min(probeDeadline, detectionStarted + VPN_NETWORK_WAIT_MS),
                callback, previousNetwork, changes);
        if (vpn == null || cancelled(callback)) {
            trace("compatible Android VPN network unavailable");
            return null;
        }
        long bindingStarted = SystemClock.elapsedRealtime();
        timing.networkDiscoveryMs = bindingStarted - detectionStarted;
        lastProbeNetwork = vpn;
        // Android can publish this VPN before netd permits it to bind a
        // socket. Keep waiting on the same Network, without sending data.
        if (!awaitProbeBinding(vpn, probeDeadline, callback, changes)) {
            return null;
        }
        timing.networkBindingMs = SystemClock.elapsedRealtime() - bindingStarted;
        changes.close();
        long proofStarted = SystemClock.elapsedRealtime();
        timing.networkWaitMs = proofStarted - detectionStarted;
        trace("Android VPN network ready");
        Result result = verifyExits(target, candidate, vpn, probeDeadline, callback, timing);
        if (result != null) {
            timing.exitProofMs = SystemClock.elapsedRealtime() - proofStarted;
        }
        return result;
    }

    private boolean awaitProbeBinding(Network vpn, long deadline, Callback callback, NetworkChanges changes)
            throws InterruptedException {
        boolean waiting = false;
        long fastUntil = SystemClock.elapsedRealtime() + FAST_BIND_WINDOW_MS;
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
                long now = SystemClock.elapsedRealtime();
                long retryMs = now < fastUntil ? FAST_BIND_RETRY_MS : CANCELLATION_CHECK_MS;
                if (now < deadline) {
                    changes.await(Math.min(retryMs, deadline - now));
                }
            }
        }
        trace("compatible Android VPN socket binding unavailable");
        return false;
    }

    private static final class FamilyProof {
        final boolean ipv6;
        final CloudflareExitProbe.Proof proof;
        final long elapsedMs;
        final int attempts;

        FamilyProof(boolean ipv6, CloudflareExitProbe.Proof proof, long elapsedMs, int attempts) {
            this.ipv6 = ipv6;
            this.proof = proof;
            this.elapsedMs = elapsedMs;
            this.attempts = attempts;
        }
    }

    private FamilyProof verifyFamily(Network vpn, String expected, boolean ipv6,
                                     long deadline, long startedAt, Callback callback)
            throws IOException, InterruptedException {
        for (int attempt = 1; attempt <= MAX_EXIT_PROBE_ATTEMPTS && up && !cancelled(callback); attempt++) {
            long remaining = deadline - SystemClock.elapsedRealtime();
            if (remaining <= 0 || Thread.currentThread().isInterrupted()) {
                break;
            }
            try {
                CloudflareExitProbe.Proof proof = checkAddress(vpn, expected, ipv6, remaining);
                return new FamilyProof(ipv6, proof, SystemClock.elapsedRealtime() - startedAt, attempt);
            } catch (IOException error) {
                if (attempt == MAX_EXIT_PROBE_ATTEMPTS
                        || deadline - SystemClock.elapsedRealtime() < MIN_EXIT_RETRY_BUDGET_MS) {
                    throw error;
                }
                // Each address family retries its own early failure. A valid
                // result remains local to this exact handshake and Network.
                Thread.sleep(EXIT_RETRY_BACKOFF_MS);
            }
        }
        throw new IOException("VPN_EXIT_PROBE_TIMEOUT");
    }

    private Result verifyExits(TunnelProfile target, TunnelProfile.Candidate candidate, Network vpn,
                               long probeDeadline, Callback callback, AttemptTiming timing)
            throws InterruptedException {
        boolean dualStack = !target.ipv6Exit.isEmpty();
        ExecutorService executor = Executors.newFixedThreadPool(dualStack ? 2 : 1);
        ExecutorCompletionService<FamilyProof> completed = new ExecutorCompletionService<>(executor);
        long startedAt = SystemClock.elapsedRealtime();
        Future<FamilyProof> v4 = completed.submit(
                () -> verifyFamily(vpn, candidate.exit, false, probeDeadline, startedAt, callback));
        Future<FamilyProof> v6 = !dualStack ? null : completed.submit(
                () -> verifyFamily(vpn, target.ipv6Exit, true, probeDeadline, startedAt, callback));
        try {
            FamilyProof ipv4 = null;
            FamilyProof ipv6 = null;
            while (up && !cancelled(callback)) {
                long wait = Math.min(CANCELLATION_CHECK_MS, probeDeadline - SystemClock.elapsedRealtime());
                if (wait <= 0) {
                    break;
                }
                Future<FamilyProof> ready = completed.poll(wait, TimeUnit.MILLISECONDS);
                if (ready == null) {
                    continue;
                }
                FamilyProof result = ready.get();
                if (result.ipv6) {
                    ipv6 = result;
                } else {
                    ipv4 = result;
                }
                if (ipv4 == null || (dualStack && ipv6 == null)) {
                    continue;
                }
                if (!up || cancelled(callback) || SystemClock.elapsedRealtime() >= probeDeadline) {
                    break;
                }
                long handshake = latestHandshake(candidate);
                if (handshake <= 0) {
                    return null;
                }
                recordProofTimings(timing, ipv4, ipv6, handshake);
                CloudflareExitProbe.rememberVerifiedProtocols(ipv4.proof, ipv6 == null ? null : ipv6.proof);
                return new Result(candidate.endpoint(), ipv4.proof.address,
                        ipv6 == null ? "" : ipv6.proof.address, timing);
            }
            trace("exit proof deadline, handshake=" + (latestHandshake(candidate) > 0));
            return null;
        } catch (ExecutionException error) {
            Throwable cause = error.getCause();
            trace("exit probe error " + (cause == null ? "unknown" : cause.getClass().getSimpleName())
                    + ", handshake=" + (latestHandshake(candidate) > 0));
            return null;
        } finally {
            v4.cancel(true);
            if (v6 != null) {
                v6.cancel(true);
            }
            executor.shutdownNow();
        }
    }

    private static void recordProofTimings(AttemptTiming timing, FamilyProof ipv4, FamilyProof ipv6,
                                           long handshakeWallMs) {
        timing.ipv4ProofProtocol = ipv4.proof.protocol;
        timing.ipv4ProofMs = ipv4.elapsedMs;
        timing.ipv4ProofAttempts = ipv4.attempts;
        if (ipv6 != null) {
            timing.ipv6ProofProtocol = ipv6.proof.protocol;
            timing.ipv6ProofMs = ipv6.elapsedMs;
            timing.ipv6ProofAttempts = ipv6.attempts;
        }
        // The kernel backend exposes wall-clock handshake time. Ignore the
        // timing sample if a clock change puts it outside the native attempt.
        long handshakeOffset = handshakeWallMs - timing.nativeActivationWallMs;
        if (timing.nativeActivationWallMs != 0 && handshakeOffset >= 0
                && handshakeOffset <= SystemClock.elapsedRealtime() - timing.nativeActivationElapsedMs) {
            timing.handshakeMs = handshakeOffset;
        }
    }

    private long latestHandshake(TunnelProfile.Candidate candidate) {
        Statistics.PeerStats stats = backend.getStatistics(tunnel).peer(candidate.key);
        return stats == null ? 0 : stats.latestHandshakeEpochMillis();
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

    private Network awaitNetwork(TunnelProfile target, long deadline, Callback callback,
                                 Network previousNetwork, NetworkChanges changes) throws InterruptedException {
        while (up && !cancelled(callback)) {
            Network ready = findNetwork(target, previousNetwork);
            if (ready != null) {
                return ready;
            }
            long remaining = deadline - SystemClock.elapsedRealtime();
            if (remaining <= 0) {
                break;
            }
            changes.await(Math.min(remaining, CANCELLATION_CHECK_MS));
        }
        return null;
    }

    private final class NetworkChanges extends ConnectivityManager.NetworkCallback implements AutoCloseable {
        private final Semaphore changes = new Semaphore(0);
        private boolean watching;

        NetworkChanges() {
            try {
                connectivity.registerNetworkCallback(new NetworkRequest.Builder()
                        .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                        .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                        .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
                        .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
                        .build(), this);
                watching = true;
            } catch (RuntimeException error) {
                // Retain bounded polling on Android versions that reject the callback.
            }
        }

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

        @Override public void onBlockedStatusChanged(Network network, boolean blocked) {
            signal();
        }

        @Override public void onLost(Network network) {
            signal();
        }

        void await(long timeoutMs) throws InterruptedException {
            if (watching) {
                changes.tryAcquire(timeoutMs, TimeUnit.MILLISECONDS);
            } else {
                Thread.sleep(timeoutMs);
            }
        }

        @Override public void close() {
            if (watching) {
                watching = false;
                connectivity.unregisterNetworkCallback(this);
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
