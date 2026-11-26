package org.morandi.proxy;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.RouteInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.Process;
import android.os.SystemClock;
import android.system.ErrnoException;

import com.wireguard.android.backend.BackendException;
import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Statistics;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.config.Config;
import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;
import com.wireguard.crypto.KeyPair;

import org.json.JSONObject;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.DatagramSocket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

public final class TunnelEngine {
    private static final long VERIFY_DEADLINE_MS = 6_500;
    private static final long VPN_NETWORK_WAIT_MS = 1_500;
    private static final long VPN_CALLBACK_GRACE_MS = 50;
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
        long ownerWaitMs;
        int bindFailures;
        int firstBindErrno;
        int lastBindErrno;
        int initiallyBlocked = -1;
        int blockedAtBind = -1;
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
    private CompletableFuture<Long> preparedServiceStart;
    private CompletableFuture<Network> preparedUnderlay;
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

    synchronized void prepareConnection(boolean permissionCheckedForTap) {
        // The activity may have just confirmed permission for this connection tap.
        // GoBackend rechecks immediately before establishing the TUN.
        if (up || preparedServiceStart != null
                || (!permissionCheckedForTap && VpnService.prepare(context) != null)) {
            return;
        }
        // Android's startService Binder transaction can block. Only the
        // notification service is prepared; fresh policy still gates native UP.
        preparedServiceStart = CompletableFuture.supplyAsync(() -> {
            try {
                return ProxyVpnService.requestPreparation(context);
            } catch (IOException error) {
                return 0L;
            }
        });
        // Port ordering can use this read while policy and profile work proceed.
        // A first connection without a verified port hint can start even if
        // Android has not yet answered the physical-network Binder calls.
        preparedUnderlay = CompletableFuture.supplyAsync(() -> currentUnderlay(connectivity, null))
                .exceptionally(error -> null);
        prepareLocalComponents();
    }

    synchronized void prepareLocalComponents() {
        // Safe during system consent. Preparation stays local and does not
        // display a notification, start a service, attach a TUN or probe.
        prepareBackend();
        CloudflareExitProbe.prepare(context);
        ProxyVpnService.prepareNotification(context);
    }

    private void prepareBackend() {
        if (backend == null && preparedBackend == null) {
            // Library loading can run with the policy request. A GoBackend
            // constructor has no profile and cannot install a VPN or send packets.
            FutureTask<GoBackend> loading = new FutureTask<>(() -> {
                GoBackend loaded = new GoBackend(context);
                // Loading the library can return before Go runtime initialization
                // finishes. Enter JNI without keys, sockets, a service or a TUN.
                loaded.getVersion();
                return loaded;
            });
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
        // Preparation already checked consent. GoBackend checks it again
        // immediately before creating the TUN for every native UP.
        if ((preparedServiceStart == null || up) && VpnService.prepare(context) != null) {
            throw new IOException("VPN_PERMISSION_REQUIRED");
        }
        TunnelProfile target = TunnelProfile.read(payload, preferredPort, allowPrivateTestAddresses);
        Key key = parsePrivateKey(privateKey);
        CompletableFuture<Network> underlayRead = preparedUnderlay;
        preparedUnderlay = null;
        if (preparedServiceStart == null || up) {
            disconnect();
        }
        long backendStarted = SystemClock.elapsedRealtime();
        long deadline = backendStarted + CONNECT_DEADLINE_MS;
        loadBackend(deadline, callback);
        long backendWaitMs = SystemClock.elapsedRealtime() - backendStarted;
        Network beforeService = underlayRead == null ? null : underlayRead.getNow(null);
        Network underlay = lastVerifiedCandidate == null && underlayRead != null ? beforeService
                : currentUnderlay(connectivity, beforeService);
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
                long serviceDeadline = finishServiceRequest();
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
                    if (VpnService.prepare(context) != null) {
                        throw new IOException("VPN_PERMISSION_REQUIRED");
                    }
                    ProxyVpnService.awaitStart(ProxyVpnService.requestStart(context), callback);
                }
                if (callback.cancelled()) {
                    throw new IOException("VPN_CONNECT_CANCELLED");
                }
                if (attempts == 1 && attemptUnderlay == null && underlayRead != null) {
                    // Only credit a result observed before this TUN existed.
                    attemptUnderlay = underlayRead.getNow(null);
                }
                // Android starts publishing the new TUN inside GoBackend.setState.
                // Observe that exact new network while native initialization finishes.
                // Neither a successful setState nor a probe alone can commit a connection.
                Set<Network> existing = new HashSet<>(Arrays.asList(connectivity.getAllNetworks()));
                CountDownLatch nativeReady = new CountDownLatch(1);
                AtomicBoolean verifying = new AtomicBoolean(true);
                BooleanSupplier active = () -> verifying.get() && !callback.cancelled()
                        && (nativeReady.getCount() != 0 || up);
                long nativeStarted = SystemClock.elapsedRealtime();
                timing.serviceWaitMs = nativeStarted - serviceStarted;
                timing.nativeActivationElapsedMs = nativeStarted;
                timing.nativeActivationWallMs = System.currentTimeMillis();
                FutureTask<ExitEvidence> verification = new FutureTask<>(() ->
                        collectExits(target, candidate, deadline, changes, existing, active, nativeReady, timing));
                Thread observer = new Thread(verification, "ProxyExitVerification");
                Result result;
                try {
                    observer.start();
                    if (backend.setState(tunnel, Tunnel.State.UP, config) != Tunnel.State.UP) {
                        throw new IOException("VPN_START_FAILED");
                    }
                    nativeReady.countDown();
                    changes.signal();
                    timing.nativeStartMs = SystemClock.elapsedRealtime() - nativeStarted;
                    trace("native tunnel started");
                    ExitEvidence evidence = verification.get();
                    result = verifiedResult(target, candidate, evidence, timing, callback);
                } finally {
                    verifying.set(false);
                    verification.cancel(true);
                }
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
                if (error instanceof BackendException backendError
                        && backendError.getReason() == BackendException.Reason.VPN_NOT_AUTHORIZED) {
                    throw new IOException("VPN_PERMISSION_REQUIRED");
                }
                if (error instanceof IOException
                        && ("VPN_PERMISSION_REQUIRED".equals(error.getMessage())
                        || "VPN_SERVICE_START_FAILED".equals(error.getMessage()))) {
                    throw new IOException(error.getMessage());
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
            AttemptTiming timing = new AttemptTiming(0);
            ExitEvidence evidence = collectExits(profile, connected,
                    SystemClock.elapsedRealtime() + VERIFY_DEADLINE_MS, changes,
                    Collections.emptySet(), () -> up, null, timing);
            return verifiedResult(profile, connected, evidence, timing, null) != null;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private long finishServiceRequest() {
        if (preparedServiceStart == null) {
            return 0;
        }
        try {
            // A stop must follow any already submitted start. Cancelling the
            // Future cannot cancel a running Android Binder transaction.
            return preparedServiceStart.join();
        } catch (CompletionException failed) {
            // The authorized connection falls back to its normal foreground start.
            return 0;
        } finally {
            preparedServiceStart = null;
        }
    }

    public synchronized void disconnect() throws IOException {
        finishServiceRequest();
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

    private static final class ExitEvidence {
        final Network network;
        final FamilyProof ipv4;
        final FamilyProof ipv6;
        final long deadline;

        ExitEvidence(Network network, FamilyProof ipv4, FamilyProof ipv6, long deadline) {
            this.network = network;
            this.ipv4 = ipv4;
            this.ipv6 = ipv6;
            this.deadline = deadline;
        }
    }

    private ExitEvidence collectExits(TunnelProfile target, TunnelProfile.Candidate candidate, long deadline,
                                      NetworkChanges changes, Set<Network> existing, BooleanSupplier active,
                                      CountDownLatch nativeReady, AttemptTiming timing) throws InterruptedException {
        long detectionStarted = SystemClock.elapsedRealtime();
        VpnNetwork selected = awaitNetwork(target, deadline, existing, active, nativeReady, changes);
        if (selected == null || !active.getAsBoolean()) {
            trace("compatible Android VPN network unavailable");
            return null;
        }
        Network vpn = selected.network();
        long selectedAt = SystemClock.elapsedRealtime();
        timing.networkDiscoveryMs = selectedAt - detectionStarted;
        long probeDeadline = Math.min(deadline, selectedAt + VERIFY_DEADLINE_MS);
        // Checking one unconnected socket sends no packets, so this can overlap
        // native UP even when Android redacts the VPN owner. netd checks the UID
        // against the netId. The two real transports still bind independently.
        timing.initiallyBlocked = changes.blockedStatus(vpn);
        if (!awaitProbeBinding(vpn, probeDeadline, active, changes, timing)) {
            return null;
        }
        long boundAt = SystemClock.elapsedRealtime();
        timing.networkBindingMs = boundAt - selectedAt;
        timing.blockedAtBind = changes.blockedStatus(vpn);
        if (nativeReady != null && nativeReady.getCount() != 0 && !selected.ownedByApp()) {
            // Android 10 or redacted ownership only permits early discovery. Wait
            // for this native UP and revalidate the profile before sending anything.
            while (active.getAsBoolean() && nativeReady.getCount() != 0) {
                long remaining = deadline - SystemClock.elapsedRealtime();
                if (remaining <= 0) {
                    return null;
                }
                nativeReady.await(Math.min(remaining, CANCELLATION_CHECK_MS), TimeUnit.MILLISECONDS);
            }
            if (!active.getAsBoolean() || !up || !matches(vpn, target)) {
                return null;
            }
            probeDeadline = Math.min(deadline, SystemClock.elapsedRealtime() + VERIFY_DEADLINE_MS);
        }
        long proofStarted = SystemClock.elapsedRealtime();
        timing.ownerWaitMs = proofStarted - boundAt;
        timing.networkWaitMs = proofStarted - detectionStarted;
        ExitEvidence result = verifyExits(target, candidate, vpn, probeDeadline, active);
        if (result != null) {
            timing.exitProofMs = SystemClock.elapsedRealtime() - proofStarted;
        }
        return result;
    }

    private Result verifiedResult(TunnelProfile target, TunnelProfile.Candidate candidate,
                                  ExitEvidence evidence, AttemptTiming timing, Callback callback) {
        // Read native statistics only after setState returns. The bound proofs,
        // routes and peer must still belong to this live, authorized attempt.
        if (evidence == null || !up || cancelled(callback) || !matches(evidence.network, target)
                || SystemClock.elapsedRealtime() >= evidence.deadline) {
            return null;
        }
        long handshake = latestHandshake(candidate);
        if (handshake <= 0 || !up || cancelled(callback)) {
            return null;
        }
        recordProofTimings(timing, evidence.ipv4, evidence.ipv6, handshake);
        return new Result(candidate.endpoint(), evidence.ipv4.proof.address,
                evidence.ipv6 == null ? "" : evidence.ipv6.proof.address, timing);
    }

    private static boolean awaitProbeBinding(Network vpn, long deadline, BooleanSupplier active,
                                             NetworkChanges changes, AttemptTiming timing)
            throws InterruptedException {
        long fastUntil = SystemClock.elapsedRealtime() + FAST_BIND_WINDOW_MS;
        try (DatagramSocket socket = new DatagramSocket(null)) {
            while (active.getAsBoolean() && SystemClock.elapsedRealtime() < deadline) {
                try {
                    vpn.bindSocket(socket);
                    return active.getAsBoolean();
                } catch (IOException error) {
                    int errno = bindingErrno(error);
                    if (timing.bindFailures++ == 0) {
                        timing.firstBindErrno = errno;
                    }
                    timing.lastBindErrno = errno;
                    long now = SystemClock.elapsedRealtime();
                    long retryMs = now < fastUntil ? FAST_BIND_RETRY_MS : CANCELLATION_CHECK_MS;
                    if (now < deadline) {
                        changes.await(Math.min(retryMs, deadline - now));
                    }
                }
            }
        } catch (IOException cannotOpenSocket) {
            return false;
        }
        return false;
    }

    private static int bindingErrno(IOException error) {
        // Network.bindSocket wraps a native ErrnoException in a SocketException.
        // Report only its numeric code. Some OEMs do not expose a nested cause.
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof ErrnoException nativeError) {
                return nativeError.errno;
            }
        }
        return -1;
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
                                     long deadline, long startedAt, BooleanSupplier active)
            throws IOException, InterruptedException {
        for (int attempt = 1; attempt <= MAX_EXIT_PROBE_ATTEMPTS && active.getAsBoolean(); attempt++) {
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

    private ExitEvidence verifyExits(TunnelProfile target, TunnelProfile.Candidate candidate, Network vpn,
                                     long probeDeadline, BooleanSupplier active) throws InterruptedException {
        boolean dualStack = !target.ipv6Exit.isEmpty();
        ExecutorService executor = Executors.newFixedThreadPool(dualStack ? 2 : 1);
        ExecutorCompletionService<FamilyProof> completed = new ExecutorCompletionService<>(executor);
        long startedAt = SystemClock.elapsedRealtime();
        Future<FamilyProof> v4 = completed.submit(
                () -> verifyFamily(vpn, candidate.exit, false, probeDeadline, startedAt, active));
        Future<FamilyProof> v6 = !dualStack ? null : completed.submit(
                () -> verifyFamily(vpn, target.ipv6Exit, true, probeDeadline, startedAt, active));
        try {
            FamilyProof ipv4 = null;
            FamilyProof ipv6 = null;
            while (active.getAsBoolean()) {
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
                if (active.getAsBoolean() && SystemClock.elapsedRealtime() < probeDeadline) {
                    return new ExitEvidence(vpn, ipv4, ipv6, probeDeadline);
                }
                break;
            }
            trace("exit proof deadline");
            return null;
        } catch (ExecutionException error) {
            Throwable cause = error.getCause();
            trace("exit probe error " + (cause == null ? "unknown" : cause.getClass().getSimpleName()));
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

    private VpnNetwork awaitNetwork(TunnelProfile target, long deadline, Set<Network> existing,
                                 BooleanSupplier active, CountDownLatch nativeReady,
                                 NetworkChanges changes) throws InterruptedException {
        // Starting discovery early must not spend a slow platform's entire post-UP
        // discovery budget while the native call is still running.
        long discoveryDeadline = deadline;
        boolean nativeDeadlineSet = false;
        CompletableFuture<VpnNetwork> readback = null;
        long nextReadback = !existing.isEmpty() && changes.isWatching()
                ? SystemClock.elapsedRealtime() + VPN_CALLBACK_GRACE_MS
                : 0;
        while (active.getAsBoolean()) {
            VpnNetwork ready = changes.matching(target, existing);
            if (ready != null) {
                trace("Android VPN discovered by callback");
                return ready;
            }
            long now = SystemClock.elapsedRealtime();
            if (!nativeDeadlineSet && (nativeReady == null || nativeReady.getCount() == 0)) {
                discoveryDeadline = Math.min(deadline, now + VPN_NETWORK_WAIT_MS);
                nativeDeadlineSet = true;
            }
            if (now >= discoveryDeadline) {
                break;
            }
            if (nativeReady != null && nativeReady.getCount() != 0) {
                // Native startup is creating this network in ConnectivityService.
                // Use callbacks here; leave Binder readbacks for the post-UP fallback.
                changes.await(Math.min(CANCELLATION_CHECK_MS, discoveryDeadline - now));
                continue;
            }
            if (readback != null && readback.isDone()) {
                ready = readback.getNow(null);
                if (ready != null) {
                    trace("Android VPN discovered by readback");
                    return ready;
                }
                readback = null;
                nextReadback = now + CANCELLATION_CHECK_MS;
            }
            if (readback == null && now >= nextReadback) {
                // A synchronous Binder call can outlast the matching callback.
                // Only one bounded readback runs at a time for this attempt.
                readback = CompletableFuture.supplyAsync(() -> findNetwork(target, existing))
                        .exceptionally(error -> null);
                readback.whenComplete((ignored, error) -> changes.signal());
            }
            long wakeAt = readback == null ? nextReadback : now + CANCELLATION_CHECK_MS;
            changes.await(Math.min(discoveryDeadline, wakeAt) - now);
        }
        return null;
    }

    private record VpnNetwork(Network network, boolean ownedByApp) {
        static VpnNetwork match(Network network, NetworkCapabilities caps, LinkProperties links,
                                TunnelProfile target) {
            if (!isCandidateVpn(caps) || !matchesRoutesAndAddresses(links, target)) {
                return null;
            }
            // The owner belongs to the network identity delivered by Android.
            boolean owned = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && caps.getOwnerUid() == Process.myUid();
            return new VpnNetwork(network, owned);
        }
    }

    private static final class NetworkMetadata {
        NetworkCapabilities capabilities;
        LinkProperties links;
        int blocked = -1;
    }

    private final class NetworkChanges extends ConnectivityManager.NetworkCallback implements AutoCloseable {
        private final Semaphore changes = new Semaphore(0);
        private final Map<Network, NetworkMetadata> available = new HashMap<>();
        private volatile boolean watching;

        boolean isWatching() {
            return watching;
        }

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

        @Override public synchronized void onAvailable(Network network) {
            available.put(network, new NetworkMetadata());
            signal();
        }

        @Override public synchronized void onLinkPropertiesChanged(Network network, LinkProperties links) {
            NetworkMetadata metadata = available.get(network);
            if (metadata != null) {
                metadata.links = links;
                signal();
            }
        }

        @Override public synchronized void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
            NetworkMetadata metadata = available.get(network);
            if (metadata != null) {
                metadata.capabilities = capabilities;
                signal();
            }
        }

        @Override public synchronized void onBlockedStatusChanged(Network network, boolean blocked) {
            NetworkMetadata metadata = available.get(network);
            if (metadata != null) {
                metadata.blocked = blocked ? 1 : 0;
                signal();
            }
        }

        synchronized int blockedStatus(Network network) {
            NetworkMetadata metadata = available.get(network);
            return metadata == null ? -1 : metadata.blocked;
        }

        @Override public synchronized void onLost(Network network) {
            available.remove(network);
            signal();
        }

        synchronized VpnNetwork matching(TunnelProfile target, Set<Network> excluded) {
            for (Map.Entry<Network, NetworkMetadata> entry : available.entrySet()) {
                NetworkMetadata metadata = entry.getValue();
                if (!excluded.contains(entry.getKey())) {
                    VpnNetwork vpn = VpnNetwork.match(entry.getKey(), metadata.capabilities, metadata.links, target);
                    if (vpn != null) {
                        return vpn;
                    }
                }
            }
            return null;
        }

        void await(long timeoutMs) throws InterruptedException {
            changes.tryAcquire(timeoutMs, TimeUnit.MILLISECONDS);
        }

        @Override public void close() {
            if (watching) {
                watching = false;
                connectivity.unregisterNetworkCallback(this);
            }
        }
    }

    private VpnNetwork findNetwork(TunnelProfile target, Set<Network> excluded) {
        // Startup has a pre-activation snapshot. Only inspect new network IDs.
        for (Network candidate : connectivity.getAllNetworks()) {
            if (!excluded.contains(candidate)) {
                VpnNetwork selected = readNetwork(candidate, target);
                if (selected != null) {
                    return selected;
                }
            }
        }
        return null;
    }

    private boolean matches(Network network, TunnelProfile target) {
        return readNetwork(network, target) != null;
    }

    private VpnNetwork readNetwork(Network network, TunnelProfile target) {
        NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
        if (!isCandidateVpn(caps)) {
            return null;
        }
        return VpnNetwork.match(network, caps, connectivity.getLinkProperties(network), target);
    }

    private static boolean isCandidateVpn(NetworkCapabilities capabilities) {
        if (capabilities == null || !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return false;
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return true;
        }
        int owner = capabilities.getOwnerUid();
        return owner < 0 || owner == Process.myUid();
    }

    private static boolean matchesRoutesAndAddresses(LinkProperties links, TunnelProfile target) {
        if (links == null) {
            return false;
        }
        List<LinkAddress> actual = links.getLinkAddresses();
        for (InetAddress expected : target.interfaceAddresses) {
            int prefix = expected instanceof Inet4Address ? 32 : 128;
            if (actual.stream().noneMatch(address -> expected.equals(address.getAddress())
                    && address.getPrefixLength() == prefix)) {
                return false;
            }
        }
        boolean ipv4Default = false;
        boolean ipv6Default = false;
        for (RouteInfo route : links.getRoutes()) {
            if (route.isDefaultRoute()) {
                if (route.getDestination().getAddress() instanceof Inet4Address) {
                    ipv4Default = true;
                } else {
                    ipv6Default = true;
                }
            }
        }
        return ipv4Default && ipv6Default == !target.ipv6Exit.isEmpty();
    }

    private static boolean cancelled(Callback callback) {
        return callback != null && callback.cancelled();
    }
}
