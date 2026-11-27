package org.morandi.proxy;

import android.content.Context;
import android.net.Network;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import org.json.JSONArray;
import org.json.JSONObject;

import com.wireguard.crypto.KeyPair;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public final class AppController {
    private static final String SESSION = "remembered_session";
    private static final String VERSION = BuildConfig.VERSION_NAME + "-android";
    private static final long STATE_INTERVAL = 30_000;
    private static final long RESTORE_INTERVAL = 5_000;
    private static final long EXIT_CHECK_INTERVAL = 45_000;
    private static final long POLICY_TIMEOUT = 90_000;
    private static final long CONSENT_POLICY_MAX_AGE_MS = 5_000;
    private static final long SESSION_EXTENSION = TimeUnit.DAYS.toSeconds(30);
    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.ROOT);
    private static AppController instance;

    private final ClientApi api;
    private final PrivateStore vault;
    private final TunnelEngine engine;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ScheduledThreadPoolExecutor worker = new ScheduledThreadPoolExecutor(1);
    private final ExecutorService presenceWorker = Executors.newSingleThreadExecutor();
    private final ExecutorService connectionPolicyWorker = Executors.newSingleThreadExecutor();
    private final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();
    private final AtomicLong intent = new AtomicLong();
    private final AtomicBoolean notificationPending = new AtomicBoolean();
    private final AtomicReference<FutureTask<KeyPair>> nextSignInIdentity = new AtomicReference<>();
    private final String defaultDeviceName;

    // All mutable session and VPN state is owned by the single worker.
    private JSONObject accountState;
    private AccountDetails accountDetails = AccountDetails.EMPTY;
    private String token = "";
    private String privateKey = "";
    private String accountSlot = "";
    private String mode = "disconnected";
    private String message = "";
    private String endpoint = "";
    private String ipv4 = "";
    private String ipv6 = "";
    private String activeProfile = "";
    private int preferredPort;
    private boolean busy;
    private boolean remember;
    private boolean localPreparationScheduled;
    private long tokenExpiresAt;
    private long policyAt;
    private long refreshAfter;
    private long verifyAfter;

    private volatile State visible;
    private volatile LoginTiming lastLoginTiming;
    private ConsentPolicy consentPolicy;

    enum IdentitySource { STORED, NEW_ON_DEMAND, NEW_FOREGROUND }

    record LoginTiming(long queueMs, long identityMs, long authenticateMs, long sessionMs,
                       IdentitySource identitySource) {}

    private record ConnectionPolicy(JSONObject state, long startedAt, long requestMs) {
        boolean freshForConsent() {
            return SystemClock.elapsedRealtime() - startedAt <= CONSENT_POLICY_MAX_AGE_MS;
        }
    }

    private record ConsentPolicy(long requested, String session, JSONObject previousState,
                                 Future<ConnectionPolicy> read) {}

    LoginTiming lastLoginTiming() {
        return lastLoginTiming;
    }

    public interface Listener {
        void onState(State state);
    }

    public static synchronized AppController get(Context context) {
        if (instance == null) {
            Context app = context.getApplicationContext();
            instance = new AppController(app, new ClientApi(app), new TunnelEngine(app));
        }
        return instance;
    }

    // Same-package instrumentation may install a fixture before launching the activity.
    static synchronized void installForTest(AppController controller) {
        if (instance != null && instance != controller) {
            instance.discardSignInPreparation();
            instance.presenceWorker.shutdownNow();
            instance.connectionPolicyWorker.shutdownNow();
            instance.worker.shutdownNow();
        }
        instance = controller;
    }

    AppController(Context context, ClientApi api, TunnelEngine engine) {
        this.api = api;
        this.engine = engine;
        vault = new PrivateStore(context);
        defaultDeviceName = deviceName(Build.MODEL);
        visible = new State(accountDetails, defaultDeviceName, "disconnected", "", "", "", "", 0, false, false);
        engine.setRevocationListener(() -> worker.execute(() -> {
            if ("connected".equals(mode) && !engine.isUp()) {
                loseConnection("VPN 已由系统断开。需要时可重新连接。", true);
                publish();
            }
        }));
        worker.execute(this::restore);
        worker.scheduleWithFixedDelay(this::tickSafely, RESTORE_INTERVAL, RESTORE_INTERVAL, TimeUnit.MILLISECONDS);
    }

    public State snapshot() {
        return visible;
    }

    public void observe(Listener listener) {
        if (listeners.addIfAbsent(listener)) {
            main.post(() -> {
                if (listeners.contains(listener)) {
                    listener.onState(visible);
                }
            });
        }
    }

    public void removeObserver(Listener listener) {
        listeners.remove(listener);
    }

    synchronized void prepareSignIn() {
        FutureTask<KeyPair> candidate = new FutureTask<>(KeyPair::new);
        if (!nextSignInIdentity.compareAndSet(null, candidate)) return;
        ClientApi.LoginWarmup warmup = api.offerLoginWarmup();
        // Restore runs first on the controller worker. A saved session does not
        // need a new device identity even if the login view was briefly shown.
        worker.execute(() -> {
            if (nextSignInIdentity.get() != candidate) return;
            if (!token.isEmpty()) {
                warmup.cancelPending();
                if (nextSignInIdentity.compareAndSet(candidate, null)) candidate.cancel(false);
            } else {
                // This executor is idle at sign-in. Actual login can claim the
                // task inline if it is still queued when a new slot is found.
                connectionPolicyWorker.execute(candidate);
                presenceWorker.execute(() -> api.warmLoginConnection(warmup));
            }
        });
    }

    synchronized void discardSignInPreparation() {
        api.cancelPendingLoginWarmup();
        FutureTask<KeyPair> candidate = nextSignInIdentity.getAndSet(null);
        if (candidate != null) candidate.cancel(false);
    }

    public void login(String username, String password, boolean rememberLogin) {
        long requestedAt = SystemClock.elapsedRealtime();
        api.cancelPendingLoginWarmup();
        worker.execute(() -> {
            if (!token.isEmpty()) {
                return;
            }
            long startedAt = SystemClock.elapsedRealtime();
            lastLoginTiming = null;
            String normalized = username.trim().toLowerCase(Locale.ROOT);
            if (normalized.isEmpty() || password.isEmpty()) {
                message = "请输入账号和密码。";
                publish();
                return;
            }
            busy = true;
            message = "";
            publish();
            FutureTask<KeyPair> candidate = nextSignInIdentity.getAndSet(null);
            String slot = "";
            try {
                slot = PrivateStore.accountSlot(normalized);
                String key = vault.read(slot);
                String publicKey;
                IdentitySource source = IdentitySource.STORED;
                if (key.isEmpty()) {
                    KeyPair identity;
                    if (candidate == null) {
                        source = IdentitySource.NEW_ON_DEMAND;
                        identity = new KeyPair();
                    } else {
                        // run() claims unfinished work if it has not started;
                        // get() joins the same calculation if it already has.
                        source = IdentitySource.NEW_FOREGROUND;
                        candidate.run();
                        identity = candidate.get();
                    }
                    key = identity.getPrivateKey().toBase64();
                    publicKey = identity.getPublicKey().toBase64();
                    vault.write(slot, key);
                } else {
                    publicKey = TunnelEngine.publicKey(key);
                }
                JSONObject request = new JSONObject()
                        .put("username", normalized)
                        .put("password", password)
                        .put("public_key", publicKey)
                        .put("device_name", defaultDeviceName)
                        .put("client_version", VERSION);
                long identityReadyAt = SystemClock.elapsedRealtime();
                JSONObject response;
                try {
                    response = api.call("authenticate", "", request);
                } finally {
                    request.remove("password");
                }
                long authenticatedAt = SystemClock.elapsedRealtime();
                String issued = response.getString("token");
                long expiry = response.getLong("token_expires_at");
                if (!ClientApi.validToken(issued) || expiry <= epochSeconds()) {
                    throw new IOException("INVALID_SESSION");
                }
                acceptState(response);
                token = issued;
                tokenExpiresAt = expiry;
                accountSlot = slot;
                privateKey = key;
                remember = rememberLogin;
                rememberSession();
                lastLoginTiming = new LoginTiming(startedAt - requestedAt, identityReadyAt - startedAt,
                        authenticatedAt - identityReadyAt, SystemClock.elapsedRealtime() - authenticatedAt, source);
            } catch (Exception failure) {
                if (hasCode(failure, "DEVICE_REVOKED") && !slot.isEmpty()) {
                    erase(slot);
                }
                message = textFor(failure);
            } finally {
                if (candidate != null) candidate.cancel(false);
                busy = false;
                publish();
            }
        });
    }

    public void confirmDevice(String name) {
        work(() -> {
            if (token.isEmpty() || registered()) {
                return;
            }
            String trimmed = name.trim();
            if (trimmed.isEmpty() || trimmed.length() > 64
                    || trimmed.codePoints().anyMatch(Character::isISOControl)) {
                throw new ClientApi.ApiError("INVALID_DEVICE_NAME");
            }
            JSONObject response = api.call("enroll", token,
                    new JSONObject().put("device_name", trimmed).put("confirm", true));
            acceptState(response);
            if (!registered()) {
                throw new ClientApi.ApiError("DEVICE_CONFIRMATION_REQUIRED");
            }
            tokenExpiresAt = epochSeconds() + SESSION_EXTENSION;
            rememberSession();
        });
    }

    public void refresh() {
        work(() -> {
            if (!token.isEmpty()) {
                refreshPolicy();
            }
        });
    }

    long prepareVpnConsent() {
        long requested = intent.incrementAndGet();
        worker.execute(() -> {
            if (requested != intent.get()) {
                return;
            }
            discardConsentPolicy();
            if (registered() && !token.isEmpty() && tokenExpiresAt > epochSeconds()) {
                String session = token;
                // This same-click HTTPS read only prepares policy. Android consent
                // still gates service startup, routing and every exit probe.
                Future<ConnectionPolicy> read = presenceWorker.submit(() -> {
                    if (requested != intent.get()) {
                        throw new IOException("VPN_CONNECT_CANCELLED");
                    }
                    return requestConnectionPolicy(session);
                });
                consentPolicy = new ConsentPolicy(requested, session, accountState, read);
            }
            engine.prepareLocalComponents();
        });
        return requested;
    }

    void finishVpnConsent(long consentRequest, boolean granted) {
        long previous = intent.get();
        // Restoring an activity in a new process can return a valid system result
        // without any in-memory prefetch. The attempt uses a normal fresh read.
        if ((previous != 0 && consentRequest != 0 && previous != consentRequest)
                || !intent.compareAndSet(previous, previous + 1)) {
            return;
        }
        long requested = previous + 1;
        long requestedAt = SystemClock.elapsedRealtime();
        // A restored Activity result can start a fresh attempt. Only an
        // in-process result for the matching click can reuse its system consent.
        long matchingConsentRequest = consentRequest == previous ? consentRequest : 0;
        worker.execute(() -> {
            if (requested != intent.get()) {
                return;
            }
            if (granted && registered() && !token.isEmpty()) {
                connectInternal(requested, requestedAt, matchingConsentRequest, matchingConsentRequest != 0);
                return;
            }
            discardConsentPolicy();
            if (!granted && ("disconnected".equals(mode) || "protected".equals(mode))) {
                message = "系统未授权 VPN。需要连接时，请允许 Android 的 VPN 请求。";
                publish();
            }
        });
    }

    public void connect() {
        connect(false);
    }

    // The foreground activity can pass the result of VpnService.prepare from
    // this tap. Other callers use connect(), including after process restoration.
    void connect(boolean permissionCheckedForTap) {
        long requestedAt = SystemClock.elapsedRealtime();
        long requested = intent.incrementAndGet();
        worker.execute(() -> connectInternal(requested, requestedAt, 0, permissionCheckedForTap));
    }

    private volatile ConnectionTiming lastConnectTiming;

    static final class ConnectionTiming {
        final long totalMs;
        final long policyMs;
        final long queueMs;
        final long preparationMs;
        final long policyWaitMs;
        final long consentPolicyAgeMs;
        final long backendWaitMs;
        final long serviceWaitMs;
        final long serviceRequestMs, foregroundAckMs, baselineReadMs;
        final boolean retriedServiceStart;
        final long nativeStartMs;
        final long networkWaitMs;
        final long networkDiscoveryMs;
        final long networkBindingMs;
        final long ownerWaitMs;
        final int bindFailures;
        final int firstBindErrno;
        final int lastBindErrno;
        final int initiallyBlocked;
        final int blockedAtBind;
        final long exitProofMs;
        final long handshakeMs;
        final long ipv4ProofMs;
        final long ipv6ProofMs;
        final int ipv4ProofAttempts;
        final int ipv6ProofAttempts;
        final String ipv4ProofProtocol;
        final String ipv6ProofProtocol;
        final int attempts;
        final int firstAttemptedPort;
        final Network orderingUnderlay;
        final Network verifiedUnderlay;

        ConnectionTiming(long totalMs, long policyMs, long queueMs, long preparationMs,
                         long policyWaitMs, long consentPolicyAgeMs, TunnelEngine.AttemptTiming attempt) {
            this.totalMs = totalMs;
            this.policyMs = policyMs;
            this.queueMs = queueMs;
            this.preparationMs = preparationMs;
            this.policyWaitMs = policyWaitMs;
            this.consentPolicyAgeMs = consentPolicyAgeMs;
            this.backendWaitMs = attempt.backendWaitMs;
            this.serviceWaitMs = attempt.serviceWaitMs;
            this.serviceRequestMs = attempt.serviceRequestMs;
            this.foregroundAckMs = attempt.foregroundAckMs;
            this.baselineReadMs = attempt.baselineReadMs;
            this.retriedServiceStart = attempt.retriedServiceStart;
            this.nativeStartMs = attempt.nativeStartMs;
            this.networkWaitMs = attempt.networkWaitMs;
            this.networkDiscoveryMs = attempt.networkDiscoveryMs;
            this.networkBindingMs = attempt.networkBindingMs;
            this.ownerWaitMs = attempt.ownerWaitMs;
            this.bindFailures = attempt.bindFailures;
            this.firstBindErrno = attempt.firstBindErrno;
            this.lastBindErrno = attempt.lastBindErrno;
            this.initiallyBlocked = attempt.initiallyBlocked;
            this.blockedAtBind = attempt.blockedAtBind;
            this.exitProofMs = attempt.exitProofMs;
            this.handshakeMs = attempt.handshakeMs;
            this.ipv4ProofMs = attempt.ipv4ProofMs;
            this.ipv6ProofMs = attempt.ipv6ProofMs;
            this.ipv4ProofAttempts = attempt.ipv4ProofAttempts;
            this.ipv6ProofAttempts = attempt.ipv6ProofAttempts;
            this.ipv4ProofProtocol = attempt.ipv4ProofProtocol;
            this.ipv6ProofProtocol = attempt.ipv6ProofProtocol;
            this.attempts = attempt.attempts;
            this.firstAttemptedPort = attempt.firstAttemptedPort;
            this.orderingUnderlay = attempt.orderingUnderlay;
            this.verifiedUnderlay = attempt.verifiedUnderlay;
        }
    }

    ConnectionTiming lastConnectTiming() {
        return lastConnectTiming;
    }

    private void connectInternal(long requested, long requestedAt, long consentRequest,
                                 boolean permissionCheckedForTap) {
        if (requested != intent.get() || token.isEmpty() || "connected".equals(mode)) {
            return;
        }
        long startedAt = SystemClock.elapsedRealtime();
        lastConnectTiming = null;
        mode = "connecting";
        message = "";
        busy = true;
        publish();
        Future<ConnectionPolicy> policy = null;
        try {
            String session = requirePolicySession();
            ConnectionPolicy freshPolicy = consumeConsentPolicy(consentRequest, session);
            if (freshPolicy == null) {
                policy = connectionPolicyWorker.submit(() -> requestConnectionPolicy(session));
            }
            // Android service setup and the fresh HTTPS request can proceed concurrently.
            // The worker still applies the response before activating the TUN.
            long preparationStarted = SystemClock.elapsedRealtime();
            engine.prepareConnection(permissionCheckedForTap);
            long policyWaitStarted = SystemClock.elapsedRealtime();
            if (requested != intent.get()) {
                return;
            }
            if (freshPolicy != null && !freshPolicy.freshForConsent()) {
                freshPolicy = null;
                policy = connectionPolicyWorker.submit(() -> requestConnectionPolicy(session));
            }
            if (freshPolicy == null) {
                freshPolicy = awaitConnectionPolicy(policy);
            }
            long policyWaitMs = SystemClock.elapsedRealtime() - policyWaitStarted;
            if (requested != intent.get()) {
                return;
            }
            long consentPolicyAgeMs = policy == null
                    ? SystemClock.elapsedRealtime() - freshPolicy.startedAt() : -1;
            applyPolicy(freshPolicy.state());
            if (!registered() || tunnel() == null) {
                throw new ClientApi.ApiError("DEVICE_CONFIRMATION_REQUIRED");
            }
            demandActiveAccount();
            if (preferredPort != 0 && !ports().contains(preferredPort)) {
                preferredPort = 0;
            }
            TunnelEngine.Result result = engine.connect(accountState, privateKey, preferredPort,
                    new TunnelEngine.Callback() {
                        @Override
                        public void trying(String candidate) {
                            endpoint = candidate;
                            publish();
                        }
                        @Override
                        public boolean cancelled() {
                            return requested != intent.get();
                        }
                    });
            if (requested != intent.get()) {
                return;
            }
            if (!engine.isUp()) {
                throw new IOException("TUNNEL_NOT_RUNNING");
            }
            activeProfile = tunnel().toString();
            endpoint = result.endpoint;
            ipv4 = result.ipv4;
            ipv6 = result.ipv6 == null ? "" : result.ipv6;
            lastConnectTiming = new ConnectionTiming(
                    SystemClock.elapsedRealtime() - requestedAt, freshPolicy.requestMs(),
                    startedAt - requestedAt, policyWaitStarted - preparationStarted,
                    policyWaitMs, consentPolicyAgeMs, result.timing);
            mode = "connected";
            verifyAfter = SystemClock.elapsedRealtime() + EXIT_CHECK_INTERVAL;
            reportPresence("connected");
        } catch (Exception failure) {
            if (!handleSessionFailure(failure)) {
                loseConnection(textFor(failure), false);
            }
        } finally {
            if (policy != null) {
                policy.cancel(true);
            }
            if (requested != intent.get()) {
                loseConnection("", false);
            }
            busy = false;
            publish();
        }
    }

    private ConnectionPolicy requestConnectionPolicy(String session) throws Exception {
        long startedAt = SystemClock.elapsedRealtime();
        JSONObject update = api.call("state", session, null);
        return new ConnectionPolicy(update, startedAt, SystemClock.elapsedRealtime() - startedAt);
    }

    private ConnectionPolicy consumeConsentPolicy(long requested, String session) throws InterruptedException {
        ConsentPolicy prepared = consentPolicy;
        if (prepared == null) {
            return null;
        }
        try {
            // A pending or expired speculative request must never delay the regular
            // post-consent read. Reuse only a response started within five seconds,
            // for this exact click/session with no intervening account update.
            if (prepared.requested() == requested && prepared.session().equals(session)
                    && prepared.previousState() == accountState && prepared.read().isDone()) {
                ConnectionPolicy policy = awaitConnectionPolicy(prepared.read());
                return policy.freshForConsent() ? policy : null;
            }
        } catch (InterruptedException interrupted) {
            throw interrupted;
        } catch (Exception ignored) {
            // A prefetch failure is handled by the ordinary authorized read.
        } finally {
            discardConsentPolicy();
        }
        return null;
    }

    private void discardConsentPolicy() {
        if (consentPolicy != null) {
            consentPolicy.read().cancel(true);
            consentPolicy = null;
        }
    }

    private static ConnectionPolicy awaitConnectionPolicy(Future<ConnectionPolicy> policy) throws Exception {
        try {
            return policy.get();
        } catch (ExecutionException failed) {
            if (failed.getCause() instanceof Exception cause) {
                throw cause;
            }
            throw failed;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw interrupted;
        }
    }

    public void disconnect() {
        intent.incrementAndGet();
        worker.execute(() -> {
            mode = "disconnecting";
            message = "";
            publish();
            boolean stopped = stopEngine();
            mode = stopped ? "disconnected" : "protected";
            if (stopped) {
                reportPresence("disconnected");
            }
            publish();
        });
    }

    public void logout() {
        intent.incrementAndGet();
        worker.execute(() -> {
            busy = true;
            boolean stopped = stopEngine();
            String previous = token;
            clearSession(false);
            if (!previous.isEmpty()) {
                try {
                    api.call("logout", previous, new JSONObject());
                } catch (Exception failure) {
                    if (stopped) {
                        message = "本机已退出。服务器暂未确认注销。";
                    }
                }
            }
            mode = stopped ? "disconnected" : "protected";
            busy = false;
            publish();
        });
    }

    public void removeDevice(String id) {
        if (!id.matches("[a-f0-9]{12}")) {
            return;
        }
        work(() -> {
            if (token.isEmpty()) {
                return;
            }
            if (id.equals(registration().optString("device_id"))) {
                if (!stopEngine()) {
                    mode = "protected";
                    throw new IOException("TUNNEL_STOP_FAILED");
                }
                mode = "disconnected";
                publish();
            }
            JSONObject response = api.call("device-delete", token, new JSONObject().put("device_id", id));
            if (response.optBoolean("current")) {
                intent.incrementAndGet();
                clearSession(true);
                mode = "disconnected";
                message = "已移除此设备。";
            } else {
                refreshPolicy();
            }
        });
    }

    public void setPreferredPort(int port) {
        worker.execute(() -> {
            if (!engine.isUp() && !"connecting".equals(mode) && (port == 0 || ports().contains(port))) {
                preferredPort = port;
                publish();
            }
        });
    }

    private void restore() {
        try {
            String record = vault.read(SESSION);
            if (record.isEmpty()) {
                return;
            }
            JSONObject saved = new JSONObject(record);
            long expiry = saved.getLong("expires");
            if (expiry <= epochSeconds() || !ClientApi.validToken(saved.getString("token"))) {
                erase(SESSION);
                return;
            }
            String slot = saved.getString("slot");
            if (!slot.matches("device\\.[A-Za-z0-9_=-]{40,60}")) {
                throw new IOException("PRIVATE_STORE_INVALID");
            }
            String key = vault.read(slot);
            if (key.isEmpty()) {
                erase(SESSION);
                return;
            }
            token = saved.getString("token");
            accountSlot = slot;
            privateKey = key;
            tokenExpiresAt = expiry;
            remember = true;
            message = "正在恢复已保存的登录…";
            publish();
            refreshPolicy();
        } catch (Exception failure) {
            if (!handleSessionFailure(failure)) {
                // Keep the saved session and retry promptly against the account origin.
                message = token.isEmpty() ? textFor(failure) : restoreFailureText(failure);
            }
        } finally {
            publish();
            if (token.isEmpty()) {
                CompletableFuture.runAsync(vault::warmKey);
            }
        }
    }

    private void rememberSession() {
        try {
            if (remember) {
                vault.write(SESSION, new JSONObject().put("token", token)
                        .put("slot", accountSlot).put("expires", tokenExpiresAt).toString());
            } else {
                vault.remove(SESSION);
            }
        } catch (Exception failure) {
            erase(SESSION);
            message = "本次可以使用，系统暂时无法记住登录。";
        }
    }

    private void refreshPolicy() throws Exception {
        applyPolicy(api.call("state", requirePolicySession(), null));
    }

    private String requirePolicySession() throws ClientApi.ApiError {
        if (token.isEmpty() || tokenExpiresAt <= epochSeconds()) {
            throw new ClientApi.ApiError("LOGIN_REQUIRED");
        }
        return token;
    }

    private void applyPolicy(JSONObject update) throws Exception {
        boolean restoring = accountState == null;
        acceptState(update);
        if (restoring) {
            message = "";
        }
        enforceActiveProfile();
    }

    private void acceptState(JSONObject update) throws Exception {
        if (update.optInt("schema", 0) != 1
                || update.optJSONObject("account") == null || update.optJSONObject("registration") == null) {
            throw new IOException("INVALID_API_RESPONSE");
        }
        update.remove("token");
        update.remove("token_expires_at");
        accountState = update;
        accountDetails = new AccountDetails(update);
        policyAt = SystemClock.elapsedRealtime();
        refreshAfter = policyAt + STATE_INTERVAL;
        if (!localPreparationScheduled && registered() && "active".equals(account().optString("status"))) {
            // A restored, already-authorized device has no consent dialog in
            // which to load these components. Run the local work after this
            // account operation publishes, before the next connection tap.
            localPreparationScheduled = true;
            worker.execute(engine::prepareLocalComponents);
        }
        if (preferredPort != 0 && !ports().contains(preferredPort)) {
            preferredPort = 0;
        }
    }

    private void enforceActiveProfile() {
        if (!"connected".equals(mode)) {
            return;
        }
        JSONObject profile = tunnel();
        if (!registered() || !"active".equals(account().optString("status"))
                || profile == null || !profile.toString().equals(activeProfile)) {
            loseConnection("账号状态或入口配置已更新，请按当前权限重新连接。", true);
        }
    }

    private void reportPresence(String status) {
        if (token.isEmpty() || !registered()) {
            return;
        }
        String session = token;
        long requested = intent.get();
        presenceWorker.execute(() -> {
            if (requested != intent.get()) {
                return;
            }
            try {
                api.call("presence", session, new JSONObject().put("mode", status)
                        .put("transport", status.equals("connected") ? "wireguard-udp" : JSONObject.NULL));
            } catch (ClientApi.ApiError error) {
                worker.execute(() -> {
                    if (session.equals(token) && requested == intent.get() && handleSessionFailure(error)) {
                        publish();
                    }
                });
            } catch (Exception ignored) {
                // Presence reports are advisory, independent of verified connection state.
            }
        });
    }

    private void tickSafely() {
        if ("connected".equals(mode)) {
            if (!engine.isUp()) {
                loseConnection("VPN 已由系统断开。需要时可重新连接。", true);
                publish();
            } else if (SystemClock.elapsedRealtime() >= verifyAfter) {
                verifyAfter = SystemClock.elapsedRealtime() + EXIT_CHECK_INTERVAL;
                if (!engine.verifyConnected()) {
                    loseConnection("网络变化后未能验证出口，VPN 已断开。可以重新连接。", true);
                    publish();
                }
            }
        }
        if (token.isEmpty() || SystemClock.elapsedRealtime() < refreshAfter) {
            return;
        }
        refreshAfter = SystemClock.elapsedRealtime() + (accountState == null ? RESTORE_INTERVAL : STATE_INTERVAL);
        try {
            refreshPolicy();
        } catch (Exception failure) {
            if (!handleSessionFailure(failure)) {
                if ("connected".equals(mode) && SystemClock.elapsedRealtime() - policyAt >= POLICY_TIMEOUT) {
                    loseConnection("暂时无法核验账号状态，VPN 已断开。", false);
                } else if (accountState == null) {
                    message = restoreFailureText(failure);
                }
            }
        }
        publish();
    }

    private boolean stopEngine() {
        discardConsentPolicy();
        try {
            engine.disconnect();
            if (engine.isUp()) {
                throw new IOException("TUNNEL_STOP_FAILED");
            }
        } catch (Exception failure) {
            message = "系统仍在关闭 VPN。请在 Android 的 VPN 设置中检查连接。";
            return false;
        }
        activeProfile = "";
        endpoint = "";
        ipv4 = "";
        ipv6 = "";
        verifyAfter = 0;
        return true;
    }

    private void loseConnection(String reason, boolean report) {
        if (stopEngine()) {
            mode = "disconnected";
            message = reason;
            if (report) {
                reportPresence("disconnected");
            }
        } else {
            mode = "protected";
        }
    }

    private boolean handleSessionFailure(Exception failure) {
        boolean revoked = hasCode(failure, "DEVICE_REVOKED");
        if (!revoked && !hasCode(failure, "LOGIN_REQUIRED")) {
            return false;
        }
        boolean stopped = stopEngine();
        clearSession(revoked);
        mode = stopped ? "disconnected" : "protected";
        if (stopped) {
            message = textFor(failure);
        }
        return true;
    }

    private void clearSession(boolean removeKey) {
        discardSignInPreparation();
        if (removeKey && !accountSlot.isEmpty()) {
            erase(SESSION, accountSlot);
        } else {
            erase(SESSION);
        }
        token = "";
        tokenExpiresAt = 0;
        accountState = null;
        accountDetails = AccountDetails.EMPTY;
        accountSlot = "";
        privateKey = "";
        remember = false;
        preferredPort = 0;
        refreshAfter = 0;
        policyAt = 0;
    }

    private void erase(String... slots) {
        try {
            vault.remove(slots);
        } catch (IOException ignored) {
            // An explicit logout also revokes the remote session in the normal path.
        }
    }

    private void demandActiveAccount() throws Exception {
        String status = account().optString("status");
        if (!"active".equals(status)) {
            throw new ClientApi.ApiError("ACCOUNT_" + status.toUpperCase(Locale.ROOT));
        }
    }

    private JSONObject account() {
        return object(accountState, "account");
    }

    private JSONObject registration() {
        return object(accountState, "registration");
    }

    private JSONObject tunnel() {
        return accountState == null ? null : accountState.optJSONObject("tunnel");
    }

    private boolean registered() {
        return "registered".equals(registration().optString("status"));
    }

    private List<Integer> ports() {
        return advertisedPorts(tunnel());
    }

    private static List<Integer> advertisedPorts(JSONObject profile) {
        ArrayList<Integer> result = new ArrayList<>();
        JSONArray values = profile == null ? null : profile.optJSONArray("native_udp_ports");
        if (values != null) {
            for (int i = 0; i < Math.min(16, values.length()); i++) {
                int port = values.optInt(i);
                if (port > 0 && port <= 65535 && !result.contains(port)) {
                    result.add(port);
                }
            }
        }
        return Collections.unmodifiableList(result);
    }

    private void work(Work operation) {
        worker.execute(() -> {
            busy = true;
            message = "";
            publish();
            try {
                operation.run();
            } catch (Exception failure) {
                if (!handleSessionFailure(failure)) {
                    message = textFor(failure);
                }
            } finally {
                busy = false;
                publish();
            }
        });
    }

    private void publish() {
        visible = new State(accountDetails, defaultDeviceName, mode, message, endpoint, ipv4, ipv6,
                preferredPort, !token.isEmpty(), busy);
        if (!notificationPending.compareAndSet(false, true)) return;
        main.post(() -> {
            notificationPending.set(false);
            State state = visible;
            for (Listener listener : listeners) {
                listener.onState(state);
            }
        });
    }

    private static String deviceName(String model) {
        String value = model == null ? "" : model.replaceAll("[\\p{Cc}\\p{Cf}]", "").trim();
        if (value.length() > 40) {
            value = value.substring(0, 40);
        }
        return value.isEmpty() ? "Android 设备" : value;
    }

    private static boolean hasCode(Exception failure, String code) {
        return failure instanceof ClientApi.ApiError remote && code.equals(remote.code);
    }

    private static String accountTransportText(Exception failure) {
        if (!(failure instanceof ClientApi.ApiError error)) {
            return "";
        }
        return switch (error.code) {
            case "ACCOUNT_API_UNREACHABLE" -> "无法连接账号服务。请检查网络后重试。（ACCOUNT_API_UNREACHABLE）";
            case "ACCOUNT_API_TLS_FAILED" -> "无法验证账号服务的安全连接。请检查系统日期和时间后重试。（ACCOUNT_API_TLS_FAILED）";
            case "API_UNAVAILABLE" -> "账号服务暂时没有返回可用响应。请稍后重试。（API_UNAVAILABLE）";
            default -> "";
        };
    }

    private static String restoreFailureText(Exception failure) {
        String transport = accountTransportText(failure);
        return (transport.isEmpty() ? "暂时无法核验账号。" : transport) + "正在重试已保存的登录。";
    }

    private static String textFor(Exception failure) {
        String transport = accountTransportText(failure);
        if (!transport.isEmpty()) {
            return transport;
        }
        String error = failure instanceof ClientApi.ApiError apiError ? apiError.code : failure.getMessage();
        if (error == null) {
            return "操作未完成，请稍后重试。";
        }
        return switch (error) {
            case "INVALID_CREDENTIALS" -> "账号或密码有误。";
            case "LOGIN_REQUIRED" -> "登录已过期，请重新登录。";
            case "DEVICE_REVOKED" -> "此设备的登记已撤销，请重新登录并登记。";
            case "DEVICE_LIMIT", "DEVICE_LIMIT_REACHED", "DEVICE_CAP_REACHED" -> "设备名额已用完。可在账号页移除不再使用的设备。";
            case "INVALID_NAME", "INVALID_DEVICE_NAME" -> "请输入 1 到 64 个字符的设备名称。";
            case "DEVICE_CONFIRMATION_REQUIRED" -> "请先确认登记此设备。";
            case "RATE_LIMITED", "LOGIN_RATE_LIMITED", "TOO_MANY_ATTEMPTS" -> "登录尝试过多，请稍后再试。";
            case "ACCOUNT_EXPIRED" -> "账号已到期。";
            case "ACCOUNT_DISABLED" -> "账号当前不可用。";
            case "ACCOUNT_QUOTA", "ACCOUNT_QUOTA_EXCEEDED" -> "本周期用量已达到限额。";
            case "ACCOUNT_SERVER_BUDGET" -> "服务端出站保护已启用。";
            case "ACCOUNT_UNAVAILABLE", "CONTROL_SERVICE_UNAVAILABLE" -> "暂时无法核验账号，请稍后重试。";
            case "PRIVATE_STORE_INVALID", "PRIVATE_STORE_UNAVAILABLE" -> "系统暂时无法读取本机设备身份，请解锁设备后重试。";
            case "VPN_PERMISSION_REQUIRED", "VPN_CONSENT_REQUIRED" -> "请先允许 Android 的 VPN 请求。";
            case "TUNNEL_NOT_RUNNING", "VPN_EXIT_NOT_VERIFIED" -> "未能验证出口。可稍后重试或选择其他可用 UDP 端口。";
            case "TUNNEL_STOP_FAILED", "VPN_STOP_FAILED" -> "系统仍在关闭 VPN，请稍后重试。";
            case "VPN_SERVICE_START_FAILED" -> "Android 未能启动 VPN 服务，请返回应用后重试。";
            default -> failure instanceof IOException
                    ? "连接未完成，请检查网络后重试。" : "操作未完成，请稍后重试。";
        };
    }

    private static JSONObject object(JSONObject value, String key) {
        JSONObject child = value == null ? null : value.optJSONObject(key);
        return child == null ? new JSONObject() : child;
    }

    private static long epochSeconds() {
        return Instant.now().getEpochSecond();
    }

    @FunctionalInterface
    private interface Work {
        void run() throws Exception;
    }

    public static final class Device {
        public final String id;
        public final String name;
        public final boolean current;

        private Device(String id, String name, boolean current) {
            this.id = id;
            this.name = name;
            this.current = current;
        }
    }

    public static final class State {
        public final String username, mode, message, endpoint, verifiedIpv4, verifiedIpv6;
        public final String deviceId, periodLabel, expiresLabel, defaultDeviceName;
        public final String accountStatus;
        public final int preferredPort;
        public final boolean signedIn, registered, busy;
        public final long usedBytes, quotaBytes;
        public final List<Device> devices;
        public final List<Integer> ports;

        private State(AccountDetails account, String deviceName, String mode, String message, String endpoint,
                      String ipv4, String ipv6, int port, boolean signedIn, boolean busy) {
            username = account.username;
            accountStatus = account.accountStatus;
            deviceId = account.deviceId;
            registered = account.registered;
            periodLabel = account.periodLabel;
            expiresLabel = account.expiresLabel;
            usedBytes = account.usedBytes;
            quotaBytes = account.quotaBytes;
            devices = account.devices;
            ports = account.ports;
            this.mode = mode;
            this.message = message;
            this.endpoint = endpoint;
            this.verifiedIpv4 = ipv4;
            this.verifiedIpv6 = ipv6;
            this.defaultDeviceName = deviceName;
            this.signedIn = signedIn;
            this.busy = busy;
            this.preferredPort = port;
        }
    }

    // Connection progress changes independently of the latest account response.
    private static final class AccountDetails {
        private static final Pattern DEVICE_ID = Pattern.compile("[a-f0-9]{12}");
        static final AccountDetails EMPTY = new AccountDetails(null);
        final String username, accountStatus, deviceId, periodLabel, expiresLabel;
        final boolean registered;
        final long usedBytes, quotaBytes;
        final List<Device> devices;
        final List<Integer> ports;

        AccountDetails(JSONObject data) {
            JSONObject account = object(data, "account");
            JSONObject registration = object(data, "registration");
            JSONObject cycle = object(account, "cycle");
            username = account.optString("username");
            accountStatus = account.optString("status");
            deviceId = registration.optString("device_id");
            registered = "registered".equals(registration.optString("status"));
            usedBytes = Math.max(0, account.optLong("used_bytes", 0));
            quotaBytes = account.optLong("limit_bytes", -1);
            this.ports = advertisedPorts(data == null ? null : data.optJSONObject("tunnel"));
            String begin = date(cycle.opt("start_at"));
            String end = date(cycle.opt("end_at"));
            this.periodLabel = begin.isEmpty() || end.isEmpty() ? "" : begin + " 至 " + end;
            this.expiresLabel = date(account.opt("expires_at"));

            ArrayList<Device> active = new ArrayList<>();
            JSONArray values = data == null ? null : data.optJSONArray("devices");
            if (values != null) {
                for (int i = 0; i < values.length(); i++) {
                    JSONObject item = values.optJSONObject(i);
                    if (item == null || item.optBoolean("revoked")) {
                        continue;
                    }
                    String id = item.optString("id");
                    if (DEVICE_ID.matcher(id).matches()) {
                        active.add(new Device(id, item.optString("name", "未命名设备"), item.optBoolean("current")));
                    }
                }
            }
            this.devices = Collections.unmodifiableList(active);
        }

        private static String date(Object value) {
            try {
                if (value instanceof Number number && number.longValue() > 0) {
                    return DATE.format(Instant.ofEpochSecond(number.longValue()).atZone(ZoneId.systemDefault()));
                }
                if (value instanceof String text && !text.isEmpty()) {
                    return DATE.format(Instant.parse(text).atZone(ZoneId.systemDefault()));
                }
            } catch (RuntimeException ignored) {
                return "";
            }
            return "";
        }
    }
}
