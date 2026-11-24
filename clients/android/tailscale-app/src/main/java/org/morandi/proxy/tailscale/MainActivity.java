package org.morandi.proxy.tailscale;

import android.app.Activity;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONObject;

public final class MainActivity extends Activity {
    private static final int VPN_PERMISSION = 1;
    private static final String SESSION = "client-session";
    private static final String ACCOUNT = "client-account";
    private static final String DIRECT = "已断开 · 当前直连";
    private final AtomicInteger generation = new AtomicInteger();
    private final AccountClient accounts = new AccountClient();
    private TextView status;
    private EditText username;
    private EditText password;
    private Button login;
    private Button connect;
    private Button disconnect;
    private String token;
    private volatile LocalControl control;
    private volatile Network verifiedNetwork;
    private Network stoppingNetwork;
    private ConnectivityManager networks;
    private final ConnectivityManager.NetworkCallback networkChanges = new ConnectivityManager.NetworkCallback() {
        @Override public void onLost(Network network) {
            if (network.equals(verifiedNetwork)) runOnUiThread(() -> recover(network));
        }
    };

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        var layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(36, 44, 36, 24);
        var name = new TextView(this);
        name.setText("Proxy");
        name.setTextSize(32);
        layout.addView(name);
        status = new TextView(this);
        status.setId(R.id.status);
        status.setText("请登录");
        status.setTextSize(18);
        layout.addView(status);
        username = new EditText(this);
        username.setId(R.id.username);
        username.setHint("账号");
        username.setSingleLine();
        layout.addView(username);
        password = new EditText(this);
        password.setId(R.id.password);
        password.setHint("密码");
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setSingleLine();
        layout.addView(password);
        login = button(layout, "登录", this::login);
        login.setId(R.id.login);
        connect = button(layout, "连接", this::requestVpn);
        connect.setId(R.id.connect);
        disconnect = button(layout, "断开并恢复直连", this::disconnect);
        disconnect.setId(R.id.disconnect);
        connect.setEnabled(false);
        disconnect.setEnabled(false);
        var scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(layout);
        layout.setOnApplyWindowInsetsListener((view, insets) -> {
            float density = getResources().getDisplayMetrics().density;
            int side = Math.round(20 * density);
            if (Build.VERSION.SDK_INT >= 30) {
                var edges = insets.getInsets(android.view.WindowInsets.Type.systemBars());
                view.setPadding(edges.left + side, edges.top + side, edges.right + side, edges.bottom + side);
            } else {
                view.setPadding(side, side, side, side);
            }
            return insets;
        });
        setContentView(scroll);
        networks = getSystemService(ConnectivityManager.class);
        networks.registerDefaultNetworkCallback(networkChanges);
        login.setEnabled(false);
        EngineHost.CLIENT_ACTIONS.execute(this::restoreSession);
    }

    private Button button(LinearLayout layout, String text, Runnable action) {
        var button = new Button(this);
        button.setText(text);
        button.setOnClickListener(ignored -> action.run());
        layout.addView(button);
        return button;
    }

    private void login() {
        String name = username.getText().toString().trim();
        String secret = password.getText().toString();
        login.setEnabled(false);
        status.setText("正在登录");
        int attempt = generation.incrementAndGet();
        EngineHost.CLIENT_ACTIONS.execute(() -> {
            try {
                var host = EngineHost.from(this);
                String owner = host.decryptFromPref(ACCOUNT);
                if (!owner.isEmpty() && !name.equals(owner)) throw new IOException("ACCOUNT_SWITCH_REQUIRES_RESET");
                String session = accounts.login(name, secret, host.deviceId());
                long expiry = System.currentTimeMillis() + TimeUnit.HOURS.toMillis(11);
                host.encryptToPref(ACCOUNT, name);
                host.encryptToPref(SESSION, new JSONObject().put("token", session).put("expires", expiry).toString());
                runOnUiThread(() -> {
                    if (generation.get() == attempt) showLogin(session, DIRECT);
                });
            } catch (Exception failure) {
                runOnUiThread(() -> {
                    if (generation.get() != attempt) return;
                    login.setEnabled(true);
                    status.setText(message(failure));
                });
            }
        });
    }

    private void restoreSession() {
        String session = null;
        try {
            var host = EngineHost.from(this);
            String saved = host.decryptFromPref(SESSION);
            if (!saved.isEmpty()) {
                var value = new JSONObject(saved);
                if (value.getLong("expires") > System.currentTimeMillis()) session = value.getString("token");
            }
        } catch (Exception ignored) { }
        String restored = session;
        runOnUiThread(() -> {
            if (generation.get() == 0) showLogin(restored, restored == null ? "请登录" : DIRECT);
        });
    }

    private void showLogin(String session, String label) {
        token = session;
        password.setText("");
        for (View item : new View[] { username, password, login }) {
            item.setVisibility(session == null ? View.VISIBLE : View.GONE);
        }
        login.setEnabled(session == null);
        connect.setEnabled(session != null);
        disconnect.setEnabled(false);
        status.setText(label);
    }

    private void requestVpn() {
        var permission = VpnService.prepare(this);
        if (permission == null) connect();
        else startActivityForResult(permission, VPN_PERMISSION);
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == VPN_PERMISSION && result == RESULT_OK) connect();
    }

    private void connect() {
        if (token == null) return;
        int attempt = generation.incrementAndGet();
        long start = SystemClock.elapsedRealtime();
        String session = token;
        connect.setEnabled(false);
        disconnect.setEnabled(true);
        status.setText("正在连接");
        EngineHost.CLIENT_ACTIONS.execute(() -> {
            try {
                checkPending(attempt, Long.MAX_VALUE);
                var profile = accounts.profile(session, false);
                checkPending(attempt, Long.MAX_VALUE);
                var engine = new LocalControl(EngineHost.from(this).engine());
                beginVpnService(attempt);
                control = engine;
                if (profile.key() != null) {
                    engine.enroll(profile.coordinator(), profile.key());
                    long deadline = SystemClock.elapsedRealtime() + 10_000;
                    while (!engine.readState().hasNodeKey()) {
                        checkPending(attempt, deadline);
                        Thread.sleep(125);
                    }
                    while (true) {
                        checkPending(attempt, deadline);
                        try {
                            accounts.profile(session, true);
                            break;
                        } catch (IOException failure) {
                            if (!"TAILSCALE_ENROLLMENT_PENDING".equals(failure.getMessage())) throw failure;
                            Thread.sleep(125);
                        }
                    }
                }
                checkPending(attempt, Long.MAX_VALUE);
                engine.selectExitNode(profile.exitId());
                var verified = new ExitCheck(this).verify(engine, profile, () -> generation.get() != attempt);
                long elapsed = SystemClock.elapsedRealtime() - start;
                runOnUiThread(() -> {
                    if (generation.get() != attempt) return;
                    verifiedNetwork = verified;
                    status.setText("已连接 · " + elapsed + " ms");
                    if (!verified.equals(networks.getActiveNetwork())) recover(verified);
                });
            } catch (Exception failure) {
                stopEngine();
                boolean expired = "LOGIN_REQUIRED".equals(failure.getMessage());
                if (expired) {
                    try { EngineHost.from(this).encryptToPref(SESSION, ""); } catch (Exception ignored) { }
                }
                runOnUiThread(() -> {
                    if (generation.get() != attempt) return;
                    stopService(new Intent(this, BridgeVpnService.class));
                    showLogin(expired ? null : token, message(failure));
                });
            }
        });
    }

    private void beginVpnService(int attempt) throws Exception {
        var started = new CompletableFuture<Void>();
        runOnUiThread(() -> {
            try {
                checkPending(attempt, Long.MAX_VALUE);
                startForegroundService(new Intent(this, BridgeVpnService.class).setAction(BridgeVpnService.START));
                started.complete(null);
            } catch (Exception failure) {
                started.completeExceptionally(failure);
            }
        });
        started.get(5, TimeUnit.SECONDS);
    }

    private void stopEngine() {
        if (control != null) {
            try { control.stop(); } catch (IOException ignored) { }
            control = null;
        }
    }

    private void recover(Network lost) {
        if (!lost.equals(verifiedNetwork) || token == null) return;
        verifiedNetwork = null;
        connect();
    }

    private void checkPending(int attempt, long deadline) throws IOException {
        if (generation.get() != attempt) throw new IOException("CONNECTION_CANCELLED");
        if (SystemClock.elapsedRealtime() >= deadline) throw new IOException("ENROLLMENT_TIMEOUT");
    }

    private void disconnect() {
        int attempt = generation.incrementAndGet();
        Network formerVpn = verifiedNetwork == null ? stoppingNetwork : verifiedNetwork;
        stoppingNetwork = formerVpn;
        verifiedNetwork = null;
        accounts.cancelCurrentRequest();
        stopService(new Intent(this, BridgeVpnService.class));
        disconnect.setEnabled(false);
        status.setText("正在恢复直连");
        EngineHost.CLIENT_ACTIONS.execute(() -> {
            stopEngine();
            long deadline = SystemClock.elapsedRealtime() + 5_000;
            while (formerVpn != null && networks.getNetworkCapabilities(formerVpn) != null &&
                    generation.get() == attempt && SystemClock.elapsedRealtime() < deadline) {
                SystemClock.sleep(40);
            }
            boolean closed = formerVpn == null || networks.getNetworkCapabilities(formerVpn) == null;
            runOnUiThread(() -> {
                if (generation.get() != attempt) return;
                status.setText(closed ? DIRECT : "VPN 正在停止，请稍候");
                connect.setEnabled(closed && token != null);
                disconnect.setEnabled(!closed);
                if (closed) stoppingNetwork = null;
            });
        });
    }

    @Override
    protected void onDestroy() {
        generation.incrementAndGet();
        verifiedNetwork = null;
        networks.unregisterNetworkCallback(networkChanges);
        accounts.cancelCurrentRequest();
        stopService(new Intent(this, BridgeVpnService.class));
        EngineHost.CLIENT_ACTIONS.execute(this::stopEngine);
        super.onDestroy();
    }

    private static String message(Exception error) {
        String code = error.getMessage();
        return switch (code == null ? "" : code) {
            case "INVALID_CREDENTIALS" -> "账号或密码有误";
            case "ACCOUNT_SWITCH_REQUIRES_RESET" -> "本机已绑定其他账号，请先在后台撤销原设备，再清除本应用数据。";
            case "TAILSCALE_ACCOUNT_NOT_ACTIVE" -> "账号当前不可连接";
            case "DEVICE_LIMIT_EXCEEDED" -> "已达到设备上限";
            case "LOGIN_REQUIRED" -> "登录已过期";
            case "EXIT_NOT_VERIFIED" -> "暂时无法验证代理出口";
            default -> "暂时无法连接，请重试";
        };
    }
}
