package org.morandi.proxy.tailscale;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

public final class MainActivity extends Activity {
    private static final int VPN_PERMISSION = 1;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
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
        status.setText("请登录");
        status.setTextSize(18);
        layout.addView(status);
        username = new EditText(this);
        username.setHint("账号");
        username.setSingleLine();
        layout.addView(username);
        password = new EditText(this);
        password.setHint("密码");
        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setSingleLine();
        layout.addView(password);
        login = button(layout, "登录", this::login);
        connect = button(layout, "连接", this::requestVpn);
        disconnect = button(layout, "断开并恢复直连", this::disconnect);
        connect.setEnabled(false);
        disconnect.setEnabled(false);
        setContentView(layout);
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
        worker.execute(() -> {
            try {
                String session = accounts.login(name, secret, EngineHost.from(this).deviceId());
                runOnUiThread(() -> {
                    token = session;
                    password.setText("");
                    for (View item : new View[] { username, password, login }) item.setVisibility(View.GONE);
                    connect.setEnabled(true);
                    status.setText("已断开 · 当前直连");
                });
            } catch (Exception failure) {
                runOnUiThread(() -> {
                    login.setEnabled(true);
                    status.setText(message(failure));
                });
            }
        });
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
        int attempt = generation.incrementAndGet();
        long start = SystemClock.elapsedRealtime();
        String session = token;
        connect.setEnabled(false);
        disconnect.setEnabled(true);
        status.setText("正在连接");
        startForegroundService(new Intent(this, BridgeVpnService.class));
        worker.execute(() -> {
            try {
                var profile = accounts.profile(session, false);
                checkPending(attempt, Long.MAX_VALUE);
                var engine = new LocalControl(EngineHost.from(this).engine());
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
                new ExitCheck(this).verify(engine, profile, () -> generation.get() != attempt);
                long elapsed = SystemClock.elapsedRealtime() - start;
                runOnUiThread(() -> {
                    if (generation.get() == attempt) status.setText("已连接 · " + elapsed + " ms");
                });
            } catch (Exception failure) {
                try { if (control != null) control.stop(); } catch (IOException ignored) { }
                runOnUiThread(() -> {
                    if (generation.get() != attempt) return;
                    stopService(new Intent(this, BridgeVpnService.class));
                    if ("LOGIN_REQUIRED".equals(failure.getMessage())) {
                        token = null;
                        for (View item : new View[] { username, password, login }) item.setVisibility(View.VISIBLE);
                        login.setEnabled(true);
                    }
                    connect.setEnabled(token != null);
                    disconnect.setEnabled(false);
                    status.setText(message(failure));
                });
            }
        });
    }

    private void checkPending(int attempt, long deadline) throws IOException {
        if (generation.get() != attempt) throw new IOException("CONNECTION_CANCELLED");
        if (SystemClock.elapsedRealtime() >= deadline) throw new IOException("ENROLLMENT_TIMEOUT");
    }

    private void disconnect() {
        generation.incrementAndGet();
        stopService(new Intent(this, BridgeVpnService.class));
        disconnect.setEnabled(false);
        status.setText("正在恢复直连");
        worker.execute(() -> {
            try {
                if (control != null) control.stop();
                runOnUiThread(() -> {
                    status.setText("已断开 · 当前直连");
                    connect.setEnabled(token != null);
                });
            } catch (IOException failure) {
                runOnUiThread(() -> status.setText(message(failure)));
            }
        });
    }

    @Override
    protected void onDestroy() {
        generation.incrementAndGet();
        stopService(new Intent(this, BridgeVpnService.class));
        worker.shutdownNow();
        super.onDestroy();
    }

    private static String message(Exception error) {
        String code = error.getMessage();
        return switch (code == null ? "" : code) {
            case "INVALID_CREDENTIALS" -> "账号或密码有误";
            case "TAILSCALE_ACCOUNT_NOT_ACTIVE" -> "账号当前不可连接";
            case "DEVICE_LIMIT_EXCEEDED" -> "已达到设备上限";
            case "LOGIN_REQUIRED" -> "登录已过期";
            case "EXIT_NOT_VERIFIED" -> "暂时无法验证代理出口";
            default -> "暂时无法连接，请重试";
        };
    }
}
