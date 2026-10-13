package dev.oracleproxy.client;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.wireguard.android.backend.Tunnel;
import com.wireguard.config.Config;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final int CHOOSE_CONFIG = 201;
    private static final int VPN_CONSENT = 202;
    private static final int MAX_CONFIG_BYTES = 32768;

    private final ExecutorService vpnWorker = Executors.newSingleThreadExecutor();
    private OracleProxyApp app;
    private TextView status;
    private Button connectButton;
    private Button disconnectButton;
    private boolean busy;

    @Override public void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        app = (OracleProxyApp) getApplication();

        final LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(32, 32, 32, 32);

        final TextView title = new TextView(this);
        title.setText("Oracle Proxy · Android Alpha");
        title.setTextSize(23);
        content.addView(title);

        status = new TextView(this);
        status.setPadding(0, 24, 0, 24);
        status.setTextSize(16);
        status.setText("未导入配置。\n不会自动连接 VPN。");
        content.addView(status);

        final Button importButton = new Button(this);
        importButton.setText("从本机文件导入 WireGuard .conf");
        importButton.setOnClickListener(v -> chooseConfig());
        content.addView(importButton);

        connectButton = new Button(this);
        connectButton.setText("请求 Android VPN 授权并连接");
        connectButton.setOnClickListener(v -> requestVpn());
        content.addView(connectButton);

        disconnectButton = new Button(this);
        disconnectButton.setText("主动断开 VPN");
        disconnectButton.setOnClickListener(v -> disconnect());
        content.addView(disconnectButton);

        final TextView warning = new TextView(this);
        warning.setText(
            "\n注意：这是未经过实机安全验证的 Alpha。\n" +
            "此版只有基础 WireGuard 连接，不具备经验证的断线防泄漏、" +
            "UU 分流或自动恢复能力。\n\n" +
            "Android 设置中的“始终开启 VPN / 阻止无 VPN 连接”" +
            "需要单独实机检查。本应用不会自行打开这些选项。\n\n" +
            "导入配置只保存在当前应用进程内存中，不上传、不写入持久存储。" +
            "应用进程结束后，需要重新导入。");
        warning.setTextSize(14);
        content.addView(warning);

        final ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(content);
        setContentView(scroll);
        refreshButtons();
    }

    private void chooseConfig() {
        if (busy) return;
        final Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        startActivityForResult(intent, CHOOSE_CONFIG);
    }

    @Override protected void onActivityResult(final int requestCode,
                                               final int resultCode,
                                               final Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK) {
            if (requestCode == VPN_CONSENT) {
                showStatus("Android 未授权 VPN；没有连接。");
            }
            return;
        }
        if (requestCode == CHOOSE_CONFIG && data != null && data.getData() != null) {
            importConfig(data);
        } else if (requestCode == VPN_CONSENT) {
            connectAfterPermission();
        }
    }

    private void importConfig(final Intent data) {
        if (busy) return;
        busy = true;
        refreshButtons();
        showStatus("正在本地验证配置…");
        vpnWorker.execute(() -> {
            byte[] raw = null;
            try (InputStream stream = getContentResolver().openInputStream(data.getData())) {
                if (stream == null) throw new Exception("无法读取配置文件。");
                final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                final byte[] chunk = new byte[4096];
                int length;
                while ((length = stream.read(chunk)) != -1) {
                    if (buffer.size() + length > MAX_CONFIG_BYTES) {
                        throw new Exception("配置文件过大（超过 32 KiB）。");
                    }
                    buffer.write(chunk, 0, length);
                }
                Arrays.fill(chunk, (byte) 0);
                raw = buffer.toByteArray();
                final Config parsed = Config.parse(new ByteArrayInputStream(raw));
                final String rejection = ConfigSafety.rejectReason(parsed);
                if (rejection != null) throw new Exception(rejection);

                // Never silently replace the config of a running tunnel.
                if (app.backend().getState(app.getTunnel()) != Tunnel.State.DOWN) {
                    throw new Exception("请先主动断开旧隧道，再导入新的配置。");
                }
                app.setConfig(parsed);
                runOnUiThread(() -> showStatus(
                    "配置验证通过（已脱敏，不显示密钥）。\n尚未连接 VPN。"));
            } catch (Exception ignored) {
                // Never print/serialize exceptions from parsers: some contain secret lines.
                runOnUiThread(() -> showStatus(
                    "配置读取或验证未通过。请检查 Address、DNS、AllowedIPs、Endpoint。"));
            } finally {
                if (raw != null) Arrays.fill(raw, (byte) 0);
                runOnUiThread(() -> { busy = false; refreshButtons(); });
            }
        });
    }

    private void requestVpn() {
        if (busy || app.getConfig() == null) {
            showStatus("请先导入配置。");
            return;
        }
        // Android's platform confirmation is mandatory; no silent authorization.
        final Intent intent = VpnService.prepare(this);
        if (intent != null) {
            startActivityForResult(intent, VPN_CONSENT);
        } else {
            connectAfterPermission();
        }
    }

    private void connectAfterPermission() {
        if (busy || app.getConfig() == null) return;
        final Config selectedConfig = app.getConfig();
        busy = true;
        refreshButtons();
        showStatus("正在启动隧道；尚未验证实际握手…");
        vpnWorker.execute(() -> {
            try {
                final Tunnel.State state = app.backend().setState(
                    app.getTunnel(), Tunnel.State.UP, selectedConfig);
                final String message = state == Tunnel.State.UP
                    ? "隧道进程已启动（UP）。\n注意：UP 不等于已完成握手，更不代表没有泄漏。"
                    : "隧道未能启动。";
                runOnUiThread(() -> showStatus(message));
            } catch (Exception ignored) {
                // Avoid revealing config, keys, endpoint or raw native errors.
                runOnUiThread(() -> showStatus(
                    "隧道启动失败。未确认连接安全性，请勿依赖本测试版保护流量。"));
            } finally {
                runOnUiThread(() -> { busy = false; refreshButtons(); });
            }
        });
    }

    private void disconnect() {
        if (busy) return;
        busy = true;
        refreshButtons();
        showStatus("正在主动关闭隧道…");
        vpnWorker.execute(() -> {
            try {
                app.backend().setState(app.getTunnel(), Tunnel.State.DOWN, null);
                runOnUiThread(() -> showStatus(
                    "隧道已主动关闭。普通直连可能恢复；当前没有启用断线保护。"));
            } catch (Exception ignored) {
                runOnUiThread(() -> showStatus("无法确认隧道是否已关闭。"));
            } finally {
                runOnUiThread(() -> { busy = false; refreshButtons(); });
            }
        });
    }

    private void refreshButtons() {
        connectButton.setEnabled(!busy && app.getConfig() != null);
        disconnectButton.setEnabled(!busy);
    }

    private void showStatus(final String message) {
        status.setText(message);
    }

    @Override protected void onDestroy() {
        vpnWorker.shutdown();
        super.onDestroy();
    }
}
