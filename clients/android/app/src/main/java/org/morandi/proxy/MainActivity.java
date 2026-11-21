package org.morandi.proxy;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.text.InputFilter;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class MainActivity extends Activity {
    private static final int VPN_PERMISSION = 1;
    private static final int CONNECTION = 0;
    private static final int ACCOUNT = 1;
    private static final int DIAGNOSTICS = 2;

    private AppController controller;
    private AppController.State state;
    private boolean consentPending;
    private boolean showingLogin;
    private boolean showingRegistration;
    private boolean showingSessionPending;
    private boolean watching;
    private int page;
    private Palette palette;
    private LinearLayout frame;
    private LinearLayout body;
    private ScrollView scroll;
    private EditText username;
    private EditText password;
    private EditText deviceName;
    private TextView loginFeedback;
    private TextView registrationFeedback;
    private LinearLayout registrationDevices;
    private TextView sessionFeedback;
    private Button sessionRefresh;
    private Button authRecovery;
    private TextView connectionStatus;
    private TextView connectionFeedback;
    private TextView connectionEndpoint;
    private TextView verifiedIpv4;
    private TextView verifiedIpv6;
    private View connectionMarker;
    private LinearLayout portPanel;
    private Button connectAction;
    private Button disconnectAction;
    private Button portAction;
    private Button loginAction;
    private Button confirmAction;
    private CheckBox remember;
    private Button[] tabs;
    private int renderedPage = -1;
    private final int[] scrollPositions = new int[3];
    private final AppController.Listener listener = value -> runOnUiThread(() -> {
        if (watching && !isFinishing() && !isDestroyed()) render(value, false);
    });

    @Override
    public void onCreate(Bundle saved) {
        super.onCreate(saved);
        controller = AppController.get(getApplicationContext());
        palette = new Palette((getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES);
        if (saved != null) {
            page = Math.max(CONNECTION, Math.min(DIAGNOSTICS, saved.getInt("page")));
            consentPending = saved.getBoolean("vpnConsentPending");
        }
        render(controller.snapshot(), true);
    }

    @Override
    protected void onStart() {
        super.onStart();
        watching = true;
        controller.observe(listener);
        render(controller.snapshot(), false);
    }

    @Override
    protected void onStop() {
        watching = false;
        controller.removeObserver(listener);
        super.onStop();
    }

    @Override
    protected void onSaveInstanceState(Bundle out) {
        out.putInt("page", page);
        out.putBoolean("vpnConsentPending", consentPending);
        super.onSaveInstanceState(out);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != VPN_PERMISSION) return;
        consentPending = false;
        AppController.State current = controller.snapshot();
        if (resultCode == RESULT_OK && current.signedIn && current.registered) {
            controller.connect();
        } else if (resultCode != RESULT_OK) {
            controller.reportConsentDenied();
        }
        render(controller.snapshot(), false);
    }

    private void render(AppController.State value, boolean first) {
        state = value;
        boolean login = !value.signedIn;
        boolean sessionPending = value.signedIn && orEmpty(value.username).isEmpty();
        boolean registration = value.signedIn && !sessionPending && !value.registered;
        if (first || login != showingLogin || registration != showingRegistration
                || sessionPending != showingSessionPending) {
            showingLogin = login;
            showingRegistration = registration;
            showingSessionPending = sessionPending;
            if (login || registration || sessionPending) page = CONNECTION;
            buildShell();
            if (login) buildLogin();
            else if (registration) buildRegistration();
            else if (sessionPending) buildSessionPending();
            if (login || registration || sessionPending) {
                authRecovery = button("再次断开 VPN", R.id.disconnect, false, controller::disconnect);
                add(body, authRecovery, 9);
            }
        }
        boolean recovery = isProtected() || isDisconnecting();
        if (login) {
            loginAction.setEnabled(!state.busy && !recovery);
            loginAction.setText(state.busy ? "正在登录…" : "登录");
            showFeedback(loginFeedback, messageLabel(state.message));
        } else if (registration) {
            confirmAction.setEnabled(!state.busy && !recovery);
            confirmAction.setText(state.busy ? "正在登记…" : "确认登记");
            showFeedback(registrationFeedback, messageLabel(state.message));
            populateDevices(registrationDevices);
            registrationDevices.setVisibility(hasDevices() ? View.VISIBLE : View.GONE);
        } else if (sessionPending) {
            sessionRefresh.setEnabled(!state.busy && !recovery);
            showFeedback(sessionFeedback, messageLabel(state.message));
        } else {
            renderPage(false);
        }
        if (login || registration || sessionPending) {
            authRecovery.setVisibility(recovery ? View.VISIBLE : View.GONE);
            authRecovery.setEnabled(!isDisconnecting());
            updateText(authRecovery, isDisconnecting() ? "正在断开 VPN…" : "再次断开 VPN");
        }
    }

    private void buildShell() {
        renderedPage = -1;
        frame = new LinearLayout(this);
        frame.setOrientation(LinearLayout.VERTICAL);
        frame.setBackgroundColor(palette.background);
        frame.setLayoutParams(new ViewGroup.LayoutParams(-1, -1));

        if (Build.VERSION.SDK_INT >= 30) {
            getWindow().setDecorFitsSystemWindows(false);
            getWindow().setStatusBarColor(Color.TRANSPARENT);
            getWindow().setNavigationBarColor(Color.TRANSPARENT);
            frame.setOnApplyWindowInsetsListener((view, insets) -> {
                Insets bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                Insets keyboard = insets.getInsets(WindowInsets.Type.ime());
                view.setPadding(bars.left, bars.top, bars.right, Math.max(bars.bottom, keyboard.bottom));
                return insets;
            });
        } else {
            getWindow().setStatusBarColor(palette.background);
            getWindow().setNavigationBarColor(palette.background);
            getWindow().getDecorView().setSystemUiVisibility(palette.dark ? 0 :
                    View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        }

        FrameLayout headerHost = new FrameLayout(this);
        LinearLayout header = column();
        header.setPadding(dp(22), dp(15), dp(22), dp(9));
        headerHost.addView(header, centeredWidth());
        frame.addView(headerHost, new LinearLayout.LayoutParams(-1, -2));
        add(header, heading("Proxy", 30), 0);

        if (!showingLogin && !showingRegistration && !showingSessionPending) {
            LinearLayout nav = new LinearLayout(this);
            boolean stacked = getResources().getConfiguration().screenWidthDp < 340
                    || getResources().getConfiguration().fontScale >= 1.45f;
            nav.setOrientation(stacked ? LinearLayout.VERTICAL : LinearLayout.HORIZONTAL);
            nav.setPadding(dp(4), dp(4), dp(4), dp(4));
            nav.setBackground(shape(palette.panel, 19, palette.border));
            add(header, nav, 13);
            String[] titles = {"连接", "账号", "诊断"};
            int[] ids = {R.id.nav_connection, R.id.nav_account, R.id.nav_diagnostics};
            tabs = new Button[titles.length];
            for (int index = 0; index < titles.length; index++) {
                final int destination = index;
                Button tab = button(titles[index], ids[index], false, () -> openPage(destination));
                tab.setMinimumHeight(dp(48));
                tab.setTextSize(14);
                tab.setPadding(dp(7), dp(8), dp(7), dp(8));
                LinearLayout.LayoutParams params = stacked
                        ? new LinearLayout.LayoutParams(-1, -2)
                        : new LinearLayout.LayoutParams(0, -2, 1);
                if (index > 0) {
                    if (stacked) params.topMargin = dp(3);
                    else params.leftMargin = dp(3);
                }
                nav.addView(tab, params);
                tabs[index] = tab;
            }
        }

        scroll = new ScrollView(this);
        scroll.setFillViewport(false);
        scroll.setVerticalScrollBarEnabled(false);
        frame.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        FrameLayout contentHost = new FrameLayout(this);
        scroll.addView(contentHost, new ScrollView.LayoutParams(-1, -2));
        body = column();
        body.setPadding(dp(22), dp(8), dp(22), dp(30));
        contentHost.addView(body, centeredWidth());
        setContentView(frame);
        frame.requestApplyInsets();
        if (Build.VERSION.SDK_INT >= 30) {
            frame.post(() -> {
                android.view.WindowInsetsController insets = getWindow().getInsetsController();
                int lightBars = android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                        | android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
                if (insets != null) insets.setSystemBarsAppearance(palette.dark ? 0 : lightBars, lightBars);
            });
        }
    }

    private FrameLayout.LayoutParams centeredWidth() {
        int width = getResources().getDisplayMetrics().widthPixels;
        return new FrameLayout.LayoutParams(Math.min(width, dp(600)), -2, Gravity.TOP | Gravity.CENTER_HORIZONTAL);
    }

    private void buildLogin() {
        LinearLayout panel = card(body, 22);
        add(panel, heading("登录账号", 25), 0);
        add(panel, text("使用管理员分配的账号和密码登录。", 15, palette.secondary), 7);
        username = input(panel, "账号", R.id.username, InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, View.AUTOFILL_HINT_USERNAME);
        username.setFilters(new InputFilter[] {new InputFilter.LengthFilter(64)});
        username.setImeOptions(EditorInfo.IME_ACTION_NEXT);
        password = input(panel, "密码", R.id.password, InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_VARIATION_PASSWORD, View.AUTOFILL_HINT_PASSWORD);
        password.setFilters(new InputFilter[] {new InputFilter.LengthFilter(128)});
        password.setSaveEnabled(false);
        password.setImeOptions(EditorInfo.IME_ACTION_GO);
        password.setOnEditorActionListener((view, action, event) -> {
            if (action != EditorInfo.IME_ACTION_GO) return false;
            submitLogin();
            return true;
        });
        remember = new CheckBox(this);
        remember.setId(R.id.remember_login);
        remember.setText("记住登录");
        remember.setTextSize(15);
        remember.setTextColor(palette.primary);
        remember.setMinHeight(dp(48));
        remember.setButtonTintList(ColorStateList.valueOf(palette.accent));
        remember.setPadding(dp(2), 0, 0, 0);
        add(panel, remember, 9);
        loginAction = button("登录", R.id.login, true, this::submitLogin);
        add(panel, loginAction, 4);
        loginFeedback = text("", 14, palette.secondary);
        loginFeedback.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        add(panel, loginFeedback, 12);
    }

    private void submitLogin() {
        if (state.busy || isProtected() || isDisconnecting()) return;
        String loginName = username.getText().toString().trim();
        String secret = password.getText().toString();
        if (loginName.isEmpty()) {
            username.setError("请输入账号");
            username.requestFocus();
        } else if (secret.isEmpty()) {
            password.setError("请输入密码");
            password.requestFocus();
        } else {
            hideKeyboard();
            password.getText().clear();
            controller.login(loginName, secret, remember.isChecked());
        }
    }

    private void buildRegistration() {
        LinearLayout panel = card(body, 22);
        add(panel, heading("登记本机", 25), 0);
        add(panel, text("为这台设备填写名称，方便在账号中管理。", 15, palette.secondary), 7);
        deviceName = input(panel, "设备名称", R.id.device_name, InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_CAP_SENTENCES, null);
        deviceName.setFilters(new InputFilter[] {new InputFilter.LengthFilter(64)});
        deviceName.setText(orEmpty(state.defaultDeviceName));
        confirmAction = button("确认登记", R.id.device_confirm, true, () -> {
            String name = deviceName.getText().toString().trim();
            if (name.isEmpty()) {
                deviceName.setError("请输入设备名称");
                deviceName.requestFocus();
            } else {
                hideKeyboard();
                controller.confirmDevice(name);
            }
        });
        add(panel, confirmAction, 17);
        registrationFeedback = text("", 14, palette.secondary);
        registrationFeedback.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        add(panel, registrationFeedback, 12);
        registrationDevices = card(body, 14);
        Button exit = button("退出登录", R.id.logout, false, this::confirmLogout);
        add(body, exit, 7);
    }

    private void buildSessionPending() {
        LinearLayout panel = card(body, 22);
        add(panel, heading("等待账号核验", 25), 0);
        sessionFeedback = text("", 14, palette.secondary);
        sessionFeedback.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        add(panel, sessionFeedback, 10);
        sessionRefresh = button("重新核验", R.id.refresh_account, true, controller::refresh);
        add(panel, sessionRefresh, 12);
        add(body, button("退出登录", R.id.logout, false, this::confirmLogout), 8);
    }

    private void openPage(int destination) {
        if (page == destination) return;
        scrollPositions[page] = scroll.getScrollY();
        page = destination;
        renderPage(true);
    }

    private void renderPage(boolean navigation) {
        if (page == CONNECTION && page == renderedPage) {
            updateConnection();
            return;
        }
        final int position = navigation ? scrollPositions[page] : scroll.getScrollY();
        int focused = frame.findFocus() == null ? View.NO_ID : frame.findFocus().getId();
        body.removeAllViews();
        for (int i = 0; i < tabs.length; i++) {
            Button tab = tabs[i];
            boolean selected = i == page;
            tab.setSelected(selected);
            tab.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
            tab.setTextColor(selected ? palette.accent : palette.secondary);
            tab.setBackground(tappable(selected ? palette.tint : palette.panel, 14, null));
        }
        switch (page) {
            case ACCOUNT -> buildAccount();
            case DIAGNOSTICS -> buildDiagnostics();
            default -> buildConnection();
        }
        renderedPage = page;
        ScrollView currentScroll = scroll;
        currentScroll.post(() -> {
            if (scroll == currentScroll) currentScroll.scrollTo(0, position);
        });
        if (!navigation && focused != View.NO_ID && !frame.isInTouchMode()) {
            View replacement = frame.findViewById(focused);
            if (replacement != null && replacement.isEnabled()) replacement.requestFocus();
        }
    }

    private void buildConnection() {
        LinearLayout control = card(body, 6);
        LinearLayout statusRow = new LinearLayout(this);
        statusRow.setGravity(Gravity.CENTER_VERTICAL);
        statusRow.setOrientation(LinearLayout.HORIZONTAL);
        connectionMarker = new View(this);
        connectionMarker.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        LinearLayout.LayoutParams dot = new LinearLayout.LayoutParams(dp(10), dp(10));
        dot.rightMargin = dp(10);
        statusRow.addView(connectionMarker, dot);
        connectionStatus = heading("", 25);
        connectionStatus.setId(R.id.connection_status);
        connectionStatus.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        statusRow.addView(connectionStatus, new LinearLayout.LayoutParams(0, -2, 1));
        add(control, statusRow, 0);
        connectionFeedback = text("", 14, palette.secondary);
        connectionFeedback.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        add(control, connectionFeedback, 8);

        connectAction = button("连接", R.id.connect, true, this::requestConnect);
        disconnectAction = button("断开并恢复直连", R.id.disconnect, false, controller::disconnect);
        add(control, connectAction, 18);
        add(control, disconnectAction, 18);

        LinearLayout details = card(body, 14);
        add(details, heading("连接详情", 18), 0);
        connectionEndpoint = detail(details, "连接入口", "", R.id.connection_endpoint, 14);
        verifiedIpv4 = detail(details, "已验证 IPv4 出口", "", R.id.verified_ipv4, 10);
        verifiedIpv6 = detail(details, "已验证 IPv6 出口", "", R.id.verified_ipv6, 10);

        portPanel = card(body, 14);
        add(portPanel, heading("UDP 端口", 18), 0);
        portAction = button("", R.id.udp_port, false, this::choosePort);
        add(portPanel, portAction, 10);
        updateConnection();
    }

    private void updateConnection() {
        updateText(connectionStatus, statusLabel(state.mode));
        connectionMarker.setBackground(shape(statusColor(state.mode), 12, null));
        showFeedback(connectionFeedback, messageLabel(state.message));

        boolean active = isConnected() || isWorking() || isProtected();
        disconnectAction.setVisibility(active ? View.VISIBLE : View.GONE);
        disconnectAction.setEnabled(!isDisconnecting());
        updateText(disconnectAction, isProtected() ? "再次断开 VPN" : "断开并恢复直连");
        connectAction.setVisibility(active ? View.GONE : View.VISIBLE);
        connectAction.setEnabled(!state.busy && !consentPending);
        updateText(connectAction, consentPending ? "等待 VPN 授权…" : "连接");

        updateText(connectionEndpoint, printable(state.endpoint));
        updateText(verifiedIpv4, printable(state.verifiedIpv4));
        updateText(verifiedIpv6, printable(state.verifiedIpv6));
        portPanel.setVisibility(state.ports == null || state.ports.isEmpty() ? View.GONE : View.VISIBLE);
        updateText(portAction, portLabel(state.preferredPort));
        portAction.setContentDescription("UDP 端口，" + portLabel(state.preferredPort));
        portAction.setEnabled(!state.busy && !active && !consentPending);
    }

    private void requestConnect() {
        if (state.busy || consentPending) return;
        Intent request = VpnService.prepare(this);
        if (request == null) controller.connect();
        else {
            consentPending = true;
            try {
                startActivityForResult(request, VPN_PERMISSION);
            } catch (android.content.ActivityNotFoundException error) {
                consentPending = false;
                Toast.makeText(this, "本机无法打开系统 VPN 授权。", Toast.LENGTH_LONG).show();
            }
            render(controller.snapshot(), false);
        }
    }

    private void choosePort() {
        List<Integer> choices = new ArrayList<>();
        choices.add(0);
        if (state.ports != null) for (Integer port : state.ports)
            if (port != null && port > 0 && port <= 65535 && !choices.contains(port)) choices.add(port);
        String[] labels = choices.stream().map(MainActivity::portLabel).toArray(String[]::new);
        dialog()
                .setTitle("UDP 端口")
                .setSingleChoiceItems(labels, choices.indexOf(state.preferredPort), (dialog, position) -> {
                    controller.setPreferredPort(choices.get(position));
                    dialog.dismiss();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void buildAccount() {
        LinearLayout usage = card(body, 6);
        add(usage, heading(printable(state.username), 23), 0);
        String accountStatus = accountLabel(state.accountStatus);
        if (!accountStatus.isEmpty()) add(usage, text(accountStatus, 14, palette.secondary), 4);
        add(usage, text("本周期已用", 14, palette.secondary), 14);
        String amount = dataSize(state.usedBytes);
        if (state.quotaBytes > 0) amount += " / " + dataSize(state.quotaBytes);
        add(usage, heading(amount, 20), 5);
        if (state.quotaBytes > 0) {
            ProgressBar bar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
            bar.setMax(1000);
            bar.setProgress((int) Math.max(0, Math.min(1000, state.usedBytes / (double) state.quotaBytes * 1000)));
            bar.setProgressTintList(ColorStateList.valueOf(palette.accent));
            bar.setProgressBackgroundTintList(ColorStateList.valueOf(palette.tint));
            bar.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, dp(12));
            params.topMargin = dp(8);
            usage.addView(bar, params);
        }
        detail(usage, "当前周期", printable(state.periodLabel), View.NO_ID, 14);
        detail(usage, "账号到期", printable(state.expiresLabel), View.NO_ID, 9);
        String message = messageLabel(state.message);
        if (!message.isEmpty()) add(usage, text(message, 14, palette.secondary), 9);
        Button refresh = button(state.busy ? "正在处理…" : "刷新账号状态", R.id.refresh_account, false, controller::refresh);
        refresh.setEnabled(!state.busy);
        add(usage, refresh, 14);

        LinearLayout devices = card(body, 14);
        populateDevices(devices);

        Button exit = button("退出登录", R.id.logout, false, this::confirmLogout);
        exit.setEnabled(!state.busy);
        add(body, exit, 15);
    }

    private boolean hasDevices() {
        return state.devices != null && !state.devices.isEmpty();
    }

    private void populateDevices(LinearLayout container) {
        container.removeAllViews();
        add(container, heading("已登记设备", 18), 0);
        if (!hasDevices()) {
            add(container, text("暂无设备记录", 15, palette.secondary), 10);
            return;
        }
        for (AppController.Device device : state.devices) {
            divider(container);
            add(container, heading(printable(device.name), 16), 10);
            if (device.current) add(container, text("本机", 14, palette.secondary), 4);
            Button remove = button("移除设备", View.NO_ID, false, () -> confirmRemoval(device));
            remove.setContentDescription("移除设备，" + printable(device.name));
            remove.setEnabled(!state.busy);
            add(container, remove, 7);
        }
    }

    private AlertDialog.Builder dialog() {
        return new AlertDialog.Builder(this, palette.dark
                ? android.R.style.Theme_Material_Dialog_Alert
                : android.R.style.Theme_Material_Light_Dialog_Alert);
    }

    private void confirmRemoval(AppController.Device device) {
        String label = printable(device.name);
        dialog()
                .setTitle("移除设备")
                .setMessage(device.current ? "移除本机后将断开，并需要重新登记。" : "移除「" + label + "」后，该设备需要重新登记。")
                .setNegativeButton("取消", null)
                .setPositiveButton("移除", (dialog, which) -> controller.removeDevice(device.id))
                .show();
    }

    private void confirmLogout() {
        dialog()
                .setTitle("退出登录")
                .setMessage("退出时会断开当前连接。")
                .setNegativeButton("取消", null)
                .setPositiveButton("退出登录", (dialog, which) -> controller.logout())
                .show();
    }

    private void buildDiagnostics() {
        LinearLayout diagnostics = card(body, 6);
        add(diagnostics, heading("连接诊断", 20), 0);
        detail(diagnostics, "状态", statusLabel(state.mode), View.NO_ID, 13);
        detail(diagnostics, "连接入口", printable(state.endpoint), View.NO_ID, 9);
        detail(diagnostics, "端口偏好", portLabel(state.preferredPort), View.NO_ID, 9);
        detail(diagnostics, "IPv4 出口", printable(state.verifiedIpv4), View.NO_ID, 9);
        detail(diagnostics, "IPv6 出口", printable(state.verifiedIpv6), View.NO_ID, 9);
        String message = diagnosticCode(state.message);
        if (!message.isEmpty()) detail(diagnostics, "诊断代码", message, View.NO_ID, 9);
        Button copy = button("复制连接诊断", R.id.copy_diagnostics, false, this::copyDiagnostics);
        add(diagnostics, copy, 15);
    }

    private void copyDiagnostics() {
        String report = String.format(Locale.ROOT, "Proxy Android 连接诊断\n状态：%s\n连接入口：%s\n端口偏好：%s\nIPv4 出口：%s\nIPv6 出口：%s\n诊断代码：%s",
                statusLabel(state.mode), printable(state.endpoint), portLabel(state.preferredPort),
                printable(state.verifiedIpv4), printable(state.verifiedIpv6),
                printable(diagnosticCode(state.message)));
        ClipboardManager clipboard = getSystemService(ClipboardManager.class);
        if (clipboard != null) {
            clipboard.setPrimaryClip(ClipData.newPlainText("Proxy Android 连接诊断", report));
            if (Build.VERSION.SDK_INT < 33) Toast.makeText(this, "已复制连接诊断", Toast.LENGTH_SHORT).show();
        }
    }

    private int statusColor(String mode) {
        if ("connected".equals(mode)) return palette.online;
        if (isWorking() || isProtected()) return palette.accent;
        return palette.secondary;
    }

    private boolean isConnected() {
        return "connected".equals(state.mode);
    }

    private boolean isDisconnecting() {
        return "disconnecting".equals(state.mode) || "stopping".equals(state.mode);
    }

    private boolean isProtected() {
        return "protected".equals(state.mode);
    }

    private boolean isWorking() {
        return switch (orEmpty(state.mode)) {
            case "connecting", "reconnecting", "disconnecting", "verifying", "starting", "stopping" -> true;
            default -> false;
        };
    }

    private static String statusLabel(String mode) {
        return switch (orEmpty(mode)) {
            case "connected" -> "已连接";
            case "connecting", "starting" -> "正在连接";
            case "reconnecting" -> "正在重新连接";
            case "verifying" -> "正在验证出口";
            case "disconnecting", "stopping" -> "正在恢复直连";
            case "protected" -> "断开尚未确认";
            case "error", "failed" -> "连接未完成";
            default -> "已断开";
        };
    }

    private static String messageLabel(String message) {
        return switch (orEmpty(message)) {
            case "" -> "";
            case "LOGIN_REQUIRED", "DEVICE_REVOKED", "SESSION_EXPIRED", "UNAUTHORIZED" -> "登录已失效，请重新登录。";
            case "LOGIN_FAILED", "INVALID_CREDENTIALS" -> "账号或密码不正确。";
            case "RATE_LIMITED" -> "登录尝试过多，请稍后再试。";
            case "DEVICE_LIMIT_REACHED", "DEVICE_LIMIT" -> "已达设备名额上限，请先移除一台设备。";
            case "ACCOUNT_NOT_ACTIVE", "ACCOUNT_DISABLED", "ACCOUNT_EXPIRED", "QUOTA_EXHAUSTED" -> "账号当前无法连接，请检查到期时间和用量。";
            case "VPN_PERMISSION_REQUIRED" -> "请重试连接并在系统弹窗中授予 VPN 权限。";
            case "VPN_PERMISSION_DENIED", "VPN_CONSENT_DENIED" -> "已取消 VPN 授权。再次点按连接可重新授权。";
            case "VPN_PERMISSION_REVOKED", "VPN_REVOKED" -> "系统已收回 VPN 权限。";
            case "EGRESS_NOT_VERIFIED", "EGRESS_PROBE_FAILED", "UDP_ALLOWED_INGRESS_UNREACHABLE" -> "未能验证出口，可稍后重试。";
            case "API_UNAVAILABLE", "NETWORK_ERROR", "API_ENDPOINTS_UNAVAILABLE" -> "暂时无法访问账号服务，请检查网络后重试。";
            default -> diagnosticCode(message).isEmpty() ? message : "操作未完成（" + message + "）。";
        };
    }

    private static String accountLabel(String accountStatus) {
        return switch (orEmpty(accountStatus)) {
            case "active" -> "账号可用";
            case "disabled" -> "账号已停用";
            case "expired" -> "账号已到期";
            case "quota", "quota_exceeded" -> "本周期用量已达上限";
            case "server_budget" -> "服务端出站保护已启用";
            case "unavailable" -> "暂时无法核验账号";
            default -> "";
        };
    }

    private static String diagnosticCode(String message) {
        return message != null && message.matches("[A-Z][A-Z0-9_]{1,100}") ? message : "";
    }

    private static String orEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String printable(String value) {
        return orEmpty(value).trim().isEmpty() ? "—" : value;
    }

    private static String portLabel(int port) {
        return port > 0 ? Integer.toString(port) : "优先可用端口";
    }

    private static String dataSize(long bytes) {
        double amount = Math.max(0, bytes);
        String[] units = {"B", "KB", "MB", "GB", "TB", "PB"};
        int unit = 0;
        while (amount >= 1000 && unit < units.length - 1) {
            amount /= 1000;
            unit++;
        }
        return String.format(Locale.getDefault(), unit == 0 ? "%.0f %s" : "%.2f %s", amount, units[unit]);
    }

    private void showFeedback(TextView view, String feedback) {
        updateText(view, feedback);
        view.setVisibility(feedback.isEmpty() ? View.GONE : View.VISIBLE);
    }

    private static void updateText(TextView view, String value) {
        if (!value.contentEquals(view.getText())) view.setText(value);
    }

    private EditText input(LinearLayout parent, String label, int id, int type, String autofill) {
        TextView title = text(label, 14, palette.primary);
        title.setLabelFor(id);
        add(parent, title, 14);
        EditText control = new EditText(this);
        control.setId(id);
        control.setTextSize(16);
        control.setTextColor(palette.primary);
        control.setSingleLine(true);
        control.setInputType(type);
        control.setMinimumHeight(dp(52));
        control.setPadding(dp(12), dp(9), dp(12), dp(9));
        control.setBackground(shape(palette.input, 13, palette.border));
        if (autofill != null) control.setAutofillHints(autofill);
        control.setOnFocusChangeListener((view, active) -> view.setBackground(
                shape(palette.input, 13, active ? palette.accent : palette.border)));
        add(parent, control, 5);
        return control;
    }

    private TextView detail(LinearLayout parent, String title, String value, int id, int gap) {
        add(parent, text(title, 14, palette.secondary), gap);
        TextView label = heading(value, 16);
        if (id != View.NO_ID) label.setId(id);
        add(parent, label, 3);
        return label;
    }

    private void divider(LinearLayout container) {
        View line = new View(this);
        line.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        line.setBackgroundColor(palette.border);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, dp(1));
        params.topMargin = dp(12);
        container.addView(line, params);
    }

    private LinearLayout card(LinearLayout parent, int gap) {
        LinearLayout card = column();
        card.setBackground(shape(palette.panel, 22, palette.border));
        card.setPadding(dp(18), dp(17), dp(18), dp(17));
        add(parent, card, gap);
        return card;
    }

    private LinearLayout column() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    private void add(LinearLayout parent, View view, int gap) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(-1, -2);
        params.topMargin = dp(gap);
        parent.addView(view, params);
    }

    private TextView heading(String value, int size) {
        TextView view = text(value, size, palette.primary);
        view.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        return view;
    }

    private TextView text(String value, int size, int color) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setBreakStrategy(android.text.Layout.BREAK_STRATEGY_SIMPLE);
        return view;
    }

    private Button button(String label, int id, boolean primary, Runnable action) {
        Button view = new Button(this);
        if (id != View.NO_ID) view.setId(id);
        view.setText(label);
        view.setAllCaps(false);
        view.setTextSize(16);
        view.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        view.setMinHeight(dp(52));
        view.setMinimumHeight(dp(52));
        view.setPadding(dp(13), dp(9), dp(13), dp(9));
        view.setStateListAnimator(null);
        view.setTextColor(new ColorStateList(
                new int[][] {new int[] {-android.R.attr.state_enabled}, new int[] {}},
                new int[] {primary ? palette.textOnAccent : palette.secondary,
                        primary ? palette.textOnAccent : palette.accent}));
        view.setBackground(tappable(primary ? palette.action : palette.tint, 15, null));
        view.setOnClickListener(unused -> action.run());
        return view;
    }

    private GradientDrawable shape(int fill, int radius, Integer stroke) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(radius));
        if (stroke != null) drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    private RippleDrawable tappable(int fill, int radius, Integer stroke) {
        return new RippleDrawable(ColorStateList.valueOf(palette.ripple),
                shape(fill, radius, stroke), shape(Color.WHITE, radius, null));
    }

    private void hideKeyboard() {
        View focus = getCurrentFocus();
        InputMethodManager input = getSystemService(InputMethodManager.class);
        if (focus != null && input != null) input.hideSoftInputFromWindow(focus.getWindowToken(), 0);
    }

    private int dp(int size) {
        return Math.round(size * getResources().getDisplayMetrics().density);
    }

    private static final class Palette {
        final boolean dark;
        final int background, panel, input, border, primary, secondary, accent, action, tint, online, ripple, textOnAccent;

        Palette(boolean dark) {
            this.dark = dark;
            background = dark ? 0xFF10141C : 0xFFF1F4F9;
            panel = dark ? 0xFF1A222E : 0xFFFFFFFF;
            input = dark ? 0xFF121821 : 0xFFF7F9FD;
            border = dark ? 0xFF344151 : 0xFFD9E2EE;
            primary = dark ? 0xFFF3F6FC : 0xFF152236;
            secondary = dark ? 0xFFB4C0CF : 0xFF475A72;
            accent = dark ? 0xFFB7D0FF : 0xFF2456A4;
            action = dark ? 0xFFABC8FD : 0xFF2856A0;
            tint = dark ? 0xFF223653 : 0xFFE8F0FC;
            online = dark ? 0xFF8CD5BD : 0xFF16735A;
            ripple = dark ? 0x309BC0FF : 0x26335588;
            textOnAccent = dark ? 0xFF152A4A : Color.WHITE;
        }
    }
}
