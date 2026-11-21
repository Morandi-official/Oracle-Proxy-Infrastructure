package org.morandi.proxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.SystemClock;

import com.wireguard.android.backend.GoBackend;

import java.io.IOException;

public final class ProxyVpnService extends GoBackend.VpnService {
    private static final String CHANNEL = "proxy_vpn";
    private static final int NOTIFICATION = 7721;
    private static final String START = "org.morandi.proxy.VPN_START";
    private static final String DISCONNECT = "org.morandi.proxy.VPN_DISCONNECT";
    private static final long START_TIMEOUT_MS = 2_500;
    private static final long STOP_TIMEOUT_MS = 1_500;
    private static volatile ProxyVpnService live;
    private static volatile boolean startFailed;
    private volatile boolean foreground;

    static void start(Context context, TunnelEngine.Callback callback)
            throws IOException, InterruptedException {
        startFailed = false;
        try {
            context.startForegroundService(new Intent(context, ProxyVpnService.class)
                    .setAction(START));
        } catch (RuntimeException error) {
            throw new IOException("VPN_SERVICE_START_FAILED");
        }
        long deadline = SystemClock.elapsedRealtime() + START_TIMEOUT_MS;
        while (SystemClock.elapsedRealtime() < deadline && !callback.cancelled()) {
            ProxyVpnService service = live;
            if (service != null && service.foreground) {
                return;
            }
            if (startFailed) {
                break;
            }
            Thread.sleep(25);
        }
        throw new IOException(callback.cancelled() ? "VPN_CONNECT_CANCELLED"
                : "VPN_SERVICE_START_FAILED");
    }

    static boolean stop(Context context) {
        context.stopService(new Intent(context, ProxyVpnService.class));
        long deadline = SystemClock.elapsedRealtime() + STOP_TIMEOUT_MS;
        // GoBackend's singleton is reset on the main thread during onDestroy.
        // Waiting here prevents the next attempt from reusing a stopped service.
        while (live != null && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(20);
        }
        return live == null;
    }

    @Override public void onCreate() {
        super.onCreate();
        live = this;
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (DISCONNECT.equals(action)) {
            AppController.get(getApplicationContext()).disconnect();
            return START_NOT_STICKY;
        }
        if (!START.equals(action)) {
            stopSelf();
            return START_NOT_STICKY;
        }
        try {
            Notification notification = notification();
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFICATION, notification,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
            } else {
                startForeground(NOTIFICATION, notification);
            }
            foreground = true;
        } catch (RuntimeException error) {
            startFailed = true;
            stopSelf();
        }
        return START_NOT_STICKY;
    }

    private Notification notification() {
        NotificationManager notifications = getSystemService(NotificationManager.class);
        NotificationChannel channel = new NotificationChannel(CHANNEL, "VPN 连接",
                NotificationManager.IMPORTANCE_LOW);
        notifications.createNotificationChannel(channel);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;
        Intent open = new Intent(this, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent openAction = PendingIntent.getActivity(this, 0, open, flags);
        Intent disconnect = new Intent(this, ProxyVpnService.class).setAction(DISCONNECT);
        PendingIntent disconnectAction = PendingIntent.getService(this, 1, disconnect, flags);
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("Proxy")
                .setContentText("VPN 运行中")
                .setContentIntent(openAction)
                .setOnlyAlertOnce(true)
                .setOngoing(true)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .addAction(new Notification.Action.Builder(null, "断开", disconnectAction).build())
                .build();
    }

    @Override public void onDestroy() {
        foreground = false;
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
        if (live == this) {
            live = null;
        }
    }
}
