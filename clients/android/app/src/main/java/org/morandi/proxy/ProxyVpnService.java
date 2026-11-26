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
    private static final Object LIFECYCLE = new Object();
    private static ProxyVpnService live;
    private static boolean startFailed;
    private boolean foreground;

    static long requestPreparation(Context context) throws IOException {
        return requestStart(context, false);
    }

    static long requestStart(Context context) throws IOException {
        return requestStart(context, true);
    }

    private static long requestStart(Context context, boolean requireForeground) throws IOException {
        synchronized (LIFECYCLE) {
            startFailed = false;
        }
        long deadline = SystemClock.elapsedRealtime() + START_TIMEOUT_MS;
        try {
            Intent intent = new Intent(context, ProxyVpnService.class).setAction(START);
            if (requireForeground) {
                context.startForegroundService(intent);
            } else {
                // A fast policy denial can cancel preparation before Android
                // delivers onStartCommand. The foreground-service contract
                // would crash the app if torn down before startForeground.
                context.startService(intent);
            }
        } catch (RuntimeException error) {
            throw new IOException("VPN_SERVICE_START_FAILED");
        }
        return deadline;
    }

    static void awaitStart(long deadline, TunnelEngine.Callback callback)
            throws IOException, InterruptedException {
        synchronized (LIFECYCLE) {
            while (!callback.cancelled() && !startFailed) {
                if (live != null && live.foreground) {
                    return;
                }
                long remaining = deadline - SystemClock.elapsedRealtime();
                if (remaining <= 0) {
                    break;
                }
                // Lifecycle changes wake this immediately. The timeout also checks
                // cancellation when the system has yet to dispatch onStartCommand.
                LIFECYCLE.wait(Math.min(80, remaining));
            }
        }
        throw new IOException(callback.cancelled() ? "VPN_CONNECT_CANCELLED"
                : "VPN_SERVICE_START_FAILED");
    }

    static boolean stop(Context context) {
        context.stopService(new Intent(context, ProxyVpnService.class));
        long deadline = SystemClock.elapsedRealtime() + STOP_TIMEOUT_MS;
        // GoBackend's singleton is reset on the main thread during onDestroy.
        // Waiting here prevents the next attempt from reusing a stopped service.
        boolean interrupted = false;
        try {
            synchronized (LIFECYCLE) {
                while (live != null) {
                    long remaining = deadline - SystemClock.elapsedRealtime();
                    if (remaining <= 0) {
                        return false;
                    }
                    try {
                        LIFECYCLE.wait(remaining);
                    } catch (InterruptedException error) {
                        interrupted = true;
                    }
                }
                return true;
            }
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override public void onCreate() {
        super.onCreate();
        synchronized (LIFECYCLE) {
            live = this;
        }
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
            synchronized (LIFECYCLE) {
                foreground = true;
                LIFECYCLE.notifyAll();
            }
        } catch (RuntimeException error) {
            synchronized (LIFECYCLE) {
                startFailed = true;
                LIFECYCLE.notifyAll();
            }
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
                .setContentText("VPN 服务运行中")
                .setContentIntent(openAction)
                .setOnlyAlertOnce(true)
                .setOngoing(true)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .addAction(new Notification.Action.Builder(null, "断开", disconnectAction).build())
                .build();
    }

    @Override public void onDestroy() {
        synchronized (LIFECYCLE) {
            foreground = false;
        }
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
        synchronized (LIFECYCLE) {
            if (live == this) {
                live = null;
            }
            LIFECYCLE.notifyAll();
        }
    }
}
