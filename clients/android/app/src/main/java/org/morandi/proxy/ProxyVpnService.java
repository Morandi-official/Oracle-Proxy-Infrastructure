package org.morandi.proxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ServiceInfo;
import android.os.Binder;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.util.Log;
import android.system.ErrnoException;
import android.system.Os;

import com.wireguard.android.backend.GoBackend;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;

public final class ProxyVpnService extends GoBackend.VpnService {
    private static final String CHANNEL = "proxy_vpn";
    private static final int NOTIFICATION = 7721;
    private static final String PREPARE_BINDING = "org.morandi.proxy.PREPARE_VPN_BINDING";
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static volatile ConsentBinding consentBinding;
    private static final String START = "org.morandi.proxy.VPN_START";
    private static final String START_GENERATION = "start_generation";
    private static final String FOREGROUND_REQUIRED = "foreground_required";
    private static final String DISCONNECT = "org.morandi.proxy.VPN_DISCONNECT";
    private static final long START_TIMEOUT_MS = 2_500;
    private static final long STOP_TIMEOUT_MS = 1_500;
    private static final Object LIFECYCLE = new Object();
    private static final AtomicBoolean PREPARING_NOTIFICATION = new AtomicBoolean();
    private static volatile Notification notificationTemplate;
    private static ProxyVpnService live;
    private static long sequence = SystemClock.elapsedRealtimeNanos();
    private static long requestedGeneration;
    private static boolean startFailed;
    private long foregroundGeneration;
    static volatile boolean captureCarrierInodesForTest;
    private long carrierInode4 = -1;
    private long carrierInode6 = -1;

    // Only the explicit, non-exported service component accepts this action. Binding
    // creates the service without invoking onStartCommand or installing a VPN.
    @Override public IBinder onBind(Intent intent) {
        if (intent != null && PREPARE_BINDING.equals(intent.getAction())) return new Binder();
        return super.onBind(intent);
    }

    static ConsentBinding bindWhileAwaitingConsent(Context context) {
        // Called from the activity main thread after the system prompt has been launched.
        releaseConsentBinding();
        Context application = context.getApplicationContext();
        ConsentBinding binding = new ConsentBinding(application);
        try {
            Intent intent = new Intent(application, ProxyVpnService.class).setAction(PREPARE_BINDING);
            if (application.bindService(intent, binding, Context.BIND_AUTO_CREATE)) {
                consentBinding = binding;
                MAIN.postDelayed(binding.timeout, 10_000);
                return binding;
            }
        } catch (RuntimeException unavailable) {
            // A device which refuses this optional binding follows standard startup.
        }
        binding.close();
        return null;
    }

    private static void releaseConsentBinding() {
        ConsentBinding binding = consentBinding;
        if (binding == null) return;
        if (Looper.myLooper() == Looper.getMainLooper()) binding.close();
        else MAIN.post(binding.timeout);
    }

    static final class ConsentBinding implements ServiceConnection, AutoCloseable {
        private final Context context;
        private final Runnable timeout = this::close;
        private boolean closed;

        ConsentBinding(Context context) {
            this.context = context;
        }

        @Override public void onServiceConnected(ComponentName name, IBinder binder) {}
        @Override public void onServiceDisconnected(ComponentName name) {}
        @Override public void onBindingDied(ComponentName name) { close(); }
        @Override public void onNullBinding(ComponentName name) { close(); }

        @Override public void close() {
            // All ServiceConnection callbacks and this cleanup run on the main thread.
            if (closed) return;
            closed = true;
            if (consentBinding == this) consentBinding = null;
            MAIN.removeCallbacks(timeout);
            try {
                context.unbindService(this);
            } catch (IllegalArgumentException alreadyReleased) {
                // A failed bind may not have registered its ServiceConnection.
            }
        }
    }

    static void prepareNotification(Context context) {
        if (notificationTemplate != null || !PREPARING_NOTIFICATION.compareAndSet(false, true)) {
            return;
        }
        try {
            new Thread(() -> {
                try {
                    notification(context);
                } catch (RuntimeException ignored) {
                    // Service startup can build the notification normally.
                } finally {
                    PREPARING_NOTIFICATION.set(false);
                }
            }, "ProxyNotificationPreparation").start();
        } catch (RuntimeException ignored) {
            PREPARING_NOTIFICATION.set(false);
        }
    }

    static long requestPreparation(Context context) throws IOException {
        return requestStart(context, false);
    }

    static long requestStart(Context context) throws IOException {
        return requestStart(context, true);
    }

    private static long requestStart(Context context, boolean requireForeground) throws IOException {
        long generation;
        synchronized (LIFECYCLE) {
            generation = ++sequence;
            requestedGeneration = generation;
            startFailed = false;
        }
        long deadline = SystemClock.elapsedRealtime() + START_TIMEOUT_MS;
        try {
            Intent intent = new Intent(context, ProxyVpnService.class).setAction(START)
                    .putExtra(START_GENERATION, generation).putExtra(FOREGROUND_REQUIRED, requireForeground);
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
        } finally {
            // Once Android accepts a start request it owns the service lifetime.
            releaseConsentBinding();
        }
        return deadline;
    }

    static void awaitStart(long deadline, TunnelEngine.Callback callback)
            throws IOException, InterruptedException {
        synchronized (LIFECYCLE) {
            while (!callback.cancelled() && !startFailed) {
                if (live != null && requestedGeneration != 0 && live.foregroundGeneration == requestedGeneration) {
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
        releaseConsentBinding();
        synchronized (LIFECYCLE) {
            requestedGeneration = 0;
            LIFECYCLE.notifyAll();
        }
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

    @Override public boolean protect(int socket) {
        boolean protectedFromTunnel = super.protect(socket);
        if (protectedFromTunnel && captureCarrierInodesForTest) {
            // Pinned GoBackend calls this public service API for its own v4/v6 UDP
            // sockets. Duplicate briefly so collecting metadata cannot close its FD.
            try (ParcelFileDescriptor copy = ParcelFileDescriptor.fromFd(socket)) {
                SocketAddress local = Os.getsockname(copy.getFileDescriptor());
                if (local instanceof InetSocketAddress address) {
                    long inode = Os.fstat(copy.getFileDescriptor()).st_ino;
                    synchronized (LIFECYCLE) {
                        if (address.getAddress() instanceof Inet4Address) carrierInode4 = inode;
                        if (address.getAddress() instanceof Inet6Address) carrierInode6 = inode;
                    }
                    logCarrierReceiveOptionsForTest(copy.getFd(), address.getAddress() instanceof Inet6Address);
                }
            } catch (IOException | ErrnoException | RuntimeException unavailable) {
                // Socket protection itself succeeded. Diagnostics are optional.
            }
        }
        return protectedFromTunnel;
    }

    // Observes a duplicate of an already-protected FD only during load acceptance.
    private static native int[] carrierReceiveOptionsForTest(int fd);

    private static void logCarrierReceiveOptionsForTest(int fd, boolean ipv6) {
        int receiveBytes = -1;
        int gro = -1;
        try {
            int[] options = carrierReceiveOptionsForTest(fd);
            if (options != null && options.length == 2) {
                receiveBytes = options[0];
                gro = options[1];
            }
        } catch (UnsatisfiedLinkError unavailable) {
            // Stock upstream libraries on 32-bit devices do not include this observation.
        }
        Log.i("ProxySpeedAcceptance", "ANDROID_PERF_CARRIER_SOCKET_" + (ipv6 ? "V6" : "V4")
                + "=RCVBUF_BYTES:" + receiveBytes + ";UDP_GRO:" + gro);
    }

    static long[] carrierInodesForTest() {
        synchronized (LIFECYCLE) {
            return live == null ? new long[]{-1, -1} : new long[]{live.carrierInode4, live.carrierInode6};
        }
    }

    @Override public Builder getBuilder() {
        // Enabled explicitly on the dedicated acceptance emulator.
        if (!Log.isLoggable("ProxyVpnTiming", Log.DEBUG)) {
            return super.getBuilder();
        }
        return new Builder() {
            @Override public ParcelFileDescriptor establish() {
                long started = SystemClock.elapsedRealtimeNanos();
                try {
                    return super.establish();
                } finally {
                    Log.d("ProxyVpnTiming", "ESTABLISH_NS=" + (SystemClock.elapsedRealtimeNanos() - started));
                }
            }
        };
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
        long generation = intent.getLongExtra(START_GENERATION, 0);
        boolean current;
        synchronized (LIFECYCLE) {
            current = generation != 0 && generation == requestedGeneration;
        }
        // A cancelled preparation can already have an onStartCommand posted
        // on Android's main thread. Stop only this startId if it arrives late.
        if (!current && !intent.getBooleanExtra(FOREGROUND_REQUIRED, false)) {
            stopSelfResult(startId);
            return START_NOT_STICKY;
        }
        try {
            // Even a superseded startForegroundService request has to promote
            // before stopping; a normal preparation above has no such contract.
            Notification notification = notification(this).clone();
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFICATION, notification,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
            } else {
                startForeground(NOTIFICATION, notification);
            }
            synchronized (LIFECYCLE) {
                if (generation != 0 && generation == requestedGeneration) {
                    foregroundGeneration = generation;
                    LIFECYCLE.notifyAll();
                    return START_NOT_STICKY;
                }
            }
        } catch (RuntimeException error) {
            synchronized (LIFECYCLE) {
                if (generation == requestedGeneration) {
                    startFailed = true;
                    LIFECYCLE.notifyAll();
                }
            }
        }
        stopSelfResult(startId);
        return START_NOT_STICKY;
    }

    private static Notification notification(Context context) {
        Notification prepared = notificationTemplate;
        if (prepared != null) {
            return prepared;
        }
        NotificationManager notifications = context.getSystemService(NotificationManager.class);
        NotificationChannel channel = new NotificationChannel(CHANNEL, "VPN 连接",
                NotificationManager.IMPORTANCE_LOW);
        notifications.createNotificationChannel(channel);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE;
        Intent open = new Intent(context, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent openAction = PendingIntent.getActivity(context, 0, open, flags);
        Intent disconnect = new Intent(context, ProxyVpnService.class).setAction(DISCONNECT);
        PendingIntent disconnectAction = PendingIntent.getService(context, 1, disconnect, flags);
        Notification built = new Notification.Builder(context, CHANNEL)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("Proxy")
                .setContentText("VPN 服务运行中")
                .setContentIntent(openAction)
                .setOnlyAlertOnce(true)
                .setOngoing(true)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .addAction(new Notification.Action.Builder(null, "断开", disconnectAction).build())
                .build();
        notificationTemplate = built;
        return built;
    }

    @Override public void onDestroy() {
        synchronized (LIFECYCLE) {
            foregroundGeneration = 0;
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
