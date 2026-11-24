package org.morandi.proxy.tailscale;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.net.IpPrefix;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import libtailscale.IPNService;
import libtailscale.ParcelFileDescriptor;
import libtailscale.VPNServiceBuilder;

/** Owns the Android VPN interface requested by the Tailscale engine. */
public final class BridgeVpnService extends VpnService implements IPNService {
    static final String START = "org.morandi.proxy.action.START_TAILSCALE";
    private static final String PREPARE = "org.morandi.proxy.action.PREPARE_TAILSCALE";
    private static final String ATTEMPT = "proxy_attempt";
    private static final String CHANNEL = "tailscale_vpn";
    private static final int NOTIFICATION = 7721;
    private static final AtomicLong ATTEMPTS = new AtomicLong();
    // These service handles are installed and consumed on the main thread.
    private static BridgeVpnService prepared;
    private static long pendingPreparation;
    private final String identifier = UUID.randomUUID().toString();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final AtomicBoolean closed = new AtomicBoolean();
    private boolean attached;
    private boolean authorized;
    private long preparedAttempt;
    private long preparedAtMs;

    static long prepareForeground(Context context) {
        long attempt = ATTEMPTS.incrementAndGet();
        prepared = null;
        pendingPreparation = attempt;
        try {
            context.startForegroundService(new Intent(context, BridgeVpnService.class)
                    .setAction(PREPARE).putExtra(ATTEMPT, attempt));
            return attempt;
        } catch (RuntimeException unavailable) {
            // Keep the ordinary authorized service start available if preparation was rejected.
            pendingPreparation = 0;
            return 0;
        }
    }

    static long startAuthorized(Context context, long attempt) {
        var service = prepared;
        boolean current = attempt != 0 && pendingPreparation == attempt;
        pendingPreparation = 0;
        prepared = null;
        if (current && service != null && service.preparedAttempt == attempt
                && !service.closed.get() && prepare(context) == null) {
            service.attachAuthorized();
            return service.preparedAtMs;
        }
        context.startForegroundService(new Intent(context, BridgeVpnService.class).setAction(START));
        return -1;
    }

    static void stop(Context context) {
        prepared = null;
        pendingPreparation = 0;
        context.stopService(new Intent(context, BridgeVpnService.class));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        boolean preparing = PREPARE.equals(action);
        long attempt = preparing ? intent.getLongExtra(ATTEMPT, 0) : 0;
        if (preparing && (attempt == 0 || attempt != pendingPreparation)) {
            if (!authorized && pendingPreparation == 0) stopSelf(startId);
            return START_NOT_STICKY;
        }
        if ((!START.equals(action) && !preparing) || prepare(this) != null) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        startForeground(NOTIFICATION, notification("正在准备 VPN"));
        if (preparing) {
            preparedAttempt = attempt;
            preparedAtMs = SystemClock.elapsedRealtime();
            prepared = this;
            return START_NOT_STICKY;
        }
        if (prepared == this) prepared = null;
        attachAuthorized();
        return START_NOT_STICKY;
    }

    private void attachAuthorized() {
        authorized = true;
        EngineHost.WORKER.execute(() -> {
            if (closed.get() || attached) {
                return;
            }
            try {
                EngineHost host = EngineHost.from(this);
                host.engine();
                host.attach(this);
                attached = true;
            } catch (IOException | RuntimeException failure) {
                disconnectVPN();
            }
        });
    }

    @Override
    public String id() {
        return identifier;
    }

    @Override
    public VPNServiceBuilder newBuilder() {
        VpnService.Builder builder = new Builder().setSession("Proxy");
        Network network = EngineHost.from(this).underlyingNetwork();
        if (network != null) {
            builder.setUnderlyingNetworks(new Network[] { network });
        }
        return new TunnelBuilder(builder);
    }

    void updateUnderlyingNetwork(Network network) {
        main.post(() -> {
            if (!closed.get()) {
                setUnderlyingNetworks(network == null ? new Network[0] : new Network[] { network });
            }
        });
    }

    @Override
    public void updateVpnStatus(boolean active) {
        if (active) {
            main.post(() -> {
                if (!closed.get()) {
                    getSystemService(NotificationManager.class)
                            .notify(NOTIFICATION, notification("VPN 已启动"));
                }
            });
        }
    }

    @Override
    public void close() {
        disconnectVPN();
    }

    @Override
    public void disconnectVPN() {
        main.post(this::stopSelf);
    }

    @Override
    public void onRevoke() {
        detach();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        if (prepared == this) {
            prepared = null;
            if (pendingPreparation == preparedAttempt) pendingPreparation = 0;
        }
        detach();
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }

    private void detach() {
        if (closed.compareAndSet(false, true)) {
            EngineHost.WORKER.execute(() -> {
                if (attached) {
                    EngineHost.from(this).detach(this);
                    attached = false;
                }
            });
        }
    }

    private Notification notification(String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW));
        int icon = getApplicationInfo().icon;
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(icon)
                .setContentTitle("Proxy")
                .setContentText(text)
                .setOngoing(true)
                .build();
    }

    private static final class TunnelBuilder implements VPNServiceBuilder {
        private final VpnService.Builder builder;

        TunnelBuilder(VpnService.Builder builder) {
            this.builder = builder;
        }

        @Override public void setMTU(int mtu) { builder.setMtu(mtu); }
        @Override public void addDNSServer(String server) { builder.addDnsServer(server); }
        @Override public void addSearchDomain(String domain) { builder.addSearchDomain(domain); }
        @Override public void addRoute(String address, int bits) { builder.addRoute(address, bits); }
        @Override public void addAddress(String address, int bits) { builder.addAddress(address, bits); }

        @Override
        public void excludeRoute(String address, int bits) throws UnknownHostException {
            if (Build.VERSION.SDK_INT >= 33) {
                builder.excludeRoute(new IpPrefix(InetAddress.getByName(address), bits));
            }
        }

        @Override
        public ParcelFileDescriptor establish() throws IOException {
            android.os.ParcelFileDescriptor descriptor = builder.establish();
            if (descriptor == null) {
                throw new IOException("TAILSCALE_VPN_PERMISSION_REQUIRED");
            }
            return descriptor::detachFd;
        }
    }
}
