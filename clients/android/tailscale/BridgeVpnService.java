package org.morandi.proxy.tailscale;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.IpPrefix;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import libtailscale.IPNService;
import libtailscale.ParcelFileDescriptor;
import libtailscale.VPNServiceBuilder;

/** Owns the Android VPN interface requested by the Tailscale engine. */
public final class BridgeVpnService extends VpnService implements IPNService {
    private static final String CHANNEL = "tailscale_vpn";
    private static final int NOTIFICATION = 7721;
    private final String identifier = UUID.randomUUID().toString();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final AtomicBoolean closed = new AtomicBoolean();
    private boolean attached;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (prepare(this) != null) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        startForeground(NOTIFICATION, notification("正在准备 VPN"));
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
        return START_NOT_STICKY;
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
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
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
