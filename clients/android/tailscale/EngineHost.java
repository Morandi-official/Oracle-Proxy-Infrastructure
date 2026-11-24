package org.morandi.proxy.tailscale;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.RouteInfo;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Collections;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import libtailscale.AppContext;
import libtailscale.Application;
import libtailscale.Libtailscale;
import org.json.JSONArray;
import org.json.JSONObject;

/** Android platform adapter for a single Tailscale engine and its private identity. */
final class EngineHost implements AppContext {
    private static final String KEY_ALIAS = "org.morandi.proxy.tailscale.state";
    private static final String PREFIX = "statestore-";
    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final int NONCE_BYTES = 12;
    static final Executor WORKER = Executors.newSingleThreadExecutor();
    private static EngineHost host;

    private final Context context;
    private final SharedPreferences state;
    private final ConnectivityManager networks;
    private Application engine;
    private NetworkSnapshot publishedNetwork;
    private BridgeVpnService vpn;

    private EngineHost(Context context) {
        this.context = context.getApplicationContext();
        state = this.context.getSharedPreferences("tailscale_state", Context.MODE_PRIVATE);
        networks = this.context.getSystemService(ConnectivityManager.class);
    }

    static synchronized EngineHost from(Context context) {
        if (host == null) {
            host = new EngineHost(context);
        }
        return host;
    }

    synchronized Application engine() throws IOException {
        if (engine == null) {
            var root = new java.io.File(context.getNoBackupFilesDir(), "tailscale");
            if (!root.isDirectory() && !root.mkdirs()) {
                throw new IOException("TAILSCALE_STATE_DIRECTORY_UNAVAILABLE");
            }
            engine = Libtailscale.start(root.getAbsolutePath(), "", false, this);
            var request = new NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build();
            networks.registerNetworkCallback(request, new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(Network network) { scheduleNetworkUpdate(); }
                @Override public void onLost(Network network) { scheduleNetworkUpdate(); }
                @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
                    scheduleNetworkUpdate();
                }
                @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
                    scheduleNetworkUpdate();
                }
            });
            scheduleNetworkUpdate();
        }
        return engine;
    }

    private SecretKey stateKey(boolean create) throws Exception {
        KeyStore keys = KeyStore.getInstance("AndroidKeyStore");
        keys.load(null);
        if (keys.getKey(KEY_ALIAS, null) instanceof SecretKey secret) {
            return secret;
        }
        if (!create || !state.getAll().isEmpty()) {
            throw new IOException("TAILSCALE_STATE_KEY_MISSING");
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return generator.generateKey();
    }

    @Override
    public synchronized void encryptToPref(String name, String value) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, stateKey(true));
        if (cipher.getIV().length != NONCE_BYTES) {
            throw new IOException("TAILSCALE_STATE_NONCE_INVALID");
        }
        cipher.updateAAD(name.getBytes(StandardCharsets.UTF_8));
        byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        byte[] stored = ByteBuffer.allocate(NONCE_BYTES + encrypted.length)
                .put(cipher.getIV()).put(encrypted).array();
        if (!state.edit().putString(name, Base64.encodeToString(stored, Base64.NO_WRAP)).commit()) {
            throw new IOException("TAILSCALE_STATE_WRITE_FAILED");
        }
    }

    @Override
    public synchronized String decryptFromPref(String name) throws Exception {
        String value = state.getString(name, null);
        if (value == null) {
            return "";
        }
        byte[] stored = Base64.decode(value, Base64.NO_WRAP);
        if (stored.length < NONCE_BYTES + 16) {
            throw new IOException("TAILSCALE_STATE_INVALID");
        }
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, stateKey(false), new GCMParameterSpec(128, stored, 0, NONCE_BYTES));
        cipher.updateAAD(name.getBytes(StandardCharsets.UTF_8));
        return new String(cipher.doFinal(stored, NONCE_BYTES, stored.length - NONCE_BYTES), StandardCharsets.UTF_8);
    }

    @Override
    public String getStateStoreKeysJSON() {
        JSONArray keys = new JSONArray();
        for (String name : state.getAll().keySet()) {
            if (name.startsWith(PREFIX)) {
                keys.put(name.substring(PREFIX.length()));
            }
        }
        return keys.toString();
    }

    Network underlyingNetwork() {
        Network active = networks.getActiveNetwork();
        if (isInternetNetwork(active)) {
            return active;
        }
        Network fallback = null;
        for (Network candidate : networks.getAllNetworks()) {
            if (isInternetNetwork(candidate)) {
                NetworkCapabilities capabilities = networks.getNetworkCapabilities(candidate);
                if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                        && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    return candidate;
                }
                if (fallback == null) {
                    fallback = candidate;
                }
            }
        }
        return fallback;
    }

    void attach(BridgeVpnService service) {
        vpn = service;
        Libtailscale.requestVPN(service);
        service.updateUnderlyingNetwork(underlyingNetwork());
        scheduleNetworkUpdate();
    }

    void detach(BridgeVpnService service) {
        if (vpn == service) {
            vpn = null;
        }
        Libtailscale.serviceDisconnect(service);
    }

    private void scheduleNetworkUpdate() {
        WORKER.execute(this::publishNetwork);
    }

    private void publishNetwork() {
        Network network = underlyingNetwork();
        LinkProperties properties = network == null ? null : networks.getLinkProperties(network);
        if (network != null && properties == null) {
            return;  // A later link-properties callback supplies the full route and DNS snapshot.
        }
        String iface = "";
        String gateway = "";
        StringBuilder dns = new StringBuilder();
        if (properties != null) {
            iface = properties.getInterfaceName() == null ? "" : properties.getInterfaceName();
            for (RouteInfo route : properties.getRoutes()) {
                if (route.isDefaultRoute() && route.getGateway() != null) {
                    gateway = route.getGateway().getHostAddress();
                    if (route.getGateway() instanceof Inet4Address) break;
                }
            }
            for (var server : properties.getDnsServers()) {
                dns.append(server.getHostAddress()).append(' ');
            }
            if (properties.getDomains() != null) {
                dns.append('\n').append(properties.getDomains());
            }
        }
        var next = new NetworkSnapshot(network, iface, gateway, dns.toString());
        if (!next.equals(publishedNetwork)) {
            publishedNetwork = next;
            Libtailscale.onAndroidNetworkChanged(iface, network == null ? 0 : network.getNetworkHandle(),
                    gateway, next.dns());
            if (vpn != null) {
                vpn.updateUnderlyingNetwork(network);
            }
        }
    }

    private record NetworkSnapshot(Network network, String iface, String gateway, String dns) {}

    private boolean isInternetNetwork(Network network) {
        NetworkCapabilities available = network == null ? null : networks.getNetworkCapabilities(network);
        return available != null && available.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                && available.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
    }

    @Override
    public boolean bindSocketToNetwork(int descriptor) {
        Network network = underlyingNetwork();
        if (network == null) {
            return false;
        }
        try (ParcelFileDescriptor socket = ParcelFileDescriptor.fromFd(descriptor)) {
            network.bindSocket(socket.getFileDescriptor());
            return true;
        } catch (IOException | RuntimeException failure) {
            return false;
        }
    }

    @Override
    public String getInterfacesAsJson() throws Exception {
        JSONArray interfaces = new JSONArray();
        var all = NetworkInterface.getNetworkInterfaces();
        if (all != null) {
            for (NetworkInterface net : Collections.list(all)) {
                JSONArray addresses = new JSONArray();
                for (InterfaceAddress address : net.getInterfaceAddresses()) {
                    String ip = address.getAddress().getHostAddress();
                    int zone = ip.indexOf('%');
                    addresses.put(new JSONObject().put("ip", zone < 0 ? ip : ip.substring(0, zone))
                            .put("prefixLen", address.getNetworkPrefixLength()));
                }
                interfaces.put(new JSONObject().put("name", net.getName()).put("index", net.getIndex())
                        .put("mtu", net.getMTU()).put("up", net.isUp()).put("loopback", net.isLoopback())
                        .put("pointToPoint", net.isPointToPoint()).put("multicast", net.supportsMulticast())
                        .put("addrs", addresses));
            }
        }
        return interfaces.toString();
    }

    @Override public String getOSVersion() { return Build.VERSION.RELEASE; }
    @Override public long getSDKInt() { return Build.VERSION.SDK_INT; }
    @Override public String getDeviceName() { return Build.MODEL; }
    @Override public String getInstallSource() { return ""; }
    @Override public boolean shouldUseGoogleDNSFallback() { return false; }
    @Override public boolean isChromeOS() { return context.getPackageManager().hasSystemFeature("android.hardware.type.pc"); }
    @Override public boolean isClientLoggingEnabled() { return false; }
    @Override public void log(String tag, String line) { }
    @Override public byte[] getUserCACertsPEM() { return new byte[0]; }
    @Override public String getSyspolicyStringValue(String key) throws IOException { throw new IOException("no such key"); }
    @Override public boolean getSyspolicyBooleanValue(String key) throws IOException { throw new IOException("no such key"); }
    @Override public String getSyspolicyStringArrayJSONValue(String key) throws IOException { throw new IOException("no such key"); }
    @Override public boolean hardwareAttestationKeySupported() { return false; }
    @Override public String hardwareAttestationKeyCreate() { throw new UnsupportedOperationException(); }
    @Override public void hardwareAttestationKeyRelease(String id) { throw new UnsupportedOperationException(); }
    @Override public byte[] hardwareAttestationKeyPublic(String id) { throw new UnsupportedOperationException(); }
    @Override public byte[] hardwareAttestationKeySign(String id, byte[] data) { throw new UnsupportedOperationException(); }
    @Override public void hardwareAttestationKeyLoad(String id) { throw new UnsupportedOperationException(); }
}
