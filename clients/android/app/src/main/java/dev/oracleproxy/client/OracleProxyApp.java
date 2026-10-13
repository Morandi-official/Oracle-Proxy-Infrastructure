package dev.oracleproxy.client;

import android.app.Application;

import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.config.Config;

/**
 * In-memory app state. No keys/configs are saved to disk or Android backups.
 * This alpha is intentionally not an always-on reconnect service.
 */
public final class OracleProxyApp extends Application {
    private GoBackend backend;
    private Config config;

    private final Tunnel tunnel = new Tunnel() {
        @Override public String getName() {
            return "oracle";
        }

        @Override public void onStateChange(final State newState) {
            // The library's UP state indicates a tunnel process exists,
            // NOT proof of a fresh WireGuard handshake or no leakage.
        }
    };

    synchronized GoBackend backend() {
        if (backend == null) {
            backend = new GoBackend(this);
        }
        return backend;
    }

    synchronized Config getConfig() {
        return config;
    }

    synchronized void setConfig(final Config importedConfig) {
        config = importedConfig;
    }

    Tunnel getTunnel() {
        return tunnel;
    }
}
