package org.morandi.proxy.tailscale;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.util.Log;

/** Disposable emulator fixture. No production URL or credentials. */
public final class RuntimeFixture extends Activity {
    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        if (VpnService.prepare(this) != null) {
            Log.e("ProxyTailLab", "TAILSCALE_ANDROID_VPN_PERMISSION_MISSING");
            finish();
            return;
        }
        startForegroundService(new Intent(this, BridgeVpnService.class));
        EngineHost.WORKER.execute(() -> {
            try {
                var control = new LocalControl(EngineHost.from(this).engine());
                var state = control.readState();
                if (state.hasNodeKey() || !("NeedsLogin".equals(state.state()) || "Stopped".equals(state.state()))) {
                    throw new IllegalStateException("UNEXPECTED_FIXTURE_NODE_STATE");
                }
                control.stop();
                Log.i("ProxyTailLab", "TAILSCALE_ANDROID_RUNTIME_LOCAL_CONTROL=PASS");
            } catch (Exception failure) {
                Log.e("ProxyTailLab", "TAILSCALE_ANDROID_RUNTIME_FAILED_" + failure.getClass().getSimpleName());
            }
        });
    }
}
