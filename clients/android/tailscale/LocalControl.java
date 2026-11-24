package org.morandi.proxy.tailscale;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import libtailscale.Application;
import libtailscale.LocalAPIResponse;
import org.json.JSONObject;

/** Reads the daemon directly through its JNI binding on a worker thread. */
public final class LocalControl {
    private static final String STATUS = "/localapi/v0/status?peers=false";
    private static final int MAX_STATUS_BYTES = 65_536;
    private final Application application;

    public LocalControl(Application application) {
        this.application = Objects.requireNonNull(application);
    }

    public DaemonState readState() throws IOException {
        try {
            LocalAPIResponse response = application.callLocalAPI(3_000, "GET", STATUS, null);
            byte[] bytes = response.bodyBytes();
            if (response.statusCode() != 200 || bytes == null || bytes.length > MAX_STATUS_BYTES) {
                throw new IOException("INVALID_TAILSCALE_STATUS");
            }
            JSONObject state = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
            return new DaemonState(state.getString("BackendState"), state.optBoolean("HaveNodeKey"));
        } catch (Exception error) {
            // Native errors may include URLs so the caller receives a fixed code.
            throw new IOException("TAILSCALE_LOCAL_CONTROL_UNAVAILABLE");
        }
    }

    public record DaemonState(String state, boolean hasNodeKey) {}
}
