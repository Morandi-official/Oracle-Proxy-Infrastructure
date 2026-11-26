package org.morandi.proxy;

import android.app.UiAutomation;
import android.net.LinkProperties;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

/** Read-only instrumentation. These are aggregate guest counters for the load interval. */
final class GuestLoadCounters implements AutoCloseable {
    private static final String[] COUNTERS = {
            "Udp.InErrors", "Udp.RcvbufErrors", "Udp.SndbufErrors", "Udp.InCsumErrors",
            "Ip.ReasmReqds", "Ip.ReasmFails", "Ip.FragFails", "Ip.InDiscards", "Ip.OutDiscards",
            "Tcp.OutSegs", "Tcp.RetransSegs", "Tun.RxDrop", "Tun.TxDrop", "Nic.RxDrop", "Nic.TxDrop"
    };

    private final UiAutomation automation;
    private final LinkProperties vpn;
    private final LinkProperties physical;
    private final String direction;
    private final Map<String, Long> before;

    GuestLoadCounters(UiAutomation automation, LinkProperties vpn, LinkProperties physical, boolean upload) {
        this.automation = automation;
        this.vpn = vpn;
        this.physical = physical;
        direction = upload ? "UPLOAD" : "DOWNLOAD";
        before = snapshot();
    }

    private Map<String, Long> snapshot() {
        // Both paths are fixed. Never copy raw proc or shell output into logs.
        try {
            ParcelFileDescriptor handle = automation.executeShellCommand("cat /proc/net/snmp /proc/net/dev");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new ParcelFileDescriptor.AutoCloseInputStream(handle), StandardCharsets.US_ASCII))) {
                return read(reader, vpn == null ? null : vpn.getInterfaceName(),
                        physical == null ? null : physical.getInterfaceName());
            }
        } catch (IOException | RuntimeException denied) {
            return Collections.emptyMap();
        }
    }

    static Map<String, Long> read(BufferedReader reader, String tunnel, String physical) throws IOException {
        Map<String, Long> values = new HashMap<>();
        Map<String, String[]> headers = new HashMap<>();
        String line;
        while ((line = reader.readLine()) != null) {
            int colon = line.indexOf(':');
            if (colon < 1) continue;
            String name = line.substring(0, colon).trim();
            String[] fields = line.substring(colon + 1).trim().split("\\s+");
            if (name.equals("Tcp") || name.equals("Udp") || name.equals("Ip")) {
                if (!Character.isDigit(fields[0].isEmpty() ? ' ' : fields[0].charAt(0))) {
                    headers.put(name, fields);
                } else {
                    String[] header = headers.get(name);
                    if (header == null || header.length != fields.length) continue;
                    for (int i = 0; i < fields.length; i++) {
                        number(values, name + "." + header[i], fields[i]);
                    }
                }
            } else if (fields.length == 16 && (name.equals(tunnel) || name.equals(physical))) {
                String label = name.equals(tunnel) ? "Tun" : "Nic";
                number(values, label + ".RxDrop", fields[3]);
                number(values, label + ".TxDrop", fields[11]);
            }
        }
        return values;
    }

    private static void number(Map<String, Long> values, String field, String raw) {
        try {
            long counter = Long.parseLong(raw);
            if (counter >= 0) values.put(field, counter);
        } catch (NumberFormatException ignored) {
            // A missing or inaccessible counter will be represented by -1.
        }
    }

    static long delta(Map<String, Long> first, Map<String, Long> last, String key) {
        long a = first.getOrDefault(key, -1L);
        long b = last.getOrDefault(key, -1L);
        return a >= 0 && b >= a ? b - a : -1;
    }

    @Override public void close() {
        Map<String, Long> after = snapshot();
        StringJoiner detail = new StringJoiner(";");
        detail.add("TUN_MTU=" + (vpn == null ? -1 : vpn.getMtu()));
        detail.add("NIC_MTU=" + (physical == null ? -1 : physical.getMtu()));
        for (String key : COUNTERS) detail.add(key + "=" + delta(before, after, key));
        Log.i("ProxySpeedAcceptance", "ANDROID_PERF_GUEST_LOAD_" + direction + "=" + detail);
    }
}
