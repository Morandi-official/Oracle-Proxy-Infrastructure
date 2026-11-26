package org.morandi.proxy;

import android.app.UiAutomation;
import android.net.LinkProperties;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

/** Read-only guest and protected WireGuard socket counters for a transfer interval. */
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
    private final long[] carrierInodes;

    GuestLoadCounters(UiAutomation automation, LinkProperties vpn, LinkProperties physical, boolean upload) {
        this.automation = automation;
        this.vpn = vpn;
        this.physical = physical;
        direction = upload ? "UPLOAD" : "DOWNLOAD";
        carrierInodes = ProxyVpnService.carrierInodesForTest();
        before = snapshot();
    }

    private Map<String, Long> snapshot() {
        // All paths are fixed. Never copy raw proc or shell output into logs.
        try {
            ParcelFileDescriptor handle = automation.executeShellCommand(
                    "cat /proc/net/snmp /proc/net/dev /proc/net/udp /proc/net/udp6");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new ParcelFileDescriptor.AutoCloseInputStream(handle), StandardCharsets.US_ASCII))) {
                return read(reader, vpn == null ? null : vpn.getInterfaceName(),
                        physical == null ? null : physical.getInterfaceName(), carrierInodes, Process.myUid());
            }
        } catch (IOException | RuntimeException denied) {
            return Collections.emptyMap();
        }
    }

    static Map<String, Long> read(BufferedReader reader, String tunnel, String physical,
                                  long[] carrier, int uid) throws IOException {
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
                number(values, label + ".TxPackets", fields[9]);
            } else if (!name.isEmpty() && Character.isDigit(name.charAt(0)) && fields.length == 12
                    && fields[6].equals(Integer.toString(uid))) {
                // Kernel udp{,6} prints UID, inode and socket drops at these positions.
                // Only the actual service-owned socket inode and its family qualify.
                boolean v6 = fields[0].indexOf(':') == 32;
                int family = v6 ? 1 : 0;
                if ((v6 || fields[0].indexOf(':') == 8) && carrier[family] > 0
                        && fields[8].equals(Long.toString(carrier[family]))) {
                    number(values, v6 ? "Carrier6.Drops" : "Carrier4.Drops", fields[11]);
                }
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
        boolean same = Arrays.equals(carrierInodes, ProxyVpnService.carrierInodesForTest());
        Log.i("ProxySpeedAcceptance", "ANDROID_PERF_CARRIER_" + direction
                + "=V4_SOCKET_DROPS:" + (same ? delta(before, after, "Carrier4.Drops") : -1)
                + ";V6_SOCKET_DROPS:" + (same ? delta(before, after, "Carrier6.Drops") : -1)
                + ";TUN_TX_PACKETS:" + delta(before, after, "Tun.TxPackets"));
    }
}
