package dev.oracleproxy.client;

import com.wireguard.config.Config;
import com.wireguard.config.Peer;
import com.wireguard.config.InetNetwork;

import java.net.Inet4Address;
import java.net.Inet6Address;

/**
 * Conservative routing preflight, not a no-leak guarantee.
 *
 * The first release does not support per-app exclusions: they require
 * separate UI consent and verification on actual Android versions.
 */
public final class ConfigSafety {
    private ConfigSafety() {}

    public static String rejectReason(final Config config) {
        if (config.getPeers().size() != 1) {
            return "测试版只接受一个 WireGuard Peer。";
        }
        if (config.getInterface().getAddresses().isEmpty()) {
            return "配置缺少客户端 Address。";
        }
        if (config.getInterface().getDnsServers().isEmpty()) {
            return "配置缺少 DNS；本测试版不会使用未知的 DNS 路径。";
        }

        boolean fullIPv4 = false;
        boolean fullIPv6 = false;
        for (final Peer peer : config.getPeers()) {
            if (!peer.getEndpoint().isPresent()) {
                return "配置缺少服务器 Endpoint。";
            }
            for (final InetNetwork network : peer.getAllowedIps()) {
                if (network.getMask() == 0 && network.getAddress() instanceof Inet4Address) {
                    fullIPv4 = true;
                }
                if (network.getMask() == 0 && network.getAddress() instanceof Inet6Address) {
                    fullIPv6 = true;
                }
            }
        }
        if (!fullIPv4 || !fullIPv6) {
            return "测试版要求 IPv4 与 IPv6 默认路由都进入 VPN（0.0.0.0/0、::/0）。";
        }
        if (!config.getInterface().getExcludedApplications().isEmpty() ||
            !config.getInterface().getIncludedApplications().isEmpty()) {
            return "测试版暂不接受应用分流规则；请使用独立测试配置。";
        }
        return null;
    }
}
