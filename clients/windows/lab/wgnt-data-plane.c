/* G12: encrypted UDP packet counters across real upstream Windows SCM peers.
 * Strictly disposable GitHub Windows runner ONLY. No driver installation,
 * service start/stop, adapter creation, WFP, DNS or default route manipulation.
 * Prints only counters (no key material or identity).
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include "wireguard.h"

typedef struct { uint64_t tx, rx, handshake; } SNAP;

static int read_snap(WIREGUARD_GET_CONFIGURATION_FUNC *query,
                     WIREGUARD_ADAPTER_HANDLE adapter, SNAP *s) {
    unsigned char storage[4096] = {0};
    DWORD length = sizeof(storage);
    if (!query(adapter, (WIREGUARD_INTERFACE *)storage, &length) ||
        length < sizeof(WIREGUARD_INTERFACE) + sizeof(WIREGUARD_PEER)) return 0;
    WIREGUARD_INTERFACE *iface = (WIREGUARD_INTERFACE *)storage;
    if (iface->PeersCount != 1) return 0;
    WIREGUARD_PEER *peer =
        (WIREGUARD_PEER *)(storage + sizeof(WIREGUARD_INTERFACE));
    s->tx = peer->TxBytes;
    s->rx = peer->RxBytes;
    s->handshake = peer->LastHandshake;
    SecureZeroMemory(storage,sizeof(storage));
    return 1;
}

static int send_lab_packets(const char *source, const char *destination) {
    SOCKET fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == INVALID_SOCKET) return 0;
    struct sockaddr_in src = {0}, dest = {0};
    src.sin_family = AF_INET;
    src.sin_port = htons(0);
    src.sin_addr.s_addr = inet_addr(source);
    dest.sin_family = AF_INET;
    dest.sin_port = htons(55002);
    dest.sin_addr.s_addr = inet_addr(destination);
    if (bind(fd, (struct sockaddr *)&src, sizeof(src)) != 0) {
        closesocket(fd);
        return 0;
    }
    char data[144] = "OracleProxy G12 isolated encrypted-payload probe (not a leak/no-VPN test)";
    int accepted = 0;
    for (int i = 0; i < 32; i++) {
        data[140] = (char)i;
        int bytes = sendto(fd,data,sizeof(data),0,(struct sockaddr *)&dest,sizeof(dest));
        if (bytes == (int)sizeof(data)) accepted++;
        Sleep(30);
    }
    closesocket(fd);
    return accepted > 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2 || wcslen(argv[1]) > 500) return 2;
    HMODULE dll = LoadLibraryExW(argv[1], NULL,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!dll) {
        fputs("DATA_LAB_FAIL: signed driver DLL failed to load\n", stderr);
        return 2;
    }

    WIREGUARD_OPEN_ADAPTER_FUNC *open_adapter =
        (void *)GetProcAddress(dll,"WireGuardOpenAdapter");
    WIREGUARD_CLOSE_ADAPTER_FUNC *close_adapter =
        (void *)GetProcAddress(dll,"WireGuardCloseAdapter");
    WIREGUARD_GET_CONFIGURATION_FUNC *get_config =
        (void *)GetProcAddress(dll,"WireGuardGetConfiguration");
    if (!open_adapter || !close_adapter || !get_config) {
        FreeLibrary(dll);
        return 2;
    }

    int ok = 0;
    WIREGUARD_ADAPTER_HANDLE a = open_adapter(L"lab-peer-a");
    WIREGUARD_ADAPTER_HANDLE b = open_adapter(L"lab-peer-b");
    if (!a || !b) {
        fputs("DATA_LAB_FAIL: both test tunnels must already be running\n",stderr);
        goto done;
    }
    SNAP before_a={0}, before_b={0}, after_a={0}, after_b={0};
    if (!read_snap(get_config,a,&before_a) || !read_snap(get_config,b,&before_b) ||
        before_a.handshake == 0 || before_b.handshake == 0) {
        fputs("DATA_LAB_FAIL: no verified handshake baseline\n",stderr);
        goto done;
    }

    WSADATA ws;
    if (WSAStartup(MAKEWORD(2,2), &ws) != 0) goto done;
    int send_a = send_lab_packets("10.249.129.1","10.249.129.2");
    int send_b = send_lab_packets("10.249.129.2","10.249.129.1");
    WSACleanup();
    if (!send_a || !send_b) {
        fputs("DATA_LAB_FAIL: scoped UDP socket bind/send did not succeed\n",stderr);
        goto done;
    }

    for (int i=0;i<10;i++) {
        Sleep(600);
        if (!read_snap(get_config,a,&after_a) || !read_snap(get_config,b,&after_b))
            continue;
        if (after_a.tx > before_a.tx && after_a.rx > before_a.rx &&
            after_b.tx > before_b.tx && after_b.rx > before_b.rx) {
            puts("DATA_LAB_PASS: both real WireGuardNT peers transmitted and received encrypted IPv4 user packets; no routes/WFP/DNS changed by probe");
            ok = 1; break;
        }
    }
    if (!ok) {
        /* No secrets; these are limited test-only link counters. */
        fprintf(stderr, "DATA_LAB_FAIL: driver byte counters did not all advance (A tx:%llu rx:%llu; B tx:%llu rx:%llu)\n",
           (unsigned long long)(after_a.tx-before_a.tx),
           (unsigned long long)(after_a.rx-before_a.rx),
           (unsigned long long)(after_b.tx-before_b.tx),
           (unsigned long long)(after_b.rx-before_b.rx));
    }

done:
    if (b) close_adapter(b);
    if (a) close_adapter(a);
    FreeLibrary(dll);
    return ok ? 0 : 1;
}
