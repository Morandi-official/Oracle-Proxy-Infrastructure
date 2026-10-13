/*
 * G6 - REAL WireGuardNT kernel-adapter / localhost handshake laboratory.
 * Copyright 2026. This harness is NOT a Windows application or installer.
 *
 * Runs ONLY on a disposable GitHub-hosted Windows VM. Configures two temporary
 * peers restricted to RFC1918 /32s, UDP 127.0.0.1 and non-default routes.
 * No DNS, WFP edits, route edits, Oracle, existing WireSock or user keys.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "wireguard.h"

#define LAB_PORT_A 52741
#define LAB_PORT_B 52742
#define LAB_A_NAME L"OracleLabTestA"
#define LAB_B_NAME L"OracleLabTestB"

typedef struct ALIGNED(8) {
    WIREGUARD_INTERFACE iface;
    WIREGUARD_PEER peer;
    WIREGUARD_ALLOWED_IP allowed;
} LAB_CONFIG;

static void fail(const char *message) {
    fprintf(stderr, "LAB_FAIL: %s [Win32=%lu]\n", message, (unsigned long)GetLastError());
}

static void configure(LAB_CONFIG *cfg, const unsigned char *private_key,
                      const unsigned char *peer_public, WORD listen_port,
                      WORD endpoint_port, DWORD peer_ip_host) {
    ZeroMemory(cfg, sizeof(*cfg));
    cfg->iface.Flags = WIREGUARD_INTERFACE_HAS_PRIVATE_KEY |
                       WIREGUARD_INTERFACE_HAS_LISTEN_PORT |
                       WIREGUARD_INTERFACE_REPLACE_PEERS;
    cfg->iface.ListenPort = listen_port;
    memcpy(cfg->iface.PrivateKey, private_key, 32);
    cfg->iface.PeersCount = 1;

    cfg->peer.Flags = WIREGUARD_PEER_HAS_PUBLIC_KEY |
                      WIREGUARD_PEER_HAS_ENDPOINT |
                      WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE |
                      WIREGUARD_PEER_REPLACE_ALLOWED_IPS;
    memcpy(cfg->peer.PublicKey, peer_public, 32);
    cfg->peer.PersistentKeepalive = 1;
    cfg->peer.Endpoint.Ipv4.sin_family = AF_INET;
    cfg->peer.Endpoint.Ipv4.sin_port = htons(endpoint_port);
    cfg->peer.Endpoint.Ipv4.sin_addr.s_addr = htonl(0x7f000001u);
    cfg->peer.AllowedIPsCount = 1;

    cfg->allowed.Address.V4.S_un.S_addr = htonl(peer_ip_host);
    cfg->allowed.AddressFamily = AF_INET;
    cfg->allowed.Cidr = 32;
}

static uint64_t handshake(WIREGUARD_GET_CONFIGURATION_FUNC *get_config,
                          WIREGUARD_ADAPTER_HANDLE adapter) {
    /* 4 KiB is ample for this fixed one-peer config, with no dynamic alloc. */
    unsigned char storage[4096] = {0};
    DWORD length = (DWORD)sizeof(storage);
    if (!get_config(adapter, (WIREGUARD_INTERFACE *)storage, &length)) {
        return 0;
    }
    WIREGUARD_INTERFACE *iface = (WIREGUARD_INTERFACE *)storage;
    if (iface->PeersCount != 1 ||
        length < sizeof(WIREGUARD_INTERFACE) + sizeof(WIREGUARD_PEER)) {
        return 0;
    }
    WIREGUARD_PEER *peer = (WIREGUARD_PEER *)(storage + sizeof(WIREGUARD_INTERFACE));
    return peer->LastHandshake;
}

int wmain(int argc, wchar_t **argv) {
    int exit_code = 1;
    FILE *secrets = NULL;
    HMODULE lib = NULL;
    WIREGUARD_ADAPTER_HANDLE a = NULL, b = NULL;
    int a_up = 0, b_up = 0;
    int driver_initially_absent = 0;
    LAB_CONFIG ca = {0}, cb = {0};
    unsigned char keybytes[128] = {0};

    WIREGUARD_CREATE_ADAPTER_FUNC *create = NULL;
    WIREGUARD_CLOSE_ADAPTER_FUNC *close_adapter = NULL;
    WIREGUARD_SET_CONFIGURATION_FUNC *set_config = NULL;
    WIREGUARD_GET_CONFIGURATION_FUNC *get_config = NULL;
    WIREGUARD_SET_ADAPTER_STATE_FUNC *set_state = NULL;
    WIREGUARD_DELETE_DRIVER_FUNC *delete_driver = NULL;
    WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC *driver_version = NULL;

    if (argc != 3 || wcslen(argv[1]) > 500 || wcslen(argv[2]) > 500) {
        fail("Expected absolute DLL and ephemeral secret-file paths");
        goto done;
    }
    if (GetFileAttributesW(argv[1]) == INVALID_FILE_ATTRIBUTES) {
        fail("Pinned vendor DLL missing");
        goto done;
    }

    lib = LoadLibraryExW(argv[1], NULL,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!lib) { fail("Official signed DLL cannot load"); goto done; }

#define BIND(name, symbol) do {                                            \
    name = (void *)GetProcAddress(lib, symbol);                            \
    if (!name) { fail("Official WireGuardNT export unavailable"); goto done; } \
} while (0)
    BIND(create, "WireGuardCreateAdapter");
    BIND(close_adapter, "WireGuardCloseAdapter");
    BIND(set_config, "WireGuardSetConfiguration");
    BIND(get_config, "WireGuardGetConfiguration");
    BIND(set_state, "WireGuardSetAdapterState");
    BIND(delete_driver, "WireGuardDeleteDriver");
    BIND(driver_version, "WireGuardGetRunningDriverVersion");
#undef BIND

    /* Decline to mutate a runner with any preexisting WireGuardNT driver. */
    SetLastError(0);
    if (driver_version() != 0) {
        fail("Preexisting WireGuardNT driver detected; aborting lab");
        goto done;
    }
    driver_initially_absent = 1;

    secrets = _wfopen(argv[2], L"rb");
    if (!secrets || fread(keybytes, 1, sizeof(keybytes), secrets) != sizeof(keybytes) ||
        fgetc(secrets) != EOF) {
        fail("Invalid temporary laboratory keys");
        goto done;
    }
    fclose(secrets); secrets = NULL;

    /* [private A, public B, private B, public A], from ephemeral X25519 keys */
    configure(&ca, keybytes, keybytes + 32, LAB_PORT_A, LAB_PORT_B, 0x0af98102u);
    configure(&cb, keybytes + 64, keybytes + 96, LAB_PORT_B, LAB_PORT_A, 0x0af98101u);
    SecureZeroMemory(keybytes, sizeof(keybytes));

    a = create(LAB_A_NAME, L"WireGuard", NULL);
    if (!a) { fail("Creating isolated lab adapter A failed"); goto done; }
    b = create(LAB_B_NAME, L"WireGuard", NULL);
    if (!b) { fail("Creating isolated lab adapter B failed"); goto done; }

    if (!set_config(a, &ca.iface, (DWORD)sizeof(ca)) ||
        !set_config(b, &cb.iface, (DWORD)sizeof(cb))) {
        fail("Configuring limited /32 peer entries failed");
        goto done;
    }
    SecureZeroMemory(&ca, sizeof(ca));
    SecureZeroMemory(&cb, sizeof(cb));

    if (!set_state(a, WIREGUARD_ADAPTER_STATE_UP)) {
        fail("Starting lab adapter A failed"); goto done;
    }
    a_up = 1;
    if (!set_state(b, WIREGUARD_ADAPTER_STATE_UP)) {
        fail("Starting lab adapter B failed"); goto done;
    }
    b_up = 1;

    for (int i = 0; i < 65; i++) {
        uint64_t a_handshake = handshake(get_config, a);
        uint64_t b_handshake = handshake(get_config, b);
        if (a_handshake != 0 && b_handshake != 0) {
            puts("LAB_PASS: two real WireGuardNT adapters completed a local UDP WireGuard handshake; no default routes/DNS/WFP");
            exit_code = 0;
            break;
        }
        Sleep(1000);
    }
    if (exit_code) fail("No two-sided WireGuard handshake within bounded deadline");

done:
    SecureZeroMemory(keybytes, sizeof(keybytes));
    SecureZeroMemory(&ca, sizeof(ca));
    SecureZeroMemory(&cb, sizeof(cb));
    if (secrets) fclose(secrets);
    if (b) {
        if (b_up) (void)set_state(b, WIREGUARD_ADAPTER_STATE_DOWN);
        close_adapter(b);
    }
    if (a) {
        if (a_up) (void)set_state(a, WIREGUARD_ADAPTER_STATE_DOWN);
        close_adapter(a);
    }
    if (driver_initially_absent && delete_driver) {
        (void)delete_driver();
    }
    if (lib) FreeLibrary(lib);
    puts("LAB_CLEANUP: adapter handles closed, delete-driver requested, ephemeral VM will be destroyed by GitHub");
    return exit_code;
}
