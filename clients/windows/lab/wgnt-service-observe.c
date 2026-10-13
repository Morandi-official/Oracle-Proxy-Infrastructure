/* G7 read-only observer of TWO already-installed upstream SCM tunnel services.
 * Uses official signed WireGuardNT DLL. Does not create adapters or change routes.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include "wireguard.h"

static uint64_t last_handshake(WIREGUARD_GET_CONFIGURATION_FUNC *query,
                               WIREGUARD_ADAPTER_HANDLE adapter) {
    unsigned char storage[4096] = {0};
    DWORD length = sizeof(storage);
    if (!query(adapter, (WIREGUARD_INTERFACE *)storage, &length) ||
        length < sizeof(WIREGUARD_INTERFACE) + sizeof(WIREGUARD_PEER)) {
        return 0;
    }
    WIREGUARD_INTERFACE *iface = (WIREGUARD_INTERFACE *)storage;
    if (iface->PeersCount != 1) return 0;
    WIREGUARD_PEER *peer =
        (WIREGUARD_PEER *)(storage + sizeof(WIREGUARD_INTERFACE));
    return peer->LastHandshake;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2 || wcslen(argv[1]) > 500) {
        fputs("LAB_FAIL: signed DLL path required\n", stderr);
        return 2;
    }
    HMODULE dll = LoadLibraryExW(argv[1], NULL,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!dll) { fputs("LAB_FAIL: driver DLL not available\n", stderr); return 2; }

    WIREGUARD_OPEN_ADAPTER_FUNC *open_adapter =
        (void *)GetProcAddress(dll, "WireGuardOpenAdapter");
    WIREGUARD_CLOSE_ADAPTER_FUNC *close_adapter =
        (void *)GetProcAddress(dll, "WireGuardCloseAdapter");
    WIREGUARD_GET_CONFIGURATION_FUNC *get_config =
        (void *)GetProcAddress(dll, "WireGuardGetConfiguration");
    if (!open_adapter || !close_adapter || !get_config) {
        fputs("LAB_FAIL: expected official read-only API missing\n", stderr);
        FreeLibrary(dll);
        return 2;
    }

    WIREGUARD_ADAPTER_HANDLE a = NULL, b = NULL;
    int success = 0;
    for (int i = 0; i < 70; i++) {
        if (!a) a = open_adapter(L"lab-peer-a");
        if (!b) b = open_adapter(L"lab-peer-b");
        if (a && b && last_handshake(get_config,a) != 0 &&
            last_handshake(get_config,b) != 0) {
            puts("SCM_LAB_PASS: both real upstream tunnel.dll SCM services completed WireGuardNT crypto handshakes");
            success = 1;
            break;
        }
        Sleep(1000);
    }
    if (!success)
        fputs("SCM_LAB_FAIL: no two-way verified handshake within 70 seconds\n", stderr);
    if (b) close_adapter(b);
    if (a) close_adapter(a);
    FreeLibrary(dll);
    return success ? 0 : 1;
}
