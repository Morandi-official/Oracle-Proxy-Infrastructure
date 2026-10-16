/*
 * R34: disposable, same-host native WireGuardNT application nonce/peer counters.
 * Not SYSTEM production attestation, not a physical-route/WFP no-leak proof.
 * Fixed synthetic peers only; no adapter, service, route, DNS, or WFP mutation.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "wireguard.h"

typedef struct { uint64_t tx, rx, handshake; } SNAP;
static int ci_only(void) {
    wchar_t x[32]={0}, y[32]={0};
    return GetEnvironmentVariableW(L"GITHUB_ACTIONS",x,32)>0 &&
        wcscmp(x,L"true")==0 &&
        GetEnvironmentVariableW(L"RUNNER_ENVIRONMENT",y,32)>0 &&
        wcscmp(y,L"github-hosted")==0;
}
static int read_peer(WIREGUARD_GET_CONFIGURATION_FUNC *get,
                     WIREGUARD_ADAPTER_HANDLE adapter,SNAP *s) {
    unsigned char buf[4096]={0};
    DWORD size=sizeof(buf);
    if(!get(adapter,(WIREGUARD_INTERFACE*)buf,&size) ||
       size<sizeof(WIREGUARD_INTERFACE)+sizeof(WIREGUARD_PEER)) return 0;
    WIREGUARD_INTERFACE *it=(WIREGUARD_INTERFACE*)buf;
    if(it->PeersCount!=1) { SecureZeroMemory(buf,sizeof(buf));return 0; }
    WIREGUARD_PEER *p=(WIREGUARD_PEER*)(buf+sizeof(WIREGUARD_INTERFACE));
    s->tx=p->TxBytes;s->rx=p->RxBytes;s->handshake=p->LastHandshake;
    SecureZeroMemory(buf,sizeof(buf));
    return 1;
}
static SOCKET bound(const char *ip,unsigned short port) {
    SOCKET s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(s==INVALID_SOCKET) return INVALID_SOCKET;
    DWORD timeout=4000;
    struct sockaddr_in a={0};
    a.sin_family=AF_INET;a.sin_port=htons(port);
    if(InetPtonA(AF_INET,ip,&a.sin_addr)!=1 ||
       setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout))!=0 ||
       bind(s,(struct sockaddr*)&a,sizeof(a))!=0) {
        closesocket(s);return INVALID_SOCKET;
    }
    return s;
}
static int same_ip(const struct sockaddr_in *a,const char *ip) {
    struct in_addr parsed={0};
    return a->sin_family==AF_INET &&
        InetPtonA(AF_INET,ip,&parsed)==1 &&
        a->sin_addr.s_addr==parsed.s_addr;
}
static int nonce_echo(int corrupt,int replay) {
    SOCKET client=INVALID_SOCKET,server=INVALID_SOCKET;
    const char *src="10.249.129.1", *dst="10.249.129.2";
    unsigned char challenge[48]={0}, response[64]={0};
    struct sockaddr_in target={0},from={0},reply={0};
    int ok=0;
    client=bound(src,0);server=bound(dst,55334);
    if(client==INVALID_SOCKET||server==INVALID_SOCKET) goto done;
    memcpy(challenge,"R34-CI-NONCE-V1",15);
    if(BCryptGenRandom(NULL,challenge+16,32,BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0) goto done;
    target.sin_family=AF_INET; target.sin_port=htons(55334);
    if(InetPtonA(AF_INET,dst,&target.sin_addr)!=1) goto done;
    if(sendto(client,(char*)challenge,sizeof(challenge),0,
       (struct sockaddr*)&target,sizeof(target))!=(int)sizeof(challenge)) goto done;
    int fromlen=sizeof(from);
    int count=recvfrom(server,(char*)response,sizeof(response),0,
        (struct sockaddr*)&from,&fromlen);
    if(count!=(int)sizeof(challenge) || !same_ip(&from,src) ||
       memcmp(response,challenge,sizeof(challenge))!=0) goto done;
    if(corrupt) response[17]^=1;
    if(replay) response[16]^=1; /* fixed negative stale-response simulation */
    if(sendto(server,(char*)response,sizeof(challenge),0,
       (struct sockaddr*)&from,fromlen)!=(int)sizeof(challenge)) goto done;
    int replylen=sizeof(reply);
    count=recvfrom(client,(char*)response,sizeof(response),0,
        (struct sockaddr*)&reply,&replylen);
    ok=count==(int)sizeof(challenge) && same_ip(&reply,dst) &&
       ntohs(reply.sin_port)==55334 &&
       memcmp(response,challenge,sizeof(challenge))==0;
done:
    SecureZeroMemory(challenge,sizeof(challenge));
    SecureZeroMemory(response,sizeof(response));
    if(client!=INVALID_SOCKET) closesocket(client);
    if(server!=INVALID_SOCKET) closesocket(server);
    return ok;
}
int wmain(int argc,wchar_t **argv) {
    if(!ci_only() || argc!=2 || wcslen(argv[1])>500) {
        fputs("R34_REFUSED: disposable Windows runner required\n",stderr);return 4;
    }
    int ok=0, wsa=0;
    HMODULE dll=LoadLibraryExW(argv[1],NULL,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if(!dll) return 2;
    WIREGUARD_OPEN_ADAPTER_FUNC *open_adapter=
        (void*)GetProcAddress(dll,"WireGuardOpenAdapter");
    WIREGUARD_CLOSE_ADAPTER_FUNC *close_adapter=
        (void*)GetProcAddress(dll,"WireGuardCloseAdapter");
    WIREGUARD_GET_CONFIGURATION_FUNC *get=
        (void*)GetProcAddress(dll,"WireGuardGetConfiguration");
    WIREGUARD_ADAPTER_HANDLE a=NULL,b=NULL;
    if(!open_adapter||!close_adapter||!get) goto done;
    a=open_adapter(L"lab-peer-a");b=open_adapter(L"lab-peer-b");
    if(!a||!b) goto done;
    SNAP a0={0},b0={0},a1={0},b1={0};
    if(!read_peer(get,a,&a0)||!read_peer(get,b,&b0)||
       !a0.handshake||!b0.handshake) goto done;
    WSADATA wd;
    if(WSAStartup(MAKEWORD(2,2),&wd)!=0) goto done;
    wsa=1;
    if(!nonce_echo(0,0)) goto done;
    /* Real Winsock negative responses MUST be rejected. */
    if(nonce_echo(1,0) || nonce_echo(0,1)) goto done;
    Sleep(800);
    if(!read_peer(get,a,&a1)||!read_peer(get,b,&b1)||
       a1.tx<=a0.tx||a1.rx<=a0.rx||b1.tx<=b0.tx||b1.rx<=b0.rx) goto done;
    puts("R34_NATIVE_NONCE_ECHO_PASS: random challenge, negative corruption/replay checks, both real WireGuardNT peers' encrypted counters advanced; isolated same-host narrow-route proof only");
    ok=1;
done:
    if(!ok) fputs("R34_NATIVE_NONCE_ECHO_FAIL: challenge, peer counters or disposable-lab preconditions\n",stderr);
    if(wsa) WSACleanup();
    if(b) close_adapter(b);
    if(a) close_adapter(a);
    FreeLibrary(dll);
    return ok?0:1;
}
