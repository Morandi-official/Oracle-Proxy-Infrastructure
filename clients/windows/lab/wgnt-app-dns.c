/*
 * G14 Windows disposable hosted CI only:
 * Real Winsock application-level UDP delivery and synthetic DNS A/AAAA
 * request/response over the two already active narrow-route WireGuardNT
 * interfaces. No adapter, service, firewall, DNS system, default route or
 * registry changes. No production host, keys, names or network targets.
 *
 * Both peer tunnel IPs exist ON THE SAME CI HOST. Positive application
 * delivery plus driver byte counters cannot by itself prove all packets
 * traversed encrypted WireGuard rather than a local Windows IP path.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "wireguard.h"

typedef struct { uint64_t tx, rx, handshake; } SNAP;
static const char *ip_a="10.249.129.1", *ip_b="10.249.129.2";
static int is_ci(void) {
    wchar_t one[32]={0}, two[32]={0};
    return GetEnvironmentVariableW(L"GITHUB_ACTIONS",one,32)>0
       && wcscmp(one,L"true")==0
       && GetEnvironmentVariableW(L"RUNNER_ENVIRONMENT",two,32)>0
       && wcscmp(two,L"github-hosted")==0;
}
static int read_snap(WIREGUARD_GET_CONFIGURATION_FUNC *query,
                     WIREGUARD_ADAPTER_HANDLE adapter, SNAP *s) {
    unsigned char storage[4096]={0};
    DWORD length=sizeof(storage);
    if (!query(adapter,(WIREGUARD_INTERFACE *)storage,&length) ||
        length < sizeof(WIREGUARD_INTERFACE)+sizeof(WIREGUARD_PEER)) return 0;
    WIREGUARD_INTERFACE *it=(WIREGUARD_INTERFACE *)storage;
    if (it->PeersCount != 1) return 0;
    WIREGUARD_PEER *peer=(WIREGUARD_PEER *)(storage+sizeof(WIREGUARD_INTERFACE));
    s->tx=peer->TxBytes; s->rx=peer->RxBytes; s->handshake=peer->LastHandshake;
    SecureZeroMemory(storage,sizeof(storage));
    return 1;
}
static SOCKET bind_udp(const char *addr, unsigned short port) {
    SOCKET s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if (s==INVALID_SOCKET) return INVALID_SOCKET;
    DWORD ms=3500;
    if (setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char *)&ms,sizeof(ms))) { fprintf(stderr,"G14_TRACE: socket timeout config err=%d\n",WSAGetLastError()); goto fail; }
    struct sockaddr_in a={0};
    a.sin_family=AF_INET;
    a.sin_port=htons(port);
    if (InetPtonA(AF_INET,addr,&a.sin_addr)!=1 ||
        bind(s,(struct sockaddr *)&a,sizeof(a))) { fprintf(stderr,"G14_TRACE: socket bind err=%d\n",WSAGetLastError()); goto fail; }
    return s;
fail:
    closesocket(s);
    return INVALID_SOCKET;
}
static int endpoint(const char *addr, unsigned short port, struct sockaddr_in *a) {
    ZeroMemory(a,sizeof(*a));
    a->sin_family=AF_INET; a->sin_port=htons(port);
    return InetPtonA(AF_INET,addr,&a->sin_addr)==1;
}
static int received_from(const struct sockaddr_in *a,const char *ip) {
    struct in_addr expected={0};
    return InetPtonA(AF_INET,ip,&expected)==1 &&
        a->sin_family==AF_INET && a->sin_addr.s_addr==expected.s_addr;
}
static int exchange(const char *src,const char *dst,unsigned short dstport) {
    SOCKET client=INVALID_SOCKET, server=INVALID_SOCKET;
    int ok=0;
    client=bind_udp(src,0); server=bind_udp(dst,dstport);
    if (client==INVALID_SOCKET || server==INVALID_SOCKET) goto done;
    struct sockaddr_in target={0}, peer={0}, replyto={0};
    if (!endpoint(dst,dstport,&target)) goto done;
    unsigned char sent[1200], got[1500];
    memset(sent,0xa6,sizeof(sent));
    memcpy(sent,"G14_WINSOCK_APP_DELIVERY",24);
    sent[1199]=0x5a;
    int sentlen=sendto(client,(char *)sent,sizeof(sent),0,
                       (struct sockaddr *)&target,sizeof(target));
    if(sentlen!=(int)sizeof(sent)) { fprintf(stderr,"G14_TRACE: app send err=%d bytes=%d\n",WSAGetLastError(),sentlen); goto done; }
    int peerlen=sizeof(peer);
    int len=recvfrom(server,(char *)got,sizeof(got),0,
                     (struct sockaddr *)&peer,&peerlen);
    if (len!=(int)sizeof(sent) || !received_from(&peer,src) ||
        memcmp(got,sent,sizeof(sent))) { fprintf(stderr,"G14_TRACE: app recv len=%d expected=%u err=%d\n",len,(unsigned)sizeof(sent),WSAGetLastError()); goto done; }
    /* Echo reply demonstrates the application socket also receives B->A. */
    if (sendto(server,(char *)got,len,0,(struct sockaddr *)&peer,peerlen)!=len) { fprintf(stderr,"G14_TRACE: app echo send err=%d\n",WSAGetLastError()); goto done; }
    int addrlen=sizeof(replyto);
    len=recvfrom(client,(char *)got,sizeof(got),0,
                 (struct sockaddr *)&replyto,&addrlen);
    if (len!=(int)sizeof(sent) || !received_from(&replyto,dst) ||
        ntohs(replyto.sin_port)!=dstport || memcmp(got,sent,sizeof(sent))) { fprintf(stderr,"G14_TRACE: app echo recv len=%d expected=%u err=%d\n",len,(unsigned)sizeof(sent),WSAGetLastError()); goto done; }
    ok=1;
done:
    if (server!=INVALID_SOCKET) closesocket(server);
    if (client!=INVALID_SOCKET) closesocket(client);
    return ok;
}

/* Exactly two synthetic queries "lab.invalid", with no real system resolver. */
static const unsigned char name[]={3,'l','a','b',7,'i','n','v','a','l','i','d',0};
static const unsigned char a_answer[]={203,0,113,53};
static const unsigned char aaaa_answer[]={
  0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x35
};
static void put16(unsigned char *p, unsigned short value) {
    p[0]=(unsigned char)(value>>8); p[1]=(unsigned char)value;
}
static int dns_one(unsigned short qtype,unsigned short id) {
    SOCKET client=INVALID_SOCKET, server=INVALID_SOCKET;
    struct sockaddr_in dst={0}, from={0}, responsefrom={0};
    unsigned char query[128]={0}, wire[512]={0}, response[256]={0}, received[512]={0};
    const unsigned char *answer=qtype==1?a_answer:aaaa_answer;
    size_t rdlen=qtype==1?sizeof(a_answer):sizeof(aaaa_answer);
    int ok=0;
    if(qtype!=1 && qtype!=28) return 0;
    client=bind_udp(ip_a,0);
    server=bind_udp(ip_b,53);
    if(client==INVALID_SOCKET || server==INVALID_SOCKET) goto done;
    if(!endpoint(ip_b,53,&dst)) goto done;
    put16(query,id); put16(query+2,0x0100); put16(query+4,1);
    memcpy(query+12,name,sizeof(name));
    size_t question=12+sizeof(name);
    put16(query+question,qtype); put16(query+question+2,1);
    size_t qlen=question+4;
    if(sendto(client,(char *)query,(int)qlen,0,
              (struct sockaddr *)&dst,sizeof(dst))!=(int)qlen) goto done;
    int fromlen=sizeof(from);
    int n=recvfrom(server,(char *)wire,sizeof(wire),0,
                   (struct sockaddr *)&from,&fromlen);
    if(n!=(int)qlen || !received_from(&from,ip_a) ||
       memcmp(wire,query,qlen)) goto done;
    memcpy(response,query,qlen);
    put16(response+2,0x8180); put16(response+6,1);
    size_t pos=qlen;
    response[pos++]=0xc0; response[pos++]=0x0c;
    put16(response+pos,qtype); pos+=2;
    put16(response+pos,1); pos+=2;
    response[pos++]=0; response[pos++]=0;
    response[pos++]=0; response[pos++]=30;
    put16(response+pos,(unsigned short)rdlen); pos+=2;
    memcpy(response+pos,answer,rdlen); pos+=rdlen;
    if(sendto(server,(char *)response,(int)pos,0,
              (struct sockaddr *)&from,fromlen)!=(int)pos) goto done;
    int recvlen=sizeof(responsefrom);
    n=recvfrom(client,(char *)received,sizeof(received),0,
               (struct sockaddr *)&responsefrom,&recvlen);
    if(n!=(int)pos || !received_from(&responsefrom,ip_b) ||
       ntohs(responsefrom.sin_port)!=53 ||
       memcmp(received,response,pos)) goto done;
    ok=1;
done:
    if(server!=INVALID_SOCKET) closesocket(server);
    if(client!=INVALID_SOCKET) closesocket(client);
    return ok;
}
int wmain(int argc,wchar_t **argv) {
    if(!is_ci() || argc!=2 || wcslen(argv[1])>500) {
        fputs("G14_REFUSED: disposable CI and fixed signed WireGuardNT DLL required\n",stderr);
        return 4;
    }
    HMODULE dll=LoadLibraryExW(argv[1],NULL,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if(!dll) { fputs("G14_FAIL: driver DLL unavailable\n",stderr); return 2; }
    WIREGUARD_OPEN_ADAPTER_FUNC *open_adapter=
        (void *)GetProcAddress(dll,"WireGuardOpenAdapter");
    WIREGUARD_CLOSE_ADAPTER_FUNC *close_adapter=
        (void *)GetProcAddress(dll,"WireGuardCloseAdapter");
    WIREGUARD_GET_CONFIGURATION_FUNC *query=
        (void *)GetProcAddress(dll,"WireGuardGetConfiguration");
    int ok=0, wsa_started=0;
    WIREGUARD_ADAPTER_HANDLE a=NULL,b=NULL;
    if(!open_adapter || !close_adapter || !query) goto done;
    a=open_adapter(L"lab-peer-a"); b=open_adapter(L"lab-peer-b");
    if(!a || !b) goto done;
    SNAP a0={0},b0={0},a1={0},b1={0};
    if(!read_snap(query,a,&a0) || !read_snap(query,b,&b0) ||
       !a0.handshake || !b0.handshake) goto done;
    WSADATA ws;
    if(WSAStartup(MAKEWORD(2,2),&ws)!=0) goto done;
    wsa_started=1;
    int app=exchange(ip_a,ip_b,55141) && exchange(ip_b,ip_a,55142);
    if(!app) {
        fputs("G14_FAIL: app UDP socket did not receive authenticated test payload/echo on both tunnel IPs\n",stderr);
        goto done;
    }
    int dns=dns_one(1,0x1411) && dns_one(28,0x1428);
    if(!dns) {
        fputs("G14_FAIL: synthetic UDP/53 A/AAAA query or reply not delivered\n",stderr);
        goto done;
    }
    Sleep(800);
    if(!read_snap(query,a,&a1) || !read_snap(query,b,&b1) ||
       a1.tx<=a0.tx || a1.rx<=a0.rx || b1.tx<=b0.tx || b1.rx<=b0.rx) {
        fputs("G14_FAIL: native driver counters not increasing on both sides\n",stderr);
        goto done;
    }
    puts("G14_PASS: two-way real Winsock UDP app socket delivery + inner synthetic DNS A/AAAA; genuine WireGuardNT Tx/Rx counters advanced. Localhost-only, not cross-host or no-leak proof.");
    ok=1;
done:
    if(wsa_started) WSACleanup();
    if(b && close_adapter) close_adapter(b);
    if(a && close_adapter) close_adapter(a);
    FreeLibrary(dll);
    if(!ok) fputs("G14_ERROR: application delivery proof NOT attained\n",stderr);
    return ok?0:1;
}
