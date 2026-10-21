/* Non-shipped disposable hosted acceptance fault. GPL-3.0-or-later.
 * Dynamic WFP session closes on process death; no persistent firewall edits.
 * The sole target is the fixed acceptance Oracle WireGuard UDP endpoint. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#pragma comment(lib,"fwpuclnt.lib")
#pragma comment(lib,"rpcrt4.lib")
static const GUID fault_layer={0xe195ba5f,0xb047,0x4bdb,{0xa8,0x61,0x96,0xa3,0x35,0x47,0x66,0x03}};
__declspec(dllexport) DWORD __cdecl fixture_udp_loss_begin(HANDLE *output){
 if(!output)return ERROR_INVALID_PARAMETER;*output=NULL;
 FWPM_SESSION0 session={0};session.flags=FWPM_SESSION_FLAG_DYNAMIC;
 session.displayData.name=L"Oracle Proxy disposable UDP fault";
 HANDLE engine=NULL;DWORD e=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,&session,&engine);if(e)return e;
 FWPM_SUBLAYER0 sub={0};sub.subLayerKey=fault_layer;sub.weight=0xffff;
 sub.displayData.name=L"Oracle Proxy disposable UDP fault";
 e=FwpmSubLayerAdd0(engine,&sub,NULL);if(e)goto failed;
 FWPM_FILTER_CONDITION0 c[4]={0};
 c[0].fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS;c[0].conditionValue.type=FWP_UINT32;c[0].conditionValue.uint32=0x98439c64;
 c[1].fieldKey=FWPM_CONDITION_IP_REMOTE_PORT;c[1].conditionValue.type=FWP_UINT16;c[1].conditionValue.uint16=51820;
 c[2].fieldKey=FWPM_CONDITION_IP_PROTOCOL;c[2].conditionValue.type=FWP_UINT8;c[2].conditionValue.uint8=IPPROTO_UDP;
 c[3].fieldKey=FWPM_CONDITION_DIRECTION;c[3].conditionValue.type=FWP_UINT32;c[3].conditionValue.uint32=FWP_DIRECTION_OUTBOUND;
 for(int i=0;i<4;i++)c[i].matchType=FWP_MATCH_EQUAL;
 FWPM_FILTER0 filter={0};UINT64 weight=0xffffffffffffffffULL;
 filter.layerKey=FWPM_LAYER_DATAGRAM_DATA_V4;filter.subLayerKey=fault_layer;
 filter.displayData.name=L"Oracle Proxy disposable fixed Oracle UDP loss";
 filter.weight.type=FWP_UINT64;filter.weight.uint64=&weight;
 filter.action.type=FWP_ACTION_BLOCK;filter.numFilterConditions=4;filter.filterCondition=c;
 e=FwpmFilterAdd0(engine,&filter,NULL,NULL);if(e)goto failed;
 *output=engine;return ERROR_SUCCESS;
failed:
 FwpmEngineClose0(engine);return e;
}
__declspec(dllexport) DWORD __cdecl fixture_udp_loss_end(HANDLE engine){return FwpmEngineClose0(engine);}
