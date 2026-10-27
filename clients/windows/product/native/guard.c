/* Oracle Proxy owned WFP policy. GPL-3.0-or-later.
 * Uses the Windows SDK ABI. No shell, packet driver or third-party rule edits.
 * Policy must be exercised on disposable Windows before any release. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <sddl.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#pragma comment(lib,"fwpuclnt.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"rpcrt4.lib")
#define API __declspec(dllexport) DWORD __cdecl
static DWORD stage=0;
static SRWLOCK policy_lock=SRWLOCK_INIT;
static HANDLE tun_engine=NULL,tun_process=NULL;
static UINT64 tun_value=0,tun_filters[8]={0};
static const GUID provider={0x4936aef1,0x9f84,0x4291,{0x88,0x72,0x36,0x47,0x19,0x80,0x21,0xa1}};
static const GUID sublayer={0xbb18a732,0x9015,0x4871,{0x92,0x01,0xc1,0x62,0xa1,0x40,0x77,0x92}};
/* Must match the fixed Wintun GUID fenced by TunReceipt and the owned core. */
static const GUID oracle_tun_guid={0x62e2af98,0x7089,0x6f2c,{0x24,0x6b,0x4a,0x59,0x60,0xcf,0xc9,0x78}};
static const GUID *ale[]={&FWPM_LAYER_ALE_AUTH_CONNECT_V4,&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,&FWPM_LAYER_ALE_AUTH_CONNECT_V6,&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
static const GUID *boot[]={&FWPM_LAYER_OUTBOUND_TRANSPORT_V4,&FWPM_LAYER_INBOUND_TRANSPORT_V4,&FWPM_LAYER_OUTBOUND_TRANSPORT_V6,&FWPM_LAYER_INBOUND_TRANSPORT_V6};
static BOOL system_only(void){
 HANDLE token=NULL; BYTE data[256];DWORD length=0;BOOL ok=FALSE;PSID sid=NULL;
 if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return FALSE;
 if(GetTokenInformation(token,TokenUser,data,sizeof(data),&length)&&ConvertStringSidToSidW(L"S-1-5-18",&sid))ok=EqualSid(((TOKEN_USER*)data)->User.Sid,sid);
 if(sid)LocalFree(sid);CloseHandle(token);return ok;
}
static DWORD open_engine(HANDLE *engine){return FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,NULL,engine);}
static DWORD objects(HANDLE engine){
 FWPM_PROVIDER0 p={0};p.providerKey=provider;p.displayData.name=L"Oracle Proxy product";p.flags=FWPM_PROVIDER_FLAG_PERSISTENT;
 DWORD e=FwpmProviderAdd0(engine,&p,NULL);if(e&&e!=FWP_E_ALREADY_EXISTS)return e;
 FWPM_SUBLAYER0 s={0};s.subLayerKey=sublayer;s.providerKey=(GUID*)&provider;s.displayData.name=L"Oracle Proxy access boundary";s.flags=FWPM_SUBLAYER_FLAG_PERSISTENT;s.weight=0x7000;
 e=FwpmSubLayerAdd0(engine,&s,NULL);return e==FWP_E_ALREADY_EXISTS?0:e;
}
static DWORD enumerate_owned(HANDLE engine,BOOL remove,DWORD *persistent,DWORD *boot_count){
 // WFP requires an explicit layer in non-NULL enumeration templates.
 // An all-zero action mask cannot match anything either.
 for(int layer=0;layer<8;layer++){
  FWPM_FILTER_ENUM_TEMPLATE0 t={0};t.providerKey=(GUID*)&provider;t.layerKey=layer<4?*ale[layer]:*boot[layer-4];t.actionMask=0xffffffff;
  t.flags=FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME|FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;HANDLE iterator=NULL;
  DWORD e=FwpmFilterCreateEnumHandle0(engine,&t,&iterator);if(e)return e;
  for(;;){
   FWPM_FILTER0 **filters=NULL;UINT32 count=0;e=FwpmFilterEnum0(engine,iterator,128,&filters,&count);if(e)break;
   for(UINT32 i=0;i<count;i++){
    if(persistent&&(filters[i]->flags&FWPM_FILTER_FLAG_PERSISTENT))(*persistent)++;
    if(boot_count&&(filters[i]->flags&FWPM_FILTER_FLAG_BOOTTIME))(*boot_count)++;
    if(remove){e=FwpmFilterDeleteById0(engine,filters[i]->filterId);if(e)break;}
   }
   if(filters)FwpmFreeMemory0((void**)&filters);if(e||count<128)break;
  }
  FwpmFilterDestroyEnumHandle0(engine,iterator);if(e)return e;
 }
 return 0;
}
static DWORD remove_filters(HANDLE engine){return enumerate_owned(engine,TRUE,NULL,NULL);}
static void close_tun(void){if(tun_process)CloseHandle(tun_process);tun_process=NULL;if(tun_engine)FwpmEngineClose0(tun_engine);tun_engine=NULL;tun_value=0;ZeroMemory(tun_filters,sizeof(tun_filters));}
static DWORD core_state(void){
 if(!tun_process)return 0;
 DWORD code=0,state=0;
 if(GetExitCodeProcess(tun_process,&code)&&code==STILL_ACTIVE)state|=1;
 if(WaitForSingleObject(tun_process,0)==WAIT_TIMEOUT)state|=2;
 return state;
}
static DWORD live_tun(UINT64 value,const wchar_t *core_path,DWORD core_pid){
 if(!core_pid)return ERROR_INVALID_PARAMETER;
 tun_process=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,core_pid);
 if(!tun_process)return GetLastError();
 wchar_t image[32768];DWORD length=32768;HANDLE token=NULL;BYTE user[256];DWORD needed=0;PSID system_sid=NULL;DWORD session_id=1;
 BOOL valid=QueryFullProcessImageNameW(tun_process,0,image,&length)&&_wcsicmp(image,core_path)==0&&ProcessIdToSessionId(core_pid,&session_id)&&session_id==0&&OpenProcessToken(tun_process,TOKEN_QUERY,&token);
 if(valid)valid=GetTokenInformation(token,TokenUser,user,sizeof(user),&needed)&&ConvertStringSidToSidW(L"S-1-5-18",&system_sid)&&EqualSid(((TOKEN_USER*)user)->User.Sid,system_sid);
 if(system_sid)LocalFree(system_sid);if(token)CloseHandle(token);
 if(!valid||core_state()!=3){close_tun();return ERROR_ACCESS_DENIED;}

 NET_LUID actual={0};DWORD e=ConvertInterfaceAliasToLuid(L"OracleProxy",&actual);if(e||actual.Value!=value){close_tun();return ERROR_INVALID_DATA;}
 FWPM_SESSION0 session={0};session.displayData.name=L"Oracle Proxy live tunnel lease";session.flags=FWPM_SESSION_FLAG_DYNAMIC;
 e=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,&session,&tun_engine);if(e){close_tun();return e;}
 e=FwpmTransactionBegin0(tun_engine,0);
 if(!e){
  FWPM_FILTER_CONDITION0 condition={0};condition.matchType=FWP_MATCH_EQUAL;condition.conditionValue.type=FWP_UINT64;condition.conditionValue.uint64=&value;
  // Bind authorization to the actual packet path, not the source-address
  // interface. Incoming response reauthorization has no next-hop value, so
  // a separate arrival-interface rule is required (and vice versa).
  for(int i=0;i<8&&!e;i++){
   condition.fieldKey=(i%2)==0?FWPM_CONDITION_IP_NEXTHOP_INTERFACE:FWPM_CONDITION_IP_ARRIVAL_INTERFACE;
   stage++;FWPM_FILTER0 f={0};f.providerKey=(GUID*)&provider;f.subLayerKey=sublayer;f.layerKey=*ale[i/2];f.displayData.name=L"Oracle Proxy current tunnel packet path";
   UINT64 weight=220;f.weight.type=FWP_UINT64;f.weight.uint64=&weight;f.action.type=FWP_ACTION_PERMIT;f.numFilterConditions=1;f.filterCondition=&condition;
   e=FwpmFilterAdd0(tun_engine,&f,NULL,&tun_filters[i]);
  }
  if(!e)e=FwpmTransactionCommit0(tun_engine);else FwpmTransactionAbort0(tun_engine);
 }
 if(e)close_tun();else tun_value=value;return e;
}
static DWORD add(HANDLE engine,const GUID *layer,BOOL at_boot,FWP_ACTION_TYPE action,UINT8 weight,FWPM_FILTER_CONDITION0 *conditions,UINT32 count){
 stage++;FWPM_FILTER0 f={0};f.providerKey=(GUID*)&provider;f.subLayerKey=sublayer;f.layerKey=*layer;f.displayData.name=L"Oracle Proxy fixed access policy";
 f.flags=at_boot?FWPM_FILTER_FLAG_BOOTTIME:FWPM_FILTER_FLAG_PERSISTENT;
 UINT64 exact_weight=weight;f.weight.type=FWP_UINT64;f.weight.uint64=&exact_weight;f.action.type=action;f.numFilterConditions=count;f.filterCondition=conditions;
 return FwpmFilterAdd0(engine,&f,NULL,NULL);
}
static FWPM_FILTER_CONDITION0 number(const GUID *key,FWP_DATA_TYPE type,UINT32 value){
 FWPM_FILTER_CONDITION0 c={0};c.fieldKey=*key;c.matchType=FWP_MATCH_EQUAL;c.conditionValue.type=type;
 if(type==FWP_UINT8)c.conditionValue.uint8=(UINT8)value;else if(type==FWP_UINT16)c.conditionValue.uint16=(UINT16)value;else c.conditionValue.uint32=value;return c;
}
static DWORD permit_app(HANDLE engine,const wchar_t *path,BOOL system){
 FWP_BYTE_BLOB *appid=NULL;DWORD e=FwpmGetAppIdFromFileName0(path,&appid);if(e)return e;
 FWPM_FILTER_CONDITION0 c[2]={0};c[0].fieldKey=FWPM_CONDITION_ALE_APP_ID;c[0].matchType=FWP_MATCH_EQUAL;c[0].conditionValue.type=FWP_BYTE_BLOB_TYPE;c[0].conditionValue.byteBlob=appid;
 PSECURITY_DESCRIPTOR sd=NULL;FWP_BYTE_BLOB blob={0};UINT32 count=1;
 if(system){
  if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;CC;;;SY)",SDDL_REVISION_1,&sd,&blob.size)){FwpmFreeMemory0((void**)&appid);return GetLastError();}
  blob.data=(UINT8*)sd;c[1].fieldKey=FWPM_CONDITION_ALE_USER_ID;c[1].matchType=FWP_MATCH_EQUAL;c[1].conditionValue.type=FWP_SECURITY_DESCRIPTOR_TYPE;c[1].conditionValue.sd=&blob;count=2;
 }
 for(int i=0;i<4&&!e;i++)e=add(engine,ale[i],FALSE,FWP_ACTION_PERMIT,240,c,count);
 if(sd)LocalFree(sd);FwpmFreeMemory0((void**)&appid);return e;
}
static DWORD dhcp_rule(HANDLE engine,const GUID *layer,BOOL at_boot,int index,FWPM_FILTER_CONDITION0 *base){
 FWPM_FILTER_CONDITION0 c[5]={0};CopyMemory(c,base,3*sizeof(*base));
 if(at_boot){
  // Before BFE loads the persistent identity rules, permit only the
  // broadcast/multicast DHCP bootstrap destinations for outbound packets.
  if(index==0){c[3]=number(&FWPM_CONDITION_IP_REMOTE_ADDRESS,FWP_UINT32,0xffffffff);return add(engine,layer,TRUE,FWP_ACTION_PERMIT,210,c,4);}
  if(index==2){
   FWP_BYTE_ARRAY16 target={{0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,1,0,2}};
   c[3].fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS;c[3].matchType=FWP_MATCH_EQUAL;c[3].conditionValue.type=FWP_BYTE_ARRAY16_TYPE;c[3].conditionValue.byteArray16=&target;
   DWORD e=add(engine,layer,TRUE,FWP_ACTION_PERMIT,210,c,4);if(e)return e;
   target.byteArray16[1]=0x05;target.byteArray16[15]=3;return add(engine,layer,TRUE,FWP_ACTION_PERMIT,210,c,4);
  }
  return add(engine,layer,TRUE,FWP_ACTION_PERMIT,210,c,3);
 }
 // Low numbered UDP ports are not privileged on Windows. Port-only live
 // exceptions would let an ordinary app use UDP/68 as an escape channel.
 wchar_t host[MAX_PATH];UINT length=GetSystemDirectoryW(host,MAX_PATH);
 if(!length||length>MAX_PATH-15)return ERROR_INVALID_NAME;
 wcscat_s(host,MAX_PATH,L"\\svchost.exe");
 FWP_BYTE_BLOB *appid=NULL;DWORD e=FwpmGetAppIdFromFileName0(host,&appid);if(e)return e;
 c[3].fieldKey=FWPM_CONDITION_ALE_APP_ID;c[3].matchType=FWP_MATCH_EQUAL;c[3].conditionValue.type=FWP_BYTE_BLOB_TYPE;c[3].conditionValue.byteBlob=appid;
 PSECURITY_DESCRIPTOR sd=NULL;FWP_BYTE_BLOB blob={0};
 if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;CC;;;SY)(A;;CC;;;LS)(A;;CC;;;NS)",SDDL_REVISION_1,&sd,&blob.size)){FwpmFreeMemory0((void**)&appid);return GetLastError();}
 blob.data=(UINT8*)sd;c[4].fieldKey=FWPM_CONDITION_ALE_USER_ID;c[4].matchType=FWP_MATCH_EQUAL;c[4].conditionValue.type=FWP_SECURITY_DESCRIPTOR_TYPE;c[4].conditionValue.sd=&blob;
 e=add(engine,layer,FALSE,FWP_ACTION_PERMIT,210,c,5);
 LocalFree(sd);FwpmFreeMemory0((void**)&appid);return e;
}
static DWORD necessities(HANDLE engine,const GUID *layer,BOOL at_boot,int index){
 DWORD e=0;FWPM_FILTER_CONDITION0 c[4];
 c[0]=number(&FWPM_CONDITION_IP_PROTOCOL,FWP_UINT8,IPPROTO_UDP);
 c[1]=number(&FWPM_CONDITION_IP_LOCAL_PORT,FWP_UINT16,index<2?68:546);
 c[2]=number(&FWPM_CONDITION_IP_REMOTE_PORT,FWP_UINT16,index<2?67:547);
 e=dhcp_rule(engine,layer,at_boot,index,c);if(e)return e;
 if(index>=2){
  c[0]=number(&FWPM_CONDITION_IP_PROTOCOL,FWP_UINT8,IPPROTO_ICMPV6);
  c[2]=number(&FWPM_CONDITION_ICMP_CODE,FWP_UINT16,0);
  for(UINT32 type=133;type<=137;type++){
   if(type==133&&(index%2)==1)continue;if((type==134||type==137)&&(index%2)==0)continue;
   c[1]=number(&FWPM_CONDITION_ICMP_TYPE,FWP_UINT16,type);UINT32 count=3;
   FWP_V6_ADDR_AND_MASK local={{0xfe,0x80},10};FWP_BYTE_ARRAY16 router={{0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,2}};
   if(type==133||type==134||type==137){
    ZeroMemory(&c[3],sizeof(c[3]));c[3].fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS;c[3].matchType=FWP_MATCH_EQUAL;count=4;
    if(type==133){c[3].conditionValue.type=FWP_BYTE_ARRAY16_TYPE;c[3].conditionValue.byteArray16=&router;}
    else{c[3].conditionValue.type=FWP_V6_ADDR_MASK;c[3].conditionValue.v6AddrMask=&local;}
   }
   e=add(engine,layer,at_boot,FWP_ACTION_PERMIT,210,c,count);if(e)return e;
  }
 }
 return 0;
}
API OpGuardStage(void){return stage;}
static DWORD apply_internal(const wchar_t *service_path,const wchar_t *core_path,const wchar_t *uu_paths,UINT64 tun_luid,DWORD core_pid){
 stage=0;
 if(!system_only())return ERROR_ACCESS_DENIED;
 close_tun();
 HANDLE engine=NULL;DWORD e=open_engine(&engine);if(e)return e;
 e=FwpmTransactionBegin0(engine,0);if(e){FwpmEngineClose0(engine);return e;}
 e=objects(engine);if(!e)e=remove_filters(engine);
 for(int i=0;i<4&&!e;i++){
  e=add(engine,ale[i],FALSE,FWP_ACTION_BLOCK,1,NULL,0);if(e)break;
  FWPM_FILTER_CONDITION0 loop=number(&FWPM_CONDITION_FLAGS,FWP_UINT32,FWP_CONDITION_FLAG_IS_LOOPBACK);loop.matchType=FWP_MATCH_FLAGS_ALL_SET;
  e=add(engine,ale[i],FALSE,FWP_ACTION_PERMIT,250,&loop,1);if(e)break;
  e=necessities(engine,ale[i],FALSE,i);if(e)break;
  e=add(engine,boot[i],TRUE,FWP_ACTION_BLOCK,1,NULL,0);if(e)break;
  e=necessities(engine,boot[i],TRUE,i);
 }
 if(!e)e=permit_app(engine,service_path,TRUE);if(!e)e=permit_app(engine,core_path,TRUE);
 if(uu_paths)for(const wchar_t *p=uu_paths;*p&&!e;p+=lstrlenW(p)+1)e=permit_app(engine,p,FALSE);
 if(!e)e=FwpmTransactionCommit0(engine);else FwpmTransactionAbort0(engine);
 FwpmEngineClose0(engine);if(!e&&tun_luid)e=live_tun(tun_luid,core_path,core_pid);return e;
}
API OpGuardApply(const wchar_t *service_path,const wchar_t *core_path,const wchar_t *uu_paths,UINT64 value,DWORD core_pid){AcquireSRWLockExclusive(&policy_lock);DWORD e=apply_internal(service_path,core_path,uu_paths,value,core_pid);ReleaseSRWLockExclusive(&policy_lock);return e;}
API OpGuardAuthorizeTun(const wchar_t *core_path,UINT64 value,DWORD core_pid){
 if(!system_only())return ERROR_ACCESS_DENIED;
 AcquireSRWLockExclusive(&policy_lock);close_tun();
 HANDLE engine=NULL;DWORD persistent=0,boot_count=0;DWORD e=open_engine(&engine);
 if(!e){e=enumerate_owned(engine,FALSE,&persistent,&boot_count);FwpmEngineClose0(engine);}
 if(!e&&(persistent<16||boot_count<8))e=ERROR_ACCESS_DENIED;
 if(!e)e=live_tun(value,core_path,core_pid);
 ReleaseSRWLockExclusive(&policy_lock);return e;
}
API OpGuardSuspendTun(void){if(!system_only())return ERROR_ACCESS_DENIED;AcquireSRWLockExclusive(&policy_lock);close_tun();ReleaseSRWLockExclusive(&policy_lock);return 0;}
API OpGuardCoreState(void){AcquireSRWLockShared(&policy_lock);DWORD state=core_state();ReleaseSRWLockShared(&policy_lock);return state;}
API OpGuardTunReady(void){
 AcquireSRWLockExclusive(&policy_lock);NET_LUID actual={0};BOOL ok=tun_engine&&core_state()==3&&ConvertInterfaceAliasToLuid(L"OracleProxy",&actual)==0&&actual.Value==tun_value;
 for(int i=0;i<8&&ok;i++){FWPM_FILTER0 *filter=NULL;ok=FwpmFilterGetById0(tun_engine,tun_filters[i],&filter)==0;if(filter)FwpmFreeMemory0((void**)&filter);}
 if(!ok)close_tun();ReleaseSRWLockExclusive(&policy_lock);return ok?1:0;
}
static DWORD clear_internal(void){
 if(!system_only())return ERROR_ACCESS_DENIED;
 close_tun();
 HANDLE engine=NULL;DWORD e=open_engine(&engine);if(e)return e;
 FWPM_PROVIDER0 *existing=NULL;e=FwpmProviderGetByKey0(engine,&provider,&existing);
 if(e==FWP_E_PROVIDER_NOT_FOUND){FwpmEngineClose0(engine);return 0;}
 if(existing)FwpmFreeMemory0((void**)&existing);
 if(e){FwpmEngineClose0(engine);return e;}
 e=FwpmTransactionBegin0(engine,0);if(!e){e=remove_filters(engine);if(!e)e=FwpmTransactionCommit0(engine);else FwpmTransactionAbort0(engine);}FwpmEngineClose0(engine);return e;
}
API OpGuardClear(void){AcquireSRWLockExclusive(&policy_lock);DWORD e=clear_internal();ReleaseSRWLockExclusive(&policy_lock);return e;}
API OpGuardCount(DWORD *persistent,DWORD *boot_count){
 HANDLE engine=NULL;DWORD e=open_engine(&engine);if(e)return e;*persistent=0;*boot_count=0;
 FWPM_PROVIDER0 *existing=NULL;e=FwpmProviderGetByKey0(engine,&provider,&existing);
 if(e==FWP_E_PROVIDER_NOT_FOUND){FwpmEngineClose0(engine);return 0;}
 if(existing)FwpmFreeMemory0((void**)&existing);if(e){FwpmEngineClose0(engine);return e;}
 e=enumerate_owned(engine,FALSE,persistent,boot_count);FwpmEngineClose0(engine);return e;
}
API OpTunLuid(UINT64 *value){NET_LUID luid={0};DWORD e=ConvertInterfaceAliasToLuid(L"OracleProxy",&luid);if(!e)*value=luid.Value;return e;}
/* Read-only cold-start/recovery proof. Metadata status is not absence: any
 * matching OS interface-table row, including Down, remains present. */
API OpTunPresence(DWORD *present){
 if(!present)return ERROR_INVALID_PARAMETER;
 *present=1; /* Unknown/error must never certify that the interface vanished. */
 MIB_IF_TABLE2 *table=NULL;DWORD e=GetIfTable2(&table);
 if(e)return e;if(!table)return ERROR_INVALID_DATA;
 BOOL found=FALSE;
 for(ULONG i=0;i<table->NumEntries;i++){
  int match=CompareStringOrdinal(table->Table[i].Alias,-1,L"OracleProxy",-1,TRUE);
  if(!match){e=GetLastError();FreeMibTable(table);return e?e:ERROR_INVALID_DATA;}
  if(match==CSTR_EQUAL||memcmp(&table->Table[i].InterfaceGuid,&oracle_tun_guid,sizeof(GUID))==0){found=TRUE;break;}
 }
 FreeMibTable(table);*present=found?1:0;return NO_ERROR;
}
API OpTunDormant(void){
 NET_LUID luid={0};if(ConvertInterfaceAliasToLuid(L"OracleProxy",&luid)!=0)return 0;
 MIB_IF_ROW2 row={0};row.InterfaceLuid=luid;if(GetIfEntry2(&row)!=0||row.OperStatus==IfOperStatusUp)return 0;
 MIB_IPFORWARD_TABLE2 *table=NULL;if(GetIpForwardTable2(AF_UNSPEC,&table)!=0)return 0;
 BOOL ok=TRUE;
 for(ULONG i=0;i<table->NumEntries&&ok;i++)if(table->Table[i].InterfaceLuid.Value==luid.Value){
  SOCKADDR_INET *address=&table->Table[i].DestinationPrefix.Prefix;
  if(address->si_family==AF_INET){BYTE *ip=(BYTE*)&address->Ipv4.sin_addr.s_addr;if((ip[0]&0xf0)!=0xe0&&!(ip[0]==255&&ip[1]==255&&ip[2]==255&&ip[3]==255))ok=FALSE;}
  else if(address->si_family==AF_INET6){BYTE *ip=address->Ipv6.sin6_addr.u.Byte;if(ip[0]!=0xff&&!(ip[0]==0xfe&&(ip[1]&0xc0)==0x80))ok=FALSE;}
  else ok=FALSE;
 }
 FreeMibTable(table);return ok?1:0;
}
/* Read-only physical default route selection for the SYSTEM control channel.
 * Keep recovery API traffic usable even when the ordinary default is the TUN. */
API OpPhysicalIPv4Index(void){
 if(!system_only())return 0;
 MIB_IPFORWARD_TABLE2 *table=NULL;if(GetIpForwardTable2(AF_INET,&table)!=NO_ERROR)return 0;
 NET_LUID owned={0};ConvertInterfaceAliasToLuid(L"OracleProxy",&owned);
 ULONG index=0;UINT64 best=~(UINT64)0;
 for(ULONG i=0;i<table->NumEntries;i++){
  MIB_IPFORWARD_ROW2 *route=&table->Table[i];
  if(route->DestinationPrefix.PrefixLength!=0||route->Loopback||(owned.Value&&route->InterfaceLuid.Value==owned.Value))continue;
  MIB_IF_ROW2 nic={0};nic.InterfaceLuid=route->InterfaceLuid;
  if(GetIfEntry2(&nic)!=NO_ERROR||nic.OperStatus!=IfOperStatusUp||nic.Type==IF_TYPE_SOFTWARE_LOOPBACK)continue;
  MIB_IPINTERFACE_ROW info;InitializeIpInterfaceEntry(&info);info.Family=AF_INET;info.InterfaceLuid=route->InterfaceLuid;
  if(GetIpInterfaceEntry(&info)!=NO_ERROR)continue;
  UINT64 metric=(UINT64)route->Metric+info.Metric;
  if(metric<best){best=metric;index=route->InterfaceIndex;}
 }
 FreeMibTable(table);return index;
}
