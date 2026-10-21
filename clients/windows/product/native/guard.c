/* Oracle Proxy owned WFP policy. GPL-3.0-or-later.
 * Uses the Windows SDK ABI. No shell, packet driver or third-party rule edits.
 * Policy must be exercised on disposable Windows before any release. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <sddl.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <wchar.h>
#pragma comment(lib,"fwpuclnt.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"rpcrt4.lib")
#define API __declspec(dllexport) DWORD __cdecl
static DWORD stage=0;
static SRWLOCK policy_lock=SRWLOCK_INIT;
static HANDLE tun_engine=NULL;
static UINT64 tun_value=0,tun_filters[4]={0};
static const GUID provider={0x4936aef1,0x9f84,0x4291,{0x88,0x72,0x36,0x47,0x19,0x80,0x21,0xa1}};
static const GUID sublayer={0xbb18a732,0x9015,0x4871,{0x92,0x01,0xc1,0x62,0xa1,0x40,0x77,0x92}};
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
static void close_tun(void){if(tun_engine)FwpmEngineClose0(tun_engine);tun_engine=NULL;tun_value=0;ZeroMemory(tun_filters,sizeof(tun_filters));}
static DWORD live_tun(UINT64 value){
 NET_LUID actual={0};DWORD e=ConvertInterfaceAliasToLuid(L"OracleProxy",&actual);if(e||actual.Value!=value)return ERROR_INVALID_DATA;
 FWPM_SESSION0 session={0};session.displayData.name=L"Oracle Proxy live tunnel lease";session.flags=FWPM_SESSION_FLAG_DYNAMIC;
 e=FwpmEngineOpen0(NULL,RPC_C_AUTHN_WINNT,NULL,&session,&tun_engine);if(e)return e;
 e=FwpmTransactionBegin0(tun_engine,0);
 if(!e){
  FWPM_FILTER_CONDITION0 condition={0};condition.fieldKey=FWPM_CONDITION_IP_LOCAL_INTERFACE;condition.matchType=FWP_MATCH_EQUAL;condition.conditionValue.type=FWP_UINT64;condition.conditionValue.uint64=&value;
  for(int i=0;i<4&&!e;i++){
   stage++;FWPM_FILTER0 f={0};f.providerKey=(GUID*)&provider;f.subLayerKey=sublayer;f.layerKey=*ale[i];f.displayData.name=L"Oracle Proxy current tunnel only";
   f.weight.type=FWP_UINT8;f.weight.uint8=220;f.action.type=FWP_ACTION_PERMIT;f.numFilterConditions=1;f.filterCondition=&condition;
   e=FwpmFilterAdd0(tun_engine,&f,NULL,&tun_filters[i]);
  }
  if(!e)e=FwpmTransactionCommit0(tun_engine);else FwpmTransactionAbort0(tun_engine);
 }
 if(e)close_tun();else tun_value=value;return e;
}
static DWORD add(HANDLE engine,const GUID *layer,BOOL at_boot,FWP_ACTION_TYPE action,UINT8 weight,FWPM_FILTER_CONDITION0 *conditions,UINT32 count){
 stage++;FWPM_FILTER0 f={0};f.providerKey=(GUID*)&provider;f.subLayerKey=sublayer;f.layerKey=*layer;f.displayData.name=L"Oracle Proxy fixed access policy";
 f.flags=at_boot?FWPM_FILTER_FLAG_BOOTTIME:FWPM_FILTER_FLAG_PERSISTENT;
 f.weight.type=FWP_UINT8;f.weight.uint8=weight;f.action.type=action;f.numFilterConditions=count;f.filterCondition=conditions;
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
static DWORD apply_internal(const wchar_t *service_path,const wchar_t *core_path,const wchar_t *uu_paths,UINT64 tun_luid){
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
 FwpmEngineClose0(engine);if(!e&&tun_luid)e=live_tun(tun_luid);return e;
}
API OpGuardApply(const wchar_t *service_path,const wchar_t *core_path,const wchar_t *uu_paths,UINT64 value){AcquireSRWLockExclusive(&policy_lock);DWORD e=apply_internal(service_path,core_path,uu_paths,value);ReleaseSRWLockExclusive(&policy_lock);return e;}
API OpGuardSuspendTun(void){if(!system_only())return ERROR_ACCESS_DENIED;AcquireSRWLockExclusive(&policy_lock);close_tun();ReleaseSRWLockExclusive(&policy_lock);return 0;}
API OpGuardTunReady(void){
 AcquireSRWLockShared(&policy_lock);NET_LUID actual={0};BOOL ok=tun_engine&&ConvertInterfaceAliasToLuid(L"OracleProxy",&actual)==0&&actual.Value==tun_value;
 for(int i=0;i<4&&ok;i++){FWPM_FILTER0 *filter=NULL;ok=FwpmFilterGetById0(tun_engine,tun_filters[i],&filter)==0;if(filter)FwpmFreeMemory0((void**)&filter);}
 ReleaseSRWLockShared(&policy_lock);return ok?1:0;
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
