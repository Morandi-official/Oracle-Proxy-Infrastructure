// Disposable SYSTEM-only measurement. This executable is never packaged.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <cfgmgr32.h>
#include <netcfgx.h>
#include <devguid.h>
#include <wrl/client.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cwchar>
#include <iostream>
#include <map>
#include <string>
#include <vector>

using Microsoft::WRL::ComPtr;
using Clock = std::chrono::steady_clock;
using Tick = Clock::time_point;
static const GUID expectedGuid = {0x62e2af98,0x7089,0x6f2c,{0x24,0x6b,0x4a,0x59,0x60,0xcf,0xc9,0x78}};
struct Failure { const char* reason; };
[[noreturn]] static void Fail(const char* reason) { throw Failure{reason}; }
static void Ok(HRESULT hr, const char* reason) {
    if (hr == NETCFG_S_REBOOT) Fail("REBOOT");
    if (hr != S_OK) Fail(reason);
}
static long long Elapsed(Tick t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-t).count();
}
struct Text {
    LPWSTR value = nullptr;
    ~Text() { CoTaskMemFree(value); }
    std::wstring read(const char* reason) const {
        if (!value || !value[0]) Fail(reason);
        return value;
    }
};
template<class I, class E> static ComPtr<I> Next(E* cursor) {
    ComPtr<I> item;
    ULONG count = 0;
    HRESULT hr = cursor->Next(1,item.GetAddressOf(),&count);
    if (hr == S_FALSE && count == 0) return {};
    Ok(hr,"ENUM");
    if (!item || count != 1) Fail("ENUM");
    return item;
}
static std::wstring Env(const wchar_t* key) {
    wchar_t buf[MAX_PATH] = {};
    DWORD size = GetEnvironmentVariableW(key,buf,MAX_PATH);
    if (!size || size >= MAX_PATH) Fail("INPUT");
    return buf;
}
static NET_LUID OwnerLuid() {
    if (Env(L"ORACLE_BINDING_LAB") != L"DISPOSABLE_WINDOWS_RUNNER") Fail("FIXTURE");
    DWORD session=1;
    HANDLE token=nullptr;
    if (!ProcessIdToSessionId(GetCurrentProcessId(),&session) || session!=0 ||
        !OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) Fail("SYSTEM");
    alignas(void*) BYTE info[256] = {}; DWORD size=0;
    BOOL system = GetTokenInformation(token,TokenUser,info,sizeof(info),&size) &&
        IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(info)->User.Sid,WinLocalSystemSid);
    CloseHandle(token);
    if (!system) Fail("SYSTEM");
    std::wstring raw = Env(L"ORACLE_TEST_CREATED_LUID");
    if (raw.size()>20 || raw.find_first_not_of(L"0123456789")!=std::wstring::npos) Fail("INPUT");
    NET_LUID luid = {};
    try { luid.Value=std::stoull(raw); } catch (...) { Fail("INPUT"); }
    if (!luid.Value) Fail("INPUT");
    return luid;
}
static void VerifyNic(NET_LUID expected) {
    NET_LUID back={}; MIB_IF_ROW2 row={}; row.InterfaceLuid=expected;
    if (ConvertInterfaceGuidToLuid(&expectedGuid,&back)!=NO_ERROR || back.Value!=expected.Value ||
        GetIfEntry2(&row)!=NO_ERROR || row.InterfaceLuid.Value!=expected.Value || row.InterfaceGuid!=expectedGuid ||
        row.Type!=IF_TYPE_PROP_VIRTUAL || row.OperStatus!=IfOperStatusDown ||
        wcscmp(row.Alias,L"OracleProxy") || wcscmp(row.Description,L"sing-tun Tunnel")) Fail("IDENTITY");
}
static void VerifyPnp(std::wstring pnp) {
    DEVINST node=0; ULONG status=0,problem=0;
    if (_wcsnicmp(pnp.c_str(),L"SWD\\WINTUN\\",11) ||
        CM_Locate_DevNodeW(&node,pnp.data(),CM_LOCATE_DEVNODE_NORMAL)!=CR_SUCCESS ||
        CM_Get_DevNode_Status(&status,&problem,node,0)!=CR_SUCCESS || (status & DN_HAS_PROBLEM)) Fail("PNP");
}
struct Session {
    ComPtr<INetCfg> cfg;
    ComPtr<INetCfgLock> lock;
    bool locked=false,initialized=false;
    void acquire() {
        Ok(CoCreateInstance(CLSID_CNetCfg,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(cfg.GetAddressOf())),"COM");
        Ok(cfg.As(&lock),"COM");
        Text owner;
        Ok(lock->AcquireWriteLock(200,L"Disposable Wintun measurement",&owner.value),"LOCK");
        locked=true;
    }
    void init() { Ok(cfg->Initialize(nullptr),"INIT");initialized=true; }
    void reinit() { Ok(cfg->Uninitialize(),"READBACK");initialized=false;init(); }
    void finish() {
        Ok(cfg->Uninitialize(),"READBACK");initialized=false;
        Ok(lock->ReleaseWriteLock(),"LOCK");locked=false;
    }
    ~Session() {
        if (initialized) cfg->Uninitialize();
        if (locked) lock->ReleaseWriteLock();
    }
};
struct Receipt {
    NET_LUID luid;
    std::wstring pnp;
    std::map<std::wstring,bool> original;
};
static ComPtr<INetCfgComponent> Owned(INetCfg* cfg, Receipt& r) {
    VerifyNic(r.luid);
    ComPtr<IEnumNetCfgComponent> enumerator;
    Ok(cfg->EnumComponents(&GUID_DEVCLASS_NET,enumerator.GetAddressOf()),"ENUM");
    ComPtr<INetCfgComponent> target;
    while(auto nic=Next<INetCfgComponent>(enumerator.Get())) {
        GUID id={};Ok(nic->GetInstanceGuid(&id),"ENUM");
        if (id!=expectedGuid) continue;
        if (target) Fail("IDENTITY");
        Text name;Ok(nic->GetPnpDevNodeId(&name.value),"PNP");
        std::wstring pnp=name.read("PNP");VerifyPnp(pnp);
        if (!r.pnp.empty() && _wcsicmp(r.pnp.c_str(),pnp.c_str())) Fail("PNP");
        r.pnp=pnp;target=nic;
    }
    if(!target) Fail("IDENTITY");
    return target;
}
struct Binding { ComPtr<INetCfgBindingPath> path; bool enabled; };
using Bindings=std::map<std::wstring,Binding>;
// A path may have service/filter edges, but it can end on only our previously
// witnessed adapter. A path touching another adapter cannot be mutated.
static void VerifyPath(INetCfgBindingPath* path, const Receipt& r) {
    ComPtr<IEnumNetCfgBindingInterface> edges;
    Ok(path->EnumBindingInterfaces(edges.GetAddressOf()),"PATH");
    unsigned adapters=0;
    while(auto edge=Next<INetCfgBindingInterface>(edges.Get())) {
        ComPtr<INetCfgComponent> lower; GUID kind={};
        Ok(edge->GetLowerComponent(lower.GetAddressOf()),"PATH");Ok(lower->GetClassGuid(&kind),"PATH");
        if(kind!=GUID_DEVCLASS_NET) continue;
        GUID id={};Text node;
        Ok(lower->GetInstanceGuid(&id),"PATH");Ok(lower->GetPnpDevNodeId(&node.value),"PATH");
        if (id!=expectedGuid || _wcsicmp(node.read("PATH").c_str(),r.pnp.c_str())) Fail("PATH");
        ++adapters;
    }
    if(adapters!=1) Fail("PATH");
}
static Bindings ReadPaths(INetCfg* cfg, Receipt& r) {
    auto nic=Owned(cfg,r);
    ComPtr<INetCfgComponentBindings> bindings;Ok(nic.As(&bindings),"ENUM");
    ComPtr<IEnumNetCfgBindingPath> paths;Ok(bindings->EnumBindingPaths(EBP_ABOVE,paths.GetAddressOf()),"ENUM");
    Bindings result;
    bool ipv4=false,ipv6=false;
    while(auto path=Next<INetCfgBindingPath>(paths.Get())) {
        ComPtr<INetCfgComponent> owner;Text inf;
        Ok(path->GetOwner(owner.GetAddressOf()),"PATH");Ok(owner->GetId(&inf.value),"PATH");
        const auto protocol=inf.read("PATH");
        bool v4=!_wcsicmp(protocol.c_str(),L"ms_tcpip"),v6=!_wcsicmp(protocol.c_str(),L"ms_tcpip6");
        if (!v4 && !v6) continue;
        VerifyPath(path.Get(),r);
        Text token;Ok(path->GetPathToken(&token.value),"PATH");
        const auto key=std::wstring(v4?L"4|":L"6|")+token.read("PATH");
        HRESULT enabled=path->IsEnabled();
        if ((enabled!=S_OK && enabled!=S_FALSE) || result.size()>=64 ||
            !result.emplace(key,Binding{path,enabled==S_OK}).second) Fail("PATH");
        ipv4|=v4;ipv6|=v6;
    }
    if (!ipv4 || !ipv6) Fail("PATH");
    return result;
}
struct Timings {
    const char* phase;
    long long lock=0,identify=0,stage=0,apply=0,readback=0;
    ~Timings(){
        std::cout<<"PHASE "<<phase<<' '<<lock<<' '<<identify<<' '<<stage<<' '<<apply<<' '<<readback<<std::endl;
    }
};
static void Change(Receipt& r, bool restore, bool& mayHaveChanged) {
    Timings tm{restore?"restore":"before"};Session s;
    Tick start=Clock::now();s.acquire();tm.lock=Elapsed(start);
    start=Clock::now();s.init();auto paths=ReadPaths(s.cfg.Get(),r);
    if(!restore){
        if(!r.original.empty()) Fail("BASELINE");
        bool v4=false,v6=false;
        for(const auto& [id,b]:paths) {
            r.original.emplace(id,b.enabled);
            if (b.enabled) {v4|=id[0]==L'4';v6|=id[0]==L'6';}
        }
        if (!v4 || !v6) Fail("BASELINE");
    }
    if (paths.size()!=r.original.size()) Fail("DRIFT");
    for(const auto& [id,b]:paths) if (!r.original.count(id)) Fail("DRIFT");
    tm.identify=Elapsed(start);
    start=Clock::now();bool staged=false;
    try {
        for(auto& [id,b]:paths){
            const bool desired=restore && r.original.at(id);
            if (b.enabled!=desired){Ok(b.path->Enable(desired?TRUE:FALSE),"STAGE");staged=true;}
        }
        tm.stage=Elapsed(start);start=Clock::now();
        if(staged){mayHaveChanged=true;Ok(s.cfg->Apply(),"APPLY");}
        tm.apply=Elapsed(start);
    } catch (...) {s.cfg->Cancel();throw;}
    start=Clock::now();paths.clear();s.reinit();
    auto verify=ReadPaths(s.cfg.Get(),r);
    if(verify.size()!=r.original.size()) Fail("READBACK");
    for(const auto& [id,b]:verify){
        auto expected=r.original.find(id);
        if(expected==r.original.end() || b.enabled!=(restore && expected->second)) Fail("READBACK");
    }
    verify.clear();s.finish();tm.readback=Elapsed(start);
}
int main() {
    HRESULT apartment=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    if(FAILED(apartment)){std::cout<<"FAILED_COM"<<std::endl;return 1;}
    int code=0;
    try{
        Receipt receipt{OwnerLuid(),{},{}};
        bool maybe=false;
        try{
            Change(receipt,false,maybe);
            std::cout<<"READBACK 1\nUNBOUND"<<std::endl;
            char command[16]={};
            if(!std::cin.getline(command,sizeof(command)) || std::string(command)!="RESTORE") Fail("PARENT_ENDED");
            Change(receipt,true,maybe);
            maybe=false;
            std::cout<<"RESTORED\nHELPER_COMPLETE"<<std::endl;
        }catch(...){
            if(maybe){
                try{Change(receipt,true,maybe);}
                catch(...){std::cout<<"FAILED_ROLLBACK"<<std::endl;}
            }
            throw;
        }
    }catch(const Failure& e){std::cout<<"FAILED_"<<e.reason<<std::endl;code=1;}
    catch(...){std::cout<<"FAILED_COM"<<std::endl;code=1;}
    CoUninitialize();
    return code;
}
