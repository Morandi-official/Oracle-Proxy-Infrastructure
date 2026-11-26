// Oracle Proxy owned, sessionless Wintun IPv4/IPv6 binding transaction.
// GPL-3.0-or-later. The original binding choices are persisted on this single
// PnP instance before disabling either protocol. No physical NIC is writable.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <netcfgx.h>
#include <devguid.h>
#include <wrl/client.h>
#include <algorithm>
#include <chrono>

#include <cwchar>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <utility>

namespace {
using Microsoft::WRL::ComPtr;
using Clock = std::chrono::steady_clock;
static const GUID expectedGuid = {0x62e2af98,0x7089,0x6f2c,{0x24,0x6b,0x4a,0x59,0x60,0xcf,0xc9,0x78}};
struct Failure { const char* reason; };
[[noreturn]] static void Fail(const char* reason) { throw Failure{reason}; }
static void Ok(HRESULT hr, const char* reason) {
    if (hr == NETCFG_S_REBOOT || hr == NETCFG_E_NEED_REBOOT) Fail("REBOOT");
    if (hr != S_OK) Fail(reason);
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
static void RequireSystem() {
    DWORD session=1;
    HANDLE token=nullptr;
    if (!ProcessIdToSessionId(GetCurrentProcessId(),&session) || session!=0 ||
        !OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)) Fail("SYSTEM");
    alignas(void*) BYTE info[256]={};
    DWORD size=0;
    BOOL system=GetTokenInformation(token,TokenUser,info,sizeof(info),&size) &&
        IsWellKnownSid(reinterpret_cast<TOKEN_USER*>(info)->User.Sid,WinLocalSystemSid);
    CloseHandle(token);
    if (!system) Fail("SYSTEM");
}
static void VerifyNic(NET_LUID expected,bool requireDown=true) {
    NET_LUID back={}; MIB_IF_ROW2 row={}; row.InterfaceLuid=expected;
    if (ConvertInterfaceGuidToLuid(&expectedGuid,&back)!=NO_ERROR || back.Value!=expected.Value ||
        GetIfEntry2(&row)!=NO_ERROR || row.InterfaceLuid.Value!=expected.Value || row.InterfaceGuid!=expectedGuid ||
        row.Type!=IF_TYPE_PROP_VIRTUAL || (requireDown && row.OperStatus!=IfOperStatusDown) ||
        wcscmp(row.Alias,L"OracleProxy") || wcscmp(row.Description,L"sing-tun Tunnel")) Fail("IDENTITY");
}
static DEVINST VerifyPnp(std::wstring pnp) {
    DEVINST node=0; ULONG status=0,problem=0;
    if (_wcsnicmp(pnp.c_str(),L"SWD\\WINTUN\\",11) ||
        CM_Locate_DevNodeW(&node,pnp.data(),CM_LOCATE_DEVNODE_NORMAL)!=CR_SUCCESS ||
        CM_Get_DevNode_Status(&status,&problem,node,0)!=CR_SUCCESS ||
        (status & (DN_STARTED|DN_HAS_PROBLEM))!=DN_STARTED) Fail("PNP");
    return node;
}
struct Session {
    ComPtr<INetCfg> cfg;
    ComPtr<INetCfgLock> lock;
    bool locked=false,initialized=false,pending=false;
    void create() {
        Ok(CoCreateInstance(CLSID_CNetCfg,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(cfg.GetAddressOf())),"COM");
    }
    void acquire() {
        create();
        Ok(cfg.As(&lock),"COM");
        Text owner;
        Ok(lock->AcquireWriteLock(200,L"Oracle Proxy private adapter",&owner.value),"LOCK");
        locked=true;
    }
    void init() { Ok(cfg->Initialize(nullptr),"INIT");initialized=true; }
    void finish() {
        initialized=false;
        HRESULT uninit=cfg->Uninitialize(),unlocked=S_OK;
        if(locked){locked=false;unlocked=lock->ReleaseWriteLock();}
        lock.Reset();cfg.Reset();
        Ok(uninit,"READBACK");Ok(unlocked,"LOCK");
    }
    ~Session() {
        if (initialized) { if(pending) cfg->Cancel(); cfg->Uninitialize(); }
        if (locked) lock->ReleaseWriteLock();
    }
};
struct Receipt {
    NET_LUID luid;
    std::wstring pnp;
    std::map<std::wstring,bool> original;
};
static ComPtr<INetCfgComponent> Owned(INetCfg* cfg, Receipt& r,bool requireDown=true) {
    VerifyNic(r.luid,requireDown);
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
        // Windows may cascade TCP/IP disablement to these four upper-layer
        // components on this adapter. They are observed, never explicitly set.
        const bool dependent=!_wcsicmp(protocol.c_str(),L"ms_msclient") ||
            !_wcsicmp(protocol.c_str(),L"ms_netbios") || !_wcsicmp(protocol.c_str(),L"ms_netbt") ||
            !_wcsicmp(protocol.c_str(),L"ms_server");
        VerifyPath(path.Get(),r);
        Text token;Ok(path->GetPathToken(&token.value),"PATH");
        const wchar_t* kind=v4?L"4|":v6?L"6|":dependent?L"D|":L"N|";
        const auto key=std::wstring(kind)+protocol+L"|"+token.read("PATH");
        HRESULT enabled=path->IsEnabled();
        if ((enabled!=S_OK && enabled!=S_FALSE) || result.size()>=64 ||
            !result.emplace(key,Binding{path,enabled==S_OK}).second) Fail("PATH");
        ipv4|=v4;ipv6|=v6;
    }
    if (!ipv4 || !ipv6) Fail("PATH");
    return result;
}
// The PnP store attaches this journal to the adapter instance. It is written
// in one property update and read back before a binding can be changed.
static const DEVPROPKEY receiptKey={{0xefdc660c,0xab4f,0x4ab9,{0x87,0x9f,0xa9,0x29,0x1d,0x5b,0x77,0x63}},2};
static constexpr size_t MaxReceiptChars=32768;
using Strings=std::vector<std::wstring>;
static SRWLOCK transactionLock=SRWLOCK_INIT;
// A lost or externally altered persistent receipt must not be treated as
// success on the same live holder. The same value survives in the devnode.
static std::vector<wchar_t>& CurrentJournal() {
    static std::vector<wchar_t> journal;
    return journal;
}
struct TransactionLock {
    TransactionLock(){AcquireSRWLockExclusive(&transactionLock);}
    ~TransactionLock(){ReleaseSRWLockExclusive(&transactionLock);}
};
struct Apartment {
    HRESULT hr;
    Apartment():hr(CoInitializeEx(nullptr,COINIT_MULTITHREADED)){
        if(FAILED(hr) && hr!=RPC_E_CHANGED_MODE) Fail("COM");
    }
    ~Apartment(){if(SUCCEEDED(hr)) CoUninitialize();}
};
struct Owner { DWORD pid; ULONGLONG created; };
static ULONGLONG Created(HANDLE process) {
    FILETIME birth={},end={},kernel={},user={};
    if(!GetProcessTimes(process,&birth,&end,&kernel,&user)) Fail("OWNER");
    return (static_cast<ULONGLONG>(birth.dwHighDateTime)<<32)|birth.dwLowDateTime;
}
static bool OwnerEnded(const Owner& owner) {
    HANDLE handle=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,owner.pid);
    if(!handle){if(GetLastError()==ERROR_INVALID_PARAMETER) return true;Fail("OWNER");}
    try {
        const bool replaced=Created(handle)!=owner.created;
        const DWORD wait=WaitForSingleObject(handle,0);
        if(wait!=WAIT_TIMEOUT && wait!=WAIT_OBJECT_0) Fail("OWNER");
        CloseHandle(handle);return replaced || wait==WAIT_OBJECT_0;
    }catch(...){CloseHandle(handle);throw;}
}
static ULONGLONG Number(const std::wstring& str,ULONGLONG limit) {
    if(str.empty() || str.size()>20) Fail("JOURNAL");
    ULONGLONG value=0;
    for(const auto ch:str){
        if(ch<L'0' || ch>L'9' || value>(limit-(ch-L'0'))/10) Fail("JOURNAL");
        value=value*10+(ch-L'0');
    }
    if(!value) Fail("JOURNAL");
    return value;
}
static std::vector<wchar_t> ReadProperty(DEVINST node) {
    DEVPROPTYPE type=DEVPROP_TYPE_EMPTY;ULONG bytes=0;
    auto rc=CM_Get_DevNode_PropertyW(node,&receiptKey,&type,nullptr,&bytes,0);
    if(rc==CR_NO_SUCH_VALUE) return {};
    if(rc!=CR_BUFFER_SMALL || bytes<4 ||
       bytes%sizeof(wchar_t) || bytes>MaxReceiptChars*sizeof(wchar_t)) Fail("JOURNAL");
    std::vector<wchar_t> data(bytes/sizeof(wchar_t));
    const ULONG capacity=bytes;
    rc=CM_Get_DevNode_PropertyW(node,&receiptKey,&type,reinterpret_cast<PBYTE>(data.data()),&bytes,0);
    if(rc!=CR_SUCCESS || type!=DEVPROP_TYPE_STRING_LIST || bytes!=capacity ||
       data.back()!=0 || data[data.size()-2]!=0) Fail("JOURNAL");
    return data;
}
static Strings Decode(const std::vector<wchar_t>& data) {
    Strings fields;
    for(size_t pos=0;pos+1<data.size();){
        auto end=std::find(data.begin()+pos,data.end(),wchar_t(0));
        if(end==data.end() || end==data.begin()+pos || fields.size()>=70) Fail("JOURNAL");
        fields.emplace_back(data.begin()+pos,end);
        pos=static_cast<size_t>(end-data.begin())+1;
    }
    return fields;
}
static std::vector<wchar_t> Encode(const Receipt& r,const Owner& owner) {
    Strings fields={L"OracleProxy-Bindings-1",std::to_wstring(r.luid.Value),r.pnp,
                    std::to_wstring(owner.pid),std::to_wstring(owner.created)};
    for(const auto& [id,enabled]:r.original)
        fields.emplace_back(std::wstring(enabled?L"+":L"-")+id);
    std::vector<wchar_t> data;
    for(const auto& field:fields){
        if(data.size()+field.size()+2>MaxReceiptChars) Fail("JOURNAL");
        data.insert(data.end(),field.begin(),field.end());data.push_back(0);
    }
    data.push_back(0);
    return data;
}
static void Store(DEVINST node,const std::vector<wchar_t>& data){
    auto rc=CM_Set_DevNode_PropertyW(node,&receiptKey,DEVPROP_TYPE_STRING_LIST,
        reinterpret_cast<PBYTE>(const_cast<wchar_t*>(data.data())),static_cast<ULONG>(data.size()*sizeof(wchar_t)),0);
    if(rc!=CR_SUCCESS || ReadProperty(node)!=data) Fail("JOURNAL");
}
static void Clear(DEVINST node,const std::vector<wchar_t>& expected){
    if(expected.empty() || ReadProperty(node)!=expected ||
       CM_Set_DevNode_PropertyW(node,&receiptKey,DEVPROP_TYPE_EMPTY,nullptr,0,0)!=CR_SUCCESS ||
       !ReadProperty(node).empty()) Fail("JOURNAL");
    CurrentJournal().clear();
}
static bool MapMatches(const Receipt& receipt,const Bindings& current,bool restored){
    if(current.size()!=receipt.original.size()) return false;
    for(const auto& [id,b]:current){
        const auto it=receipt.original.find(id);
        if(it==receipt.original.end()) return false;
        const bool original=it->second;
        const bool ip=id[0]==L'4' || id[0]==L'6';
        if(restored || id[0]==L'N') {
            if(b.enabled!=original) return false;
        }else if(ip) {
            if(b.enabled) return false;
        }else if(b.enabled && !original) {
            return false; // Only a downward dependency transition is allowed.
        }
    }
    return true;
}
static void Capture(Receipt& r,const Bindings& current){
    bool v4=false,v6=false;
    for(const auto& [id,b]:current){
        r.original.emplace(id,b.enabled);
        if(b.enabled){v4|=id[0]==L'4';v6|=id[0]==L'6';}
    }
    if(!v4 || !v6) Fail("BASELINE");
}
static void LoadOriginal(Receipt& r,const Strings& fields,const Bindings& bindings) {
    if(fields.size()<7 || fields[0]!=L"OracleProxy-Bindings-1" ||
       _wcsicmp(r.pnp.c_str(),fields[2].c_str()) || fields.size()!=bindings.size()+5) Fail("JOURNAL");
    bool v4=false,v6=false;
    for(size_t i=5;i<fields.size();++i){
        const auto& field=fields[i];
        if(field.size()<4 || (field[0]!=L'+' && field[0]!=L'-')) Fail("JOURNAL");
        const auto id=field.substr(1);
        if(!bindings.count(id) || !r.original.emplace(id,field[0]==L'+').second) Fail("DRIFT");
        if(field[0]==L'+'){v4|=id[0]==L'4';v6|=id[0]==L'6';}
    }
    if(!v4 || !v6) Fail("JOURNAL");
}
static bool TransientRead(const Failure& failure) {
    const std::string reason=failure.reason;
    return reason=="PNP" || reason=="IDENTITY" || reason=="ENUM" || reason=="PATH" ||
        reason=="INIT" || reason=="READBACK" || reason=="DRIFT";
}
static void VerifyLive(const Receipt& r){VerifyPnp(r.pnp);VerifyNic(r.luid);}
static void AwaitReadback(Receipt& r,bool restore){
    const auto deadline=Clock::now()+std::chrono::milliseconds(2500);
    for(;;){
        try{
            VerifyLive(r);Sleep(15);VerifyLive(r);
            Session reader;reader.create();reader.init();
            {
                auto paths=ReadPaths(reader.cfg.Get(),r);
                if(!MapMatches(r,paths,restore)) Fail("READBACK");
            }
            reader.finish();VerifyLive(r);return;
        }catch(const Failure& failure){
            if(!TransientRead(failure) || Clock::now()>=deadline) throw;
            Sleep(20);
        }
    }
}
static void Change(NET_LUID luid,bool restore) {
    if(!luid.Value) Fail("IDENTITY");
    const Owner caller={GetCurrentProcessId(),Created(GetCurrentProcess())};
    auto& liveJournal=CurrentJournal();
    Session writer;writer.acquire();writer.init();
    Receipt receipt{luid,{},{}};
    std::vector<wchar_t> originalBytes;
    if(restore && liveJournal.empty()){
        // A separately attested recovery process may find an unrelated previous
        // installation with no per-device transaction. Confirming absence of
        // our own property is read-only even for a dormant admin-Up interface.
        {auto owned=Owned(writer.cfg.Get(),receipt,false);}
        if(ReadProperty(VerifyPnp(receipt.pnp)).empty()){
            writer.finish();return;
        }
    }
    bool staged=false;
    {
        auto paths=ReadPaths(writer.cfg.Get(),receipt);
        const DEVINST node=VerifyPnp(receipt.pnp);
        originalBytes=ReadProperty(node);
        if(!liveJournal.empty() && originalBytes!=liveJournal) Fail("JOURNAL");
        if(!originalBytes.empty()){
            const auto fields=Decode(originalBytes);
            LoadOriginal(receipt,fields,paths);
            const auto savedLuid=Number(fields[1],~0ULL);
            const Owner saved={static_cast<DWORD>(Number(fields[3],MAXDWORD)),Number(fields[4],~0ULL)};
            const bool sameProcess=caller.pid==saved.pid && caller.created==saved.created;
            if(!sameProcess && !OwnerEnded(saved)) Fail("OWNER");
            if(savedLuid!=luid.Value){
                // An old, removed creator can leave properties associated with
                // a re-created SWD instance. Only clear satisfied history; never
                // apply stale binding choices to a different network interface.
                if(sameProcess || !MapMatches(receipt,paths,true)) Fail("DRIFT");
                Clear(node,originalBytes);originalBytes.clear();receipt.original.clear();
            }
        }
        if(originalBytes.empty()){
            Capture(receipt,paths);
            if(restore){
                paths.clear();writer.finish();
                return; // Satisfied history, on a positively identified new interface.
            }
            originalBytes=Encode(receipt,caller);
            Store(node,originalBytes);
        }
        liveJournal=originalBytes;
        for(auto& [id,b]:paths){
            const bool original=receipt.original.at(id);
            if(!original && b.enabled) Fail("DRIFT");
            if(id[0]!=L'4' && id[0]!=L'6'){
                if(id[0]==L'N' && b.enabled!=original) Fail("DRIFT");
                continue;
            }
            const bool desired=restore && original;
            if(b.enabled!=desired){
                writer.pending=true;
                Ok(b.path->Enable(desired?TRUE:FALSE),"STAGE");staged=true;
            }
        }
    } // No child COM interface can outlive a changing network graph.
    if(staged){Ok(writer.cfg->Apply(),"APPLY");writer.pending=false;}
    writer.finish();
    AwaitReadback(receipt,restore);
    const DEVINST node=VerifyPnp(receipt.pnp);
    if(restore) Clear(node,originalBytes);
    else if(ReadProperty(node)!=originalBytes) Fail("JOURNAL");
}
// A failed Apply may have briefly invalidated the device graph, before the
// normal post-Apply waiter could run. Reopen a new writer only for a transient
// observation of this same device; each restore re-reads its durable receipt.
static void Restore(NET_LUID luid) {
    const auto deadline=Clock::now()+std::chrono::milliseconds(2500);
    for(;;) {
        try{Change(luid,true);return;}
        catch(const Failure& failure){
            if(!TransientRead(failure) || Clock::now()>=deadline) throw;
            Sleep(20);
        }
    }
}
// Wintun 0.14.1 builds the SWD instance ID from the GUID supplied to
// WintunCreateAdapter. Reconfirm it against the new NetCfg/PnP identity.
static std::wstring FixedSoftwareDevice() {
    wchar_t guid[40]={};
    if(!StringFromGUID2(expectedGuid,guid,_countof(guid))) Fail("IDENTITY");
    return std::wstring(L"SWD\\WINTUN\\")+guid;
}
struct PresentDevices {
    HDEVINFO set;
    PresentDevices():set(SetupDiGetClassDevsW(&GUID_DEVCLASS_NET,nullptr,nullptr,DIGCF_PRESENT)){
        if(set==INVALID_HANDLE_VALUE) Fail("LOOKUP");
    }
    ~PresentDevices(){SetupDiDestroyDeviceInfoList(set);}
};
static void VerifyDepartedNode(const std::wstring& fixed) {
    DEVINST located=0;
    auto id=fixed;
    // Stopped, disabled, problem or inaccessible nodes are not proof of removal.
    auto result=CM_Locate_DevNodeW(&located,id.data(),CM_LOCATE_DEVNODE_NORMAL);
    if(result==CR_SUCCESS){
        ULONG status=0,problem=0;
        if(CM_Get_DevNode_Status(&status,&problem,located,0)!=CR_SUCCESS) Fail("LOOKUP");
        if(status & DN_HAS_PROBLEM) Fail("PRESENT_PROBLEM");
        if(status & DN_STARTED) Fail("PRESENT_STARTED");
        Fail("PRESENT_STOPPED");
    }
    if(result!=CR_NO_SUCH_DEVNODE) Fail("LOOKUP");
    PresentDevices devices;
    for(DWORD i=0;;++i){
        SP_DEVINFO_DATA item={};item.cbSize=sizeof(item);
        if(!SetupDiEnumDeviceInfo(devices.set,i,&item)){
            if(GetLastError()==ERROR_NO_MORE_ITEMS) break;
            Fail("LOOKUP");
        }
        wchar_t instance[MAX_DEVICE_ID_LEN]={};
        if(!SetupDiGetDeviceInstanceIdW(devices.set,&item,instance,_countof(instance),nullptr)) Fail("LOOKUP");
        if(!_wcsicmp(instance,fixed.c_str())) Fail("SETUP_PRESENT");
    }
}
struct Departure {
    NET_LUID previous={};
    std::vector<wchar_t> previousJournal;
};
static Departure& DepartedWitness(){static Departure value;return value;}
static void CheckDepartedJournal(const std::vector<wchar_t>& data,const std::wstring& fixed,NET_LUID previous) {
    const auto fields=Decode(data);
    if(fields.size()<7 || fields[0]!=L"OracleProxy-Bindings-1" ||
       Number(fields[1],~0ULL)!=previous.Value || _wcsicmp(fields[2].c_str(),fixed.c_str())) Fail("JOURNAL");
    const Owner owner={static_cast<DWORD>(Number(fields[3],MAXDWORD)),Number(fields[4],~0ULL)};
    if(!OwnerEnded(owner)) Fail("OWNER");
}
static void WitnessDeparture(NET_LUID previous) {
    auto& witness=DepartedWitness();
    if(witness.previous.Value || !CurrentJournal().empty()) Fail("OWNER");
    VerifyNic(previous);
    const auto fixed=FixedSoftwareDevice();
    VerifyDepartedNode(fixed);
    DEVINST phantom=0; auto id=fixed;
    auto rc=CM_Locate_DevNodeW(&phantom,id.data(),CM_LOCATE_DEVNODE_PHANTOM);
    std::vector<wchar_t> journal;
    if(rc==CR_SUCCESS){
        wchar_t observed[MAX_DEVICE_ID_LEN]={};
        if(CM_Get_Device_IDW(phantom,observed,_countof(observed),0)!=CR_SUCCESS ||
           _wcsicmp(observed,fixed.c_str())) Fail("PNP");
        journal=ReadProperty(phantom);
        // A surviving devnode must account for its original binding choices.
        if(journal.empty()) Fail("MISSING_JOURNAL");
        CheckDepartedJournal(journal,fixed,previous);
    }else if(rc!=CR_NO_SUCH_DEVNODE){
        Fail("PNP");
    }
    VerifyDepartedNode(fixed);
    witness.previousJournal=std::move(journal);witness.previous=previous;
}
static void VerifyFreshBindings(NET_LUID previous,NET_LUID fresh) {
    auto& witness=DepartedWitness();
    if(!fresh.Value || !previous.Value || witness.previous.Value!=previous.Value) Fail("OWNER");
    const auto fixed=FixedSoftwareDevice();
    Receipt receipt{fresh,fixed,{}};
    const auto deadline=Clock::now()+std::chrono::milliseconds(1800);
    for(;;){
        try {
            Session reader;reader.create();reader.init();
            {
                auto paths=ReadPaths(reader.cfg.Get(),receipt);
                const auto current=ReadProperty(VerifyPnp(fixed));
                if(!current.empty() && current!=witness.previousJournal) Fail("JOURNAL");
                if(witness.previousJournal.empty()){
                    // The old devnode (including its property) was entirely gone.
                    // The newly created independent instance must have both protocols on.
                    Capture(receipt,paths);
                }else{
                    // Never transplant path activity across device generations.
                    // The newly materialized device must already satisfy its full
                    // captured map, including other bindings and dependency cascades.
                    LoadOriginal(receipt,Decode(witness.previousJournal),paths);
                    if(!MapMatches(receipt,paths,true)) Fail("DRIFT");
                }
            }
            reader.finish();VerifyLive(receipt);return;
        }catch(const Failure& issue){
            receipt.original.clear();
            if(!TransientRead(issue) || Clock::now()>=deadline) throw;
            Sleep(20);
        }
    }
}
static DWORD Run(ULONG64 expected,bool restore) {
    try{
        RequireSystem();Apartment apartment;TransactionLock serial;
        NET_LUID luid={};luid.Value=expected;
        try{if(restore) Restore(luid);else Change(luid,false);return ERROR_SUCCESS;}
        catch(...){
            // If a Park staged or committed any change, its original map exists.
            // Attempt restoration in a fresh transaction; incomplete restoration
            // stays journalled for the owner's close/recovery path.
            if(!restore && !CurrentJournal().empty()){
                try{Restore(luid);}catch(...){}
            }
            throw;
        }
    }catch(const Failure& e){
        if(!strcmp(e.reason,"SYSTEM")) return ERROR_ACCESS_DENIED;
        if(!strcmp(e.reason,"LOCK")) return ERROR_BUSY;
        if(!strcmp(e.reason,"REBOOT")) return ERROR_SUCCESS_REBOOT_REQUIRED;
        if(!strcmp(e.reason,"OWNER")) return ERROR_INVALID_OWNER;
        if(!strcmp(e.reason,"DRIFT")) return ERROR_REVISION_MISMATCH;
        if(!strcmp(e.reason,"PNP")) return ERROR_DEVICE_NOT_CONNECTED;
        if(!strcmp(e.reason,"IDENTITY")) return ERROR_NOT_FOUND;
        if(!strcmp(e.reason,"READBACK")) return ERROR_NO_MATCH;
        if(!strcmp(e.reason,"JOURNAL")) return ERROR_INVALID_DATA;
        return ERROR_INVALID_STATE;
    }catch(...){return ERROR_GEN_FAILURE;}
}
} // namespace

extern "C" __declspec(dllexport) DWORD __cdecl OpParkIpBindings(ULONG64 creatorLuid){
    return Run(creatorLuid,false);
}
extern "C" __declspec(dllexport) DWORD __cdecl OpRestoreIpBindings(ULONG64 creatorLuid){
    return Run(creatorLuid,true);
}

// The SYSTEM recovery process which witnessed the exact departed node is the
// only process able to compare the replacement. Neither phase edits bindings.
extern "C" __declspec(dllexport) DWORD __cdecl OpDormantDepartureEvidence(ULONG64 oldLuid,ULONG64 newLuid) {
    try {
        RequireSystem();Apartment apartment;TransactionLock serial;
        NET_LUID oldId={},newId={};oldId.Value=oldLuid;newId.Value=newLuid;
        if(!oldId.Value) Fail("IDENTITY");
        if(newId.Value) VerifyFreshBindings(oldId,newId);
        else WitnessDeparture(oldId);
        return ERROR_SUCCESS;
    }catch(const Failure& failure){
        const auto* r=failure.reason;
        if(!strcmp(r,"PRESENT_STARTED")) return 1;
        if(!strcmp(r,"PRESENT_STOPPED")) return 2;
        if(!strcmp(r,"PRESENT_PROBLEM")) return 3;
        if(!strcmp(r,"SETUP_PRESENT")) return 4;
        if(!strcmp(r,"MISSING_JOURNAL")) return 5;
        if(!strcmp(r,"JOURNAL")) return 6;
        if(!strcmp(r,"OWNER")) return 7;
        return newLuid ? 8 : 9;
    }catch(...){return 9;}
}
