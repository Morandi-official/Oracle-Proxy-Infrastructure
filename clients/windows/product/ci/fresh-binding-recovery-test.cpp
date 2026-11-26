// Exercise the production fresh-adapter transaction with controlled NetCfg state.
// The Python test inserts the exact production routines at the marked locations.
#include <string>
#include <map>
#include <vector>
#include <stdexcept>
#include <cwchar>
#include <chrono>
#include <cstring>
#include <iostream>
#include <utility>
struct Clock{ static auto now(){static std::chrono::steady_clock::time_point t{};return t+=std::chrono::milliseconds(400);} };
using Strings=std::vector<std::wstring>;
using DEVINST=int;
using DWORD=unsigned;
constexpr bool TRUE=true,FALSE=false;
#ifndef _WIN32
#define _wcsicmp wcscasecmp
#endif
struct Failure{const char* reason;};
[[noreturn]] void Fail(const char* r){throw Failure{r};}
void Ok(int hr,const char* why){if(hr) Fail(why);}
void Sleep(int){}
struct NET_LUID{unsigned long long Value;};
struct Receipt{NET_LUID luid;std::wstring pnp;std::map<std::wstring,bool> original;};
static std::map<std::wstring,bool> state,desired;
static int applyCount,stageCount;
static bool breakApply;
static bool diskExists,propertyExists;
struct Path{
    std::wstring id;
    int Enable(bool v){
        if(id[0]!=L'4' && id[0]!=L'6')throw std::logic_error("foreign write");
        ++stageCount;desired[id]=v;return 0;
    }
};
using Bindings=std::map<std::wstring,struct Binding>;
struct Binding{Path* path;bool enabled;};
struct MockConfig {
    MockConfig* Get(){return this;}
    int Apply(){
        ++applyCount;
        for(const auto& [k,v]:desired) state[k]=v;
        if(desired.count(L"4|ms_tcpip|a")||desired.count(L"6|ms_tcpip6|b"))
            state[L"D|ms_server|c"]=state.at(L"4|ms_tcpip|a")&&state.at(L"6|ms_tcpip6|b");
        desired.clear();
        if(breakApply){breakApply=false;return 1;}
        return 0;
    }
};
struct Cfg{MockConfig m;MockConfig* operator->(){return &m;} MockConfig* Get(){return &m;}};
struct Session{
    Cfg cfg;bool pending=false;void create(){}void acquire(){}void init(){}void finish(){}
    ~Session(){if(pending)desired.clear();}
};
static std::map<std::wstring,Path> handles;
static Bindings ReadPaths(MockConfig*,Receipt& t){
    if(t.luid.Value!=12) throw std::logic_error("foreign LUID");
    Bindings paths;
    for(const auto& [k,v]:state){
        handles[k]=Path{k};paths.emplace(k,Binding{&handles.at(k),v});
    }
    return paths;
}
const std::wstring fixed=L"fixed";
std::wstring FixedSoftwareDevice(){return fixed;}
void VerifyLive(const Receipt& r){if(r.pnp!=fixed) throw std::logic_error("foreign PnP");}
int VerifyPnp(const std::wstring& s){if(s!=fixed)Fail("PNP");return 9;}
static const std::vector<wchar_t> saved={L'A',0,0};
static Strings fields;
Strings Decode(const std::vector<wchar_t>& j){if(j!=saved)Fail("JOURNAL");return fields;}
std::vector<wchar_t> ReadProperty(int n){if(n!=9)Fail("PNP");return propertyExists?saved:std::vector<wchar_t>{};}
std::vector<wchar_t> ReadProtectedBindingReceipt(){return diskExists?saved:std::vector<wchar_t>{};}
void StoreProtectedBindingReceipt(const std::vector<wchar_t>& j){if(j!=saved)Fail("JOURNAL");diskExists=true;}
void Store(int n,const std::vector<wchar_t>& j){if(n!=9||j!=saved)Fail("JOURNAL");propertyExists=true;}
void ClearProtectedBindingReceipt(const std::vector<wchar_t>& j){if(j!=saved)Fail("JOURNAL");diskExists=false;}
void Clear(int n,const std::vector<wchar_t>& j){if(n!=9||j!=saved)Fail("JOURNAL");propertyExists=false;ClearProtectedBindingReceipt(j);}
struct Departure{NET_LUID previous;std::vector<wchar_t> previousJournal;};
static Departure w;
Departure& DepartedWitness(){return w;}
void CheckDepartedJournal(const std::vector<wchar_t>& j,const std::wstring& k,NET_LUID p){if(j!=saved||k!=fixed||p.Value!=7)Fail("OWNER");}
bool TransientRead(const Failure&){return false;}
static bool MapMatches(const Receipt&,const Bindings&,bool);
void AwaitReadback(Receipt& r,bool exact){auto paths=ReadPaths(nullptr,r);if(!MapMatches(r,paths,exact))Fail("READBACK");}

// INSERT_BINDING_MAP_ROUTINES
// INSERT_FRESH_RECOVERY_ROUTINES
int main(){
    auto setup=[](bool off,bool record){
        state={{L"4|ms_tcpip|a",!off},{L"6|ms_tcpip6|b",!off},{L"D|ms_server|c",!off},{L"N|other|d",false}};
        fields={L"OracleProxy-Bindings-1",L"7",fixed,L"123",L"123456",L"+4|ms_tcpip|a",L"+6|ms_tcpip6|b",L"+D|ms_server|c",L"-N|other|d"};
        w={{7},record?saved:std::vector<wchar_t>{}};propertyExists=false;diskExists=record;
        applyCount=stageCount=0;breakApply=false;desired.clear();
    };
    auto run=[](const char* code){
        try{RecoverFreshBindings({7},{12});if(*code)throw std::logic_error("missing failure");}
        catch(const Failure& f){if(std::strcmp(code,f.reason)){std::cerr<<code<<" vs "<<f.reason;throw;}}
    };
    auto expect=[](bool b){if(!b)throw std::logic_error("wrong result");};
    setup(true,true);run("");expect(stageCount==2&&applyCount==1&&!propertyExists&&!diskExists&&state[L"D|ms_server|c"]);
    setup(false,true);run("");expect(stageCount==0&&applyCount==0&&!diskExists);
    setup(true,true);state[L"N|other|d"]=true;run("FRESH_FLAGS");expect(applyCount==0&&diskExists);
    setup(true,true);state[L"4|ms_tcpip|a"]=true;run("FRESH_FLAGS");expect(applyCount==0&&diskExists);
    setup(true,true);state.erase(L"6|ms_tcpip6|b");state[L"6|ms_tcpip6|new"]=false;run("FRESH_TOKENS");expect(applyCount==0&&diskExists);
    setup(true,true);state.erase(L"N|other|d");state[L"N|third|d"]=false;run("FRESH_COMPONENTS");expect(applyCount==0&&diskExists);
    setup(true,false);run("FRESH_UNRECORDED");expect(applyCount==0);
    setup(false,false);run("");expect(applyCount==0);
    setup(true,true);breakApply=true;const auto initial=state;run("APPLY");expect(applyCount==2&&state==initial&&diskExists&&propertyExists);
}
