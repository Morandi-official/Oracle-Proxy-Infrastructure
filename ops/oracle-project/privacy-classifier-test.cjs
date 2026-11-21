const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict');
const source=fs.readFileSync(require('node:path').join(__dirname,'../../server/admin-oracle/static/console/privacy.js'),'utf8');
const primary='192.0.2.8',backup='198.51.100.7',ipv6='2603:c020:c015:8100::10';
(async()=>{for(const [rows,expected,exits=[primary,backup,ipv6]] of [
 [[{type:'srflx',address:primary,relatedAddress:'0.0.0.0'},{type:'host',address:'fcaa-test.local'}],{oracle_verified:true,local_exposed:false,unexpected_public:false}],
 [[{type:'srflx',address:backup}],{oracle_verified:true,local_exposed:false,unexpected_public:false}],
 [[{type:'srflx',address:'152.67.156.100'}],{oracle_verified:false,local_exposed:false,unexpected_public:true}],
 [[{type:'srflx',address:primary}],{oracle_verified:false,local_exposed:false,unexpected_public:false},[]],
 [[{type:'srflx',address:primary,relatedAddress:'203.0.113.1'}],{oracle_verified:false,local_exposed:false,unexpected_public:true}],
 [[{type:'srflx',address:primary,relatedAddress:'192.168.1.2'}],{oracle_verified:true,local_exposed:true,unexpected_public:false}],
 [[{type:'host',address:'2001:db8::1'}],{oracle_verified:false,local_exposed:false,unexpected_public:true}],
 [[{type:'srflx',address:'2603:c020:c015:8100::10'}],{oracle_verified:true,local_exposed:false,unexpected_public:false}],
 [[{type:'srflx',address:'2603:c020:c015:8100::11'}],{oracle_verified:false,local_exposed:false,unexpected_public:true}],
 // Exact owner report: bracketed Oracle IPv6 and unspecified related address.
 [[{type:'host',address:'bf6e5347-4828-4712-b606-4147e3f4b613.local'},{type:'host',address:'17df88f2-d131-4e4b-834e-a4e0493dd75a.local'},{type:'srflx',address:'[2603:c020:c015:8100::10]',relatedAddress:'[::]'},{type:'srflx',address:primary,relatedAddress:'0.0.0.0'}],{oracle_verified:true,local_exposed:false,unexpected_public:false}],
 [[{type:'srflx',address:'[2603:C020:C015:8100:0000:0000:0000:0010]',relatedAddress:'[0:0:0:0:0:0:0:0]'}],{oracle_verified:true,local_exposed:false,unexpected_public:false}],
 [[{type:'srflx',address:'[2603:c020:c015:8100::11]',relatedAddress:'[::]'}],{oracle_verified:false,local_exposed:false,unexpected_public:true}],
 [[{type:'srflx',address:primary,relatedAddress:'[2001:db8::123]'}],{oracle_verified:false,local_exposed:false,unexpected_public:true}],
 [[{type:'srflx',address:'[2603:c020:c015:8100::10]',relatedAddress:'[fd00::2]'}],{oracle_verified:true,local_exposed:true,unexpected_public:false}],
 [[{type:'host',address:'[fe90::1]'}],{oracle_verified:false,local_exposed:true,unexpected_public:false}],
 [[{type:'host',address:'[::1]'}],{oracle_verified:false,local_exposed:true,unexpected_public:false}],
 [[],{oracle_verified:false,local_exposed:false,unexpected_public:false}]]){
 let click;const elements={start:{addEventListener:(_,f)=>click=f},result:{},candidates:{parentElement:{}}};
 class PC{createDataChannel(){} async createOffer(){return{}}async setLocalDescription(){for(const c of rows)this.onicecandidate({candidate:c});this.onicecandidate({candidate:null});}close(){}}
 const document={getElementById:id=>elements[id],querySelectorAll:selector=>{assert.equal(selector,'#expected-exits code');return exits.map(textContent=>({textContent}));}};
 const context={window:{},document,RTCPeerConnection:PC,URL,setTimeout,clearTimeout};vm.runInNewContext(source,context);await click();for(const [key,v]of Object.entries(expected))assert.equal(context.window.OraclePrivacyResult[key],v,key);
 }console.log('WEBRTC_CLASSIFICATION_PUBLIC_RELATED_IPV6_MDNS_PRIVATE_AND_NO_RESPONSE=PASS')})().catch(e=>{console.error(e);process.exit(1)});
