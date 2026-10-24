const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict');
const source=fs.readFileSync(require('node:path').join(__dirname,'../../server/admin-oracle/static/console/privacy.js'),'utf8');
(async()=>{for(const [rows,expected] of [
 [[{type:'srflx',address:'152.67.156.100',relatedAddress:'0.0.0.0'},{type:'host',address:'fcaa-test.local'}],{oracle_verified:true,local_exposed:false,unexpected_public:false}],
 [[{type:'srflx',address:'152.67.156.100',relatedAddress:'203.0.113.1'}],{oracle_verified:false,local_exposed:false,unexpected_public:true}],
 [[{type:'srflx',address:'152.67.156.100',relatedAddress:'192.168.1.2'}],{oracle_verified:true,local_exposed:true,unexpected_public:false}],
 [[{type:'host',address:'2001:db8::1'}],{oracle_verified:false,local_exposed:false,unexpected_public:true}],
 [[],{oracle_verified:false,local_exposed:false,unexpected_public:false}]]){
 let click;const elements={start:{addEventListener:(_,f)=>click=f},result:{},candidates:{}};
 class PC{createDataChannel(){} async createOffer(){return{}}async setLocalDescription(){for(const c of rows)this.onicecandidate({candidate:c});this.onicecandidate({candidate:null});}close(){}}
 const context={window:{},document:{getElementById:id=>elements[id]},RTCPeerConnection:PC,setTimeout,clearTimeout};vm.runInNewContext(source,context);await click();for(const [key,v]of Object.entries(expected))assert.equal(context.window.OraclePrivacyResult[key],v,key);
 }console.log('WEBRTC_CLASSIFICATION_PUBLIC_RELATED_IPV6_MDNS_PRIVATE_AND_NO_RESPONSE=PASS')})().catch(e=>{console.error(e);process.exit(1)});
