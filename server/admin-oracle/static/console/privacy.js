"use strict";
window.OraclePrivacyResult=null;
document.getElementById('start').addEventListener('click',async()=>{
 const button=document.getElementById('start'),output=document.getElementById('result');button.disabled=true;window.OraclePrivacyResult=null;output.textContent='正在收集 ICE 候选（最多12秒）…';
 const candidates=[];let pc;
 try{
  pc=new RTCPeerConnection({iceServers:[{urls:['stun:stun.cloudflare.com:3478','stun:stun.l.google.com:19302']}],iceCandidatePoolSize:0});
  pc.createDataChannel('privacy-check');
  await new Promise(async(resolve,reject)=>{const timer=setTimeout(resolve,12000);pc.onicecandidate=e=>{if(!e.candidate){clearTimeout(timer);resolve();return;}const c=e.candidate;candidates.push({type:c.type,address:c.address,related:c.relatedAddress});};try{await pc.setLocalDescription(await pc.createOffer());}catch(e){clearTimeout(timer);reject(e);}});
  const addresses=[...new Set(candidates.filter(c=>c.type==='srflx').map(c=>c.address).filter(Boolean))];
  const local=a=>/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|127\.|f[cd][0-9a-f]{2}:|fe80:)/i.test(a || '');
  const hosts=[...new Set(candidates.flatMap(c=>[c.type==='host'?c.address:null,c.related]).filter(a=>a && a!=='0.0.0.0' && a!=='::' && local(a)))];
  const unexpected=candidates.flatMap(c=>[c.address,c.related]).some(a=>a && !a.toLowerCase().endsWith('.local') && !local(a) && a!=='0.0.0.0' && a!=='::' && a!=='152.67.156.100');
  window.OraclePrivacyResult={public_ips:addresses,local_exposed:hosts.length>0,unexpected_public:unexpected,oracle_verified:addresses.includes('152.67.156.100') && !unexpected};
  output.textContent=unexpected?'发现非Oracle公网候选，请核对是否已连接VPN。':addresses.includes('152.67.156.100')?'公网STUN候选已验证为Oracle出口。'+(hosts.length?' 浏览器仍暴露本地地址，请查看下方说明。':' 未发现明文本地地址候选。'):'未获得公网STUN候选，结果不确定，不能据此证明无泄漏。';
  document.getElementById('candidates').textContent=candidates.map(c=>`${c.type || 'unknown'} · ${c.address || '隐藏'}${c.related?' · related '+c.related:''}`).join('\n') || '无候选';
 }catch{window.OraclePrivacyResult={oracle_verified:false,error:'WEBRTC_UNAVAILABLE'};output.textContent='WebRTC不可用或检查失败，结果不确定。';}finally{if(pc)pc.close();button.disabled=false;}
});
