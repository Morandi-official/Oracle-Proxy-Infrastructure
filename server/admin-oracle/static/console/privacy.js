"use strict";
window.OraclePrivacyResult=null;
document.getElementById('start').addEventListener('click',async()=>{
 const button=document.getElementById('start'),output=document.getElementById('result');button.disabled=true;window.OraclePrivacyResult=null;output.textContent='正在收集 ICE 候选（最多12秒）…';
 const candidates=[];let pc;
 try{
  pc=new RTCPeerConnection({iceServers:[{urls:['stun:stun.cloudflare.com:3478','stun:stun.l.google.com:19302']}],iceCandidatePoolSize:0});
  pc.createDataChannel('privacy-check');
  await new Promise(async(resolve,reject)=>{const timer=setTimeout(resolve,12000);pc.onicecandidate=e=>{if(!e.candidate){clearTimeout(timer);resolve();return;}const c=e.candidate;candidates.push({type:c.type,address:c.address,related:c.relatedAddress});};try{await pc.setLocalDescription(await pc.createOffer());}catch(e){clearTimeout(timer);reject(e);}});
  // Edge may expose IPv6 ICE literals with URI brackets. Compare canonical
  // literals, while retaining the original candidate text below for diagnosis.
  const normalize=value=>{
   if(typeof value!=='string')return '';
   const raw=value.trim().toLowerCase(),literal=raw.startsWith('[')&&raw.endsWith(']')?raw.slice(1,-1):raw;
   if(!literal.includes(':'))return literal;
   try{return new URL(`http://[${literal}]/`).hostname.slice(1,-1);}catch{return raw;}
  };
  const normalized=candidates.map(c=>({...c,address:normalize(c.address),related:normalize(c.related)}));
  const addresses=[...new Set(normalized.filter(c=>c.type==='srflx').map(c=>c.address).filter(Boolean))];
  const local=a=>/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|127\.|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:|::1$)/i.test(a || '');
  const hosts=[...new Set(normalized.flatMap(c=>[c.type==='host'?c.address:null,c.related]).filter(a=>a && a!=='0.0.0.0' && a!=='::' && local(a)))];
  const oracle=a=>a==='152.67.156.100' || a?.toLowerCase()==='2603:c020:c015:8100::10';
  const verified=addresses.some(oracle);
  const unexpected=normalized.flatMap(c=>[c.address,c.related]).some(a=>a && !a.toLowerCase().endsWith('.local') && !local(a) && a!=='0.0.0.0' && a!=='::' && !oracle(a));
  window.OraclePrivacyResult={public_ips:addresses,local_exposed:hosts.length>0,unexpected_public:unexpected,oracle_verified:verified && !unexpected};
  output.textContent=unexpected?'发现非Oracle公网候选，请核对是否已连接VPN。':verified?'公网STUN候选已验证为Oracle出口。'+(hosts.length?' 浏览器仍暴露本地地址，请查看下方说明。':' 未发现明文本地地址候选。'):'未获得公网STUN候选，结果不确定，不能据此证明无泄漏。';
  document.getElementById('candidates').textContent=candidates.map(c=>`${c.type || 'unknown'} · ${c.address || '隐藏'}${c.related?' · related '+c.related:''}`).join('\n') || '无候选';
 }catch{window.OraclePrivacyResult={oracle_verified:false,error:'WEBRTC_UNAVAILABLE'};output.textContent='WebRTC不可用或检查失败，结果不确定。';}finally{if(pc)pc.close();button.disabled=false;}
});
