"use strict";
window.OraclePrivacyResult=null;
document.getElementById('start').addEventListener('click',async()=>{
 const button=document.getElementById('start'),output=document.getElementById('result');button.disabled=true;window.OraclePrivacyResult=null;output.textContent='正在收集 ICE 候选（最多12秒）…';
 const list=document.getElementById('candidates');list.textContent='';
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
  const expected=new Set([...document.querySelectorAll('#expected-exits code')].map(item=>normalize(item.textContent)));
  const verified=addresses.some(a=>expected.has(a));
  const unexpected=expected.size>0 && normalized.flatMap(c=>[c.address,c.related]).some(a=>a && !a.endsWith('.local') && !local(a) && a!=='0.0.0.0' && a!=='::' && !expected.has(a));
  window.OraclePrivacyResult={public_ips:addresses,local_exposed:hosts.length>0,unexpected_public:unexpected,oracle_verified:verified && !unexpected};
  if(!expected.size)output.textContent='无法读取 VPN 出口配置，请查看候选地址并与客户端核对。';
  else if(unexpected)output.textContent='发现未列入配置的公网候选。请确认 VPN 已连接，再核对候选地址。';
  else if(verified)output.textContent='公网候选与配置的 VPN 出口一致。'+(hosts.length?' 浏览器仍报告了明文本地地址。':' 未发现明文本地地址。');
  else output.textContent='未获得公网 STUN 候选，无法确认结果。';
  list.textContent=candidates.map(c=>`${c.type || 'unknown'} · ${c.address || '隐藏'}${c.related?' · 关联地址 '+c.related:''}`).join('\n') || '无候选';
  if(candidates.length && (unexpected || !expected.size))list.parentElement.open=true;
 }catch{window.OraclePrivacyResult={oracle_verified:false,error:'WEBRTC_UNAVAILABLE'};output.textContent='WebRTC不可用或检查失败，结果不确定。';}finally{if(pc)pc.close();button.disabled=false;}
});
