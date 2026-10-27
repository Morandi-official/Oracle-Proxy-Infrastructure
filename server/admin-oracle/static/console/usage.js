'use strict';
// Authenticated, on-demand user charts. Keep row/control nodes across polling.
const userViews=new Map(), usageCache=new Map(), usagePending=new Set();
function userById(id){return current?.users.find(u=>u.id===id);}
function renderUsers(data){
 const nodes=[];
 for(const u of data.users){
  let view=userViews.get(u.id);
  if(!view){
   const row=document.createElement('tr'), name=cell(row,'');
   const toggle=document.createElement('button');toggle.type='button';toggle.className='user-toggle';toggle.setAttribute('aria-controls','usage-'+u.id);
   const meta=document.createElement('span');meta.className='user-meta';name.append(toggle,meta);
   const used=cell(row,''),remaining=cell(row,''),expires=cell(row,''),actions=cell(row,'');
   button(actions,'编辑',()=>editUser(userById(u.id)));
   const detail=document.createElement('tr');detail.id='usage-'+u.id;detail.className='user-history';detail.hidden=true;
   const content=cell(detail,'');content.colSpan=5;
   const head=document.createElement('div');head.className='history-heading';
   const select=document.createElement('select');select.setAttribute('aria-label','流量统计范围');
   for(const [key,label] of [['day','今日'],['week','近7天'],['month','本月']]){const option=document.createElement('option');option.value=key;option.textContent=label;select.append(option);}select.value='month';
   const summary=document.createElement('span');summary.className='muted';head.append(select,summary);
   const progress=document.createElement('progress');progress.className='quota-progress';progress.setAttribute('aria-label','共享月配额已用');
   const status=document.createElement('p');status.className='muted history-status';
   const chart=document.createElement('div');chart.className='usage-chart';
   const note=document.createElement('p');note.className='muted history-note';
   content.append(head,progress,status,chart,note);
   view={row,toggle,meta,used,remaining,expires,detail,select,summary,progress,status,chart,note,open:false,entry:null};userViews.set(u.id,view);
   toggle.addEventListener('click',()=>{view.open=!view.open;view.detail.hidden=!view.open;view.toggle.setAttribute('aria-expanded',String(view.open));view.toggle.textContent=(view.open?'▾ ':'▸ ')+(userById(u.id)?.name || '账号');if(view.open)loadUserUsage(u.id);});
   select.addEventListener('change',()=>{view.entry=null;loadUserUsage(u.id,true);});
  }
  view.toggle.textContent=(view.open?'▾ ':'▸ ')+u.name;view.toggle.setAttribute('aria-expanded',String(view.open));
  view.meta.textContent=`${u.username || '未分配账号'} · ${states[u.status]} · ${u.device_count}/${u.device_limit} 台`;
  view.row.dataset.status=u.status;view.used.className='numeric';view.remaining.className='numeric';view.used.textContent=size(u.usage.rx+u.usage.tx);view.remaining.textContent=u.quota===null?'不限':size(u.remaining_bytes);view.expires.textContent=u.expires===null?'长期':time(u.expires);
  nodes.push(view.row,view.detail);
  if(view.open){renderUserUsage(u.id);loadUserUsage(u.id);}
 }
 for(const id of userViews.keys())if(!data.users.some(u=>u.id===id)){userViews.delete(id);for(const key of usageCache.keys())if(key.startsWith(id+':'))usageCache.delete(key);}
 const body=el('user-rows');if(nodes.length!==body.children.length || nodes.some((node,i)=>body.children[i]!==node))body.replaceChildren(...nodes);
 if(!nodes.length){body.replaceChildren();emptyRow('user-rows',5,'尚无用户，请新建账号。');}
}
async function loadUserUsage(id,force=false){
 const view=userViews.get(id);if(!view?.open)return;
 const window=view.select.value,key=id+':'+window,cached=usageCache.get(key);
 if(!force && cached && Date.now()-cached.at<30000){renderUserUsage(id);return;}
 if(usagePending.has(key))return;usagePending.add(key);
 if(!cached)view.status.textContent='正在读取分时用量…';
 try{const data=await api(`/api/users/${encodeURIComponent(id)}/usage?window=${window}`);usageCache.set(key,{data,at:Date.now()});renderUserUsage(id);}
 catch(error){if(userViews.get(id)?.select.value===window)view.status.textContent=error.message;}
 finally{usagePending.delete(key);}
}
function renderUserUsage(id){
 const view=userViews.get(id),u=userById(id);if(!view?.open || !u)return;
 const used=u.usage.rx+u.usage.tx;
 view.summary.textContent=u.quota===null?`本月已用 ${size(used)} · 不限额`:`本月已用 ${size(used)} / ${size(u.quota)} · 剩余 ${size(u.remaining_bytes)}`;
 view.progress.hidden=u.quota===null;view.progress.max=u.quota || 1;view.progress.value=Math.min(used,u.quota || 1);
 const entry=usageCache.get(id+':'+view.select.value);if(!entry || entry===view.entry)return;
 const data=entry.data;view.entry=entry;
 view.status.textContent=`此视图已记录 ${size(data.recorded_bytes)} · 上传 + 下载 · UTC`;
 const stale=!data.observed_at || Date.now()/1000-data.observed_at>20;
 view.note.textContent=stale?'采样已过期，当前图表不能作为实时状态。':data.history_complete?`采样 ${time(data.observed_at)}`:`细分采集始于 ${time(data.recorded_from)}；未采集部分未补零。`;
 const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');svg.setAttribute('viewBox','0 0 720 190');svg.setAttribute('role','img');svg.setAttribute('aria-label','用户'+({day:'今日小时',week:'近7天每日',month:'本月每日'})[data.window]+'流量柱状图，UTC统计');
 const make=(tag,attrs,text)=>{const node=document.createElementNS(ns,tag);for(const [k,v] of Object.entries(attrs))node.setAttribute(k,String(v));if(text!==undefined)node.textContent=text;return node;};
 const buckets=data.buckets,peak=Math.max(0,...buckets.map(b=>b.rx_bytes+b.tx_bytes)),max=Math.max(3,peak),width=640/buckets.length;
 for(let i=0;i<=(peak?3:0);i++){const y=150-i*40;svg.append(make('line',{x1:58,x2:704,y1:y,y2:y,class:'usage-grid'}),make('text',{x:52,y:y+4,'text-anchor':'end'},size(max*i/3)));}
 for(let i=0;i<buckets.length;i++){
  const b=buckets[i],value=b.rx_bytes+b.tx_bytes,height=Math.max(value?2:1,value/max*120),x=60+i*width+width*.18;
  const rect=make('rect',{x,y:150-height,width:Math.max(3,width*.64),height,rx:2,class:'usage-bar '+b.coverage});
  const date=new Date(b.start_at*1000),label=data.window==='day'?String(date.getUTCHours()).padStart(2,'0'):String(date.getUTCMonth()+1)+'/'+date.getUTCDate();
  const coverage={future:'尚未发生',unknown:'尚未采集',partial:'统计不完整',complete:b.ongoing?'采集中':'已采集'}[b.coverage];
  rect.append(make('title',{},`${date.toISOString().slice(0,16).replace('T',' ')} UTC\n${size(value)} · ${coverage}`));svg.append(rect);
  if(i%Math.ceil(buckets.length/8)===0 || i===buckets.length-1)svg.append(make('text',{x:x+width*.32,y:174,'text-anchor':'middle'},label));
 }
 if(!peak)svg.append(make('text',{x:380,y:84,'text-anchor':'middle'},'暂无已记录流量'));
 view.chart.replaceChildren(svg);
}
