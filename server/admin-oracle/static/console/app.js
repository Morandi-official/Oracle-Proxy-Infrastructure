'use strict';
const el = id => document.getElementById(id);
const time = v => v ? new Date(v * 1000).toLocaleString('zh-CN', {timeZone:'Asia/Shanghai',hour12:false})+'（UTC+8）' : '—';
const size = v => {if (v === null || v === undefined) return '未知'; let n=Number(v), i=0; const u=['B','KB','MB','GB','TB']; while(n>=1000 && i<4){n/=1000;i++;} return `${n.toFixed(i ? 2 : 0)} ${u[i]}`;};
const states={active:'可用',disabled:'已禁用',expired:'已到期',quota:'配额耗尽'};
const errors={DEVICE_LIMIT_REACHED:'设备数量已达上限，请先撤销旧设备或调整上限。',DEVICE_REVOKED:'该设备已撤销，请在客户端重新生成设备身份。',REVOKE_DEVICES_BEFORE_LOWERING_LIMIT:'请先撤销多余设备，再降低上限。',USERNAME_ALREADY_EXISTS:'登录账号已被使用。',INVALID_USERNAME:'账号须为 3 至 64 位小写字母、数字、点、下划线或连字符。',PASSWORD_LENGTH_12_TO_128_REQUIRED:'密码长度须为 12 至 128 字符。',CONTROL_SERVICE_UNAVAILABLE:'控制服务不可用，当前数据不能作为实时状态。',BASELINE_CONFIRMATION_REQUIRED:'请核对账期用量并勾选确认。',HOST_ADDRESS_REQUIRED:'该 Peer 包含网段路由，暂不能纳管；只支持独立 /32 或 /128 设备地址。',NO_FREE_IPV4_TUNNEL_ADDRESS:'当前接口没有可分配的私有 IPv4 地址。',INVALID_PUBLIC_KEY:'请输入本机生成的 WireGuard 公钥，不是私钥。',PEER_ALREADY_EXISTS:'此 Peer 已存在，请使用“绑定 / 调整已有 Peer”。',PEER_NOT_FOUND:'未找到该 Peer，请刷新后选择已有设备。',INVALID_BUDGET:'额度必须大于零，安全余量必须小于额度。',OFFICIAL_USAGE_NOT_READY:'官方报表未就绪或已过期，请等定时查询完成；无法凭空校准。',CONTROL_UNAVAILABLE:'控制服务暂时不可用；已纳管流量仍受内核规则保护。'};
let current=null, busy=false, budgetInitialized=false, lastBasic=0, baseAudit=[], activity=[];
function feedback(text, error=false){el('feedback').hidden=false;el('feedback').textContent=text;el('feedback').classList.toggle('error',error);}
async function api(path, value){
 const options={credentials:'same-origin',redirect:'error',cache:'no-store'};
 if(value){options.method='POST';options.headers={'Content-Type':'application/json','X-CSRFToken':document.querySelector('[name=csrfmiddlewaretoken]').value};options.body=JSON.stringify(value);}
 const response=await fetch(path,options); const data=await response.json().catch(()=>({error:'INVALID_RESPONSE'}));
 if(!response.ok){if(response.status===401)throw new Error('登录已失效，请重新登录。');if(response.status===403)throw new Error('会话或页面验证已过期，请重新登录。');throw new Error(errors[data.error] || `操作未完成（${data.error || response.status}）。`);}
 return data;
}
function cell(row,value){const td=document.createElement('td');td.textContent=value;row.append(td);return td;}
function button(parent,label,action){const b=document.createElement('button');b.type='button';b.textContent=label;b.addEventListener('click',action);parent.append(b);return b;}
function render(data){
 current=data;const b=data.budget;const age=data.observed_at ? Math.max(0,Date.now()/1000-data.observed_at) : null;
 el('remaining').textContent=size(b.remaining_bytes);el('outbound').textContent=size(b.measured_outbound_bytes);el('available').textContent=size(b.vpn_available_bytes ?? b.reference_available_bytes);el('available-basis').textContent=b.vpn_available_bytes===null?'保守参考值；启用保护前请校准基线':'执行预算：校准后剩余 − 安全余量';
 el('balance-basis').textContent=b.history_complete ? '手工核对基线 + 本机增量估算' : '历史未核对 / 采集有缺口';
 el('egress-interface').textContent=`VNIC ${data.nics.join(', ') || '未知'} · 仅出站 TX`;
 el('enforcement').textContent=data.error ? '采集 / 执行异常' : b.guard_blocked ? '总量保护已阻断' : b.guard_enabled ? '总量保护已启用' : '用户策略运行中';
 el('freshness').textContent=age===null?'暂无数据':`采样 ${Math.floor(age)} 秒前 · 租约 ${data.lease_seconds} 秒`;
 el('notice').classList.toggle('error',Boolean(data.error || age===null || age>20 || b.guard_blocked));
 el('budget-state').textContent=(b.guard_enabled?(b.guard_blocked?'保护已启用 · 正在阻断 VPN':'保护已启用'):'保护未启用')+' · 其他系统流量仍会消耗出站额度。';
 el('official-summary').textContent='最近查询 '+time(data.official_usage?.checked_at)+' · 账单延迟';
 el('notice').textContent=data.error ? '采集或执行异常，放行租约不再续期。请检查控制服务，不能把历史数据当成实时余额。' : b.guard_blocked ? 'VPN 总量保护正在阻断：预算已到安全阈值，或当前账期历史未知。HTTPS 与公网 SSH 保留。' : '监管正常。';
 el('usage-explanation').textContent=`用户配额统计 WireGuard 上传+下载；Oracle 出站保护统计物理 VNIC 发送字节，二者口径不同。当前采集始于 ${time(b.started_at)}。官方查询与账单延迟另列如下；本机估算不会自动冒充官方余额。`;
 const official=data.official_usage || {};
 const officialReady=official.free_tier_status==='VERIFIED_USAGE_AND_PRICE_TIER' && official.period===data.period && Number.isFinite(official.free_tier_remaining_gb) && Date.now()/1000-official.checked_at>=0 && Date.now()/1000-official.checked_at<7200;
 const gb=v=>Number.isFinite(v)?new Intl.NumberFormat('zh-CN',{maximumFractionDigits:3}).format(v)+' GB':'未知';
 el('official-limit').textContent=officialReady?gb(official.free_tier_limit_gb):'未知';el('official-used').textContent=officialReady?gb(official.free_tier_used_gb):'未知';el('official-remaining').textContent=officialReady?gb(official.free_tier_remaining_gb):'未知';
 el('official-progress').max=officialReady?official.free_tier_limit_gb:1;el('official-progress').value=officialReady?Math.min(official.free_tier_used_gb,official.free_tier_limit_gb):0;
 el('remaining-label').textContent=officialReady?'官方口径剩余出站（账单延迟）':'本账期估算剩余出站';
 if(officialReady){el('remaining').textContent=gb(official.free_tier_remaining_gb);el('balance-basis').textContent=`账单查询范围至 ${time(official.billing_through)}`;}
const labels={NOT_QUERIED:'尚未查询',METADATA_UNAVAILABLE:'实例元数据不可用',INSTANCE_PRINCIPAL_UNAVAILABLE:'实例身份认证未就绪',INSTANCE_PRINCIPAL_READY:'实例身份已认证',IAM_OR_RESOURCE_ACCESS_DENIED:'IAM 未授权或资源不可访问',AUTHENTICATION_UNAVAILABLE:'身份认证未就绪',API_UNAVAILABLE:'API 暂不可用',API_RATE_LIMITED:'API 限流',OBSERVED_WITH_UNVERIFIED_COVERAGE:'已获取指标，历史覆盖仍待核对',NO_DATA:'没有指标数据',NO_COMPLETED_DAYS:'本月尚无完整 UTC 日',ROWS_REQUIRE_SKU_REVIEW:'已获取出站用量条目，计费口径待核对',NO_EGRESS_ROWS:'未返回出站条目，不能视为零',PAGINATED_INCOMPLETE:'分页数据不完整',PROBE_UNAVAILABLE:'查询未完成',VERIFIED_USAGE_AND_PRICE_TIER:'官方用量与免费档已核对',MULTIPLE_ZONES_REQUIRE_REVIEW:'涉及多个计价区域，需核对共享规则',REVIEW_REQUIRED:'SKU 或单位仍待核对'};
 el('official-usage').textContent=`官方数据：${labels[official.free_tier_status] || '待核对'}。最近查询 ${time(official.checked_at)}；查询范围至 ${time(official.billing_through)}；用量最近变化 ${time(official.billing_changed_at)}。约每10分钟查询，Oracle入账有延迟，数值不变不一定表示查询失败。剩余为 Usage API 与官方免费档的计算值，不是实时余额；本机采样不能替代账单。`;
 el('official-rows').textContent=(official.billing_rows || []).map(r=>`${r.sku} ${r.part_number || ''}：${r.quantity} ${r.unit}`).join('\n');
 el('official-policy').textContent=official.instance_id ? `若提示未授权，在 Oracle IAM 新建仅包含此实例的动态组，匹配规则：\nALL {instance.id = '${official.instance_id}'}\n最小指标策略（请将组名和子网 compartment OCID 替换为实际值）：\nAllow dynamic-group OracleProxyUsageReader to read metrics in compartment id ${official.compartment_id} where target.metrics.namespace='oci_vcn'\n若子网位于其他 compartment，请使用子网所在 compartment。账单查询另需 tenancy 级 read usage-report；不需要 manage 权限。` : '';
 const users=new Map(data.users.map(u=>[u.id,u])); const selected=el('peer-user').value;
 el('peer-user').replaceChildren();const empty=document.createElement('option');empty.value='';empty.textContent='选择用户';el('peer-user').append(empty);
 for(const u of data.users){const option=document.createElement('option');option.value=u.id;option.textContent=u.name;el('peer-user').append(option);}el('peer-user').value=selected;
 renderUsers(data);
 const peerRow=p=>{const row=document.createElement('tr');cell(row,`${p.name || '未命名设备'} · ${p.fingerprint}${p.revoked?' · 已撤销':p.present?'':' · 接口中缺失'}`);cell(row,p.user_deleted?'已删除用户（设备已停用）':users.get(p.user_id)?.name || '未纳管（不执行用户配额）');cell(row,p.enrollment?`用户已确认 ${time(p.enrollment.confirmed_at)} · ${p.enrollment.machine_name} · ${p.enrollment.client_version}`:'旧版 / 管理员登记，待客户端确认');const client=p.client_status || {};const reported={pending:'待确认',disconnected:'已断开',protected:'保护中',connected:'已连接',recovery:'待恢复',unknown:'未上报'};cell(row,`${client.online?'近期联络':'无近期联络'} · 自报${reported[client.reported_mode] || '未知'}${client.transport?' / '+client.transport:''} · ${client.last_seen_at?time(client.last_seen_at):'—'}`);cell(row,p.allowed_ips.join(', '));cell(row,p.handshake?time(p.handshake):'尚未握手');cell(row,size(p.usage.rx+p.usage.tx));const actions=cell(row,'');button(actions,'管理',()=>manageDevice(p,data));deleteDeviceButton(actions,p);return row;};
 renderDeviceGroups(data,users,peerRow);
 if(!budgetInitialized){const f=el('budget-form');f.elements.limit.value=b.limit_bytes/1e12;f.elements.reserve.value=b.reserve_bytes/1e9;f.elements.guard.checked=b.guard_enabled;budgetInitialized=true;}
 el('budget-detail').textContent=`UTC 账期 ${b.current_period}；安全余量 ${size(b.reserve_bytes)}；历史基线 ${b.baseline_at ? time(b.baseline_at) : '未核对'}；发现计数缺口 ${b.accounting_gaps} 次。保存额度/余量不会重置已用量；填写新基线则从当前时刻重新校准。`;
 const entries=[...baseAudit,...data.audit.map(a=>({occurred_at:a.at,actor:a.actor,action:a.action,resource:a.resource}))].sort((a,b)=>b.occurred_at-a.occurred_at).slice(0,10);
 renderActivity();
 el('audit-rows').replaceChildren(...entries.map(a=>{const r=document.createElement('tr');for(const v of [time(a.occurred_at),a.actor,a.action,a.resource])cell(r,v);return r;}));
}
function renderDeviceGroups(data,users,peerRow){
 const rows=[], exceptions=[];const admin=data.administrator || {};
 const ordered=[...data.users].sort((a,b)=>Number(Boolean(b.is_admin_account))-Number(Boolean(a.is_admin_account)) || (a.username || a.name).localeCompare(b.username || b.name,'zh-CN'));
 function group(label){const r=document.createElement('tr');r.className='device-group';const c=document.createElement('th');c.scope='rowgroup';c.colSpan=8;c.textContent=label;r.append(c);rows.push(r);}
 if(!ordered.some(u=>u.is_admin_account)){group(`★ 后台管理员 ${admin.username || '当前管理员'} · 未关联同名 VPN 账号`);}
 for(const u of ordered){
  const peers=data.peers.filter(p=>p.user_id===u.id && (p.enrollment || p.revoked || u.is_admin_account));
  const pending=(data.pending_devices || []).filter(p=>p.user_id===u.id);
  group(`${u.is_admin_account?'★ 管理员 · ':''}${u.username || u.name} · ${u.name} · 已登记 ${u.device_count}/${u.device_limit} 台`);
  for(const p of peers)rows.push(peerRow(p));
  if(u.is_admin_account)for(const p of pending){const r=document.createElement('tr');cell(r,`${p.name} · ${p.id}`);cell(r,u.username);cell(r,'管理员待确认 · 不能连接 VPN');cell(r,`最近联络 ${time(p.last_seen_at)}`);const c=cell(r,`识别时间 ${time(p.created_at)}`);c.colSpan=3;const action=cell(r,'');deleteDeviceButton(action,p);rows.push(r);}
  if(!peers.length && !(u.is_admin_account && pending.length)){const r=document.createElement('tr');const c=cell(r,'暂无已确认设备');c.colSpan=8;rows.push(r);}
 }
 const orphaned=data.peers.filter(p=>!users.has(p.user_id) && (p.enrollment || p.revoked));
 if(orphaned.length){group('已删除 / 未关联账号 · 保留历史');for(const p of orphaned)rows.push(peerRow(p));}
 for(const p of data.peers){if(p.enrollment || p.revoked || users.get(p.user_id)?.is_admin_account)continue;const r=document.createElement('tr');cell(r,`${p.name || '未命名设备'} · ${p.fingerprint}`);cell(r,users.get(p.user_id)?.username || '未关联有效账号');cell(r,'无客户端确认记录 · 可能为旧版或手工接入');cell(r,time(p.client_status?.last_seen_at));const action=cell(r,'');button(action,'管理',()=>manageDevice(p,data));deleteDeviceButton(action,p);exceptions.push(r);}
 for(const p of data.pending_devices || []){const u=users.get(p.user_id);if(u?.is_admin_account)continue;const r=document.createElement('tr');cell(r,`${p.name} · ${p.id}`);cell(r,u?.username || u?.name || '账号已不可用');cell(r,`已登录、尚未确认 · ${time(p.created_at)}`);cell(r,time(p.last_seen_at));const action=cell(r,'未创建隧道 / 不占名额');deleteDeviceButton(action,p);exceptions.push(r);}
 el('peer-rows').replaceChildren(...rows);
 el('pending-device-rows').replaceChildren(...exceptions);
 el('pending-device-count').textContent=exceptions.length+' 台待核查';
 if(!exceptions.length)emptyRow('pending-device-rows',5,'暂无异常登记或未确认设备。');
}
function emptyRow(id,cols,text){const r=document.createElement('tr');const c=cell(r,text);c.colSpan=cols;el(id).append(r);}
function resetUser(){const f=el('user-form');f.reset();f.elements.id.value='';f.elements.password.required=true;el('user-delete').hidden=true;el('user-editor').open=false;el('user-editor-title').textContent='新建用户';}
function editUser(u){if(!u)return;el('user-editor').open=true;el('user-editor-title').textContent='编辑 '+(u.username || u.name);const f=el('user-form');f.elements.id.value=u.id;f.elements.name.value=u.name;f.elements.username.value=u.username || '';f.elements.device_limit.value=u.device_limit || 3;f.elements.password.value='';f.elements.password.required=!u.username;el('user-delete').hidden=false;f.elements.quota.value=u.quota===null?'':u.quota/1e9;f.elements.enabled.checked=u.enabled;if(u.expires){const d=new Date(u.expires*1000);f.elements.expires.value=new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16);}else f.elements.expires.value='';f.scrollIntoView({behavior:'smooth'});}
async function deleteUser(id){if(!id || !window.confirm('删除此用户并停用其全部设备、注销客户端登录？用量和审计历史会保留，旧设备公钥不能再次使用。'))return;if(await mutate('account.delete',{user_id:id})){if(el('user-form').elements.id.value===id)resetUser();feedback('用户已删除，全部设备已停用，用量与审计记录保留。');}}
function manageDevice(p,data){const f=el('peer-form');el('device-editor').open=true;f.elements.public_key.value=p.public_key;f.elements.public_key.readOnly=true;f.elements.name.value=p.name || p.fingerprint;f.elements.user_id.value=p.user_id || '';el('device-editor-title').textContent=`管理设备：${p.name || p.fingerprint}${p.revoked?'（已撤销，不能重新启用）':''}`;el('device-profile').hidden=false;el('device-profile').textContent=`设备识别码：${p.fingerprint}\n隧道地址：${p.allowed_ips.join(', ')}\n服务器：152.67.156.100:${data.listen_port}\n服务器公钥：${data.server_public_key || '未读取'}\nDNS：1.1.1.1 · IPv4全局路由；IPv6当前阻断\n接入说明：Windows 客户端使用账号登录及本机密钥自动获取接入信息，无需复制或导入此处配置。此处不会展示私钥。`;el('device-editor').scrollIntoView({behavior:'smooth',block:'center'});feedback('设备详情已打开。');}
function deleteDeviceButton(parent,p){if(!p.public_key)return;const b=button(parent,'删除',()=>deleteDevice(p));b.className='danger-quiet';b.setAttribute('aria-label','删除设备');}
async function deleteDevice(p){
 if(!window.confirm(`删除设备“${p.name || p.fingerprint || p.id}”？立即停用密钥、注销该设备登录并释放名额；用量与审计保留。旧密钥不能再次登记。`))return;
 if(await mutate('peer.delete',{public_key:p.public_key})){const f=el('peer-form');if(f.elements.public_key.value===p.public_key){f.reset();el('device-editor').open=false;}feedback('设备已删除，接入已停用，历史用量保留。');}
}
function renderActivity(){const max=Math.max(1,...activity.map(a=>a.count));const rows=activity.map(a=>{const row=document.createElement('div');row.className='activity-row';const name=document.createElement('span');name.textContent='◉ '+a.username;const meter=document.createElement('meter');meter.min=0;meter.max=max;meter.value=a.count;meter.setAttribute('aria-label',a.username+'近24小时操作次数');const count=document.createElement('span');count.textContent=a.count+' 次';row.append(name,meter,count);return row;});el('activity-chart').replaceChildren(...rows);if(!rows.length)el('activity-chart').textContent='近24小时暂无用户操作。';}
async function refresh(){if(busy)return;busy=true;el('refresh').disabled=true;try{if(Date.now()-lastBasic>30000){const [status,audit]=await Promise.all([api('/api/status'),api('/api/audit')]);lastBasic=Date.now();baseAudit=audit.entries;activity=audit.activity || [];el('identity').textContent=status.actor;const labels={ACTIVE:'运行中',INACTIVE:'未运行',PRESENT:'存在',ABSENT:'缺失',LISTENING:'监听中',NOT_LISTENING:'未监听'};for(const [id,k] of [['service','wg_service'],['interface','wg_interface'],['listener','udp_listener']])el(id).textContent=labels[status.snapshot?.[k]] || '未知';el('observed').textContent=status.snapshot?time(status.snapshot.observed_at):'尚无诊断';}render(await api('/api/control'));}catch(error){el('notice').classList.add('error');el('notice').textContent=`${error.message} 上次显示数据可能已过期。`;el('freshness').textContent='读取失败';}finally{busy=false;el('refresh').disabled=false;}}
async function mutate(operation,data){try{render(await api('/api/control',{operation,data}));feedback('策略已保存并执行。');return true;}catch(error){feedback(error.message,true);return false;}}
el('user-form').addEventListener('submit',async event=>{event.preventDefault();const f=event.currentTarget;const submit=f.querySelector('[type=submit]');submit.disabled=true;try{const ok=await mutate('account.save',{id:f.elements.id.value || null,name:f.elements.name.value,username:f.elements.username.value,password:f.elements.password.value,device_limit:Number(f.elements.device_limit.value),quota_bytes:f.elements.quota.value===''?null:Math.round(Number(f.elements.quota.value)*1e9),expires_at:f.elements.expires.value?Math.floor(new Date(f.elements.expires.value).getTime()/1000):null,enabled:f.elements.enabled.checked});if(ok)resetUser();}finally{submit.disabled=false;}});
el('user-reset').addEventListener('click',resetUser);
el('user-delete').addEventListener('click',()=>deleteUser(el('user-form').elements.id.value));
el('peer-form').addEventListener('submit',async event=>{event.preventDefault();const f=event.currentTarget;if(!f.reportValidity())return;const key=f.elements.public_key.value.trim();const exists=current.peers.some(p=>p.public_key===key);const ok=await mutate(exists?'peer.assign':'peer.create',{public_key:key,name:f.elements.name.value,user_id:f.elements.user_id.value});if(ok)feedback(exists?'设备归属和名称已保存。':'设备已保存；客户端仍须确认归属。');});
el('peer-form').addEventListener('reset',()=>{el('peer-form').elements.public_key.readOnly=false;el('device-profile').hidden=true;});
el('budget-form').addEventListener('submit',async event=>{event.preventDefault();const f=event.currentTarget;const source=f.elements.source.value;if(source!=='keep' && !f.elements.confirm.checked){feedback('校准前请核对账期并勾选确认。',true);return;}if(f.elements.guard.checked && current?.budget.remaining_bytes===null && source==='keep'){feedback('执行预算尚未校准，请先选择官方保守校准或手工基线。',true);return;}const data={limit_bytes:Math.round(Number(f.elements.limit.value)*1e12),reserve_bytes:Math.round(Number(f.elements.reserve.value)*1e9),guard_enabled:f.elements.guard.checked,confirm_current_period:source!=='keep' && f.elements.confirm.checked};if(source!=='official'){data.prior_usage_bytes=source==='manual' && f.elements.prior.value!==''?Math.round(Number(f.elements.prior.value)*1e9):null;}const ok=await mutate(source==='official'?'budget.calibrate':'budget.set',data);if(ok){f.elements.prior.value='';f.elements.confirm.checked=false;f.elements.source.value='keep';feedback('保护策略已保存；校准不会清除本月用量。');}});
document.addEventListener('click',event=>{const icon=event.target.closest('.help-icon');if(icon){const help=icon.closest('.help'),open=!help.classList.contains('pinned');help.classList.toggle('pinned',open);help.classList.toggle('dismissed',!open);icon.setAttribute('aria-expanded',String(open));}else{for(const help of document.querySelectorAll('.help.pinned')){help.classList.remove('pinned');help.querySelector('.help-icon').setAttribute('aria-expanded','false');}}});
document.addEventListener('keydown',event=>{if(event.key==='Escape')for(const help of document.querySelectorAll('.help')){help.classList.remove('pinned');help.classList.add('dismissed');help.querySelector('.help-icon').setAttribute('aria-expanded','false');}});
document.addEventListener('pointerover',event=>{const help=event.target.closest('.help');if(help)help.classList.remove('dismissed');});
document.addEventListener('focusin',event=>{const help=event.target.closest('.help');if(help)help.classList.remove('dismissed');});
el('refresh').addEventListener('click',refresh);refresh();setInterval(()=>{if(!document.hidden)refresh();},5000);

