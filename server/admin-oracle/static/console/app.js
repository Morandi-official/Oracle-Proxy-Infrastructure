'use strict';
const el = id => document.getElementById(id);
const time = v => v ? new Date(v * 1000).toLocaleString('zh-CN', {timeZone:'Asia/Shanghai',hour12:false})+'（UTC+8）' : '—';
const size = v => {if (v === null || v === undefined) return '未知'; let n=Number(v), i=0; const u=['B','KB','MB','GB','TB']; while(n>=1000 && i<4){n/=1000;i++;} return `${n.toFixed(i ? 2 : 0)} ${u[i]}`;};
const states={active:'可用',disabled:'已禁用',expired:'已到期',quota:'配额耗尽'};
const errors={INVALID_INGRESS_POLICY:'默认入口必须在该用户获准的 IP 范围内。',INGRESS_ISOLATION_NOT_READY:'入口隔离服务尚未就绪，请稍后刷新后再授权备用 IP。',INVALID_RATE:'限速须为0.1到10000 Mbps，空白表示不限。',ACCOUNT_CYCLE_ANCHOR_IMMUTABLE:'账号原始周期起点不能修改。',BANDWIDTH_APPLY_FAILED:'内核限速应用失败，受管流量已阻断，请检查控制服务。',CURRENT_PASSWORD_INCORRECT:"当前密码不正确。",PASSWORD_CONFIRMATION_MISMATCH:"两次新密码不一致。",PASSWORD_TOO_WEAK:"新密码强度不足，请换一个密码。",RATE_LIMITED:"操作过于频繁，请稍后再试。",PROFILE_CREATE_REJECTED:"配置创建未完成，请检查用户和设备名额；如有待核查项，先撤销它。",PROFILE_UNAVAILABLE:"该配置已停用、超额、过期或服务未就绪。",DEVICE_LIMIT_REACHED:'设备数量已达上限，请先撤销旧设备或调整上限。',DEVICE_REVOKED:'该设备已撤销，请在客户端重新生成设备身份。',REVOKE_DEVICES_BEFORE_LOWERING_LIMIT:'请先撤销多余设备，再降低上限。',USERNAME_ALREADY_EXISTS:'登录账号已被使用。',INVALID_USERNAME:'账号须为 3 至 64 位小写字母、数字、点、下划线或连字符。',PASSWORD_LENGTH_12_TO_128_REQUIRED:'密码长度须为 12 至 128 字符。',CONTROL_SERVICE_UNAVAILABLE:'控制服务不可用，当前数据不能作为实时状态。',BASELINE_CONFIRMATION_REQUIRED:'请核对账期用量并勾选确认。',HOST_ADDRESS_REQUIRED:'该 Peer 包含网段路由，暂不能纳管；只支持独立 /32 或 /128 设备地址。',NO_FREE_IPV4_TUNNEL_ADDRESS:'当前接口没有可分配的私有 IPv4 地址。',INVALID_PUBLIC_KEY:'请输入本机生成的 WireGuard 公钥，不是私钥。',PEER_ALREADY_EXISTS:'此 Peer 已存在，请使用“绑定 / 调整已有 Peer”。',PEER_NOT_FOUND:'未找到该 Peer，请刷新后选择已有设备。',INVALID_BUDGET:'额度必须大于零，安全余量必须小于额度。',OFFICIAL_USAGE_NOT_READY:'官方报表未就绪或已过期，请等定时查询完成；无法凭空校准。',CONTROL_UNAVAILABLE:'控制服务暂时不可用；已纳管流量仍受内核规则保护。'};
let current=null, busy=false, budgetInitialized=false, lastBasic=0, baseAudit=[], activity=[];
let feedbackTimer;
function feedback(text, error=false){clearTimeout(feedbackTimer);el('feedback').hidden=false;el('feedback').textContent=text;el('feedback').classList.toggle('error',error);if(!error)feedbackTimer=setTimeout(()=>{el('feedback').hidden=true;},5500);}
async function api(path, value){
 const options={credentials:'same-origin',redirect:'error',cache:'no-store'};
 if(value){options.method='POST';options.headers={'Content-Type':'application/json','X-CSRFToken':document.querySelector('[name=csrfmiddlewaretoken]').value};options.body=JSON.stringify(value);}
 const response=await fetch(path,options); const data=await response.json().catch(()=>({error:'INVALID_RESPONSE'}));
 if(!response.ok){if(response.status===401)throw new Error('登录已失效，请重新登录。');if(response.status===403)throw new Error('会话或页面验证已过期，请重新登录。');throw new Error(errors[data.error] || `操作未完成（${data.error || response.status}）。`);}
 return data;
}
function cell(row,value){const td=document.createElement('td');td.textContent=value;row.append(td);return td;}
function button(parent,label,action){const b=document.createElement('button');b.type='button';b.textContent=label;b.addEventListener('click',action);parent.append(b);return b;}
const rowSignatures=new WeakMap();
function replaceRows(id,rows){
 const body=el(id),signature=rows.map(row=>row.outerHTML).join('');
 if(rowSignatures.get(body)===signature)return;
 const focused=body.contains(document.activeElement)?document.activeElement?.dataset.focusKey:null;
 body.replaceChildren(...rows);rowSignatures.set(body,signature);
 if(focused)for(const item of body.querySelectorAll('button[data-focus-key]'))if(item.dataset.focusKey===focused){item.focus({preventScroll:true});break;}
}
function render(data){
 const endpoints=data.ingress_endpoints || {};for(const name of ['ingress_access','ingress_preferred'])for(const option of el('user-form').elements[name].options){if(option.value==='primary')option.textContent='主 IP'+(endpoints.primary?' · '+endpoints.primary:'');if(option.value==='backup')option.textContent='备用 IP'+(endpoints.backup?' · '+endpoints.backup:'');}
 current=data;renderConnections(data);const b=data.budget;const age=data.observed_at ? Date.now()/1000-data.observed_at : null;
 el('remaining').textContent=size(b.remaining_bytes);el('outbound').textContent=size(b.measured_outbound_bytes);
 el('balance-basis').textContent=b.history_complete ? '手工核对基线 + 本机增量估算' : '历史未核对 / 采集有缺口';
 el('egress-interface').textContent=`VNIC ${data.nics.join(', ') || '未知'} · 仅出站 TX`;
 const executionAge=Number.isFinite(data.enforced_at)?Date.now()/1000-data.enforced_at:null;
 const policyFresh=age!==null && age>=0 && age<=data.lease_seconds && executionAge!==null && executionAge>=0 && executionAge<=data.lease_seconds;
 el('enforcement').textContent=data.error?'策略执行异常':!policyFresh?'执行状态未确认':b.guard_blocked?'总量保护已阻断':b.guard_enabled?'用户策略与总量保护正常':'用户策略执行正常';
 el('policy-evidence').textContent=`依据控制服务上报：最近采样 ${time(data.observed_at)}；最近执行 ${time(data.enforced_at)}；放行租约 ${data.lease_seconds} 秒；错误 ${data.error || '无'}；已纳管设备 ${data.peers.filter(p=>p.managed && !p.revoked).length} 台。服务对账号启停、到期、月配额和已纳管设备执行规则；执行时间表示内核租约更新命令成功，不是网页独立读取并验证全部内核规则，也不证明每台设备已连通或逐包计量无缺口。服务器总量保护${b.guard_enabled?'已启用':'未启用'}，与用户策略分开。`;
 el('freshness').textContent=age===null?'暂无数据':age<0?'采样时钟异常':`采样 ${Math.floor(age)} 秒前 · 租约 ${data.lease_seconds} 秒`;
 el('notice').classList.toggle('error',Boolean(data.error || !policyFresh || b.guard_blocked));
 el('budget-state').textContent=(b.guard_enabled?(b.guard_blocked?'保护已启用 · 正在阻断 VPN':'保护已启用'):'保护未启用')+' · 其他系统流量仍会消耗出站额度。';
 el('official-summary').textContent='最近查询 '+time(data.official_usage?.checked_at)+' · 账单延迟';
 el('notice').textContent=data.error ? '采集或执行异常，放行租约不再续期。请检查控制服务，不能把历史数据当成实时余额。' : !policyFresh ? '控制服务最近采样或执行记录已过期，不能确认当前策略执行状态。' : b.guard_blocked ? 'VPN 总量保护正在阻断：预算已到安全阈值，或当前账期历史未知。HTTPS 与公网 SSH 保留。' : '策略采样与执行记录均在有效期内。';
 el('usage-explanation').textContent=`用户配额统计 WireGuard 上传+下载；Oracle 出站保护统计物理 VNIC 发送字节，二者口径不同。当前采集始于 ${time(b.started_at)}。官方查询与账单延迟另列如下；本机估算不会自动冒充官方余额。`;
 const official=data.official_usage || {};
 const officialReady=official.free_tier_status==='VERIFIED_USAGE_AND_PRICE_TIER' && official.period===data.period && Number.isFinite(official.free_tier_remaining_gb) && Date.now()/1000-official.checked_at>=0 && Date.now()/1000-official.checked_at<7200;
 const gb=v=>Number.isFinite(v)?new Intl.NumberFormat('zh-CN',{maximumFractionDigits:3}).format(v)+' GB':'未知';
 el('official-limit').textContent=officialReady?gb(official.free_tier_limit_gb):'未知';el('official-used').textContent=officialReady?gb(official.free_tier_used_gb):'未知';el('official-remaining').textContent=officialReady?gb(official.free_tier_remaining_gb):'未知';
 el('official-progress').max=officialReady?official.free_tier_limit_gb:1;el('official-progress').value=officialReady?Math.min(official.free_tier_used_gb,official.free_tier_limit_gb):0;
 el('remaining-label').textContent=officialReady?'官方口径剩余出站（账单延迟）':'本账期估算剩余出站';
 if(officialReady){el('remaining').textContent=gb(official.free_tier_remaining_gb);el('balance-basis').textContent=`UTC 账期 ${official.period} · 已用 ${gb(official.free_tier_used_gb)} · 查询至 ${time(official.billing_through)}`;}
const labels={NOT_QUERIED:'尚未查询',METADATA_UNAVAILABLE:'实例元数据不可用',INSTANCE_PRINCIPAL_UNAVAILABLE:'实例身份认证未就绪',INSTANCE_PRINCIPAL_READY:'实例身份已认证',IAM_OR_RESOURCE_ACCESS_DENIED:'IAM 未授权或资源不可访问',AUTHENTICATION_UNAVAILABLE:'身份认证未就绪',API_UNAVAILABLE:'API 暂不可用',API_RATE_LIMITED:'API 限流',OBSERVED_WITH_UNVERIFIED_COVERAGE:'已获取指标，历史覆盖仍待核对',NO_DATA:'没有指标数据',NO_COMPLETED_DAYS:'本月尚无完整 UTC 日',ROWS_REQUIRE_SKU_REVIEW:'已获取出站用量条目，计费口径待核对',NO_EGRESS_ROWS:'未返回出站条目，不能视为零',PAGINATED_INCOMPLETE:'分页数据不完整',PROBE_UNAVAILABLE:'查询未完成',VERIFIED_USAGE_AND_PRICE_TIER:'官方用量与免费档已核对',MULTIPLE_ZONES_REQUIRE_REVIEW:'涉及多个计价区域，需核对共享规则',REVIEW_REQUIRED:'SKU 或单位仍待核对'};
 el('official-usage').textContent=`官方数据：${labels[official.free_tier_status] || '待核对'}。最近查询 ${time(official.checked_at)}；查询范围至 ${time(official.billing_through)}；用量最近变化 ${time(official.billing_changed_at)}。账期从 ${time(official.billing_from)} 开始，按 UTC 自然月重算，并非注册后每30天。官方统计为租户范围的出站计费条目，本机统计仅为本服务器物理网卡增量；范围与入账时间不同。查询范围上限不代表已完整入账。约每10分钟查询，Oracle入账有延迟，数值不变不一定表示查询失败。剩余为 Usage API 与官方免费档的计算值，不是实时余额；本机采样不能替代账单。`;
 el('official-rows').textContent=(official.billing_rows || []).map(r=>`${r.sku} ${r.part_number || ''}：${r.quantity} ${r.unit}`).join('\n');
 el('official-policy').textContent=official.instance_id ? `若提示未授权，在 Oracle IAM 新建仅包含此实例的动态组，匹配规则：\nALL {instance.id = '${official.instance_id}'}\n最小指标策略（请将组名和子网 compartment OCID 替换为实际值）：\nAllow dynamic-group OracleProxyUsageReader to read metrics in compartment id ${official.compartment_id} where target.metrics.namespace='oci_vcn'\n若子网位于其他 compartment，请使用子网所在 compartment。账单查询另需 tenancy 级 read usage-report；不需要 manage 权限。` : '';
 const users=new Map(data.users.map(u=>[u.id,u])); const selected=el('peer-user').value;
 el('peer-user').replaceChildren();const empty=document.createElement('option');empty.value='';empty.textContent='选择用户';el('peer-user').append(empty);
 for(const u of data.users){const option=document.createElement('option');option.value=u.id;option.textContent=u.name;el('peer-user').append(option);}el('peer-user').value=selected;
 renderUsers(data);renderFlClashUsers(data);
 const peerRow=p=>{
  const row=document.createElement('tr'),identity=cell(row,'');
  const name=document.createElement('strong');name.className='cell-title';name.textContent=p.name || '未命名设备';identity.append(name);
  const fingerprint=document.createElement('span');fingerprint.className='cell-meta code';fingerprint.textContent=p.fingerprint+(p.revoked?' · 已撤销':p.present?'':' · 接口中缺失');identity.append(fingerprint);
  const status=cell(row,''),client=p.client_status || {},reported={pending:'待确认',disconnected:'已断开',protected:'保护中',connected:'已连接',recovery:'待恢复',unknown:'未上报'};
  const external=p.enrollment?.client_version==='FlClash-UDP-v1';
  const state=document.createElement('span');state.className='status-badge '+(p.revoked?'status-warning':client.online?'status-online':'status-neutral');state.textContent=p.revoked?'已撤销':external?'FlClash · UDP · '+(p.flclash_used || p.handshake?'已使用':'待使用 · 已占名额'):`${client.online?'近期联络':'无近期联络'} · 自报${reported[client.reported_mode] || '未知'}`;status.append(state);
  const enrollment=document.createElement('span');enrollment.className='cell-meta';enrollment.textContent=external?'配置身份 · '+p.enrollment.machine_name:p.enrollment?`用户已确认 · ${p.enrollment.machine_name} · ${p.enrollment.client_version}`:'旧版 / 管理员登记，待客户端确认';
  enrollment.title=p.enrollment?'确认时间 '+time(p.enrollment.confirmed_at):'管理员登记不代替客户端的归属确认';status.append(enrollment);
  const seen=document.createElement('span');seen.className='cell-meta';seen.textContent=(client.transport?client.transport+' · ':'')+'最近联络 '+time(client.last_seen_at);status.append(seen);
  const addresses=cell(row,p.allowed_ips.join(', '));addresses.className='code address-cell';
  const handshake=cell(row,p.handshake?time(p.handshake):'尚未握手');handshake.className='time-cell';
  const usage=cell(row,size(p.usage.rx+p.usage.tx));usage.className='numeric';
  const actions=cell(row,'');actions.className='row-actions';button(actions,'管理',()=>manageDevice(p,current || data)).dataset.focusKey=(p.fingerprint || p.id)+':manage';deleteDeviceButton(actions,p);return row;
 };
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
 function group(label){const r=document.createElement('tr');r.className='device-group';const c=document.createElement('th');c.scope='rowgroup';c.colSpan=6;c.textContent=label;r.append(c);rows.push(r);}
 if(!ordered.some(u=>u.is_admin_account)){group(`★ 后台管理员 ${admin.username || '当前管理员'} · 未关联同名 VPN 账号`);}
 for(const u of ordered){
  const peers=data.peers.filter(p=>p.user_id===u.id && (p.enrollment || p.revoked || u.is_admin_account));
  const pending=(data.pending_devices || []).filter(p=>p.user_id===u.id);
  group(`${u.is_admin_account?'★ 管理员 · ':''}${u.username || u.name} · ${u.name} · 已登记 ${u.device_count}/${u.device_limit} 台`);
  for(const p of peers)rows.push(peerRow(p));
  if(u.is_admin_account)for(const p of pending){const r=document.createElement('tr');cell(r,`${p.name} · ${p.id}`);cell(r,`管理员待确认 · 不能连接 VPN · 最近联络 ${time(p.last_seen_at)}`);cell(r,'尚未分配');cell(r,'尚未握手');cell(r,'—');const action=cell(r,'');action.className='row-actions';deleteDeviceButton(action,p);rows.push(r);}
  if(!peers.length && !(u.is_admin_account && pending.length)){const r=document.createElement('tr');const c=cell(r,'暂无已确认设备');c.colSpan=6;rows.push(r);}
 }
 const orphaned=data.peers.filter(p=>!users.has(p.user_id) && (p.enrollment || p.revoked));
 if(orphaned.length){group('已删除 / 未关联账号 · 保留历史');for(const p of orphaned)rows.push(peerRow(p));}
 for(const p of data.peers){if(p.enrollment || p.revoked || users.get(p.user_id)?.is_admin_account)continue;const r=document.createElement('tr');cell(r,`${p.name || '未命名设备'} · ${p.fingerprint}`);cell(r,users.get(p.user_id)?.username || '未关联有效账号');cell(r,'无客户端确认记录 · 可能为旧版或手工接入');cell(r,time(p.client_status?.last_seen_at));const action=cell(r,'');button(action,'管理',()=>manageDevice(p,current || data));deleteDeviceButton(action,p);exceptions.push(r);}
 for(const p of data.pending_devices || []){const u=users.get(p.user_id);if(u?.is_admin_account)continue;const r=document.createElement('tr');cell(r,`${p.name} · ${p.id}`);cell(r,u?.username || u?.name || '账号已不可用');cell(r,`已登录、尚未确认 · ${time(p.created_at)}`);cell(r,time(p.last_seen_at));const action=cell(r,'未创建隧道 / 不占名额');deleteDeviceButton(action,p);exceptions.push(r);}
 const exceptionCount=exceptions.length;
 replaceRows('peer-rows',rows);
 if(!exceptions.length){const r=document.createElement('tr');const c=cell(r,'暂无异常登记或未确认设备。');c.colSpan=5;exceptions.push(r);}
 replaceRows('pending-device-rows',exceptions);
 el('pending-device-count').textContent=exceptionCount+' 台待核查';
}
function emptyRow(id,cols,text){const r=document.createElement('tr');const c=cell(r,text);c.colSpan=cols;el(id).append(r);}
function updateIngressChoices(){const f=el('user-form'),access=f.elements.ingress_access.value;for(const option of f.elements.ingress_preferred.options)option.disabled=access!=='both' && option.value!==access;if(access!=='both')f.elements.ingress_preferred.value=access;}
el('user-form').elements.ingress_access.addEventListener('change',updateIngressChoices);
function resetUser(){const f=el('user-form');f.reset();updateIngressChoices();f.elements.id.value='';f.elements.password.required=true;el('user-delete').hidden=true;el('user-editor').open=false;el('user-editor-title').textContent='新建用户';}
function editUser(u){if(!u)return;el('user-editor').open=true;el('user-editor-title').textContent='编辑 '+(u.username || u.name);const f=el('user-form');f.elements.id.value=u.id;f.elements.name.value=u.name;f.elements.username.value=u.username || '';f.elements.device_limit.value=u.device_limit || 3;f.elements.password.value='';f.elements.password.required=!u.username;el('user-delete').hidden=false;f.elements.quota.value=u.quota===null?'':u.quota/1e9;f.elements.enabled.checked=u.enabled;f.elements.ingress_access.value=u.ingress?.access || 'primary';f.elements.ingress_preferred.value=u.ingress?.preferred || 'primary';updateIngressChoices();for(const direction of ['download','upload'])f.elements[direction+'_mbps'].value=u.rate?.[direction+'_bps']?u.rate[direction+'_bps']/1e6:'';if(u.expires){const d=new Date(u.expires*1000);f.elements.expires.value=new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16);}else f.elements.expires.value='';f.scrollIntoView({behavior:'smooth'});}
async function deleteUser(id){if(!id || !window.confirm('删除此用户并停用其全部设备、注销客户端登录？用量和审计历史会保留，旧设备公钥不能再次使用。'))return;if(await mutate('account.delete',{user_id:id})){if(el('user-form').elements.id.value===id)resetUser();feedback('用户已删除，全部设备已停用，用量与审计记录保留。');}}
function manageDevice(p,data){const f=el('peer-form');el('device-editor').open=true;f.elements.public_key.value=p.public_key;f.elements.public_key.readOnly=true;f.elements.name.value=p.name || p.fingerprint;f.elements.user_id.value=p.user_id || '';el('device-editor-title').textContent=`管理设备：${p.name || p.fingerprint}${p.revoked?'（已撤销，不能重新启用）':''}`;el('device-profile').hidden=false;el('device-profile').textContent=`设备识别码：${p.fingerprint}\n隧道地址：${p.allowed_ips.join(', ')}\n服务器：152.67.156.100:${data.listen_port}\n服务器公钥：${data.server_public_key || '未读取'}\nDNS、出口及 IPv6 策略：由客户端接入策略下发，请以客户端连接诊断为准\n接入说明：Windows 客户端使用账号登录及本机密钥自动获取接入信息，无需复制或导入此处配置。此处不会展示私钥。`;el('device-editor').scrollIntoView({behavior:'smooth',block:'center'});feedback('设备详情已打开。');}
function deleteDeviceButton(parent,p){if(!p.public_key || p.managed===false)return;const b=button(parent,'删除',()=>deleteDevice(p));b.className='danger-quiet';b.dataset.focusKey=(p.fingerprint || p.id)+':delete';b.setAttribute('aria-label','删除设备');}
async function deleteDevice(p){
 if(!window.confirm(`删除设备“${p.name || p.fingerprint || p.id}”？立即停用密钥、注销该设备登录并释放名额；用量与审计保留。旧密钥不能再次登记。`))return;
 if(await mutate('peer.delete',{public_key:p.public_key})){const f=el('peer-form');if(f.elements.public_key.value===p.public_key){f.reset();el('device-editor').open=false;}feedback('设备已删除，接入已停用，历史用量保留。');}
}
function renderActivity(){const max=Math.max(1,...activity.map(a=>a.count));const rows=activity.map(a=>{const row=document.createElement('div');row.className='activity-row';const name=document.createElement('span');name.textContent='◉ '+a.username;const meter=document.createElement('meter');meter.min=0;meter.max=max;meter.value=a.count;meter.setAttribute('aria-label',a.username+'近24小时操作次数');const count=document.createElement('span');count.textContent=a.count+' 次';row.append(name,meter,count);return row;});el('activity-chart').replaceChildren(...rows);if(!rows.length)el('activity-chart').textContent='近24小时暂无用户操作。';}
async function refresh(){if(busy)return;busy=true;el('refresh').disabled=true;try{if(Date.now()-lastBasic>30000){const [status,audit]=await Promise.all([api('/api/status'),api('/api/audit')]);lastBasic=Date.now();baseAudit=audit.entries;activity=audit.activity || [];el('identity').textContent=status.actor;el('identity').title=status.actor;const labels={ACTIVE:'运行中',INACTIVE:'未运行',PRESENT:'存在',ABSENT:'缺失',LISTENING:'监听中',NOT_LISTENING:'未监听'};for(const [id,k] of [['service','wg_service'],['interface','wg_interface'],['listener','udp_listener']])el(id).textContent=labels[status.snapshot?.[k]] || '未知';el('observed').textContent=status.snapshot?time(status.snapshot.observed_at):'尚无诊断';}render(await api('/api/control'));await refreshFlClash();await refreshHost();}catch(error){el('notice').classList.add('error');el('notice').textContent=`${error.message} 上次显示数据可能已过期。`;el('freshness').textContent='读取失败';}finally{busy=false;el('refresh').disabled=false;}}
async function mutate(operation,data){try{render(await api('/api/control',{operation,data}));feedback('策略已保存并执行。');return true;}catch(error){feedback(error.message,true);return false;}}
el('user-form').addEventListener('submit',async event=>{event.preventDefault();const f=event.currentTarget;const submit=f.querySelector('[type=submit]');submit.disabled=true;try{const ok=await mutate('account.save',{id:f.elements.id.value || null,name:f.elements.name.value,username:f.elements.username.value,password:f.elements.password.value,device_limit:Number(f.elements.device_limit.value),ingress_access:f.elements.ingress_access.value,ingress_preferred:f.elements.ingress_preferred.value,quota_bytes:f.elements.quota.value===''?null:Math.round(Number(f.elements.quota.value)*1e9),download_bps:f.elements.download_mbps.value===''?null:Math.round(Number(f.elements.download_mbps.value)*1e6),upload_bps:f.elements.upload_mbps.value===''?null:Math.round(Number(f.elements.upload_mbps.value)*1e6),expires_at:f.elements.expires.value?Math.floor(new Date(f.elements.expires.value).getTime()/1000):null,enabled:f.elements.enabled.checked});if(ok)resetUser();}finally{submit.disabled=false;}});
el('user-reset').addEventListener('click',resetUser);
el('user-delete').addEventListener('click',()=>deleteUser(el('user-form').elements.id.value));
el('peer-form').addEventListener('submit',async event=>{event.preventDefault();const f=event.currentTarget;if(!f.reportValidity())return;const key=f.elements.public_key.value.trim();const exists=current.peers.some(p=>p.public_key===key);const ok=await mutate(exists?'peer.assign':'peer.create',{public_key:key,name:f.elements.name.value,user_id:f.elements.user_id.value});if(ok)feedback(exists?'设备归属和名称已保存。':'设备已保存；客户端仍须确认归属。');});
el('peer-form').addEventListener('reset',()=>{el('peer-form').elements.public_key.readOnly=false;el('device-profile').hidden=true;});
el('budget-form').addEventListener('submit',async event=>{event.preventDefault();const f=event.currentTarget;const source=f.elements.source.value;if(source!=='keep' && !f.elements.confirm.checked){feedback('校准前请核对账期并勾选确认。',true);return;}if(f.elements.guard.checked && current?.budget.remaining_bytes===null && source==='keep'){feedback('执行预算尚未校准，请先选择官方保守校准或手工基线。',true);return;}const data={limit_bytes:Math.round(Number(f.elements.limit.value)*1e12),reserve_bytes:Math.round(Number(f.elements.reserve.value)*1e9),guard_enabled:f.elements.guard.checked,confirm_current_period:source!=='keep' && f.elements.confirm.checked};if(source!=='official'){data.prior_usage_bytes=source==='manual' && f.elements.prior.value!==''?Math.round(Number(f.elements.prior.value)*1e9):null;}const ok=await mutate(source==='official'?'budget.calibrate':'budget.set',data);if(ok){f.elements.prior.value='';f.elements.confirm.checked=false;f.elements.source.value='keep';feedback('保护策略已保存；校准不会清除本月用量。');}});
function positionHelp(help){
 const icon=help.querySelector('.help-icon'),text=help.querySelector('.help-text');if(!icon || !text)return;
 const anchor=icon.getBoundingClientRect(),width=Math.min(380,innerWidth-32);
 Object.assign(text.style,{position:'fixed',right:'auto',width:width+'px',left:Math.max(16,Math.min(anchor.left,innerWidth-width-16))+'px'});
 const height=text.getBoundingClientRect().height;
 text.style.top=Math.max(16,Math.min(anchor.bottom+9,innerHeight-height-16))+'px';
}
document.addEventListener('click',event=>{const icon=event.target.closest('.help-icon');if(icon){const help=icon.closest('.help'),open=!help.classList.contains('pinned');positionHelp(help);help.classList.toggle('pinned',open);help.classList.toggle('dismissed',!open);icon.setAttribute('aria-expanded',String(open));}else{for(const help of document.querySelectorAll('.help.pinned')){help.classList.remove('pinned');help.querySelector('.help-icon').setAttribute('aria-expanded','false');}}});
document.addEventListener('keydown',event=>{if(event.key==='Escape')for(const help of document.querySelectorAll('.help')){help.classList.remove('pinned');help.classList.add('dismissed');help.querySelector('.help-icon').setAttribute('aria-expanded','false');}});
document.addEventListener('pointerover',event=>{const help=event.target.closest('.help');if(help){help.classList.remove('dismissed');positionHelp(help);}});
document.addEventListener('focusin',event=>{const help=event.target.closest('.help');if(help){help.classList.remove('dismissed');positionHelp(help);}});
el('refresh').addEventListener('click',refresh);refresh();setInterval(()=>{if(!document.hidden)refresh();},5000);


// Keep the sidebar aligned with the section being inspected, including keyboard/hash navigation.
const sectionLinks=[...document.querySelectorAll('nav a[href^="#"]')];
let navigationPending=false;
function updateNavigation(){
 navigationPending=false;let active=sectionLinks[0];
 for(const link of sectionLinks){const section=document.querySelector(link.getAttribute('href'));if(section && section.getBoundingClientRect().top<=160)active=link;}
 for(const link of sectionLinks){const selected=link===active;link.classList.toggle('active',selected);if(selected)link.setAttribute('aria-current','location');else link.removeAttribute('aria-current');}
}
window.addEventListener('scroll',()=>{if(!navigationPending){navigationPending=true;requestAnimationFrame(updateNavigation);}},{passive:true});
window.addEventListener('resize',()=>{updateNavigation();for(const help of document.querySelectorAll('.help.pinned'))positionHelp(help);});window.addEventListener('hashchange',updateNavigation);updateNavigation();

function updateFlClashCapacity(){const select=el('flclash-user'),option=select.selectedOptions[0],allowed=Boolean(select.value && option && !option.disabled);el('flclash-form').querySelector('[type=submit]').disabled=!allowed;el('flclash-capacity').textContent=allowed?'可新增 '+option.dataset.remaining+' 份配置 · 与已登记设备共用上限':'请选择有剩余设备名额的可用用户';}
function renderFlClashUsers(data){const select=el('flclash-user'),value=select.value;select.replaceChildren();const empty=document.createElement('option');empty.value='';empty.textContent='选择用户';select.append(empty);for(const u of data.users.filter(u=>u.username)){const option=document.createElement('option');option.value=u.id;const remaining=Math.max(0,u.device_limit-u.device_count);option.disabled=u.status!=='active' || remaining===0 || Boolean(data.error || data.budget.guard_blocked);option.dataset.remaining=remaining;option.textContent=u.username+' · '+u.device_count+'/'+u.device_limit+' · '+(u.status!=='active'?'账号不可用':remaining?'余 '+remaining+' 个名额':'已达上限');select.append(option);}select.value=value;updateFlClashCapacity();}
el('flclash-user').addEventListener('change',updateFlClashCapacity);
async function profileLink(profile){return (await api('/api/flclash/'+profile.id,{action:'link'})).url;}
async function refreshFlClash(){try{const data=await api('/api/flclash');const rows=data.profiles.map(p=>{const row=document.createElement('tr');const u=current?.users.find(u=>u.id===p.user_id);cell(row,(u?.username || '已删除账号')+' / '+p.name);cell(row,({active:'可导入 · UDP',pending:'创建结果待核查',blocked:'暂停导入 · 核对用户状态',revoked:'已撤销'})[p.status] || p.status);cell(row,time(p.created_at)+(p.last_used_at?' · 最近使用 '+time(p.last_used_at):' · 尚无握手记录'));const actions=cell(row,'');actions.className='row-actions';if(p.status==='active'){button(actions,'复制链接',async()=>{try{await navigator.clipboard.writeText(await profileLink(p));feedback('导入链接已复制，请私下交给对应用户。');}catch(e){feedback('未能复制链接，请使用下载配置。',true);}});button(actions,'下载配置',async()=>{try{const url=await profileLink(p);const response=await fetch(url,{credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer'});if(!response.ok)throw new Error('配置暂不可下载，请检查用户状态或刷新后重试。');const blob=await response.blob();const objectUrl=URL.createObjectURL(blob);const a=document.createElement('a');a.href=objectUrl;a.download='Proxy-UDP.yaml';a.referrerPolicy='no-referrer';document.body.append(a);a.click();setTimeout(()=>{a.remove();URL.revokeObjectURL(objectUrl);},10000);}catch(e){feedback(e.message,true);}});}if(p.status!=='revoked')button(actions,'撤销',async()=>{if(!confirm('撤销 '+p.name+'？已下载配置也将停止接入，配置记录及密钥材料将删除；历史用量保留。'))return;try{await api('/api/flclash/'+p.id,{action:'revoke'});await refresh();feedback('配置已撤销并删除。');}catch(e){feedback(e.message,true);}});return row;});if(!rows.length){const row=document.createElement('tr');const c=cell(row,'暂无配置，为每台设备单独创建。');c.colSpan=4;rows.push(row);}replaceRows('flclash-rows',rows);el('flclash-status').textContent='WireGuard UDP 443 · 无备用通道';}catch(e){el('flclash-status').textContent=e.message;}}
el('flclash-form').addEventListener('submit',async event=>{event.preventDefault();const f=event.currentTarget;if(!f.reportValidity())return;const submit=f.querySelector('[type=submit]');submit.disabled=true;try{await api('/api/flclash/create',{user_id:f.elements.user_id.value});await refresh();feedback('配置已创建；复制链接或下载后导入 FlClash。');}catch(e){await refreshFlClash();feedback(e.message,true);}finally{updateFlClashCapacity();}});

const percent=v=>Number.isFinite(v)?v.toFixed(1)+'%':'采样中';
const mbps=v=>Number.isFinite(v)?(v*8/1e6).toFixed(2):'—';
function niceMaximum(value){if(!(value>0))return 1;const magnitude=10**Math.floor(Math.log10(value));return [1,2,5,10].map(v=>v*magnitude).find(v=>v>=value) || 10*magnitude;}
function hostTrend(title,rows,key,color,unit){
 const figure=document.createElement('figure'),label=document.createElement('figcaption');label.textContent=title+' · '+unit;figure.append(label);
 const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg'),points=rows.filter(r=>Number.isFinite(r[key])),scale=v=>unit==='Mbps'?v*8/1e6:v;
 svg.setAttribute('viewBox','0 0 340 128');svg.setAttribute('role','img');svg.setAttribute('aria-label',title+'，'+points.length+' 个有效时间段，空缺未补零');
 const from=rows[0]?.at || 0,to=rows.at(-1)?.at || from+1,max=niceMaximum(Math.max(0,...points.map(r=>scale(r[key])))),left=45,width=285,top=10,height=88;
 const drawText=(x,y,text,anchor='end')=>{const t=document.createElementNS(ns,'text');t.setAttribute('x',x);t.setAttribute('y',y);t.setAttribute('text-anchor',anchor);t.textContent=text;svg.append(t);};
 for(let i=0;i<=4;i++){const y=top+height-height*i/4,l=document.createElementNS(ns,'line');l.setAttribute('x1',left);l.setAttribute('x2',left+width);l.setAttribute('y1',y);l.setAttribute('y2',y);l.setAttribute('class','chart-grid');svg.append(l);drawText(left-5,y+3,new Intl.NumberFormat('zh-CN',{maximumSignificantDigits:3}).format(max*i/4));}
 let group=[];const flush=()=>{if(!group.length)return;const line=document.createElementNS(ns,'polyline');line.setAttribute('points',group.join(' '));line.setAttribute('fill','none');line.setAttribute('stroke',color);line.setAttribute('stroke-width','2');svg.append(line);if(group.length===1){const [x,y]=group[0].split(' ');const c=document.createElementNS(ns,'circle');c.setAttribute('cx',x);c.setAttribute('cy',y);c.setAttribute('r','2');c.setAttribute('fill',color);svg.append(c);}group=[];};
 for(const row of rows){if(!Number.isFinite(row[key])){flush();continue;}group.push(`${left+width*(row.at-from)/Math.max(1,to-from)} ${top+height-height*scale(row[key])/max}`);}flush();
 const stamp=at=>new Date(at*1000).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false});
 drawText(left,118,stamp(from),'start');drawText(left+width,118,stamp(to),'end');figure.append(svg);
 const detail=document.createElement('small');detail.textContent=points.length?'有效时间段 '+points.length+' / '+rows.length+' · 最近均值 '+Number(scale(points.at(-1)[key])).toFixed(unit==='%'?1:2)+' '+unit:'尚无历史采样；空缺不代表零';figure.append(detail);return figure;
}
let lastHostHistory=0,lastHostWindow='';
el('host-window').addEventListener('change',()=>refreshHost(true));
async function refreshHost(force=false){try{
 const window=el('host-window').value;
 const data=await api('/api/host-status?window='+window),s=data.sample;el('host-freshness').textContent=data.stale?'采样已过期 / 尚无数据':data.age_seconds+' 秒前 · 10 秒采样';el('host-freshness').classList.toggle('amber',data.stale);
 if(!s){el('host-alerts').textContent='尚无系统采样，未知状态不能视为正常。';el('host-alerts').classList.add('error');return;}
 el('host-alerts').classList.toggle('error',data.stale || s.alerts.length>0);el('host-alerts').textContent=(data.stale?'采样已过期，以下为历史数据。 ':'')+(s.alerts.map(a=>a.message).join(' ') || '当前未触发阈值预警。');
 el('host-cpu').textContent=percent(s.cpu_percent);el('host-load').textContent=s.cpu_count+' vCPU · 负载 '+(s.load?.map(v=>v.toFixed(2)).join(' / ') || '未知');
 el('host-memory').textContent=percent(s.memory_percent);el('host-memory-detail').textContent=size(s.memory_used_bytes)+' / '+size(s.memory_total_bytes);
 const disk=s.disks[0];el('host-disk').textContent=disk?percent(disk.used_percent):'未知';el('host-disk-detail').textContent=disk?'已用 '+size(disk.used_bytes)+' / '+size(disk.total_bytes)+' · 可用 '+size(disk.available_bytes):'磁盘不可读取';
 const n=s.network;el('host-speed').textContent=mbps(n.rx_bytes_per_second)+' / '+mbps(n.tx_bytes_per_second)+' Mbps';el('host-network-detail').textContent=n.interfaces.join(', ')+' · '+(n.packets_per_second===null?'采样中':n.packets_per_second.toFixed(0)+' 包/秒');
 el('host-details').textContent='TCP 连接 '+(s.tcp_established??'未知')+' · 连接跟踪 '+(s.conntrack_count??'未知')+' / '+(s.conntrack_max??'未知')+' · TCP 重传 '+percent(s.tcp_retransmit_percent)+' · CPU steal '+percent(s.cpu_steal_percent)+' · I/O wait '+percent(s.io_wait_percent)+' · inode '+percent(disk?.inode_percent)+' · 本轮丢包 '+(n.drops_delta??'未知')+' / 错误 '+(n.errors_delta??'未知')+(s.errors.length?' · 采集问题 '+s.errors.join(', '):'');
 if(el('host-window').value===data.window && (force || window!==lastHostWindow || Date.now()-lastHostHistory>30000)){
  lastHostHistory=Date.now();lastHostWindow=window;
  el('host-trends').replaceChildren(hostTrend('CPU',data.history,'cpu','#4338ca','%'),hostTrend('内存',data.history,'memory','#0f766e','%'),hostTrend('系统磁盘',data.history,'disk','#b45309','%'),hostTrend('1 分钟负载',data.history,'load','#0369a1','队列'),hostTrend('入站',data.history,'rx','#be185d','Mbps'),hostTrend('出站',data.history,'tx','#b45309','Mbps'));
  el('host-history-basis').textContent=(data.bucket_seconds>=3600?data.bucket_seconds/3600+' 小时':data.bucket_seconds/60+' 分钟')+'采样均值 · 采集始于 '+time(data.recorded_from)+' · 时区 UTC+8；未采集处留空';
 }
 el('host-events').replaceChildren(...data.events.map(e=>{const li=document.createElement('li');li.textContent=time(e.at)+' · '+(e.action.endsWith('resolved')?'已恢复':'预警')+' · '+e.code;return li;}));if(!data.events.length){const li=document.createElement('li');li.textContent='暂无阈值变更记录';el('host-events').append(li);}
 }catch(e){el('host-freshness').textContent='读取失败';el('host-alerts').textContent='系统监控暂不可用，已显示的数据可能过期。';el('host-alerts').classList.add('error');}}
// Read-only diagnostic reports load only while this section is expanded.
let udpDiagnosticsBusy=false;
async function refreshUdpDiagnostics(){
 if(udpDiagnosticsBusy || !el('udp-diag-details').open)return;
 udpDiagnosticsBusy=true;
 try{
  const data=await api('/api/udp-diagnostics');
  const rows=data.diagnostics.map(record=>{
   const row=document.createElement('tr');
   cell(row,time(record.started_at));cell(row,record.username+' / '+record.device_id);
   cell(row,({running:'诊断中',complete:'已完成',cancelled:'已取消',interrupted:'已中断',unavailable:'服务器观察不可用'})[record.phase] || '待核对');
   const trials=Array.isArray(record.report.trials)?record.report.trials:[];
   cell(row,trials.filter(t=>t.client?.egress_verified===true).length+' / '+trials.length+' 通过');
   const actions=cell(row,'');actions.className='row-actions';
   button(actions,'查看报告',()=>{
    el('udp-diag-report').value=JSON.stringify({diagnostic_id:record.id,started_at:record.started_at,device_id:record.device_id,phase:record.phase,report:record.report},null,2);
    el('udp-diag-dialog').showModal();
   });return row;
  });
  if(!rows.length){const row=document.createElement('tr');cell(row,'暂无记录，请在客户端的“诊断与测试”中发起。').colSpan=5;rows.push(row);}
  replaceRows('udp-diag-rows',rows);el('udp-diag-status').textContent='最近 '+data.diagnostics.length+' 条 · 只读记录';
 }catch(error){el('udp-diag-status').textContent='读取失败，请稍后刷新。';}
 finally{udpDiagnosticsBusy=false;}
}
el('udp-diag-details').addEventListener('toggle',refreshUdpDiagnostics);
el('udp-diag-refresh').addEventListener('click',refreshUdpDiagnostics);
el('udp-diag-close').addEventListener('click',()=>el('udp-diag-dialog').close());
el('udp-diag-copy').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(el('udp-diag-report').value);feedback('诊断报告已复制。');}catch{feedback('未能复制，请选择报告文字后复制。',true);}});
setInterval(()=>{if(!document.hidden && el('udp-diag-details').open)refreshUdpDiagnostics();},10000);

const passwordForm=el('admin-password-form');
if(passwordForm)passwordForm.addEventListener('submit',async event=>{
 event.preventDefault();const f=event.currentTarget;if(!f.reportValidity())return;
 if(f.elements.new_password.value!==f.elements.confirm_password.value){feedback('两次新密码不一致。',true);return;}
 const submit=f.querySelector('[type=submit]');submit.disabled=true;
 try{await api('/api/admin/password',{current_password:f.elements.current_password.value,new_password:f.elements.new_password.value,confirm_password:f.elements.confirm_password.value});feedback('管理员密码已修改。其他浏览器需用新密码重新登录。');}
 catch(error){feedback(error.message,true);}finally{f.reset();submit.disabled=false;}
});

function renderConnections(data){
 const state=data.connections || {},users=new Map(data.users.map(u=>[u.id,u]));
 el('connected-users').textContent=state.available?state.connected_users:'未知';
 el('connected-devices').textContent=state.available?state.connected_devices:'未知';
 el('registered-devices').textContent=state.registered_devices ?? '未知';
 el('connections-freshness').textContent=state.available?'采样 '+time(state.observed_at):'当前连接状态未确认';
 const rows=[];
 if(state.available)for(const peer of data.peers.filter(p=>p.connection?.connected)){
  const user=users.get(peer.user_id),row=document.createElement('tr');
  cell(row,user?.username || user?.name || '未分配用户');cell(row,peer.name || peer.fingerprint);
  cell(row,({'wireguard-udp':'WireGuard UDP','wireguard-quic':'HTTP/3','wireguard-https':'HTTPS'})[peer.client_status?.transport] || 'WireGuard');
  cell(row,time(peer.handshake));rows.push(row);
 }
 if(!rows.length){const row=document.createElement('tr'),message=cell(row,state.available?'当前没有已确认的代理连接。':'等待读取新的连接状态。');message.colSpan=4;rows.push(row);}
 replaceRows('connection-rows',rows);
}
