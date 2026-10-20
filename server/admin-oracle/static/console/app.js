const el = id => document.getElementById(id);
const labels = { ACTIVE: '运行中', INACTIVE: '未运行', PRESENT: '接口存在', ABSENT: '接口缺失', LISTENING: '监听中', NOT_LISTENING: '未监听' };
const actions = { 'snapshot.received': '收到只读诊断', 'snapshot.failed': '诊断采集失败', 'authentication.login': '账号登录', 'authentication.logout': '账号退出', 'authentication.factor_added': '绑定验证器', 'status.read': '查看服务状态' };
const time = value => new Date(value * 1000).toLocaleString('zh-CN', { timeZoneName: 'short' });
async function api(path) {
  const response = await fetch(path, { credentials: 'same-origin', redirect: 'error', cache: 'no-store' });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) throw new Error('登录已失效或需要动态码验证。请打开 /login/ 重新登录。');
    throw new Error('暂时无法读取管理服务，请稍后重试。');
  }
  return response.json();
}
let busy = false;
async function refresh() {
  if (busy) return;
  busy = true; el('refresh').disabled = true;
  try {
    const data = await api('/api/status');
    el('identity').textContent = data.actor;
    const snapshot = data.snapshot;
    el('service').textContent = labels[snapshot?.wg_service] || '未知';
    el('interface').textContent = labels[snapshot?.wg_interface] || '未知';
    el('listener').textContent = labels[snapshot?.udp_listener] || '未知';
    el('freshness').textContent = data.age_seconds === null ? '尚无数据' : data.age_seconds < 60 ? `${data.age_seconds} 秒前` : `${Math.floor(data.age_seconds / 60)} 分钟前`;
    el('observed').textContent = snapshot ? time(snapshot.observed_at) : '等待受信采集器';
    el('notice').classList.toggle('error', data.freshness !== 'fresh');
    el('notice').textContent = data.freshness === 'fresh' ? '已收到近期诊断。服务状态不代表客户端已建立握手或可以上网。' : snapshot ? '诊断数据已过期，以上为历史状态，不能据此判断服务器当前在线。' : '尚未收到服务器诊断。请先配置受信采集链路。';
    const audit = await api('/api/audit');
    const rows = audit.entries.map(entry => {
      const row = document.createElement('tr');
      for (const value of [time(entry.occurred_at), entry.actor, actions[entry.action] || entry.action, entry.resource]) {
        const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
      }
      return row;
    });
    if (!rows.length) {
      const row = document.createElement('tr'); const cell = document.createElement('td');
      cell.colSpan = 4; cell.textContent = '暂无审计记录'; row.append(cell); rows.push(row);
    }
    el('audit-rows').replaceChildren(...rows);
  } catch (error) {
    el('notice').classList.add('error');
    el('notice').textContent = `${error.message} 上次显示的数据可能已过期。`;
    el('freshness').textContent = '读取失败';
    el('audit-rows').textContent = '';
  } finally { busy = false; el('refresh').disabled = false; }
}
el('refresh').addEventListener('click', refresh);
for (const link of document.querySelectorAll('nav a')) link.addEventListener('click', () => {
  for (const other of document.querySelectorAll('nav a')) other.classList.toggle('active', link === other);
});
refresh();
setInterval(() => { if (!document.hidden) refresh(); }, 60000);
