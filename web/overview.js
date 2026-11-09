'use strict';

function overviewIssues() {
  const items=[], config=state.config;
  if(state.application?.state==='pending')items.push({title:'配置正在应用',detail:'服务状态将在应用完成后更新',route:'web',kind:'pending'});
  if(state.application?.state==='error')items.push({title:'配置应用失败',detail:state.application.message||'请查看规则运行状态',route:'web',kind:'error'});
  if(state.firewall?.state==='error')items.push({title:'防火墙管理需要检查',detail:state.firewall.message||'请检查运行环境及授权',route:'settings/environment',kind:'error'});
  for(const rule of config.rules)if(ruleProblem(rule)){
    const status=state.rules.find(s=>s.id===rule.id);
    items.push({title:rule.name,detail:status?.firewall?.state==='error'?status.firewall.message:status?.backend?.state==='error'?status.backend.message:status?.message||'服务运行异常',route:rule.kind==='web'?'web':'forwards',kind:'error'});
  }
  for(const cert of state.certificates)if(cert.error||cert.remainingDays<=30)items.push({title:cert.name||cert.id,detail:cert.error||(Date.parse(cert.expires)<=Date.now()?'证书已过期':`证书将在 ${Math.max(0,cert.remainingDays)} 天内到期`),route:'certs',kind:'warning'});
  for(const job of state.certificateJobs||[])if(job.state==='error'&&(state.certificateTasks||[]).some(t=>t.id===job.id))items.push({title:job.id,detail:job.message||'证书申请失败',route:'certs',kind:'error'});
  for(const task of config.ddns.filter(t=>t.enabled)){
    const status=state.ddns.find(s=>s.id===task.id);
    if(status?.state==='error')items.push({title:task.name,detail:status.message||'域名同步失败',route:'ddns',kind:'error'});
  }
  return items;
}

function overviewMetric(label,value,detail,glyph,route) {
  return `<a class="dashboard-metric control-link" href="#/${route}"><div class="dashboard-metric-top"><span>${esc(label)}</span>${icon(glyph)}</div><strong>${esc(value)}</strong><div class="dashboard-metric-bottom"><span>${esc(detail)}</span>${icon('arrow')}</div></a>`;
}

function overviewServiceRows(rules) {
  if(!rules.length)return `<div class="dashboard-empty">${icon('services')}<strong>从第一个网络服务开始</strong><p>连接一个网站，或为设备创建转发入口。</p>${btn('添加反向代理','add:rules','plus','primary')}</div>`;
  return `<div class="dashboard-list">${rules.slice().sort((a,b)=>Number(ruleProblem(b))-Number(ruleProblem(a))||Number(b.enabled)-Number(a.enabled)).slice(0,6).map(rule=>{
    const status=state.rules.find(s=>s.id===rule.id),routes=(rule.routes||[]).filter(r=>r.enabled),first=routes[0];
    const detail=rule.kind==='web'?(first?`${first.domains?.[0]||'未配置域名'}${first.pathPrefix||'/'}${routes.length>1?' · '+routes.length+' 条入口':''}`:'尚未启用子规则'):`${rule.listen} → ${rule.target}`;
    const fault=ruleProblem(rule),label=!rule.enabled?'已停用':fault?'需处理':status?.state==='running'?'监听就绪':'等待应用';
    return `<a class="dashboard-service control-link" href="#/${rule.kind==='web'?'web':'forwards'}" data-overview-service="${esc(rule.id)}"><span class="dashboard-service-icon">${icon(rule.kind==='web'?'services':'arrow')}</span><span class="dashboard-service-info"><strong>${esc(rule.name)}</strong><small>${esc(detail)}</small></span>${pill(label,!rule.enabled?'':fault?'error':status?.state==='running'?'good':'blue')}</a>`;
  }).join('')}</div>`;
}

function overviewNetwork() {
  const config=state.config,firewall=state.firewall||{};
  const addresses=['ipv4','ipv6'].map(family=>{
    const address=state.routerIPs?.[family];
    return `<div class="dashboard-address"><div><small>${family==='ipv4'?'IPv4':'IPv6'} 公网地址</small>${address?.error?'<span class="dashboard-warning">检测未成功</span>':''}</div><p>${esc(address?.value||(address?.loading?'正在检测…':'未获取'))}${address?.value?copyValue(address.value):''}</p></div>`;
  }).join('');
  const rows=[['管理 HTTPS',config.adminTls?.enabled?(state.adminTlsStatus?.ready?'已就绪':'未就绪'):'未启用','settings/https'],['两步验证',state.twoFactor?.enabled?'已开启':'未开启','settings/account'],['防火墙管理',firewall.state==='error'?'需要检查':firewall.enabled?'已授权':'未授权','settings/environment']];
  return `<div class="dashboard-network">${addresses}<div class="dashboard-security">${rows.map(([label,value,route])=>`<a class="control-link" href="#/${route}"><span>${label}</span><span>${value}${icon('chevron')}</span></a>`).join('')}</div></div>`;
}

function overviewCertificates() {
  if(!state.certificates.length)return `<div class="dashboard-empty compact"><p>还没有已签发的证书</p>${btn('管理证书','page:certs','shield')}</div>`;
  return `<div class="dashboard-mini-list">${state.certificates.slice().sort((a,b)=>Number(!!b.error)-Number(!!a.error)||(a.remainingDays??Infinity)-(b.remainingDays??Infinity)).slice(0,3).map(cert=>{
    const expired=Date.parse(cert.expires)<=Date.now(),days=cert.remainingDays;
    const label=cert.error?'读取失败':expired?'已过期':cert.staging?'测试证书':Number.isFinite(days)?`${days} 天`:'待检查';
    return `<a class="control-link" href="#/certs"><span><strong>${esc(cert.name||cert.id)}</strong><small>${esc(cert.domains?.[0]||cert.id)}</small></span>${pill(label,cert.error||expired?'error':days<=30?'warn':'')}</a>`;
  }).join('')}</div>`;
}

function overviewDNS() {
  const tasks=state.config.ddns;
  if(!tasks.length)return `<div class="dashboard-empty compact"><p>让域名跟随公网地址更新</p>${btn('添加 DDNS 任务','add:ddns','plus')}</div>`;
  return `<div class="dashboard-mini-list">${tasks.slice().sort((a,b)=>Number(state.ddns.find(s=>s.id===b.id)?.state==='error'&&b.enabled)-Number(state.ddns.find(s=>s.id===a.id)?.state==='error'&&a.enabled)).slice(0,3).map(task=>{
    const status=state.ddns.find(s=>s.id===task.id),label=!task.enabled?'已停用':status?.state==='error'?'同步失败':status?.state==='running'?'同步中':status?.state==='success'?'已同步':'待检查';
    const records=(task.records||[]).filter(r=>r.enabled).length;
    return `<a class="control-link" href="#/ddns"><span><strong>${esc(task.name)}</strong><small>${records} 条已启用记录${status?.updated?' · '+esc(new Date(status.updated).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})):''}</small></span>${pill(label,task.enabled&&status?.state==='error'?'error':task.enabled&&status?.state==='success'?'good':'')}</a>`;
  }).join('')}</div>`;
}

function overviewActivity() {
  const events=state.events||[];
  if(!events.length)return '<div class="dashboard-empty compact"><p>暂无操作记录，服务运行结果会显示在这里。</p></div>';
  return `<ol class="dashboard-activity">${events.slice().reverse().slice(0,5).map(event=>`<li><span class="dashboard-activity-dot"></span><p>${esc(event.message)}</p><time datetime="${esc(event.time)}" title="${esc(new Date(event.time).toLocaleString())}">${esc(new Date(event.time).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}))}</time></li>`).join('')}</ol>`;
}

function overviewPage() {
  const config=state.config,rules=config.rules,enabled=rules.filter(r=>r.enabled),running=enabled.filter(r=>state.rules.some(s=>s.id===r.id&&s.state==='running')).length;
  const issues=overviewIssues(),errors=issues.filter(i=>i.kind!=='pending'),certs=state.certificates,expiring=certs.filter(c=>c.error||c.remainingDays<=30).length;
  const title=errors.length?`${errors.length} 项状态需要关注`:state.application?.state==='pending'?'配置正在应用':!enabled.length?'准备好连接你的服务':running===enabled.length?'已启用服务的监听均已就绪':'部分服务正在等待应用';
  const note=errors.length?'查看下方事项，或进入对应页面处理。':!enabled.length?'从反向代理、端口转发或常用链接开始。':'监听状态来自 LinkNest；外网访问及后端连通性请在规则页检查。';
  const summary=`<section class="dashboard-summary ${errors.length?'attention':''}" aria-label="运行摘要"><span class="dashboard-summary-icon">${icon(errors.length?'info':'services')}</span><div><h2>${esc(title)}</h2><p>${esc(note)}</p></div><span class="dashboard-version">LinkNest ${esc(state.version)}</span></section>`;
  const notices=issues.length?`<section class="dashboard-issues" aria-label="需要处理">${issues.slice(0,4).map(item=>`<a href="#/${item.route}" class="control-link ${item.kind}">${icon('info')}<span><strong>${esc(item.title)}</strong><small>${esc(item.detail)}</small></span>${icon('chevron')}</a>`).join('')}${issues.length>4?`<p>另有 ${issues.length-4} 项，请进入对应管理页面查看完整状态。</p>`:''}</section>`:'';
  const metrics=overviewMetric('运行中的服务',running,`已启用 ${enabled.length} / 共 ${rules.length} 条规则`,'services','web')+overviewMetric('动态域名',config.ddns.filter(d=>d.enabled).length,`${config.ddns.length} 个任务 · 自动维护解析`,'globe','ddns')+overviewMetric('已签发证书',certs.length,expiring?`${expiring} 张需要关注`:'按到期时间安排续期','shield','certs')+overviewMetric('常用链接',config.bookmarks.length,'打开你的轻面板','link','bookmarks');
  return `<div class="dashboard">${summary}<div class="dashboard-metrics">${metrics}</div>${notices}<div class="dashboard-columns"><div class="dashboard-column">${panel('网络服务','优先展示异常及已启用的服务',overviewServiceRows(rules),`<div class="actions">${btn('反向代理','page:rules')}${btn('端口转发','page:forwards')}</div>`,'dashboard-services')}${panel('最近活动','最近 5 条操作与运行结果',overviewActivity(),'','dashboard-activity-panel')}</div><div class="dashboard-column">${panel('连接与安全','公网地址与管理入口',overviewNetwork(),'','dashboard-network-panel')}${panel('证书有效期','到期较近的证书优先',overviewCertificates(),ibtn('管理证书','page:certs','arrow'),'dashboard-certificates')}${panel('域名同步','关注失败任务与检查结果',overviewDNS(),ibtn('管理动态域名','page:ddns','arrow'),'dashboard-dns')}</div></div></div>`;
}
