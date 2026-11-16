'use strict';
// Buildless, same-origin UI. All configuration strings are escaped before rendering.
const $ = (s, root = document) => root.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const paths = {
  copy:'M8 8h12v13H8z M4 16H2V2h13v3', home:'M3 10 12 3l9 7v10H3z M9 20v-7h6v7', services:'M4 5h16v5H4z M4 14h16v5H4z M7 8h.01 M7 17h.01',
  globe:'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0 M3 12h18 M12 3c5 5 5 13 0 18-5-5-5-13 0-18',
  shield:'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z M9 12l2 2 4-4', link:'M10 14l4-4 M8 16l-1 1a4 4 0 0 1-6-6l5-5a4 4 0 0 1 6 0 M16 8l1-1a4 4 0 0 1 6 6l-5 5a4 4 0 0 1-6 0',
  power:'M12 2v10 M6 5a9 9 0 1 0 12 0', terminal:'M4 6l6 6-6 6 M13 18h7', settings:'M4 7h16 M4 17h16 M8 4v6 M16 14v6',
  plus:'M12 5v14 M5 12h14', refresh:'M20 12a8 8 0 1 1-2.34-5.66L20 9 M20 4v5h-5',
  edit:'m4 16 11-11 4 4L8 20H4z M13 7l4 4', trash:'M3 6h18 M9 6V3h6v3 M6 6l1 15h10l1-15 M10 10v7 M14 10v7',
  close:'m6 6 12 12 M6 18 18 6', chevron:'m7 10 5 5 5-5', sun:'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v2 M12 20v2 M2 12h2 M20 12h2 M5 5l1 1 M18 18l1 1 M5 19l1-1 M18 6l1-1',
  logout:'M10 4H4v16h6 M9 12h12 M17 8l4 4-4 4', arrow:'M7 17 17 7 M7 7h10v10', info:'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 11v6 M12 7v.1', download:'M12 3v12 M7 10l5 5 5-5 M4 17v4h16v-4', play:'m8 4 12 8-12 8z'
};
const icon = n => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="${paths[n] || paths.info}"/></svg>`;
const navs = [['overview','home','总览'],['rules','services','反向代理'],['forwards','arrow','端口转发'],['ddns','globe','动态域名'],['certs','shield','证书管理'],['bookmarks','link','轻面板'],['devices','power','网络唤醒'],['terminal','terminal','Web 终端'],['security','shield','访问过滤'],['settings','settings','设置']];
function pageFromHash(hash=location.hash){const part=hash.replace(/^#\/?/,'').split('/')[0];const name=part==='web'?'rules':part;return navs.some(x=>x[0]===name)?name:'overview';}
function navigatePage(name,tab=''){const route=name==='rules'?'web':name;const hash='#/'+route+(tab?'/'+tab:'');if(location.hash!==hash)location.hash=hash;else render();}
let state, page = pageFromHash(), loggedIn = false, toastTimer, fetching = false, terminal, socket, terminalObserver;
let renderedRoute='', serverVersion='';
function pageTransitionChanged(route){const changed=renderedRoute!==''&&renderedRoute!==route;renderedRoute=route;return changed;}
window.addEventListener('resize',()=>syncTabIndicators());
let acceptedHash=location.hash;
window.addEventListener('hashchange',()=>{
 const requestedHash=location.hash,previousHash=acceptedHash;
 const form=activeDialog&&!activeDialog.saving?activeDialog.form:document.querySelector('.main form[data-dirty="true"]');
 if(!discardDraft(form,()=>{
  if(acceptedHash!==previousHash)return;
  form.dataset.dirty='false';if(activeDialog?.form===form)closeModal(true);
  location.hash=requestedHash;
 })){history.replaceState(null,'',acceptedHash||location.pathname+location.search);return;}
 acceptedHash=location.hash;const next=pageFromHash();closeNav(false);if(page!==next)stopTerminal();page=next;panelTab=panelTabFromHash();if(loggedIn){render();window.scrollTo(0,0);}
});
const themeKey = 'linknest-theme';
try { const theme = localStorage.getItem(themeKey); if (theme) document.documentElement.dataset.theme = theme; } catch {}
const uid = () => 'r_' + Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2,'0')).join('');
function toast(message, bad=false) { const el=$('#toast'); el.textContent=message; el.className='show'+(bad?' error':''); clearTimeout(toastTimer); toastTimer=setTimeout(()=>el.className='',4500); }
async function api(path, method='GET', body, responseType='json',revision) {
  const epoch=authEpoch,controller=new AbortController(); const timeout=setTimeout(()=>controller.abort(),['ddns/record/delete','access/update','upnp/mode','upnp/policy','upnp/ports'].includes(path)?60000:30000);
  try {
    const r=await fetch('/api/'+path,{method,credentials:'same-origin',headers:{'Content-Type':'application/json','X-LinkNest-Request':'1',...(path==='config'&&method==='PUT'?{'If-Match':revision||state?.configRevision||''}:{})},body:body===undefined?undefined:JSON.stringify(body),signal:controller.signal});
    if(epoch!==authEpoch){const error=Error('已丢弃过期会话响应');error.stale=true;throw error;}
    const trustedHeader=r.headers.get('X-LinkNest-Trusted-Until');if(trustedHeader&&state?.twoFactor){if(trustedHeader==='0')delete state.twoFactor.trustedUntil;else state.twoFactor.trustedUntil=trustedHeader;}
    if(r.ok&&responseType==='blob')return await r.blob();
    let v; try { v=await r.json(); } catch { throw Error('服务返回了无法解析的数据'); }
    if(!r.ok) { if(r.status===401 && !['login','setup'].includes(path)) { loggedIn=false; stopTerminal(); renderAuth(true); } const error=Error(v.error||`请求失败 (${r.status})`);error.status=r.status;error.code=v.errorCode;error.twoFactorRequired=v.twoFactorRequired===true;throw error; } return v;
  } catch(e) { if(epoch!==authEpoch)e.stale=true;if(e.name==='AbortError') throw Error('请求超时，请检查服务状态'); throw e; } finally { clearTimeout(timeout); }
}
async function busy(button, action) {
  if(button?.disabled)return; const old=button?.innerHTML, rotating=button?.classList.contains('refresh-button');
  if(button){button.disabled=true;button.setAttribute('aria-busy','true');if(rotating)button.classList.add('is-loading');else button.insertAdjacentHTML('afterbegin','<span class="spinner"></span>');}
  try { await action(); } catch(e) { if(e.stale)return;const form=button?.closest('form');if(form?.isConnected){if(e.twoFactorRequired)requireTwoFactorInForm(form);markFormError(form,e);}else toast(e.message,true); }
  finally {if(button){button.disabled=false;button.innerHTML=old;button.classList.remove('is-loading');button.setAttribute('aria-busy','false');}}
}
function syncRefreshControls(){for(const button of $$('[data-action="refresh"]')){button.disabled=fetching;button.classList.toggle('is-loading',fetching);button.setAttribute('aria-busy',String(fetching));button.setAttribute('aria-label',fetching?'正在刷新状态':'刷新状态');}}
function btn(label, action, glyph, style='') { return `<button class="button ${style}" data-action="${action}">${glyph?icon(glyph):''}${esc(label)}</button>`; }
function ibtn(title,action,glyph) { return `<button class="icon-button${glyph==='refresh'?' refresh-button':glyph==='trash'?' danger':''}" title="${esc(title)}" aria-label="${esc(title)}" data-action="${action}">${icon(glyph)}</button>`; }
function pill(text,kind='') { return `<span class="pill ${kind}"><i class="dot"></i>${esc(text)}</span>`; }
function serviceStatePill(status,enabled){return pill(!enabled?'已停用':status?.state==='running'?'运行正常':status?.state==='error'?'启动失败':'等待应用',!enabled?'':status?.state==='running'?'good':status?.state==='error'?'error':'blue');}
function empty(title,desc,action) { return `<div class="empty">${icon('services')}<h3>${esc(title)}</h3><p>${esc(desc)}</p>${action||''}</div>`; }
function panel(title,sub,body,extra='',className='') { return `<section class="panel${className?' '+esc(className):''}"><div class="panel-head"><div><h2>${esc(title)}</h2>${sub?`<p>${esc(sub)}</p>`:''}</div>${extra}</div>${body}</section>`; }
function field(name,label,value='',hint='',type='text',wide=false) { return `<label class="field ${wide?'wide':''}"><span>${esc(label)}</span><input name="${name}" type="${type}" value="${esc(value)}" ${type==='password'?'autocomplete="new-password"':'autocomplete="off"'}>${hint?`<small>${esc(hint)}</small>`:''}</label>`; }
function area(name,label,value='',hint='') { return `<label class="field wide"><span>${esc(label)}</span><textarea name="${name}" spellcheck="false">${esc(value)}</textarea>${hint?`<small>${esc(hint)}</small>`:''}</label>`; }
function toggle(name,label,value,hint='') { return `<div class="switch-row"><span>${esc(label)}${hint?`<small>${esc(hint)}</small>`:''}</span><label class="switch"><input type="checkbox" name="${name}" aria-label="${esc(label)}" ${value?'checked':''}><i></i></label></div>`; }
function picker(name,label,value,options) { const found=options.find(x=>x[0]===value); return `<div class="field"><span>${esc(label)}</span><div class="picker"><input type="hidden" name="${esc(name)}" value="${esc(value)}"><button type="button" class="picker-trigger" aria-haspopup="listbox" aria-label="${esc(label)}：${esc(found?.[1]||'请选择')}" aria-expanded="false"><span>${esc(found?.[1]||'请选择')}</span>${icon('chevron')}</button><div class="picker-menu" role="listbox" aria-label="${esc(label)}" hidden>${options.map(([v,t])=>`<button type="button" role="option" aria-selected="${v===value}" data-value="${esc(v)}">${esc(t)}</button>`).join('')}</div></div></div>`; }
let activePicker=null;
function pickerPlacement(anchor,bounds,height){const gap=5,pad=8,left=Math.max(bounds.left+pad,Math.min(anchor.left,bounds.right-pad-anchor.width)),width=Math.min(anchor.width,bounds.right-bounds.left-pad*2),below=Math.max(0,bounds.bottom-pad-anchor.bottom-gap),above=Math.max(0,anchor.top-bounds.top-pad-gap),up=below<Math.min(height,210)&&above>below,maxHeight=Math.min(210,up?above:below);return {left,width,maxHeight,top:up?anchor.top-gap-Math.min(height,maxHeight):anchor.bottom+gap};}
function closePicker(restoreFocus=false){if(!activePicker)return;const {menu,owner,trigger}=activePicker;activePicker=null;menu.hidden=true;menu.classList.remove('picker-floating');menu.removeAttribute('style');owner.append(menu);trigger.setAttribute('aria-expanded','false');if(restoreFocus&&trigger.isConnected)trigger.focus({preventScroll:true});}
function positionPicker(){if(!activePicker)return false;const {trigger,menu,host}=activePicker,v=window.visualViewport,bounds={left:v?.offsetLeft||0,top:v?.offsetTop||0,right:(v?.offsetLeft||0)+(v?.width||innerWidth),bottom:(v?.offsetTop||0)+(v?.height||innerHeight)};if(host!==document.body){const r=host.getBoundingClientRect();bounds.left=Math.max(bounds.left,r.left);bounds.top=Math.max(bounds.top,r.top);bounds.right=Math.min(bounds.right,r.right);bounds.bottom=Math.min(bounds.bottom,r.bottom);}const anchor=trigger.getBoundingClientRect();if(!trigger.isConnected||anchor.bottom<=bounds.top||anchor.top>=bounds.bottom){closePicker();return false;}menu.style.width=Math.min(anchor.width,bounds.right-bounds.left-16)+'px';const pos=pickerPlacement(anchor,bounds,menu.scrollHeight);for(const key of ['left','top','width','maxHeight'])menu.style[key]=pos[key]+'px';return true;}
function openPicker(trigger){closePicker();const owner=trigger.closest('.picker'),menu=$('.picker-menu',owner),host=trigger.closest('dialog')||document.body;activePicker={owner,menu,trigger,host};host.append(menu);menu.classList.add('picker-floating');menu.hidden=false;trigger.setAttribute('aria-expanded','true');if(!positionPicker())return;const selected=$('[aria-selected="true"]',menu)||$('button',menu);selected?.focus({preventScroll:true});if(selected)menu.scrollTop=Math.max(0,selected.offsetTop-menu.clientHeight/2);}
window.addEventListener('resize',()=>closePicker());
window.visualViewport?.addEventListener('resize',()=>closePicker());
window.visualViewport?.addEventListener('scroll',()=>closePicker());
document.addEventListener('scroll',e=>{if(activePicker&&!activePicker.menu.contains(e.target))positionPicker();},true);
const modal=$('#modal');
modal.addEventListener('close',()=>closePicker());
let bodyY=0;
function closeModal(force=false){
 if(force)dismissDiscardPrompt();
 if(!modal.open)return false;
 const session=activeDialog;
 if(!force&&session&&!session.saving&&!discardDraft(session.form,()=>{if(activeDialog===session)closeModal(true);}))return false;
 closePicker();activeDialog=null;modal.close();return true;
}
modal.addEventListener('cancel',e=>{e.preventDefault();closeModal();});
modal.addEventListener('close',()=>{if(modal.open)return;document.body.classList.remove('modal-open');document.body.style.position='';document.body.style.top='';document.body.style.width='';window.scrollTo(0,bodyY);$('#modal-body').replaceChildren();});
function dialog(title,content,onSave,submit='保存',onOpen) {
 const sessionBefore=activeDialog,position=modal.open?bodyY:scrollY;
 if(modal.open&&sessionBefore&&!sessionBefore.saving&&!discardDraft(sessionBefore.form,()=>{
  if(activeDialog!==sessionBefore)return;
  sessionBefore.form.dataset.dirty='false';dialog(title,content,onSave,submit,onOpen);
 }))return;
 if(modal.open)closeModal(true);
 $('#modal-body').innerHTML=`<form id="dialog-form"><div class="modal-head"><h2 id="modal-title">${esc(title)}</h2><button type="button" class="icon-button" data-close aria-label="关闭">${icon('close')}</button></div><div class="modal-content">${content}<p id="form-error" class="form-error" role="alert"></p></div><div class="modal-actions dialog-footer"><button type="button" class="button" data-close>取消</button><button class="button primary" type="submit">${esc(submit)}</button></div></form>`;
 const form=$('#dialog-form'),session={id:++dialogSequence,form,revision:state?.configRevision,dirty:false,saving:false};activeDialog=session;form.dataset.revision=session.revision||'';
 $$('[data-close]',modal).forEach(x=>x.onclick=()=>closeModal());
 form.onsubmit=e=>{e.preventDefault();if(form.dataset.iconBusy==='1'||session.saving)return;const data=Object.fromEntries(new FormData(form));$$('input[type=checkbox]',form).forEach(x=>data[x.name]=x.checked);session.saving=true;busy($('button[type=submit]',form),async()=>{try{await onSave(data);session.dirty=false;form.dataset.dirty='false';if(activeDialog===session)closeModal(true);}finally{session.saving=false;}});};
 bodyY=position;document.body.classList.add('modal-open');document.body.style.position='fixed';document.body.style.top=`-${bodyY}px`;document.body.style.width='100%';modal.showModal();$('.modal-content',modal).scrollTop=0;onOpen?.(form);
}

const $$=(s,root=document)=>Array.from(root.querySelectorAll(s));
document.addEventListener('click', e=>{
  const option=e.target.closest('.picker-menu button');
  if(option&&activePicker){const {owner:p,menu,trigger}=activePicker;$('input',p).value=option.dataset.value;$('.picker-trigger span',p).textContent=option.textContent;trigger.setAttribute('aria-label',p.parentElement.querySelector(':scope > span').textContent+'：'+option.textContent);$$('[role=option]',menu).forEach(x=>x.setAttribute('aria-selected',String(x===option)));closePicker(true);$('input',p).dispatchEvent(new Event('change',{bubbles:true}));return;}
  const trigger=e.target.closest('.picker-trigger');
  if(trigger){if(activePicker?.trigger===trigger)closePicker();else openPicker(trigger);}else closePicker();
});
document.addEventListener('keydown',e=>{
 const trigger=e.target.closest('.picker-trigger');
 if(trigger&&['ArrowDown','ArrowUp'].includes(e.key)){e.preventDefault();openPicker(trigger);return;}
 if(!activePicker)return;const menu=activePicker.menu;if(e.key==='Tab'){closePicker(true);return;}if(!menu.contains(e.target))return;
 const opts=$$('button',menu),i=opts.indexOf(document.activeElement);
 if(['ArrowDown','ArrowUp','Home','End','Escape'].includes(e.key)){
  e.preventDefault();if(e.key==='Escape'){e.stopPropagation();closePicker(true);}
  else opts[e.key==='Home'?0:e.key==='End'?opts.length-1:(i+(e.key==='ArrowDown'?1:-1)+opts.length)%opts.length]?.focus();
 }
});
async function saveConfig(c,form=activeDialog?.form) {
 const revision=form?.dataset.revision||state.configRevision,epoch=++stateEpoch;
 c.dns=c.dns||{};c.dns.secret=c.dns.secret||'';
 const result=await api('config','PUT',c,'json',revision);
 if(form){form.dataset.dirty='false';form.dataset.revision=result.configRevision;form.querySelector('[data-save-error]')?.remove();form.querySelectorAll('[aria-invalid]').forEach(input=>input.removeAttribute('aria-invalid'));}
 try{const latest=await api('state');if(epoch===stateEpoch){state=latest;lastStateSuccess=Date.now();stateReadError='';refreshPageContent();}}catch(error){if(!error.stale){stateReadError='配置已保存，但状态读取失败';syncStateBanner();}}
 toast('配置已保存，正在应用；请查看运行状态');
}

async function saveItem(group,item) { const c=structuredClone(state.config);const i=c[group].findIndex(x=>x.id===item.id);if(i<0)c[group].push(item);else c[group][i]=item;if(group==='devices')deviceChecks.delete(item.id); await saveConfig(c); }
function removeItem(group,id) { const item=state.config[group].find(x=>x.id===id);dialog('删除'+(item.name||'记录'),actionNote('仅删除这条配置；运行中的对应服务会停止。不会删除目标服务器的文件。'),async()=>{const c=structuredClone(state.config);c[group]=c[group].filter(x=>x.id!==id);await saveConfig(c);},'确认删除'); }
function renderAuth(initialized) {
  serverVersion=state?.version||serverVersion;
  closeNav(false);
  authEpoch++;stateEpoch++;state=null;closeModal(true);deviceChecks.clear();accessState={bans:[],sources:[]};
  if(typeof resetUPnPState==='function')resetUPnPState();
  closePicker();
  $('#app').innerHTML=`<div class="auth"><section class="auth-intro"><img src="/icon.svg" alt=""><h1>让网络服务<br>各就其位。</h1><p>栖网 LinkNest · 把域名、入口与远程连接，收进一个轻量的控制台。</p><span class="pill">一个容器 · 自己掌控</span></section><div class="auth-form-wrap"><form class="auth-form" id="auth-form" name="linknest-login" action="/api/${initialized?'login':'setup'}" method="post" autocomplete="on"><h2>${initialized?'欢迎回来':'开始使用栖网'}</h2><p>${initialized?'登录你的网络服务控制台。':'没有默认密码。先使用容器内的初始化口令创建管理员。'}</p>${!initialized?field('token','初始化口令','','在容器 /data/bootstrap.token 中读取'):''}<label class="field" for="auth-username"><span>用户名</span><input id="auth-username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="128" placeholder="请输入管理员用户名"></label><label class="field" for="auth-password"><span>${initialized?'管理员密码':'设置管理员密码'}</span><input id="auth-password" name="password" type="password" autocomplete="${initialized?'current-password':'new-password'}" required maxlength="72" ${initialized?'':'minlength="12"'}>${initialized?'':'<small>至少 12 字节，建议使用长随机密码</small>'}</label><p id="auth-error" class="form-error" role="alert"></p><button type="submit" class="button primary">${initialized?'登录控制台':'创建管理员'}</button><div class="auth-footer">管理入口仅建议在受信局域网或 SSH 隧道中使用。<br>${serverVersion?'版本 '+esc(serverVersion)+' · ':''}不会自动开放业务端口</div></form></div></div>`;
  $('#auth-form').onsubmit=e=>{e.preventDefault();$('#auth-error').textContent='';const data=Object.fromEntries(new FormData(e.currentTarget));const b=$('button',e.currentTarget);busy(b,async()=>{try{if(!initialized)await api('setup','POST',data);const result=await api('login','POST',{username:data.username,password:data.password,code:data.code||'',trustDevice:data.trustDevice==='on'});if(result.twoFactorRequired){if(!$('#auth-code'))$('#auth-error').insertAdjacentHTML('beforebegin','<label class="field" for="auth-code"><span>动态验证码或恢复码</span><input id="auth-code" name="code" type="text" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" maxlength="64" required placeholder="输入 Authenticator 的 6 位验证码"><small>丢失手机时可使用一次性恢复码；请确认手机时间自动同步。</small></label>'+trustBrowserChoice());$('#auth-code').focus();return;}loggedIn=true;state=await api('state');lastStateSuccess=Date.now();stateReadError='';render();}catch(err){$('#auth-error').textContent=err.message;}});};
}
function render() {
  closePicker();
  if(!loggedIn||!state)return;
  serverVersion=state.version||serverVersion;
  closeNav(false);
  const layout=$('#app > .layout'),enteringPage=layout?.dataset.view!==page;
  const animate=pageTransitionChanged(page+(page==='bookmarks'?':'+panelTab:page==='forwards'?':'+forwardTab():page==='settings'?':'+settingsTab():''));
  const labels={overview:['总览','服务、域名与证书，一处掌握。'],rules:['反向代理','主规则管理监听，子规则按域名分流'],forwards:['端口转发','独立管理 TCP / UDP 转发'],ddns:['动态域名','自动跟随公网 IP · 阿里云 DNS'],certs:['证书管理','导入证书，或通过 DNS 验证申请与续期'],bookmarks:['轻面板','常用 Web 服务的私人导航页'],devices:['网络唤醒','向局域网设备发送 Wake-on-LAN 魔术包'],security:['访问过滤','只过滤栖网承接的业务连接，不影响路由器其他服务'],terminal:['Web 终端','通过 SSH 连接可信主机 · 不挂载宿主机 Shell'],settings:['设置','账户、安全开关与数据备份']};
  const [title,sub]=labels[page];
const shell=document.createElement('template');shell.innerHTML=`<div class="layout" data-view="${esc(page)}"><aside class="sidebar" id="main-sidebar" aria-label="侧栏导航"><button class="drawer-close icon-button" data-action="nav-close" aria-label="关闭菜单">${icon('close')}</button><div class="brand"><img src="/icon.svg" alt=""><div><strong>栖网</strong><small>LINKNEST</small></div></div><nav class="nav" aria-label="主导航">${navs.map(([id,ic,n])=>`${({rules:'网络服务',bookmarks:'常用工具',security:'系统管理'})[id]?'<div class="nav-group">'+({rules:'网络服务',bookmarks:'常用工具',security:'系统管理'})[id]+'</div>':''}<button data-page="${id}" class="${page===id?'active':''}" ${page===id?'aria-current="page"':''}>${icon(ic)}${n}</button>`).join('')}</nav><div class="sidebar-bottom"><div class="version">LinkNest ${esc(serverVersion)}<br>单容器 · 自托管</div><div class="sidebar-tools">${ibtn('切换外观','theme','sun')}${ibtn('退出登录','logout','logout')}</div></div></aside><button class="nav-shade" data-action="nav-close" aria-label="收起菜单" tabindex="-1"></button><main class="main"><div class="mobile-brand"><button class="icon-button nav-toggle" data-action="nav-open" aria-label="打开菜单" aria-expanded="false" aria-controls="main-sidebar"><svg class="icon" viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></svg></button><img src="/icon.svg" alt="">栖网 LinkNest <button data-action="theme" class="mobile-tool" aria-label="切换外观">${icon('sun')}</button><button data-action="logout" aria-label="退出登录">${icon('logout')}</button></div><header class="top ${animate?'page-transition':''}"><div><h1>${title}</h1><p>${sub}</p></div><div class="header-tools"><div class="actions">${ibtn('刷新状态','refresh','refresh')}</div><div id="state-status" class="state-status" role="status"></div></div></header><div id="page-content" class="${animate&&enteringPage?'page-transition':''}">${pageContentMarkup(animate&&!enteringPage)}</div></main></div>`;
  if(layout){
    // Keep navigation nodes, focus and scroll position across page changes.
    if(layout.dataset.view===page){
      // Tab changes update content, leaving the title/status shell untouched.
      patchPageContent($('#page-content',layout),$('#page-content',shell.content),animate);
      patchNode($('.top .actions',layout),$('.top .actions',shell.content));
    }else{
      $('.main',layout).replaceWith($('.main',shell.content));
      layout.dataset.view=page;
    }
    for(const button of $$('.nav [data-page]',layout)){
      const active=button.dataset.page===page;button.classList.toggle('active',active);
      if(active)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');
    }
    $('.version',layout).innerHTML=$('.version',shell.content).innerHTML;
  }else $('#app').replaceChildren(shell.content);
  syncRefreshControls();stampForms();applyRuleFilters();syncStateBanner();syncTabIndicators();
  document.fonts?.ready.then(syncTabIndicators);
}
function pageAction(){ if(page==='bookmarks'||page==='forwards'&&forwardTab()==='upnp')return ''; const actions={rules:['添加主规则','add:rules'],forwards:['添加转发','add:forwards'],ddns:['添加任务','add:ddns'],certs:['添加证书','issue'],bookmarks:['添加链接','add:bookmarks'],devices:['添加设备','add:devices'],terminal:['添加主机','add:sshHosts']};const a=actions[page];return a?btn(a[0],a[1],'plus','primary'):''; }
function ruleRows(items) { return items.map(r=>`<article class="forward-rule" data-rule-id="${esc(r.id)}"><div class="forward-rule-head"><strong>${esc(r.name)}</strong><div class="actions">${ibtn('检查后端','rule-check:'+r.id,'refresh')}${ibtn(r.enabled?'停用':'启用','toggle:'+r.id,'power')}${ibtn('编辑','edit:rules:'+r.id,'edit')}${ibtn('删除','delete:rules:'+r.id,'trash')}</div></div><div class="forward-rule-flow"><div><small>${esc(r.kind==='tcpudp'?'TCP + UDP':r.kind.toUpperCase())} · ${r.forwardMode==='kernel'?'内核加速':'兼容转发'}</small><p>${esc(r.listen)}${copyValue(r.listen)}</p></div><span>→</span><div><small>${r.preserveClientIp?'保留客户端原 IP':'目标地址'}</small><p>${esc(r.kind==='web'?((r.routes||[]).length+' 条子规则'):r.target)}${r.target?copyValue(r.target):''}</p></div></div><div class="rule-status" data-rule-status="${esc(r.id)}">${ruleStatusMarkup(r)}</div></article>`).join(''); }

function row(glyph,title,desc,actions='') { return `<div class="row"><div class="row-left"><div class="tile">${icon(glyph)}</div><div class="row-details"><strong>${esc(title)}</strong><p>${esc(desc)}</p></div></div><div class="row-right">${actions}</div></div>`; }
function overview(){return overviewPage();}

function pageContent(){const c=state.config;
  if(page==='overview')return overview();
  if(page==='rules')return proxyPage();
  if(page==='forwards')return forwardPage();
  if(page==='ddns')return ddnsPage();
  if(page==='certs')return certificatesPage();
  if(page==='bookmarks')return bookmarksPage();
  if(page==='devices')return devicesPage();
  if(page==='security')return securityPage();
  if(page==='terminal')return notice('默认关闭。指纹可自动获取，首次或发生变化时需确认；连接需管理员二次验证；SSH 密码 / 私钥仅用于本次连接，不保存。最多两个会话，每个最多 15 分钟。')+panel('SSH 主机',c.terminalEnabled?'终端已启用':'先在设置中启用 Web 终端',c.sshHosts.length?c.sshHosts.map(r=>row('terminal',r.name,`${r.username}@${r.address}`,`${c.terminalEnabled?btn('连接','connect:'+r.id,'terminal'):pill('未启用')}${ibtn('编辑','edit:sshHosts:'+r.id,'edit')}${ibtn('删除','delete:sshHosts:'+r.id,'trash')}`)).join(''):empty('暂无可信主机','填写 SSH 地址即可添加，连接前自动获取并确认主机指纹。'))+'<section id="terminal-panel" class="panel" hidden><div class="panel-head"><h2 id="terminal-title">终端</h2>'+btn('断开','disconnect','close')+'</div><div class="panel-body"><div id="terminal-screen" class="terminal-screen"></div></div></section>';
  if(page==='settings')return settingsPage();
  return '';
}
function editItem(group,id) {
  const old=id?state.config[group==='forwards'?'rules':group].find(r=>r.id===id):{};if(!old)return;let content='',title='';
  if(group==='rules'||group==='forwards'){editListener(group,id);return;}
  if(group==='ddns'){editDDNS(id);return;}
  if(group==='bookmarks'){editBookmark(id);return;}
  if(group==='devices'){title='唤醒设备';content=`<div class="form-grid">${field('name','名称',old.name)}${field('mac','MAC 地址',old.mac,'支持 AA:BB:CC:DD:EE:FF、AA-BB-CC-DD-EE-FF、AABB.CCDD.EEFF 或连续 12 位；自动整理空格及全角分隔符')}${field('broadcast','局域网广播地址',old.broadcast||'192.168.1.255','按实际网段填写，不是设备 IP','text',true)}${field('ip','设备 IP（可选）',old.ip,'用于在线检测，建议固定 DHCP 地址')}${field('checkPort','TCP 检测端口（可选）',old.checkPort||'','留空用 Ping；若禁止 Ping，可填已开放的端口，例如 22、3389','number')}</div>`;}
  if(group==='sshHosts'){title='SSH 主机';content=`<div class="form-grid">${field('name','名称',old.name)}${field('address','SSH 地址',old.address,'如 192.168.1.1:22')}${field('username','SSH 用户名',old.username||'root')}${field('fingerprint','主机 SHA256 指纹（可选）',old.fingerprint,'无需手填：首次连接自动获取；变化时询问是否信任新指纹','text',true)}</div>`;}
  dialog((id?'编辑':'添加')+title,content,async data=>{const item={...data,id:id||uid()};if(group==='devices')item.checkPort=Number(data.checkPort||0);if(group==='rules' && item.kind!=='web'){item.tls=false;item.certificate='';item.domain='';}await saveItem(group,item);});
}
function stopTerminal(){terminalObserver?.disconnect();terminalObserver=null;socket?.close();socket=null;terminal?.dispose();terminal=null;}
async function connect(id){const host=state.config.sshHosts.find(x=>x.id===id);const probe=await api('ssh/probe','POST',{address:host.address});const changed=probe.fingerprint!==host.fingerprint;dialog('连接 '+host.name,(changed?actionNote(host.fingerprint?'主机指纹已变化。可能是重装系统、密钥轮换，也可能是错误主机或中间人攻击。确认可信后才能继续。':'首次连接：已从 SSH 获取指纹。自动获取不等于已核实身份，请确认这是你的设备。',true)+`<div class="code">${host.fingerprint?'原指纹：'+esc(host.fingerprint)+'<br>':''}新指纹：${esc(probe.fingerprint)}</div>`+toggle('trustFingerprint','信任此指纹并继续连接',false,'确认后保存新指纹；取消不会修改已保存指纹'):'')+actionNote('只连接你信任的设备。优先使用 HTTPS 或 SSH 隧道保护传输；不会保存下面的密码。')+field('adminPassword','管理员密码（二次验证）','','','password')+field('password','SSH 密码','','私钥方式可留空','password')+area('privateKey','SSH 私钥（可选）','','首版支持未加密私钥，敏感内容不会保存'),async data=>{
    if(changed){if(!data.trustFingerprint)throw Error('请先确认信任此主机指纹，或取消连接');await api('ssh/trust','POST',{id:host.id,address:host.address,previous:host.fingerprint||'',fingerprint:probe.fingerprint,adminPassword:data.adminPassword});host.fingerprint=probe.fingerprint;}delete data.trustFingerprint;
    stopTerminal();const panel=$('#terminal-panel');panel.hidden=false;$('#terminal-title').textContent=host.name+' · '+host.address;
    terminal=new Terminal({cursorBlink:true,fontSize:13,scrollback:1500,theme:{background:'#111827',foreground:'#e2e8f0'},cols:90,rows:24});terminal.open($('#terminal-screen'));
    const ws=new WebSocket(`${location.protocol==='https:'?'wss':'ws'}://${location.host}/api/terminal?id=${encodeURIComponent(id)}`);socket=ws;ws.binaryType='arraybuffer';const term=terminal;
    const resize=()=>{if(!terminal)return;const w=$('#terminal-screen').clientWidth-24;const cols=Math.max(20,Math.min(250,Math.floor(w/8)));term.resize(cols,24);if(ws.readyState===1)ws.send(JSON.stringify({cols,rows:24}));};
    ws.onopen=()=>{ws.send(JSON.stringify(data));data.adminPassword=data.password=data.privateKey='';resize();};
    ws.onmessage=e=>{if(typeof e.data==='string'){try{const r=JSON.parse(e.data);if(r.error)term.writeln('\r\n'+r.error);}catch{}}else term.write(new Uint8Array(e.data));};
    ws.onclose=()=>term.writeln('\r\n[连接已关闭]');ws.onerror=()=>toast('终端连接失败，请检查权限、指纹和网络',true);
    term.onData(d=>{if(ws.readyState===1)ws.send(new TextEncoder().encode(d));});terminalObserver=new ResizeObserver(resize);terminalObserver.observe($('#terminal-screen'));resize();
    panel.scrollIntoView({block:'start'});setTimeout(()=>term.focus(),50);
  },'连接');}
async function action(key,button){if(key==='help-expand'){const el=button.closest('.notice');const open=el.classList.toggle('help-expanded');button.setAttribute('aria-expanded',String(open));button.textContent=open?'收起说明':'展开说明';return;}if(key==='copy'){await copyText(button.dataset.copy);toast('已复制地址');return;}if(key.startsWith('rule-check:')){await api('rules/check','POST',{id:key.slice(11)});await refresh(true);return;}if(key.startsWith('settings-tab:')){navigatePage('settings',key.split(':')[1]);return;}if(key==='diagnostics'){state.diagnostics=await api('diagnostics');refreshPageContent();return;}if(await upnpAction(key))return;if(noticeAction(key,button))return;if(key==='nav-open'){openNav();return;}if(key==='nav-close'){closeNav();return;}if(await twoFactorAction(key)||await securityAction(key)||await workflowAction(key))return;const [kind,a,b]=key.split(':');
  if(kind==='page'){closeNav(false);navigatePage(a,a==='bookmarks'?panelTab:'');return;}
  if(kind==='refresh'){if(socket){toast('终端连接中，请先断开再刷新');return;}await refresh(true);return;}
  if(kind==='add'||kind==='edit'){editItem(a,b);return;}
  if(kind==='delete'){removeItem(a,b);return;}
  if(kind==='theme'){const current=document.documentElement.dataset.theme;const dark=current==='dark'||(!current&&matchMedia('(prefers-color-scheme:dark)').matches);document.documentElement.dataset.theme=dark?'light':'dark';try{localStorage.setItem(themeKey,dark?'light':'dark');}catch{}return;}
  if(kind==='logout'){await api('logout','POST',{});loggedIn=false;stopTerminal();renderAuth(true);return;}
  if(kind==='toggle'){const r=state.config.rules.find(x=>x.id===a);dialog(r.enabled?'停用服务':'启用服务',actionNote(r.enabled?'停止该监听会断开相关业务连接。':`将开始监听 ${r.listen}。${r.openFirewall?'已选自动放行：获得权限时将允许外部连接此端口。':'防火墙仍由当前网络策略决定。'}`),()=>saveItem('rules',{...r,enabled:!r.enabled}),'确认');return;}
  if(kind==='run'){dialog('立即更新 DNS',actionNote('将检测公网 IP，并在有变化时实际新增或更新此阿里云记录。'),async()=>{await api('ddns/run','POST',{id:a});await refresh(true);toast('更新任务已提交');},'开始更新');return;}
  if(kind==='wake'){await api('wake','POST',{id:a});toast('唤醒包已发送，稍后复查在线状态');checkAfterWake(a);return;}
  if(kind==='device-check'){await checkDevices(a||'');return;}
  if(kind==='import-cert'){dialog('导入 PEM 证书',field('id','证书标识','','同名证书会被替换')+area('certificate','证书 / 完整证书链 PEM')+area('key','私钥 PEM'),async d=>{await api('certificates/import','POST',d);await refresh(true);toast('证书已导入');},'导入');return;}
  if(kind==='export'){const c=await api('export');const u=URL.createObjectURL(new Blob([JSON.stringify(c,null,2)],{type:'application/json'}));const link=document.createElement('a');link.href=u;link.download='linknest-config.json';link.click();setTimeout(()=>URL.revokeObjectURL(u),1000);return;}
  if(kind==='import-config'){dialog('导入配置',actionNote('将替换当前规则和导航配置。为防止误开放，导入的服务、DDNS 和终端都自动设为停用；请核对后逐项启用。',true)+area('json','配置 JSON'),async d=>{let c;try{c=JSON.parse(d.json);}catch{throw Error('JSON 格式不正确');}if(![1,2,3,4,5].includes(c.schema)||!Array.isArray(c.rules)||!Array.isArray(c.ddns))throw Error('不是有效的栖网配置');c.rules.forEach(x=>x.enabled=false);c.ddns.forEach(x=>x.enabled=false);if(c.access){c.access.autoBan.enabled=false;c.access.sources.forEach(x=>x.enabled=false);}c.terminalEnabled=false;c.adminTls={enabled:false,redirect:false,certificate:''};c.dns=state.config.dns;await saveConfig(c);},'导入并替换');return;}
  if(kind==='password'){dialog('修改用户名和密码',actionNote('保存后所有管理登录会话及浏览器信任失效。已绑定的两步验证会保留，请用新账号重新登录。')+field('username','用户名',state.username||'admin','2—128 字节')+field('currentPassword','当前密码','','用于验证此次修改','password')+(state.twoFactor?.enabled?twoFactorCodeField(false,false):'')+field('newPassword','新密码（可选）','','留空保留原密码；否则需 12—72 字节','password')+field('confirmPassword','再次输入新密码','','仅修改密码时填写','password'),async d=>{if(d.newPassword!==d.confirmPassword)throw Error('两次输入的新密码不一致');await api('account','POST',{username:d.username,currentPassword:d.currentPassword,newPassword:d.newPassword,code:d.code||''});loggedIn=false;stopTerminal();renderAuth(true);toast('账号已修改，请重新登录');},'保存并重新登录');return;}
  if(kind==='connect'){await connect(a);return;}
  if(kind==='disconnect'){stopTerminal();$('#terminal-panel').hidden=true;return;}
}
document.addEventListener('click',e=>{
 const nav=e.target.closest('[data-page]'),b=e.target.closest('[data-action]');
 if(nav){navigatePage(nav.dataset.page);return;}
 if(!b||b.disabled||b.getAttribute('aria-disabled')==='true')return;
 const [kind,value]=b.dataset.action.split(':'),tabs={'forward-tab':'forwards','panel-tab':'bookmarks','settings-tab':'settings'};
 // Navigation is immediate: disabling a tab or inserting a spinner blurs it
 // and changes the geometry that the selection indicator is moving between.
 if(tabs[kind]){navigatePage(tabs[kind],value);return;}
 if(kind==='page'){navigatePage(value);return;}
 busy(b,()=>action(b.dataset.action,b));
});
document.addEventListener('submit',e=>{if(e.target.id==='dns-form'){e.preventDefault();const c=structuredClone(state.config);c.dns=Object.fromEntries(new FormData(e.target));busy($('button',e.target),()=>saveConfig(c,e.target));}if(e.target.id==='security-form'){e.preventDefault();const d=Object.fromEntries(new FormData(e.target));const c=structuredClone(state.config);for(const k of ['blacklist','whitelist'])c[k]=d[k].split(/\r?\n/).map(x=>x.trim()).filter(Boolean);busy($('button',e.target),()=>saveConfig(c,e.target));}});
async function refresh(force=false){
 if(fetching||!loggedIn)return;fetching=true;syncRefreshControls();const epoch=stateEpoch;
 try{const latest=await api('state');if(epoch!==stateEpoch)return;state=latest;lastStateSuccess=Date.now();stateReadError='';
 if(page==='forwards'&&forwardTab()==='upnp'&&$('#upnp-status')){if(force)await refreshUPnP();syncStateBanner();return;}
 if(!modal.open)refreshPageContent();else syncStateBanner();
 }catch(error){if(!error.stale){stateReadError=error.message;syncStateBanner();}if(force)throw error;}finally{fetching=false;syncRefreshControls();}
}

let lastPoll=0;setInterval(()=>{const interval=page==='certs'&&(state?.certificateJobs||[]).some(j=>j.state==='running')?2000:10000;if(Date.now()-lastPoll>=interval&&!document.hidden&&!modal.open&&!document.body.classList.contains('nav-open')&&loggedIn&&!socket&&['overview','rules','forwards','ddns','certs','settings'].includes(page)){lastPoll=Date.now();refresh().catch(()=>{});}},2000);
window.addEventListener('DOMContentLoaded',()=>api('health').then(async h=>{serverVersion=h.version||'';if(h.authenticated){loggedIn=true;state=await api('state');lastStateSuccess=Date.now();stateReadError='';render();}else renderAuth(h.initialized);}).catch(e=>{$('#app').innerHTML=`<div class="loading">${esc(e.message)}，请刷新页面重试。</div>`;}),{once:true});
