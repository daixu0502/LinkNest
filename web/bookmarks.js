'use strict';
const defaultPanelCIDRs=['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','::1/128','fc00::/7'];
const panelBackgrounds=[['aurora','极光 · 紫蓝渐变'],['sunset','日落'],['ocean','海洋'],['forest','森林'],['dusk','暮色'],['slate','石墨'],['mist','晨雾'],['spectrum','光谱 · 全色环']];
function panelTabFromHash(hash=location.hash){const part=hash.split('/')[2];return ['sites','network','appearance','global','icons','json'].includes(part)?part:'sites';}
let panelTab=panelTabFromHash();
function panelOptions(){return state.config.panel||{};}
function bookmarkGroups(){return [...new Set([...(panelOptions().groups||[]),...state.config.bookmarks.map(b=>b.group).filter(Boolean),''])];}
function bookmarkRow(b,index){
 return `<article class="bookmark-row"><span class="bookmark-icon">${b.icon?`<img src="${esc(b.icon)}" alt="" loading="lazy" referrerpolicy="no-referrer">`:icon('link')}</span><div class="bookmark-info"><strong>${esc(b.name)}</strong><p>${esc(b.description||b.url)}</p><small>${b.internalUrls?.length?'已配置内网入口 · ':''}${b.sameTab?'当前标签页':'新标签页'} · ${b.disabled?'已停用':'已启用'}</small></div><div class="actions">${btn('↑','bookmark-up:'+b.id)}${btn('↓','bookmark-down:'+b.id)}${ibtn(b.disabled?'启用站点':'停用站点','bookmark-toggle:'+b.id,'power')}${ibtn('编辑站点','edit:bookmarks:'+b.id,'edit')}${ibtn('删除站点','delete:bookmarks:'+b.id,'trash')}</div></article>`;
}
function bookmarksPage(){
 const p=panelOptions(),c=state.config;
 const tabs=[['sites','站点管理'],['network','内网识别'],['appearance','外观与布局'],['global','全局设置'],['icons','图标库'],['json','JSON 预览']];
 const nav=`<div class="panel-tabs" role="tablist">${tabs.map(([key,name])=>`<button role="tab" aria-selected="${panelTab===key}" data-action="panel-tab:${key}">${name}</button>`).join('')}</div>`;
 if(panelTab==='icons')return nav+iconSourcesPage();
 if(panelTab==='json')return nav+panel('配置预览','只显示轻面板，不包含密码、证书和 DNS 密钥',`<div class="panel-body"><pre class="code">${esc(JSON.stringify({panel:p,bookmarks:c.bookmarks},null,2))}</pre></div>`);
 if(panelTab!=='sites'){
  let body='';
  if(panelTab==='network')body=functionNote('只决定导航使用内网还是外网链接，不是访问权限控制。自动识别仅使用实际连接来源 IP，不信任 X-Forwarded-For；经前置代理访问时识别的是代理地址。')+picker('networkMode','链接选择模式',p.networkMode||'external',[['external','默认外网'],['internal','默认内网（未配置则回退外网）'],['auto','按来源 IP 自动识别'],['mixed','混合展示内外网入口']])+area('internalCidrs','自定义内网网段',(p.internalCidrs?.length?p.internalCidrs:defaultPanelCIDRs).join('\n'),'已预填常用网段，可自行修改；清空后仍使用这些默认网段。前台可临时切换内外网，不修改此默认设置。');
  if(panelTab==='appearance')body=functionNote('使用内置前端，不加载第三方网页脚本。图片地址由访问者浏览器请求，请使用可信的 HTTPS 地址。')+`<div class="form-grid">${picker('theme','默认主题',p.theme||'auto',[['auto','跟随系统'],['light','浅色'],['dark','深色']])}${picker('layout','站点布局',p.layout||'cards',[['cards','卡片'],['compact','紧凑'],['list','列表'],['minimal','极简']])}${picker('backgroundPreset','默认背景',p.backgroundPreset||'aurora',panelBackgrounds)}${field('background','背景图片 URL',p.background,'可选；填写后覆盖默认背景。切换深浅主题仅改变卡片、菜单等表面，不改变背景。','url',true)}</div>`+toggle('showDescription','显示站点描述',!p.hideDescription)+toggle('showHeader','显示页头',!p.hideHeader)+toggle('showSearch','显示站点搜索',!p.hideSearch)+toggle('showClock','显示时间与日期',p.showClock)+picker('clockStyle','时间日期样式',p.clockStyle||'vector',[['simple','普通简约'],['vector','圆润矢量（原样式）'],['digital','数码时钟'],['stacked','上下两行']])+toggle('showWebSearch','显示网页搜索',!p.hideWebSearch)+picker('searchEngine','默认搜索引擎',p.searchEngine||'bing',[['bing','Bing'],['baidu','百度'],['google','Google'],['duckduckgo','DuckDuckGo']])+functionNote('这里只设置首次访问的默认引擎，前台可自由切换，并记住访客自己的选择。');
  if(panelTab==='global')body=`<div class="form-grid">${field('title','导航标题',p.title,'留空使用反代子规则名称')}${field('subtitle','导航副标题',p.subtitle,'常用服务，一步直达')}${field('logo','Logo 地址',p.logo,'可选，留空使用内置栖网 Logo','url',true)}${field('favicon','浏览器图标',p.favicon,'可选，留空使用内置栖网 Logo','url',true)}</div>`;
  return nav+panel(tabs.find(x=>x[0]===panelTab)[1],'保存后内置轻面板立即读取新配置',`<form id="panel-options-form" data-tab="${panelTab}" class="panel-body">${body}<div class="modal-actions"><button type="submit" class="button primary">保存配置</button></div></form>`);
 }
 const sources=c.rules.filter(r=>r.kind==='web').flatMap(r=>(r.routes||[]).filter(s=>s.backend!=='bookmarks').map(s=>({r,s})));
 const left=panel('可用反代规则','引用已有地址，不修改原有反代规则',`<div class="panel-body"><label class="field"><span>搜索规则</span><input id="source-search" placeholder="搜索规则名称或域名"></label></div><div class="source-list">${sources.map(({r,s})=>`<article class="source-item" data-search="${esc(s.name+' '+(s.domains||[]).join(' '))}"><div><strong>${esc(s.name)}</strong><small>${esc(r.name)} · ${esc(r.listen)}</small></div>${btn('添加','bookmark-import:'+r.id+':'+s.id,'plus')}</article>`).join('')||empty('暂无可引用规则','也可在右侧手动添加任意 Web 地址。')}</div>`);
 const groups=bookmarkGroups();
 const right=`<div class="bookmark-editor"><div class="child-toolbar"><strong>导航配置 · ${c.bookmarks.length} 个站点</strong><div class="actions">${btn('添加分组','bookmark-group-add','plus')}${btn('添加站点','add:bookmarks','plus')}</div></div>${groups.map((group,index)=>{const sites=c.bookmarks.filter(b=>(b.group||'')===group);return panel(group||'未分组',sites.length+' 个站点',sites.map(bookmarkRow).join('')||empty('此分组暂无站点','添加站点时选择此分组。'),group?`<div class="actions">${btn('↑','bookmark-group-up:'+index)}${btn('↓','bookmark-group-down:'+index)}${ibtn('重命名分组','bookmark-group-edit:'+index,'edit')}${ibtn('删除分组','bookmark-group-delete:'+index,'trash')}</div>`:'');}).join('')}</div>`;
 return nav+`<div class="bookmark-workbench"><aside>${left}</aside>${right}</div>`;
}
function editBookmark(id,seed={}){
 const old=id?state.config.bookmarks.find(b=>b.id===id):seed;
 dialog((id?'编辑':'添加')+'站点',`<div class="form-grid">${field('name','站点名称',old.name)}${picker('group','分组',old.group||'',bookmarkGroups().map(g=>[g,g||'未分组']))}${field('description','描述',old.description,'可选','text',true)}${area('urls','外网链接',(old.urls?.length?old.urls:[old.url||'']).join('\n'),'每行一个 HTTP/HTTPS 地址，首个为主入口')}${area('internalUrls','内网链接',(old.internalUrls||[]).join('\n'),'可选，每行一个地址；内网模式优先使用')}${iconFieldMarkup(old.icon||'',old.iconSourceUrl||'')}${iconPickerMarkup()}${picker('openMode','打开方式',old.sameTab?'same':'new',[['new','新标签页'],['same','当前标签页']])}</div>`+toggle('enabled','启用站点',!old.disabled),async d=>{
  const urls=String(d.urls).split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
  await saveItem('bookmarks',{...old,id:id||uid(),name:d.name.trim(),description:d.description.trim(),group:d.group,url:urls[0]||'',urls,internalUrls:String(d.internalUrls).split(/\r?\n/).map(s=>s.trim()).filter(Boolean),icon:d.icon.trim(),iconSourceUrl:isLocalIcon(d.icon.trim())?(d.iconSourceUrl||'').trim():'',sameTab:d.openMode==='same',disabled:!d.enabled});
 },'保存',updateIconPreview);
}
async function bookmarkAction(key){
 if(await iconSourceAction(key))return true;
 const [action,id,subID]=key.split(':');
 if(action==='panel-tab'){navigatePage('bookmarks',id);return true;}
 if(action==='bookmark-import'){
  const r=state.config.rules.find(x=>x.id===id),s=r.routes.find(x=>x.id===subID),port=r.listen.slice(r.listen.lastIndexOf(':')+1);
  const urls=(s.domains||[]).filter(h=>!h.includes('*')).map(h=>(r.tls?'https':'http')+'://'+h+':'+port+(s.pathPrefix||'/'));
  editBookmark('',{name:s.name,urls,internalUrls:s.backend==='proxy'||!s.backend?[s.target]:[]});return true;
 }
 if(action==='bookmark-toggle'){const b=state.config.bookmarks.find(x=>x.id===id);await saveItem('bookmarks',{...b,disabled:!b.disabled});return true;}
 if(action==='bookmark-up'||action==='bookmark-down'){
  const c=structuredClone(state.config),n=c.bookmarks.findIndex(x=>x.id===id),group=c.bookmarks[n].group||'';
  const indices=c.bookmarks.map((x,i)=>(x.group||'')===group?i:-1).filter(i=>i>=0),pos=indices.indexOf(n),other=indices[pos+(action==='bookmark-up'?-1:1)];
  if(other===undefined){toast('已在分组边界');return true;}[c.bookmarks[n],c.bookmarks[other]]=[c.bookmarks[other],c.bookmarks[n]];await saveConfig(c);return true;
 }
 if(action.startsWith('bookmark-group-')){
  const group=bookmarkGroups()[Number(id)]||'';
  if(action==='bookmark-group-add'||action==='bookmark-group-edit'){
   dialog(action.endsWith('add')?'添加分组':'重命名分组',field('name','分组名称',group),async d=>{const name=d.name.trim(),c=structuredClone(state.config),groups=bookmarkGroups().filter(Boolean);if(!name||groups.some(g=>g!==group&&g===name))throw Error('分组名称不能为空或重复');if(action.endsWith('edit')){c.bookmarks.forEach(b=>{if(b.group===group)b.group=name;});groups[groups.indexOf(group)]=name;}else groups.push(name);c.panel={...c.panel,groups};await saveConfig(c);});return true;
  }
  if(action==='bookmark-group-delete'){dialog('删除分组',actionNote('站点会移到“未分组”，不会删除站点。'),async()=>{const c=structuredClone(state.config);c.bookmarks.forEach(b=>{if(b.group===group)b.group='';});c.panel={...c.panel,groups:bookmarkGroups().filter(g=>g&&g!==group)};await saveConfig(c);});return true;}
  const groups=bookmarkGroups().filter(Boolean),n=groups.indexOf(group),other=n+(action.endsWith('up')?-1:1);
  if(other<0||other>=groups.length){toast('已在分组边界');return true;}
  [groups[n],groups[other]]=[groups[other],groups[n]];await saveConfig({...structuredClone(state.config),panel:{...panelOptions(),groups}});return true;
 }
 return false;
}
document.addEventListener('input',e=>{if(e.target.id==='source-search'){const query=e.target.value.trim().toLowerCase();$$('.source-item').forEach(el=>el.hidden=!el.dataset.search.toLowerCase().includes(query));}});
document.addEventListener('submit',e=>{
 if(e.target.id!=='panel-options-form')return;e.preventDefault();const form=e.target,d=Object.fromEntries(new FormData(form)),c=structuredClone(state.config);c.panel={...c.panel};
 if(form.dataset.tab==='network')Object.assign(c.panel,{networkMode:d.networkMode,internalCidrs:d.internalCidrs.split(/\r?\n/).map(s=>s.trim()).filter(Boolean)});
 if(form.dataset.tab==='global')for(const k of ['title','subtitle','logo','favicon'])c.panel[k]=d[k].trim();
 if(form.dataset.tab==='appearance')Object.assign(c.panel,{theme:d.theme,layout:d.layout,backgroundPreset:d.backgroundPreset,background:d.background.trim(),hideDescription:!form.elements.showDescription.checked,hideHeader:!form.elements.showHeader.checked,hideSearch:!form.elements.showSearch.checked,showClock:form.elements.showClock.checked,clockStyle:d.clockStyle,hideWebSearch:!form.elements.showWebSearch.checked,searchEngine:d.searchEngine});
 busy($('button[type=submit]',form),()=>saveConfig(c,form));
});
