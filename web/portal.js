'use strict';
const root=document.documentElement;
const search=document.querySelector('#site-search');
const layouts={cards:'卡片',compact:'紧凑',list:'列表',minimal:'极简'};
const engines={bing:['Bing','https://www.bing.com/search?q='],baidu:['百度','https://www.baidu.com/s?wd='],google:['Google','https://www.google.com/search?q='],duckduckgo:['DuckDuckGo','https://duckduckgo.com/?q=']};
const backgrounds=['aurora','sunset','ocean','forest','dusk','slate','mist'];
// Let the root canvas extend the same custom picture below Safari's chrome.
// The preset base color also covers loading failures and browser edge areas.
const backgroundImage=document.querySelector('.page-background');
if(backgroundImage)root.style.setProperty('--panel-background',`url(${JSON.stringify(backgroundImage.getAttribute('src'))})`);
const preferenceKey='linknest-panel-preferences-v1';
let preferences={};try{preferences=JSON.parse(localStorage.getItem(preferenceKey)||'{}')||{};}catch{}
if(typeof preferences!=='object'||Array.isArray(preferences))preferences={};
function remember(key,value){preferences[key]=value;try{localStorage.setItem(preferenceKey,JSON.stringify(preferences));}catch{}}
function markChoice(selector,key,value){document.querySelectorAll(selector).forEach(b=>b.setAttribute('aria-pressed',String(b.dataset[key]===value)));}
function setLayout(value){if(!layouts[value])value='cards';root.dataset.layout=value;const label=document.querySelector('#layout-label');if(label)label.textContent=layouts[value];markChoice('button[data-layout]','layout',value);}
function setBackground(value){root.dataset.background=backgrounds.includes(value)?value:'aurora';markChoice('button[data-background]','background',root.dataset.background);const color=getComputedStyle(root).getPropertyValue('--canvas-base').trim();if(color)document.querySelector('meta[name="theme-color"]')?.setAttribute('content',color);}
function setCardMotion(value){
 root.dataset.cardMotion=['auto','on','off'].includes(value)?value:'auto';
 markChoice('button[data-card-motion]','cardMotion',root.dataset.cardMotion);
 const status=document.querySelector('#card-motion-status');
 if(status)status.textContent=root.dataset.cardMotion==='on'?'已开启图标旋转，仅影响当前浏览器。':root.dataset.cardMotion==='off'?'图标旋转已关闭，保留卡片高亮。':matchMedia('(prefers-reduced-motion:reduce)').matches?'系统已减少动态效果，图标不旋转；可手动选择开启。':'跟随系统，鼠标悬停时图标轻微旋转。';
}
const webSearch=document.querySelector('#web-search');
function setEngine(value){if(!engines[value])value='bing';if(webSearch)webSearch.dataset.engine=value;const label=document.querySelector('#engine-label');if(label)label.textContent=engines[value][0];markChoice('button[data-engine]','engine',value);}
setLayout(layouts[preferences.layout]?preferences.layout:root.dataset.layout);
setBackground(backgrounds.includes(preferences.background)?preferences.background:root.dataset.background);
setCardMotion(preferences.cardMotion);
matchMedia('(prefers-reduced-motion:reduce)').addEventListener('change',()=>setCardMotion(root.dataset.cardMotion));
setEngine(engines[preferences.engine]?preferences.engine:webSearch?.dataset.engine);
if(['dark','light'].includes(preferences.theme))root.dataset.theme=preferences.theme;
markChoice('button[data-network]','network',root.dataset.network);
function filterSites(){
 const text=(search?.value||'').trim().toLocaleLowerCase();
 const options=[...document.querySelectorAll('[data-group-choice]')],selected=new Set(options.filter(x=>x.checked).map(x=>x.value));let found=false;
 document.querySelectorAll('.site-card').forEach(card=>{card.hidden=!card.dataset.search.toLocaleLowerCase().includes(text)||!selected.has(card.closest('.site-group').dataset.groupIndex);if(!card.hidden)found=true;});
 document.querySelectorAll('.site-group').forEach(group=>group.hidden=![...group.querySelectorAll('.site-card')].some(card=>!card.hidden));
 const empty=document.querySelector('#search-empty');if(empty)empty.hidden=found;
 const label=document.querySelector('#group-label');if(label)label.textContent=selected.size===options.length?'全部':selected.size?'已选 '+selected.size:'无分组';
}
search?.addEventListener('input',filterSites);
document.querySelectorAll('[data-group-choice]').forEach(input=>input.addEventListener('change',filterSites));
document.querySelector('#group-all')?.addEventListener('click',()=>{document.querySelectorAll('[data-group-choice]').forEach(x=>x.checked=true);filterSites();});
document.querySelectorAll('.portal-picker').forEach(details=>details.addEventListener('toggle',()=>{if(details.open)document.querySelectorAll('.portal-picker').forEach(other=>{if(other!==details)other.open=false;});}));
document.addEventListener('click',e=>{
 document.querySelectorAll('.portal-picker[open]').forEach(menu=>{if(!menu.contains(e.target))menu.open=false;});
 const b=e.target.closest('button');if(!b)return;
 if(b.dataset.layout){setLayout(b.dataset.layout);remember('layout',b.dataset.layout);}
 else if(b.dataset.background){setBackground(b.dataset.background);remember('background',b.dataset.background);}
 else if(b.dataset.cardMotion){setCardMotion(b.dataset.cardMotion);remember('cardMotion',b.dataset.cardMotion);}
 else if(b.dataset.engine){setEngine(b.dataset.engine);remember('engine',b.dataset.engine);}
 else if(b.dataset.network){const url=new URL(location.href);url.searchParams.set('network',b.dataset.network);location.assign(url.href);}
 else return;
 const menu=b.closest('details');if(menu)menu.open=false;
});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){const menu=document.querySelector('.portal-picker[open]');if(menu){menu.open=false;menu.querySelector('summary').focus();}}});
document.querySelector('#theme-toggle')?.addEventListener('click',()=>{const theme=root.dataset.theme;const dark=theme==='dark'||(!['dark','light'].includes(theme)&&matchMedia('(prefers-color-scheme:dark)').matches);root.dataset.theme=dark?'light':'dark';remember('theme',root.dataset.theme);});
webSearch?.addEventListener('submit',e=>{e.preventDefault();const query=webSearch.elements.query.value.trim();if(query)window.open(engines[webSearch.dataset.engine][1]+encodeURIComponent(query),'_blank','noopener,noreferrer');});
const clock=document.querySelector('#panel-clock');
// Original rounded vector glyphs: no SVG <text>, webfont or device font.
const clockGlyphs={
 '0':[24,'M12 4C6 4 5 9 5 20S6 36 12 36 19 31 19 20 18 4 12 4Z'],
 '1':[24,'M6 10L12 4V36M6 36H19'],
 '2':[24,'M5 11C5 2 19 2 19 11 19 17 5 24 5 30V36H19'],
 '3':[24,'M5 7C10 1 19 4 19 11 19 17 15 20 10 20M10 20C16 20 19 23 19 29 19 37 10 39 5 33'],
 '4':[24,'M17 36V4L4 26H21'],
 '5':[24,'M19 4H6V19C13 15 19 20 19 28 19 37 10 39 5 33'],
 '6':[24,'M18 6C10 0 5 10 5 23V27C5 39 19 39 19 27 19 17 5 17 5 27'],
 '7':[24,'M4 4H20L9 36'],
 '8':[24,'M12 4C2 4 3 20 12 20S22 4 12 4ZM12 20C1 20 2 36 12 36S23 20 12 20Z'],
 '9':[24,'M6 34C14 40 19 30 19 17V13C19 1 5 1 5 13 5 23 19 23 19 13'],
 ':':[12,'M6 13V14M6 27V28'],
 '-':[16,'M4 20H12'],
 ' ':[12,''],
 '周':[36,'M3 36C6 31 6 25 6 17V5H31V33Q31 36 27 36H24M10 13H27M18 8V21M10 21H27M12 26H25V32H12Z'],
 '日':[32,'M7 5H26V35H7ZM7 20H26'],
 '一':[32,'M3 21H29'],
 '二':[32,'M7 11H25M3 30H29'],
 '三':[32,'M5 8H27M8 20H24M3 33H29'],
 '四':[36,'M4 6H32V34H4ZM13 6V17Q13 24 8 26M22 6V22Q22 25 26 25H28'],
 '五':[32,'M5 6H27M15 6L11 33M5 18H24V33M3 33H29'],
 '六':[32,'M15 5L18 10M4 15H28M11 22L4 34M22 22L28 34']
};
function panelClockParts(date){
 const pad=n=>String(n).padStart(2,'0');
 return {time:`${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`,date:`${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())} 周${'日一二三四五六'[date.getDay()]}`};
}
const digitalClockGlyphs={...clockGlyphs};
const digitSegments=['abcdef','bc','abdeg','abcdg','bcfg','acdfg','acdefg','abc','abcdefg','abcdfg'];
const segmentPaths={a:'M6 4H18',b:'M20 6V18',c:'M20 22V34',d:'M6 36H18',e:'M4 22V34',f:'M4 6V18',g:'M6 20H18'};
for(let n=0;n<10;n++)digitalClockGlyphs[String(n)]=[24,[...digitSegments[n]].map(s=>segmentPaths[s]).join('')];
function createClockDrawing(className,glyphs=clockGlyphs){
 const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');
 svg.setAttribute('class',className);svg.setAttribute('aria-hidden','true');svg.setAttribute('focusable','false');
 svg.setAttribute('fill','none');svg.setAttribute('stroke','currentColor');svg.setAttribute('stroke-width','3.2');svg.setAttribute('stroke-linecap','round');svg.setAttribute('stroke-linejoin','round');
 let last='';
 return {svg,draw(text){
  if(text===last)return;last=text;let x=0;const paths=[];
  for(const ch of text){const [width,d]=glyphs[ch];if(d){const path=document.createElementNS(ns,'path');path.setAttribute('d',d);path.setAttribute('transform',`translate(${x} 0)`);paths.push(path);}x+=width;}
  svg.setAttribute('viewBox',`0 0 ${x} 40`);svg.setAttribute('width',String(x));svg.setAttribute('height','40');svg.replaceChildren(...paths);
 }};
}
function createClockText(className){const el=document.createElement('span');el.className=className;el.setAttribute('aria-hidden','true');return {svg:el,draw(text){if(el.textContent!==text)el.textContent=text;}};}
function panelClockStyle(value){return ['vector','simple','digital','stacked'].includes(value)?value:'vector';}
if(clock){
 const style=panelClockStyle(clock.dataset.clockStyle);clock.dataset.clockStyle=style;
 const textStyle=style==='simple'||style==='stacked';
 const timeDrawing=textStyle?createClockText('clock-time-text'):createClockDrawing('clock-time',style==='digital'?digitalClockGlyphs:clockGlyphs),dateDrawing=textStyle?createClockText('clock-date-text'):createClockDrawing('clock-date');clock.replaceChildren(timeDrawing.svg,dateDrawing.svg);
 const update=()=>{const now=new Date(),parts=panelClockParts(now);timeDrawing.draw(parts.time);dateDrawing.draw(parts.date);clock.dateTime=now.toISOString();clock.setAttribute('aria-label',`${parts.date} ${parts.time}`);};
 update();setInterval(()=>{if(!document.hidden)update();},1000);document.addEventListener('visibilitychange',()=>{if(!document.hidden)update();});
}
document.querySelectorAll('.panel-logo,.site-main img').forEach(img=>{const fallback=()=>{if(!img.src.endsWith('/__linknest/panel-logo.svg'))img.src='/__linknest/panel-logo.svg';};img.addEventListener('error',fallback);if(img.complete&&!img.naturalWidth)fallback();});
document.querySelectorAll('form.portal-auth').forEach(form=>form.addEventListener('submit',async e=>{
 e.preventDefault();const button=form.querySelector('button'),status=form.querySelector('[role=status]');button.disabled=true;status.textContent='正在验证…';
 try{const res=await fetch(form.action,{method:'POST',body:new URLSearchParams(new FormData(form)),credentials:'same-origin'});
  if(res.redirected&&res.ok){location.replace('/');return;}
  if(!res.ok){const text=await res.text();throw Error(text.slice(0,180)||'请求失败，请刷新后重试');}
  throw Error('访问密码不正确');
 }catch(err){status.textContent=err.message;}finally{button.disabled=false;}
}));
const wolDashboard=document.querySelector('#wol-dashboard');
let wolChecking=false,wolLastCheck=0;
async function refreshWOL(){
 if(!wolDashboard||wolChecking||document.hidden)return;
 wolChecking=true;wolLastCheck=Date.now();const button=document.querySelector('#wol-refresh'),status=document.querySelector('#wol-status');button.disabled=true;button.textContent='检测中…';
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),25000);
 try{
  const res=await fetch('/__linknest/devices/check',{method:'POST',body:new URLSearchParams({csrf:wolDashboard.dataset.csrf}),credentials:'same-origin',signal:controller.signal});
  if(res.status===403)throw Error('会话已失效，请刷新页面重新登录');if(res.status===429)throw Error('正在检测，请稍后刷新');
  const data=await res.json();if(!res.ok)throw Error(data.error||'状态读取失败');
  for(const row of wolDashboard.querySelectorAll('[data-device-id]')){
   const s=data.devices.find(x=>x.id===row.dataset.deviceId);if(!s)continue;
   const badge=row.querySelector('[data-online-state]');badge.dataset.onlineState=s.state;badge.textContent=s.state==='online'?'在线':s.state==='unconfigured'?'未配置检测':'未确认在线';
   row.querySelector('.wol-check-message').textContent=s.message;row.querySelector('.wol-checked').textContent='更新于 '+new Date(s.checked).toLocaleTimeString();
  }
  status.textContent='';
 }catch(error){status.textContent=error.name==='AbortError'?'检测超时，请稍后刷新':error instanceof SyntaxError?'状态接口不可用，请刷新页面重试':error.message;}
 finally{clearTimeout(timer);wolChecking=false;button.disabled=false;button.textContent='刷新状态';}
}
if(wolDashboard){document.querySelector('#wol-refresh').addEventListener('click',refreshWOL);refreshWOL();setInterval(()=>{if(Date.now()-wolLastCheck>=30000)refreshWOL();},2000);document.addEventListener('visibilitychange',()=>{if(!document.hidden&&Date.now()-wolLastCheck>=30000)refreshWOL();});}
document.querySelectorAll('form.wake').forEach(form=>form.addEventListener('submit',async e=>{
 e.preventDefault();const button=form.querySelector('button'),status=form.querySelector('[role=status]');button.disabled=true;button.textContent='正在发送…';
 try{const res=await fetch(form.action,{method:'POST',body:new URLSearchParams(new FormData(form)),credentials:'same-origin'});let data;try{data=await res.json();}catch{throw Error('会话失效或服务不可用，请刷新后重试');}if(!res.ok)throw Error(data.error||'发送失败');status.textContent=data.message;for(const delay of [5000,20000])setTimeout(refreshWOL,delay);}catch(err){status.textContent=err.message;}finally{button.disabled=false;button.textContent='唤醒设备';}
}));
