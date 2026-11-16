'use strict';
// Wait for the old dialog's close event before opening the next step. Otherwise
// its cleanup can erase the newly opened form, leaving an empty modal.
function nextTwoFactorDialog(open){modal.addEventListener('close',()=>requestAnimationFrame(open),{once:true});}
function browserTrustActive(){return Date.parse(state.twoFactor?.trustedUntil||'')>Date.now();}
function trustBrowserChoice(){return '<label class="trust-browser-choice"><input name="trustDevice" type="checkbox"><span>信任此浏览器 24 小时<small>期间免动态码；退出或修改账号、两步验证设置后失效。</small></span></label>';}
function twoFactorCodeField(binding=false,allowTrust=true){
 const trusted=!binding&&browserTrustActive();
 return `<div class="twofactor-proof" data-allow-trust="${allowTrust}" data-binding="${binding}"><p class="split-note trust-status"${trusted?'':' hidden'}>此浏览器在信任期内，无需动态码；仍需确认管理员密码。</p><div class="twofactor-code-entry"${trusted?' hidden':''}><label class="field"><span>${binding?'动态验证码':'动态验证码或一次性恢复码'}</span><input name="code" type="text" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" ${binding?'inputmode="numeric" pattern="[0-9]{6}" maxlength="6"':'maxlength="64"'} ${trusted?'disabled':'required'} placeholder="Authenticator 的 6 位验证码"><small>验证码只能使用一次；若刚使用过，请等待下一轮。</small></label>${allowTrust?trustBrowserChoice():''}</div></div>`;
}
function requireTwoFactorInForm(form){
 if(state.twoFactor)delete state.twoFactor.trustedUntil;
 const proof=form.querySelector('.twofactor-proof');
 if(!proof)return;
 proof.querySelector('.trust-status').hidden=true;
 proof.querySelector('.twofactor-code-entry').hidden=false;
 const input=proof.querySelector('[name=code]');input.disabled=false;input.required=true;input.focus();
}
function twoFactorPanel(){const enabled=state.twoFactor?.enabled,trusted=browserTrustActive();return panel('两步验证（2FA）','Microsoft Authenticator / 其他 TOTP 验证器',`<div class="panel-body"><div class="switch-row"><span>登录动态验证码</span>${pill(enabled?'已开启':'未开启',enabled?'good':'')}</div><p class="split-note">${enabled?`剩余一次性恢复码：${Number(state.twoFactor.recoveryCodesRemaining)||0} 个。更换手机前请保存恢复码。`:'先验证管理员密码，再扫码并输入验证码确认；未完成确认不会启用。'}</p>${trusted?`<p class="split-note">此浏览器信任至 ${esc(new Date(state.twoFactor.trustedUntil).toLocaleString())}，到期不会自动续期。</p>`:''}<div class="twofactor-actions">${enabled?btn('重新生成恢复码','2fa-recovery','refresh')+btn('关闭两步验证','2fa-disable','shield'):btn('扫码绑定','2fa-begin','shield','primary')}${trusted?btn('取消此浏览器信任','2fa-trust-revoke','shield'):''}</div></div>`);}
function showRecoveryCodes(codes){dialog('保存一次性恢复码',actionNote('仅本次显示。每个恢复码只能使用一次，必须与管理员密码一起登录。请存入密码管理器或离线保管，不要上传仓库或公开截图。',true)+`<label class="field"><span>恢复码</span><textarea id="twofactor-recovery-codes" class="twofactor-codes" readonly spellcheck="false">${esc(codes.join('\n'))}</textarea></label>`+btn('下载恢复码','2fa-download','download')+toggle('saved','我已妥善保存恢复码',false),async d=>{if(!d.saved)throw Error('请先保存恢复码，再确认关闭');},'已保存');}
async function twoFactorAction(key){
 if(!key.startsWith('2fa-'))return false;
 if(key==='2fa-trust-revoke'){await api('2fa/trust/revoke','POST',{});state=await api('state');render();toast('已取消此浏览器信任');return true;}
 if(key==='2fa-download'){const value=$('#twofactor-recovery-codes')?.value;if(value){const u=URL.createObjectURL(new Blob(['LinkNest 一次性恢复码\n账号：'+state.username+'\n\n'+value+'\n'],{type:'text/plain;charset=utf-8'}));const a=document.createElement('a');a.href=u;a.download='linknest-recovery-codes.txt';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);}return true;}
 if(key==='2fa-begin'){
  dialog('绑定 Authenticator',functionNote('建议通过 HTTPS 或 SSH 隧道绑定；二维码和密钥仅在本地生成。')+field('password','当前管理员密码','','验证后生成绑定二维码','password'),async d=>{
   const result=await api('2fa/begin','POST',{password:d.password});
   nextTwoFactorDialog(()=>dialog('扫码绑定两步验证',`<div class="twofactor-qr"><img src="${esc(result.qrDataURL)}" alt="Authenticator 绑定二维码" width="256" height="256"></div>`+functionNote('在 Microsoft Authenticator 中添加“其他账户”，扫描二维码，再填写动态验证码。绑定 10 分钟内有效。')+`<details class="twofactor-secret"><summary>无法扫码？手动输入密钥</summary><p class="code">${esc(result.secret)}</p><p class="split-note">类型：基于时间；6 位；30 秒；SHA-1。</p></details>`+field('password','当前管理员密码','','启用前再次验证','password')+twoFactorCodeField(true),async data=>{
    const enabled=await api('2fa/enable','POST',data);state=await api('state');render();nextTwoFactorDialog(()=>showRecoveryCodes(enabled.recoveryCodes));
   },'验证并启用'));
  },'生成二维码');return true;
 }
 if(key==='2fa-disable'||key==='2fa-recovery'){
  const disable=key==='2fa-disable';dialog(disable?'关闭两步验证':'重新生成恢复码',actionNote((disable?'关闭后登录只需账号密码。其他管理会话将退出。':'旧恢复码将全部作废；新恢复码仅显示一次，其他管理会话将退出。')+'所有浏览器信任也将撤销。',true)+field('password','当前管理员密码','','','password')+twoFactorCodeField(false,false),async d=>{const result=await api(disable?'2fa/disable':'2fa/recovery','POST',d);state=await api('state');render();if(disable)toast('两步验证已关闭');else nextTwoFactorDialog(()=>showRecoveryCodes(result.recoveryCodes));},disable?'验证并关闭':'生成新恢复码');return true;
 }
 return true;
}
