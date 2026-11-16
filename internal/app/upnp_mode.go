package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Two-phase switch: keep original files/leases until the Go caller has checked
// the new daemon's complete mapping list. EOF, timeout or ROLLBACK restores the
// old settings and restarts the original service. No persistent helper exists.
func buildUPnPModeScript(allow bool) string {
	secure, launch := "1", "service_start /usr/sbin/miniupnpd -S -f $tmpconf"
	expectConfig := "yes"
	if allow {
		secure, launch = "0", "service_start /usr/sbin/miniupnpd -f $tmpconf"
	}
	if allow {
		expectConfig = "no"
	}
	return `set -eu
umask 077
for cmd in uci flock mktemp md5sum sed; do command -v "$cmd" >/dev/null || exit 1; done
[ -f /etc/init.d/miniupnpd ] && [ -f /etc/config/upnpd ] || { echo '仅支持已核对的 OpenWrt miniupnpd 启动方式' >&2; exit 1; }
exec 9>/var/lock/linknest-upnp-policy.lock
flock -n 9 || { echo '其他 UPnP 配置操作正在进行' >&2; exit 1; }
[ -z "$(uci -q changes upnpd)" ] || { echo '原厂 UPnP 有未提交修改，未覆盖' >&2; exit 1; }
count=$(grep -Ec '^[[:space:]]*service_start /usr/sbin/miniupnpd (-S )?-f \$tmpconf[[:space:]]*$' /etc/init.d/miniupnpd || true)
[ "$count" = 1 ] || { echo '原厂启动脚本与已适配格式不一致，未修改' >&2; exit 1; }
grep -F 'tmpconf="/var/etc/miniupnpd.conf"' /etc/init.d/miniupnpd >/dev/null || { echo '原厂运行配置路径未适配，未修改' >&2; exit 1; }
lease=$(uci -q get upnpd.config.upnp_lease_file)
case "$lease" in /tmp/upnp.leases|/var/run/miniupnpd.leases) ;; *) echo '不支持此原厂租约路径，未修改' >&2; exit 1 ;; esac
[ -f "$lease" ] || { echo '原厂租约文件缺失，不能保证映射恢复' >&2; exit 1; }
work=$(mktemp -d /tmp/linknest-upnp-mode.XXXXXX)
case "$work" in /tmp/linknest-upnp-mode.*) ;; *) exit 1 ;; esac
mkdir "$work/delta"
cp -p /etc/init.d/miniupnpd "$work/init-old"
cp /etc/config/upnpd "$work/config-old"
cp /etc/config/upnpd "$work/upnpd"
cp "$lease" "$work/leases"
oldinit=$(md5sum /etc/init.d/miniupnpd | cut -d ' ' -f 1)
oldconfig=$(md5sum /etc/config/upnpd | cut -d ' ' -f 1)
changed=0
committed=0
cleanup() {
 if [ "$changed" = 1 ] && [ "$committed" != 1 ]; then
  currentinit=$(md5sum /etc/init.d/miniupnpd | cut -d ' ' -f 1)
  currentconfig=$(md5sum /etc/config/upnpd | cut -d ' ' -f 1)
  if { [ "$currentinit" = "$newinit" ] || [ "$currentinit" = "$oldinit" ]; } && { [ "$currentconfig" = "$newconfig" ] || [ "$currentconfig" = "$oldconfig" ]; }; then
   /etc/init.d/miniupnpd stop 9>&- >/dev/null 2>&1 || true
   cp -p "$work/init-old" /etc/init.d/.linknest-upnp-restore-$$
   mv /etc/init.d/.linknest-upnp-restore-$$ /etc/init.d/miniupnpd
   cp "$work/config-old" /etc/config/.linknest-upnp-restore-$$
   mv /etc/config/.linknest-upnp-restore-$$ /etc/config/upnpd
   cp "$work/leases" "$lease"
   /etc/init.d/miniupnpd start 9>&- >/dev/null 2>&1 || echo '原厂 UPnP 回滚启动失败，请手动检查' >&2
  else
   echo '发现并发修改，未覆盖原厂文件；请手动核对安全模式' >&2
  fi
 fi
 rm -f /etc/init.d/.linknest-upnp-new-$$ /etc/config/.linknest-upnp-new-$$
 case "$work" in /tmp/linknest-upnp-mode.*) rm -rf -- "$work" ;; esac
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
sed -E 's@^[[:space:]]*service_start /usr/sbin/miniupnpd (-S )?-f \$tmpconf[[:space:]]*$@` + launch + `@' "$work/init-old" >"$work/init-new"
chmod 755 "$work/init-new"
sh -n "$work/init-new"
uci -c "$work" -P "$work/delta" set upnpd.config.secure_mode=` + secure + `
` + upnpMaterializeUCI("upnpd") + `
[ "$(md5sum /etc/init.d/miniupnpd | cut -d ' ' -f 1)" = "$oldinit" ] && [ "$(md5sum /etc/config/upnpd | cut -d ' ' -f 1)" = "$oldconfig" ] && [ -z "$(uci -q changes upnpd)" ] || { echo '原厂文件已并发修改，中止切换' >&2; exit 1; }
newinit=$(md5sum "$work/init-new" | cut -d ' ' -f 1)
newconfig=$(md5sum "$work/upnpd" | cut -d ' ' -f 1)
cp -p "$work/init-new" /etc/init.d/.linknest-upnp-new-$$
cp "$work/upnpd" /etc/config/.linknest-upnp-new-$$
changed=1
mv /etc/init.d/.linknest-upnp-new-$$ /etc/init.d/miniupnpd
mv /etc/config/.linknest-upnp-new-$$ /etc/config/upnpd
/etc/init.d/miniupnpd stop 9>&- >/dev/null 2>&1
# The final lease file can include client updates made after our first snapshot.
if [ -s "$lease" ]; then cp "$lease" "$work/leases"; fi
cp "$work/leases" "$lease"
/etc/init.d/miniupnpd start 9>&- >/dev/null 2>&1
pid=$(cat /var/run/miniupnpd.pid)
case "$pid" in ''|*[!0-9]*) echo '原厂进程标识无效' >&2; exit 1 ;; esac
[ -r "/proc/$pid/cmdline" ] || { echo '原厂 UPnP 未启动' >&2; exit 1; }
args=" $(tr '\000' ' ' <"/proc/$pid/cmdline") "
case "$args" in *'/usr/sbin/miniupnpd '*) ;; *) echo '原厂 UPnP 进程不匹配' >&2; exit 1 ;; esac
grep -x 'secure_mode=` + expectConfig + `' /var/etc/miniupnpd.conf >/dev/null || { echo '运行时安全模式未更新' >&2; exit 1; }
` + func() string {
		if allow {
			return `case "$args" in *' -S '*) echo '进程仍启用了安全模式' >&2; exit 1 ;; esac
`
		}
		return `case "$args" in *' -S '*) ;; *) echo '进程未恢复安全模式' >&2; exit 1 ;; esac
`
	}() + `
echo LINKNEST_UPNP_MODE_READY
IFS= read -r decision
[ "$decision" = COMMIT ] || { echo '调用端未确认映射完整，已请求回滚' >&2; exit 1; }
committed=1
echo LINKNEST_UPNP_MODE_OK
`
}

func runUPnPMode(ctx context.Context, host SSHHost, password, privateKey string, allow bool, verify func(context.Context) error) error {
	return runUPnPTransaction(ctx, host, password, privateKey, buildUPnPModeScript(allow), "MODE", verify)
}

func runUPnPTransaction(ctx context.Context, host SSHHost, password, privateKey, script, operation string, verify func(context.Context) error) error {
	var auth ssh.AuthMethod
	if privateKey != "" {
		key, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return errors.New("SSH 私钥格式无效")
		}
		auth = ssh.PublicKeys(key)
	} else if password != "" {
		auth = ssh.Password(password)
	} else {
		return errors.New("请提供本次 SSH 凭据，不会保存")
	}
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", host.Address)
	if err != nil {
		return errors.New("无法连接路由器 SSH")
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	deadline := time.Now().Add(40 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	raw.SetDeadline(deadline)
	cfg := &ssh.ClientConfig{User: host.Username, Auth: []ssh.AuthMethod{auth}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != host.Fingerprint {
			return errors.New("SSH 指纹变化，未修改原厂服务")
		}
		return nil
	}}
	conn, chans, reqs, err := ssh.NewClientConn(raw, host.Address, cfg)
	if err != nil {
		return fmt.Errorf("SSH 身份或指纹验证失败：%w", err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	var stderr upnpOutput
	session.Stderr = &stderr
	input, err := session.StdinPipe()
	if err != nil {
		return err
	}
	output, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	if err = session.Start("sh -c " + upnpShellQuote(script)); err != nil {
		return err
	}
	reader := bufio.NewReader(io.LimitReader(output, 65536))
	line, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "LINKNEST_UPNP_"+operation+"_READY" {
		input.Close()
		session.Wait()
		return fmt.Errorf("原厂 UPnP 切换未就绪：%s", strings.TrimSpace(stderr.String()))
	}
	if err = verify(ctx); err != nil {
		fmt.Fprintln(input, "ROLLBACK")
		input.Close()
		session.Wait()
		return fmt.Errorf("切换后映射核对失败，已请求恢复原厂设置，请刷新核对：%w；%s", err, strings.TrimSpace(stderr.String()))
	}
	if _, err = fmt.Fprintln(input, "COMMIT"); err != nil {
		return errors.New("无法提交切换确认，请核对原厂服务")
	}
	input.Close()
	line, readErr := reader.ReadString('\n')
	waitErr := session.Wait()
	if readErr != nil || waitErr != nil || strings.TrimSpace(line) != "LINKNEST_UPNP_"+operation+"_OK" {
		return fmt.Errorf("UPnP 切换确认未完成，请核对原厂服务：%s", strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (a *App) upnpSwitchMode(w http.ResponseWriter, r *http.Request, ctx context.Context, c UPnPConfig, digest, at string) {
	if !c.Enabled {
		fail(w, 409, "请先启用 UPnP 管理")
		return
	}
	var q struct {
		upnpNativeRequest
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &q) {
		return
	}
	a.mu.Lock()
	auth := a.auth
	ok, freshFactor := a.securityProofLocked(w, r, &auth, q.AdminPassword, q.Code, true)
	if ok {
		ok = a.saveSecurityProofLocked(w, r, auth, q.TrustDevice && freshFactor)
	}
	a.mu.Unlock()
	if !ok {
		return
	}
	endpoint, err := upnpEndpoint(c.DescriptionURL)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	var host *SSHHost
	for _, h := range a.store.snapshot().SSHHosts {
		ip, _, _ := hostPort(h.Address)
		if h.ID == q.HostID && h.Username == "root" && h.Fingerprint != "" && ip == endpoint.Hostname() {
			copy := h
			host = &copy
			break
		}
	}
	if host == nil {
		fail(w, 400, "请选择与 UPnP 路由器 IP 相同、已核实指纹的 root SSH 主机")
		return
	}
	s, err := discoverUPnP(ctx, c, a.upnp.clientFactory)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	before, truncated, err := s.list(ctx)
	if err != nil || truncated {
		fail(w, 409, "无法完整读取现有映射，未切换原厂服务")
		return
	}
	started := time.Now()
	verify := func(ctx context.Context) error {
		var last error
		for attempt := 0; attempt < 12; attempt++ {
			current, err := discoverUPnP(ctx, c, a.upnp.clientFactory)
			if err == nil {
				var after []UPnPMapping
				after, _, err = current.list(ctx)
				if err == nil {
					err = upnpVerifyPreserved(before, after, time.Since(started))
				}
			}
			if err == nil {
				return nil
			}
			last = err
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
		return last
	}
	if err = runUPnPMode(ctx, *host, q.Password, q.PrivateKey, q.Enabled, verify); err != nil {
		fail(w, 502, err.Error())
		return
	}
	c.WritePolicy = "own"
	if q.Enabled {
		c.WritePolicy = "service"
	}
	c.WritePolicyUpdatedAt = time.Now().Format(time.RFC3339)
	if err = a.upnp.save(c, digest, at); err != nil {
		fail(w, 500, "原厂模式已切换，但本地记录保存失败，请重新核对")
		return
	}
	a.event("info", "UPnP 原厂安全模式已切换并核对映射")
	respond(w, 200, map[string]any{"ok": true, "message": "原厂模式已切换，现有映射已核对；SSH 凭据未保存"})
}
func upnpVerifyPreserved(before, after []UPnPMapping, elapsed time.Duration) error {
	for _, old := range before {
		if old.LeaseSeconds > 0 && time.Duration(old.LeaseSeconds)*time.Second <= elapsed {
			continue
		}
		found := false
		for _, current := range after {
			if sameUPnPMapping(old, current) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("映射未确认恢复：%s/%d", old.Protocol, old.ExternalPort)
		}
	}
	return nil
}
