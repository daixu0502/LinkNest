package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Stock MiniUPnPd permissions have no protocol field. Reserving a port therefore
// rejects both TCP and UDP, including NAT-PMP and PCP allocation requests.
func upnpForwardPorts(rules []Rule) []int {
	ports := []int{}
	for _, r := range rules {
		if !r.Enabled || r.Kind == "web" || !forwardFamily(r, false) {
			continue
		}
		_, port, err := hostPort(r.Listen)
		if err == nil && port > 0 && port <= 65535 && !slices.Contains(ports, port) {
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	return ports
}

func validateUPnPPorts(ports []int) error {
	if len(ports) > 512 {
		return errors.New("最多保护 512 个转发端口")
	}
	previous := 0
	for _, port := range ports {
		if port <= previous || port > 65535 {
			return errors.New("保护端口需为 1—65535 的升序、不重复端口列表")
		}
		previous = port
	}
	return nil
}

func upnpPortConflicts(ports []int, mappings []UPnPMapping) []UPnPMapping {
	out := []UPnPMapping{}
	for _, m := range mappings {
		if slices.Contains(ports, m.ExternalPort) {
			out = append(out, m)
		}
	}
	return out
}

func (a *App) upnpPortsStatus(rules []Rule) map[string]any {
	c, _, _, loadError := a.upnp.snapshot()
	ports := upnpForwardPorts(rules)
	return map[string]any{"enabled": c.PortProtection, "managementEnabled": c.Enabled, "forwardPorts": ports, "protectedPorts": c.ProtectedPorts, "updatedAt": c.PortsUpdatedAt, "pending": c.PortProtection && !slices.Equal(ports, c.ProtectedPorts), "error": loadError}
}

func buildUPnPPortsScript(ports []int) (string, error) {
	if err := validateUPnPPorts(ports); err != nil {
		return "", err
	}
	var commands, expected strings.Builder
	for i, port := range ports {
		id := "lnport_" + strconv.Itoa(port)
		fmt.Fprintf(&commands, "U set upnpd.%s=perm_rule\n", id)
		for _, pair := range [][2]string{{"action", "deny"}, {"ext_ports", strconv.Itoa(port)}, {"int_addr", "0.0.0.0/0"}, {"int_ports", "0-65535"}, {"linknest_owner", "ports-v1"}, {"comment", "LinkNest protected port TCP+UDP"}} {
			fmt.Fprintf(&commands, "U set %s\n", upnpShellQuote("upnpd."+id+"."+pair[0]+"="+pair[1]))
		}
		fmt.Fprintf(&commands, "U reorder upnpd.%s=%d\n", id, i)
		fmt.Fprintf(&expected, "deny %d 0.0.0.0/0 0-65535\n", port)
	}
	return `set -eu
umask 077
for cmd in uci flock mktemp md5sum sed awk cmp; do command -v "$cmd" >/dev/null || exit 1; done
[ -f /etc/init.d/miniupnpd ] && [ -f /etc/config/upnpd ] || { echo '仅支持已适配的原厂 miniupnpd' >&2; exit 1; }
grep -F 'config_foreach conf_rule_add perm_rule "$tmpconf"' /etc/init.d/miniupnpd >/dev/null || { echo '原厂权限规则生成方式未适配' >&2; exit 1; }
grep -F 'tmpconf="/var/etc/miniupnpd.conf"' /etc/init.d/miniupnpd >/dev/null || exit 1
exec 9>/var/lock/linknest-upnp-policy.lock
flock -n 9 || { echo '原厂 UPnP 配置锁被占用，请稍后重试' >&2; exit 1; }
[ -z "$(uci -q changes upnpd)" ] || { echo '原厂 UPnP 有未提交修改，未覆盖' >&2; exit 1; }
lease=$(uci -q get upnpd.config.upnp_lease_file)
case "$lease" in /tmp/upnp.leases|/var/run/miniupnpd.leases) ;; *) echo '原厂租约路径未适配' >&2; exit 1 ;; esac
[ -f "$lease" ] || { echo '租约文件缺失，未修改' >&2; exit 1; }
work=$(mktemp -d /tmp/linknest-upnp-ports.XXXXXX)
case "$work" in /tmp/linknest-upnp-ports.*) ;; *) exit 1 ;; esac
mkdir "$work/delta"
cp /etc/config/upnpd "$work/original"
cp /etc/config/upnpd "$work/upnpd"
cp "$lease" "$work/leases"
oldsum=$(md5sum /etc/config/upnpd | cut -d ' ' -f 1)
initsum=$(md5sum /etc/init.d/miniupnpd | cut -d ' ' -f 1)
changed=0
committed=0
U() { uci -c "$work" -P "$work/delta" "$@"; }
cleanup() {
 if [ "$changed" = 1 ] && [ "$committed" != 1 ]; then
  current=$(md5sum /etc/config/upnpd | cut -d ' ' -f 1)
  if [ "$current" = "$newsum" ] && [ "$(md5sum /etc/init.d/miniupnpd | cut -d ' ' -f 1)" = "$initsum" ]; then
   /etc/init.d/miniupnpd stop 9>&- >/dev/null 2>&1 || true
   cp "$work/original" /etc/config/.linknest-ports-restore-$$
   mv /etc/config/.linknest-ports-restore-$$ /etc/config/upnpd
   # Keep mappings allocated by clients during verification too. Prefer the
   # latest owner for a protocol/port; never overwrite it with a stale lease.
   if [ -f "$lease" ]; then
    awk -F: 'NF && !seen[$1 SUBSEP $2]++' "$lease" "$work/leases" >"$work/restore-leases"
    cp "$work/restore-leases" "$lease"
   else
    cp "$work/leases" "$lease"
   fi
   /etc/init.d/miniupnpd start 9>&- >/dev/null 2>&1 || echo '回滚后原厂 UPnP 启动失败，请手动核对' >&2
  else
   echo '发现并发修改，未覆盖原厂文件，请手动核对' >&2
  fi
 fi
 rm -f /etc/config/.linknest-ports-new-$$
 case "$work" in /tmp/linknest-upnp-ports.*) rm -rf -- "$work" ;; esac
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
cat >"$work/expected" <<'LINKNEST_PORTS'
` + expected.String() + `LINKNEST_PORTS
check_leases() {
 awk -F: 'NR==FNR {split($0,p," ");reserved[p[2]]=1;next} NF {if (($1!="TCP" && $1!="UDP") || $2!~/^[0-9]+$/) {print "无法校验原厂租约格式" >"/dev/stderr";exit 1} if ($2 in reserved) {print "已有映射占用保护端口 " $1 "/" $2 "，未删除，请先处理冲突" >"/dev/stderr";exit 1}}' "$work/expected" "$lease"
}
# Empty expected input needs a separate branch (awk NR==FNR on an empty first
# file would incorrectly classify the lease records as the reservation list).
if [ -s "$work/expected" ]; then check_leases; fi
for section in $(U -q show upnpd | sed -n 's/^upnpd\.\(lnport_[a-zA-Z0-9_]*\)=.*$/\1/p'); do
 [ "$(U -q get "upnpd.$section.linknest_owner")" = ports-v1 ] || { echo '同名前缀属于其他配置，未覆盖' >&2; exit 1; }
 [ "$(U -q get "upnpd.$section")" = perm_rule ] || { echo '保护规则类型不匹配，未覆盖' >&2; exit 1; }
 U delete "upnpd.$section"
done
` + commands.String() + `
` + upnpMaterializeUCI("upnpd") + `
[ "$(md5sum /etc/config/upnpd | cut -d ' ' -f 1)" = "$oldsum" ] && [ "$(md5sum /etc/init.d/miniupnpd | cut -d ' ' -f 1)" = "$initsum" ] && [ -z "$(uci -q changes upnpd)" ] || { echo '原厂配置已并发修改，中止应用' >&2; exit 1; }
newsum=$(md5sum "$work/upnpd" | cut -d ' ' -f 1)
cp "$work/upnpd" /etc/config/.linknest-ports-new-$$
mv /etc/config/.linknest-ports-new-$$ /etc/config/upnpd
changed=1
/etc/init.d/miniupnpd stop 9>&- >/dev/null 2>&1
if [ -s "$lease" ]; then cp "$lease" "$work/leases"; fi
if [ -s "$work/expected" ]; then check_leases; fi
cp "$work/leases" "$lease"
/etc/init.d/miniupnpd start 9>&- >/dev/null 2>&1
pid=$(cat /var/run/miniupnpd.pid)
case "$pid" in ''|*[!0-9]*) exit 1 ;; esac
[ -r "/proc/$pid/cmdline" ] || { echo '原厂 UPnP 未启动' >&2; exit 1; }
if [ -s "$work/expected" ]; then
 count=$(wc -l <"$work/expected")
 sed -n '/^allow /p;/^deny /p' /var/etc/miniupnpd.conf | head -n "$count" >"$work/actual"
 cmp -s "$work/expected" "$work/actual" || { echo '原厂未优先加载保护规则，已请求回滚' >&2; exit 1; }
fi
echo LINKNEST_UPNP_PORTS_READY
IFS= read -r decision
[ "$decision" = COMMIT ] || { echo '映射未确认保留，已请求回滚' >&2; exit 1; }
committed=1
echo LINKNEST_UPNP_PORTS_OK
`, nil
}

func (a *App) upnpProtectPorts(w http.ResponseWriter, r *http.Request, ctx context.Context, c UPnPConfig, digest, at string) {
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
	if !a.updateMu.TryLock() {
		fail(w, 409, "转发配置正在更新，请稍后重试")
		return
	}
	defer a.updateMu.Unlock()
	core := a.store.snapshot()
	endpoint, err := upnpEndpoint(c.DescriptionURL)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	var host *SSHHost
	for _, h := range core.SSHHosts {
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
	ports := []int{}
	if q.Enabled {
		ports = upnpForwardPorts(core.Rules)
	}
	script, err := buildUPnPPortsScript(ports)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	s, err := discoverUPnP(ctx, c, a.upnp.clientFactory)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	before, truncated, err := s.list(ctx)
	if err != nil || truncated {
		fail(w, 409, "无法完整读取原厂映射，未修改端口保护")
		return
	}
	if conflicts := upnpPortConflicts(ports, before); len(conflicts) > 0 {
		details := []string{}
		for _, m := range conflicts[:min(len(conflicts), 8)] {
			details = append(details, fmt.Sprintf("%s/%d → %s:%d", m.Protocol, m.ExternalPort, m.InternalIP, m.InternalPort))
		}
		respond(w, 409, map[string]any{"error": "已有映射冲突（" + strings.Join(details, "；") + "），未修改配置或删除映射；请先处理冲突", "conflicts": conflicts})
		return
	}
	started := time.Now()
	verify := func(ctx context.Context) error {
		var last error
		for attempt := 0; attempt < 12; attempt++ {
			current, e := discoverUPnP(ctx, c, a.upnp.clientFactory)
			if e == nil {
				after, full, e := current.list(ctx)
				if e == nil && !full {
					e = upnpVerifyPreserved(before, after, time.Since(started))
					if e == nil && len(upnpPortConflicts(ports, after)) != 0 {
						e = errors.New("核对期间发现新的保护端口冲突")
					}
					if e == nil {
						return nil
					}
				}
				if e == nil {
					e = errors.New("映射列表不完整")
				}
				last = e
			} else {
				last = e
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
		return last
	}
	if err = runUPnPTransaction(ctx, *host, q.Password, q.PrivateKey, script, "PORTS", verify); err != nil {
		fail(w, 502, err.Error())
		return
	}
	c.PortProtection, c.ProtectedPorts, c.PortsUpdatedAt = q.Enabled, ports, time.Now().Format(time.RFC3339)
	if err = a.upnp.save(c, digest, at); err != nil {
		fail(w, 500, "原厂端口权限已修改，但本地记录保存失败，请核对后重试")
		return
	}
	a.event("info", "UPnP 转发端口保护已同步并核对现有映射")
	respond(w, 200, map[string]any{"ok": true, "message": "原厂端口保护已同步；TCP 和 UDP 同时处理，现有映射已核对，SSH 凭据未保存"})
}
