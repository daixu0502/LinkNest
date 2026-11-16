package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

func (a *App) upnpAPI(w http.ResponseWriter, r *http.Request) {
	u := a.upnp
	if !u.op.TryLock() {
		fail(w, 409, "UPnP 正在执行操作，请稍后重试")
		return
	}
	defer u.op.Unlock()
	c, digest, at, loadError := u.snapshot()
	p := strings.TrimPrefix(r.URL.Path, "/api/upnp/")
	timeout := 20 * time.Second
	if p == "mode" || p == "ports" {
		timeout = 45 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	if p == "config" && r.Method == "PUT" {
		var next UPnPConfig
		if !decode(w, r, &next) {
			return
		}
		if err := validateUPnPConfig(&next); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if next.WritePolicy != c.WritePolicy {
			fail(w, 400, "请使用跨设备管理开关切换原厂安全模式")
			return
		}
		next.WritePolicyUpdatedAt = c.WritePolicyUpdatedAt
		if next.PortProtection != c.PortProtection || !slices.Equal(next.ProtectedPorts, c.ProtectedPorts) {
			fail(w, 400, "请使用保护转发端口开关及同步按钮修改原厂端口保护")
			return
		}
		next.PortsUpdatedAt = c.PortsUpdatedAt
		if c.PortProtection && (next.DescriptionURL != c.DescriptionURL || next.Interface != c.Interface) {
			fail(w, 409, "请先关闭并解除当前路由器端口保护，再更换连接地址或网卡")
			return
		}
		if err := u.save(next, digest, at); err != nil {
			fail(w, 400, err.Error())
			return
		}
		respond(w, 200, map[string]any{"ok": true, "message": "管理设置已保存；不会自动修改路由器映射或黑名单"})
		return
	}
	if p == "policy" && r.Method == "POST" {
		a.upnpApplyPolicy(w, r, ctx, c)
		return
	}
	if p == "mode" && r.Method == "POST" {
		a.upnpSwitchMode(w, r, ctx, c, digest, at)
		return
	}
	if p == "ports" && r.Method == "POST" {
		a.upnpProtectPorts(w, r, ctx, c, digest, at)
		return
	}
	if p == "state" && r.Method == "GET" {
		pending := (digest != "" || len(c.Blacklist) > 0) && digest != upnpPolicyDigest(c)
		result := map[string]any{"ok": true, "config": c, "mappings": []UPnPMapping{}, "error": loadError, "truncated": false, "appliedAt": at, "policyPending": pending, "nativePolicyApplied": digest != ""}
		ports := upnpForwardPorts(a.store.snapshot().Rules)
		result["forwardPorts"] = ports
		result["portsPending"] = c.PortProtection && !slices.Equal(ports, c.ProtectedPorts)
		result["portConflicts"] = []UPnPMapping{}
		if c.Enabled && loadError == "" {
			s, err := discoverUPnP(ctx, c, u.clientFactory)
			if err == nil {
				result["clientIP"] = s.localIP
				var mappings []UPnPMapping
				var truncated bool
				mappings, truncated, err = s.list(ctx)
				result["mappings"], result["truncated"] = mappings, truncated
				result["portConflicts"] = upnpPortConflicts(ports, mappings)
			}
			if err != nil {
				result["error"] = err.Error()
			}
		}
		respond(w, 200, result)
		return
	}
	if p != "mapping" || r.Method != "POST" {
		fail(w, 405, "不支持此 UPnP 操作")
		return
	}
	if !c.Enabled || loadError != "" {
		fail(w, 409, "请先配置并启用 UPnP 管理")
		return
	}
	var q struct {
		Operation string      `json:"operation"`
		Before    UPnPMapping `json:"before"`
		After     UPnPMapping `json:"after"`
	}
	if !decode(w, r, &q) {
		return
	}
	if q.Operation != "add" && q.Operation != "edit" && q.Operation != "delete" {
		fail(w, 400, "映射操作无效")
		return
	}
	if q.Operation != "add" {
		if err := validateUPnPMapping(q.Before); err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	if q.Operation != "delete" {
		if err := validateUPnPMapping(q.After); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if q.After.LeaseSeconds > 604800 {
			fail(w, 400, "新租期最长 7 天，0 为永久")
			return
		}
		if c.PortProtection && (slices.Contains(c.ProtectedPorts, q.After.ExternalPort) || slices.Contains(upnpForwardPorts(a.store.snapshot().Rules), q.After.ExternalPort)) {
			fail(w, 409, "此端口属于转发端口保护范围，原厂兼容模式同时保护 TCP 和 UDP")
			return
		}
		for _, b := range c.Blacklist {
			address, isMAC, _ := upnpBlockAddress(b.Address)
			_, network, _ := net.ParseCIDR(address)
			if b.Enabled && !isMAC && network != nil && network.Contains(net.ParseIP(q.After.InternalIP)) {
				fail(w, 409, "目标设备匹配本地 UPnP 黑名单，请先核对设备策略")
				return
			}
		}
		// Socket probes and existing ingress NAT both matter. Do not let UPnP
		// overwrite an enabled LinkNest listener, including reverse proxies.
		for _, rule := range a.store.snapshot().Rules {
			if !rule.Enabled || !forwardFamily(rule, false) {
				continue
			}
			_, port, _ := hostPort(rule.Listen)
			for _, proto := range ruleProtocols(rule) {
				if port == q.After.ExternalPort && strings.EqualFold(proto, q.After.Protocol) {
					fail(w, 409, "此端口与已启用的 LinkNest 规则冲突："+rule.Name)
					return
				}
			}
		}
	}
	s, err := discoverUPnP(ctx, c, u.clientFactory)
	if err == nil && c.WritePolicy != "service" {
		if s.localIP == "" || q.Operation != "add" && q.Before.InternalIP != s.localIP || q.Operation != "delete" && q.After.InternalIP != s.localIP {
			fail(w, 403, "当前采用安全模式：只能管理 LinkNest 本机（"+s.localIP+"）的映射；其他设备仅可查看。不会自动降低原厂安全限制")
			return
		}
	}
	if err == nil {
		err = s.mutate(ctx, q.Operation, q.Before, q.After)
	}
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	a.event("info", "UPnP 映射操作已确认："+q.Operation)
	respond(w, 200, map[string]any{"ok": true, "message": "UPnP 映射已更新"})
}

type upnpNativeRequest struct {
	HostID         string `json:"hostId"`
	Password       string `json:"password"`
	PrivateKey     string `json:"privateKey"`
	AdminPassword  string `json:"adminPassword"`
	Code           string `json:"code"`
	TrustDevice    bool   `json:"trustDevice"`
	DeleteExisting bool   `json:"deleteExisting"`
}

func (a *App) upnpApplyPolicy(w http.ResponseWriter, r *http.Request, ctx context.Context, c UPnPConfig) {
	if !c.Enabled {
		fail(w, 409, "请先启用 UPnP 管理")
		return
	}
	var q upnpNativeRequest
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
	var host *SSHHost
	for _, h := range a.store.snapshot().SSHHosts {
		if h.ID == q.HostID {
			copy := h
			host = &copy
			break
		}
	}
	endpoint, err := upnpEndpoint(c.DescriptionURL)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if host == nil || host.Fingerprint == "" || host.Username != "root" {
		fail(w, 400, "请选择已核实指纹的 root SSH 主机；可先在 Web 终端添加并确认指纹")
		return
	}
	h, _, err := hostPort(host.Address)
	if err != nil || h != endpoint.Hostname() {
		fail(w, 400, "SSH 主机必须是当前 UPnP 路由器的同一 IPv4 地址")
		return
	}
	script, err := buildUPnPPolicy(c)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err = runUPnPPolicy(ctx, *host, q.Password, q.PrivateKey, script); err != nil {
		fail(w, 502, err.Error())
		return
	}
	if err = a.upnp.save(c, upnpPolicyDigest(c), time.Now().Format(time.RFC3339)); err != nil {
		fail(w, 500, "路由器已应用，但本地记录保存失败；请核对后重试")
		return
	}
	// Deleting old mappings is separately confirmed and never inferred from
	// adding a device to the blacklist. MAC matching uses current ARP data.
	message := "黑名单已写入原厂防火墙并立即应用；不影响普通上网，不需要重启 UPnP"
	partial := false
	if q.DeleteExisting {
		service, err := discoverUPnP(ctx, c, a.upnp.clientFactory)
		if err == nil {
			var mappings []UPnPMapping
			var truncated bool
			mappings, truncated, err = service.list(ctx)
			if truncated {
				partial = true
				message += "；映射超过读取上限，未读取的记录保留"
			}
			if err == nil {
				macs := upnpARPMACs()
				unresolved := 0
				hasMAC := false
				for _, b := range c.Blacklist {
					_, mac, _ := upnpBlockAddress(b.Address)
					if b.Enabled && mac {
						hasMAC = true
					}
				}
				for _, m := range mappings {
					if ctx.Err() != nil {
						err = errors.Join(err, ctx.Err())
						break
					}
					if upnpBlockedMapping(c, m, macs) {
						if c.WritePolicy != "service" && m.InternalIP != service.localIP {
							err = errors.Join(err, errors.New("安全模式保留其他设备的已有映射，不能代删"))
							continue
						}
						if delErr := service.mutate(ctx, "delete", m, UPnPMapping{}); delErr != nil {
							err = errors.Join(err, delErr)
						}
					}
				}
				if hasMAC {
					for _, m := range mappings {
						if macs[m.InternalIP] == "" {
							unresolved++
						}
					}
				}
				if unresolved > 0 {
					partial = true
					message += "；有设备无法取得当前 MAC，相关已有映射保留，请刷新后手动核对"
				}
			}
		}
		if err != nil {
			partial = true
			message += "；部分已有映射未能确认删除：" + err.Error()
		}
	}
	a.event("info", "UPnP 设备黑名单已应用到路由器")
	respond(w, 200, map[string]any{"ok": true, "message": message, "warning": partial})
}
