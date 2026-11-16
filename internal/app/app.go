package app

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"linknest/web"

	"golang.org/x/crypto/bcrypt"
)

var assets = web.Files

type authConfig struct {
	Username        string           `json:"username"`
	PasswordHash    string           `json:"passwordHash"`
	TwoFactor       *twoFactorConfig `json:"twoFactor,omitempty"`
	TrustedBrowsers []trustedBrowser `json:"trustedBrowsers,omitempty"`
}
type session struct {
	expires time.Time
	secure  bool
}
type attempt struct {
	n     int
	until time.Time
}
type Event struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}
type App struct {
	applyMu                   sync.Mutex
	applyWG                   sync.WaitGroup
	applySequence             uint64
	applyRunning, applyClosed bool
	applyStatus               ApplyStatus
	terminals                 terminalRegistry
	deviceSlots               chan struct{}
	diagnostics               diagnosticCache
	iconMu                    sync.Mutex
	routerIPs                 routerIPCache
	mu                        sync.Mutex
	updateMu                  sync.Mutex
	store                     *Store
	engine                    *Engine
	dns                       *DNSManager
	certs                     *CertManager
	upnp                      *UPnPManager
	auth                      authConfig
	bootstrap                 string
	sessions                  map[string]session
	failures                  map[string]attempt
	events                    []Event
	admin                     string
	terminalSlots             chan struct{}
	twoFactorPending          *twoFactorEnrollment
}

func (a *App) event(level, message string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(message) > 400 {
		message = message[:400] + "…"
	}
	a.events = append(a.events, Event{Time: time.Now().Format(time.RFC3339), Level: level, Message: message})
	if len(a.events) > 200 {
		a.events = a.events[len(a.events)-200:]
	}
	log.Printf("[%s] %s", level, message)
}
func env(k, v string) string {
	if x := os.Getenv(k); x != "" {
		return x
	}
	return v
}
func newApp(dir, addr string, firewall bool) (*App, error) {
	s, err := newStore(dir)
	if err != nil {
		return nil, err
	}
	if err = validate(s.snapshot(), addr); err != nil {
		return nil, fmt.Errorf("配置校验失败：%w", err)
	}
	a := &App{store: s, admin: addr, sessions: map[string]session{}, failures: map[string]attempt{}, events: []Event{}, terminalSlots: make(chan struct{}, 2), deviceSlots: make(chan struct{}, 2)}
	if b, e := os.ReadFile(filepath.Join(dir, "auth.json")); e == nil {
		if e = json.Unmarshal(b, &a.auth); e != nil {
			return nil, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if err := a.validateTwoFactor(); err != nil {
		return nil, err
	}
	if a.auth.PasswordHash != "" && a.auth.Username == "" {
		// Upgrade old password-only installations without changing the password.
		a.auth.Username = env("LINKNEST_INITIAL_USERNAME", "admin")
		if !validUsername(a.auth.Username) {
			return nil, errors.New("迁移用户名无效")
		}
		b, _ := json.Marshal(a.auth)
		if err := writeAtomic(filepath.Join(dir, "auth.json"), b); err != nil {
			return nil, err
		}
	}
	if a.auth.PasswordHash == "" {
		p := filepath.Join(dir, "bootstrap.token")
		if b, e := os.ReadFile(p); e == nil {
			a.bootstrap = strings.TrimSpace(string(b))
		} else {
			a.bootstrap = token(24)
			if e = writeAtomic(p, []byte(a.bootstrap)); e != nil {
				return nil, e
			}
		}
		if len(a.bootstrap) < 32 {
			return nil, errors.New("初始化口令文件无效")
		}
	}
	a.engine = newEngine(s, a.event, newFirewall(firewall))
	a.dns = newDNS(s, a.event)
	a.certs = newCerts(s, a.event)
	a.upnp = newUPnP(s)
	return a, nil
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]any{"ok": false, "error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		fail(w, 400, "请求格式不正确或内容过大")
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		fail(w, 400, "请求只能包含一个 JSON 对象")
		return false
	}
	return true
}
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	s := r.Header.Get("Origin")
	if s == "" {
		return true
	}
	u, e := url.Parse(s)
	return e == nil && (u.Scheme == "http" || u.Scheme == "https") && strings.EqualFold(u.Host, r.Host)
}

// A Secure cookie cannot be overwritten by an HTTP response. Keep distinct
// names so HTTPS → HTTP never traps an existing browser in a login loop.
// Do not reuse the old mixed-protocol cookie, or accept HTTPS tokens over HTTP.
func adminCookieName(r *http.Request) string {
	if r.TLS != nil {
		return "__Host-linknest_session_v2"
	}
	return "linknest_http_session_v2"
}
func clearAdminCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: adminCookieName(r), Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}
func (a *App) authenticated(r *http.Request) bool {
	c, e := r.Cookie(adminCookieName(r))
	if e != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	if ok && s.secure == (r.TLS != nil) && time.Now().Before(s.expires) {
		return true
	}
	if ok && !time.Now().Before(s.expires) {
		delete(a.sessions, c.Value)
		a.terminals.revoke(c.Value)
	}
	return false
}
func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			fail(w, 405, "仅支持 GET")
			return
		}
		a.mu.Lock()
		initialized := a.auth.PasswordHash != ""
		a.mu.Unlock()
		respond(w, 200, map[string]any{"ok": true, "version": version, "initialized": initialized, "authenticated": a.authenticated(r)})
	})
	mux.HandleFunc("/api/setup", a.setup)
	mux.HandleFunc("/api/login", a.login)
	// Revocation only removes privileges; it must work even after a session expires.
	mux.HandleFunc("/api/logout", a.logout)
	mux.HandleFunc("/api/2fa/trust/revoke", a.cancelBrowserTrust)
	mux.HandleFunc(iconPrefix, func(w http.ResponseWriter, r *http.Request) { serveCachedIcon(a.store.dir, w, r) })
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if !a.authenticated(r) {
			fail(w, 401, "请登录后操作")
			return
		}
		a.api(w, r)
	})
	files := http.FileServer(http.FS(assets))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path == "/" || r.URL.Path == "/index.html") && (r.Method == "GET" || r.Method == "HEAD") {
			b, _ := assets.ReadFile("index.html")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if r.Method == "GET" {
				io.WriteString(w, strings.ReplaceAll(string(b), "__VERSION__", version))
			}
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.redirectAdmin(w, r) {
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-LinkNest-Version", version)
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data: https: http:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			if r.Method != "GET" && r.Method != "HEAD" {
				if !sameOrigin(r) || r.Header.Get("X-LinkNest-Request") != "1" {
					fail(w, 403, "请求来源校验失败")
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func (a *App) setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "仅支持 POST")
		return
	}
	var q struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &q) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.auth.PasswordHash != "" {
		fail(w, 409, "已初始化")
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Token), []byte(a.bootstrap)) != 1 {
		fail(w, 403, "初始化口令不正确")
		return
	}
	q.Username = strings.TrimSpace(q.Username)
	if !validUsername(q.Username) {
		fail(w, 400, "用户名需要 2—128 字节，不可包含控制字符")
		return
	}
	if len(q.Password) < 12 || len(q.Password) > 72 {
		fail(w, 400, "管理员密码需要 12—72 字节")
		return
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(q.Password), bcrypt.DefaultCost)
	if e != nil {
		fail(w, 500, "密码处理失败")
		return
	}
	auth := authConfig{Username: q.Username, PasswordHash: string(hash)}
	b, _ := json.Marshal(auth)
	if writeAtomic(filepath.Join(a.store.dir, "auth.json"), b) != nil {
		fail(w, 500, "无法保存账户")
		return
	}
	a.auth = auth
	a.bootstrap = ""
	os.Remove(filepath.Join(a.store.dir, "bootstrap.token"))
	respond(w, 200, map[string]bool{"ok": true})
}
func validUsername(value string) bool {
	return len(value) >= 2 && len(value) <= 128 && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "仅支持 POST")
		return
	}
	var q struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Code        string `json:"code"`
		TrustDevice bool   `json:"trustDevice"`
	}
	if !decode(w, r, &q) {
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	a.mu.Lock()
	now := time.Now()
	for k, v := range a.failures {
		if now.After(v.until) {
			delete(a.failures, k)
		}
	}
	at := a.failures[ip]
	hash := a.auth.PasswordHash
	username := a.auth.Username
	limited := at.n >= 6 && now.Before(at.until)
	if len(a.failures) > 1024 {
		limited = true
	}
	a.mu.Unlock()
	if limited {
		fail(w, 429, "登录尝试过多，请 5 分钟后重试")
		return
	}
	passwordOK := hash != "" && bcrypt.CompareHashAndPassword([]byte(hash), []byte(q.Password)) == nil
	if !passwordOK || !strings.EqualFold(strings.TrimSpace(q.Username), username) || username == "" {
		a.mu.Lock()
		at = a.failures[ip]
		at.n++
		at.until = time.Now().Add(5 * time.Minute)
		a.failures[ip] = at
		a.mu.Unlock()
		fail(w, 401, "用户名或密码不正确")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Recheck after bcrypt: a concurrent account change must not mint a session.
	if a.auth.PasswordHash != hash || a.auth.Username != username {
		fail(w, 401, "账号已变更，请重新登录")
		return
	}
	if at := a.failures[ip]; at.n >= 6 && time.Now().Before(at.until) {
		fail(w, 429, "登录尝试过多，请 5 分钟后重试")
		return
	}
	for k, v := range a.sessions {
		if time.Now().After(v.expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 32 {
		fail(w, 429, "登录会话过多，请先退出其他会话")
		return
	}
	if a.auth.TwoFactor != nil && trustedUntil(a.auth, r, time.Now()).IsZero() {
		if strings.TrimSpace(q.Code) == "" {
			respond(w, 200, map[string]any{"ok": true, "twoFactorRequired": true})
			return
		}
		next := a.auth
		if !a.consumeSecondFactor(&next, q.Code, now) {
			at = a.failures[ip]
			at.n++
			at.until = time.Now().Add(5 * time.Minute)
			a.failures[ip] = at
			fail(w, 401, "动态验证码或恢复码无效、已使用或已过期")
			return
		}
		if !a.saveSecurityProofLocked(w, r, next, q.TrustDevice) {
			return
		}
	}
	id := token(32)
	delete(a.failures, ip)
	if previous, err := r.Cookie(adminCookieName(r)); err == nil {
		delete(a.sessions, previous.Value)
	}
	a.sessions[id] = session{expires: time.Now().Add(8 * time.Hour), secure: r.TLS != nil}
	http.SetCookie(w, &http.Cookie{Name: adminCookieName(r), Value: id, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 28800})
	respond(w, 200, map[string]bool{"ok": true})
}
func (a *App) api(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/api/diagnostics" && r.Method == "GET" {
		a.diagnostics.refresh(a.engine.fw)
		respond(w, 200, a.diagnostics.snapshot())
		return
	}
	if p == "/api/rules/check" && r.Method == "POST" {
		a.checkBackend(w, r)
		return
	}
	if strings.HasPrefix(p, "/api/upnp/") {
		a.upnpAPI(w, r)
		return
	}
	if strings.HasPrefix(p, "/api/2fa/") {
		a.twoFactorAPI(w, r)
		return
	}
	if strings.HasPrefix(p, "/api/access/") {
		a.accessAPI(w, r)
		return
	}
	if p == "/api/icons/upload" {
		a.uploadIcon(w, r)
		return
	}
	if (p == "/api/password" || p == "/api/account") && r.Method == "POST" {
		var q struct {
			CurrentPassword string `json:"currentPassword"`
			NewPassword     string `json:"newPassword"`
			Username        string `json:"username"`
			Code            string `json:"code"`
			TrustDevice     bool   `json:"trustDevice"`
		}
		if !decode(w, r, &q) {
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		auth := a.auth
		if ok, _ := a.securityProofLocked(w, r, &auth, q.CurrentPassword, q.Code, true); !ok {
			return
		}
		username := a.auth.Username
		if p == "/api/account" {
			if !validUsername(q.Username) {
				fail(w, 400, "用户名需 2—128 字节，不能包含控制字符或首尾空白")
				return
			}
			username = q.Username
		}
		if (p == "/api/password" || q.NewPassword != "") && (len(q.NewPassword) < 12 || len(q.NewPassword) > 72) {
			fail(w, 400, "新密码需要 12—72 字节")
			return
		}
		hash := []byte(a.auth.PasswordHash)
		if q.NewPassword != "" {
			var err error
			hash, err = bcrypt.GenerateFromPassword([]byte(q.NewPassword), bcrypt.DefaultCost)
			if err != nil {
				fail(w, 500, "密码处理失败")
				return
			}
		}
		auth.Username, auth.PasswordHash = username, string(hash)
		auth.TrustedBrowsers = nil
		data, _ := json.Marshal(auth)
		if writeAtomic(filepath.Join(a.store.dir, "auth.json"), data) != nil {
			fail(w, 500, "无法保存密码")
			return
		}
		a.auth = auth
		a.sessions = map[string]session{}
		a.terminals.revoke("")
		a.twoFactorPending = nil
		clearAdminCookie(w, r)
		clearTrustCookie(w, r)
		respond(w, 200, map[string]bool{"ok": true})
		return
	}
	if p == "/api/state" && r.Method == "GET" {
		c, revision := a.store.snapshotRevision()
		hasSecret := c.DNS.Secret != ""
		c, credentialFlags := redactedConfig(c)
		a.mu.Lock()
		events := append([]Event{}, a.events...)
		username := a.auth.Username
		twoFactor := twoFactorState(a.auth)
		if until := trustedUntil(a.auth, r, time.Now()); !until.IsZero() {
			twoFactor["trustedUntil"] = until.Format(time.RFC3339Nano)
		}
		a.mu.Unlock()
		respond(w, 200, map[string]any{"ok": true, "version": version, "config": c, "configRevision": revision, "application": a.applicationStatus(), "diagnostics": a.diagnostics.snapshot(), "username": username, "twoFactor": twoFactor, "dnsSecretSet": hasSecret, "credentialFlags": credentialFlags, "interfaces": interfaces(), "routerIPs": a.routerIPs.snapshot(), "rules": a.ruleStatuses(revision), "firewall": a.engine.fw.get(), "ddns": a.dns.status(), "certificates": a.certs.list(), "certificateTasks": a.certs.tasks(), "certificateJobs": a.certs.status(), "events": events, "adminAddress": a.admin, "adminTlsStatus": a.adminTLSStatus(), "upnpPorts": a.upnpPortsStatus(c.Rules)})
		return
	}
	if p == "/api/config" && r.Method == "PUT" {
		var c Config
		if !decode(w, r, &c) {
			return
		}
		if r.Header.Get("If-Match") == "" {
			fail(w, 428, "页面缺少配置版本，请刷新后重试")
			return
		}
		migrateConfig(&c)
		if err := validate(c, a.admin); err != nil {
			fail(w, 400, err.Error())
			return
		}
		a.updateMu.Lock()
		defer a.updateMu.Unlock()
		if c.AdminTLS.Enabled {
			pair, e := a.adminCertificate(c.AdminTLS)
			if e != nil {
				fail(w, 400, e.Error())
				return
			}
			oldTLS := a.store.snapshot().AdminTLS
			if c.AdminTLS.Redirect && (!oldTLS.Redirect || !oldTLS.Enabled || oldTLS.Certificate != c.AdminTLS.Certificate) {
				h := r.Host
				if host, _, e := net.SplitHostPort(h); e == nil {
					h = host
				}
				if pair.Leaf.VerifyHostname(h) != nil {
					fail(w, 400, "请先使用证书覆盖的域名进入后台并验证 HTTPS，再开启自动跳转")
					return
				}
			}
		}
		before := a.store.snapshot()
		if err := a.store.saveExpected(c, r.Header.Get("If-Match")); err != nil {
			if errors.Is(err, errConfigConflict) {
				fail(w, 412, err.Error())
				return
			}
			if errors.Is(err, errCredentialChange) {
				fail(w, 400, err.Error())
				return
			}
			fail(w, 500, "保存失败："+err.Error())
			return
		}
		if !c.TerminalEnabled {
			a.mu.Lock()
			a.terminals.revoke("")
			a.mu.Unlock()
		}
		a.queueApply()
		a.dns.configChanged(before, a.store.snapshot())
		a.event("info", "配置已保存，正在应用")
		_, revision := a.store.snapshotRevision()
		respond(w, 202, map[string]any{"ok": true, "configRevision": revision, "applyState": "pending"})
		return
	}
	if p == "/api/export" && r.Method == "GET" {
		c := a.store.snapshot()
		c, _ = redactedConfig(c)
		w.Header().Set("Content-Disposition", "attachment; filename=linknest-config.json")
		respond(w, 200, c)
		return
	}
	if p == "/api/ddns/run" && r.Method == "POST" {
		var q struct {
			ID string `json:"id"`
		}
		if !decode(w, r, &q) {
			return
		}
		a.updateMu.Lock()
		defer a.updateMu.Unlock()
		for _, d := range a.store.snapshot().DDNS {
			if d.ID == q.ID {
				if !a.dns.start(d) {
					fail(w, 409, "正在更新中")
					return
				}
				respond(w, 202, map[string]bool{"ok": true})
				return
			}
		}
		fail(w, 404, "规则不存在")
		return
	}
	if p == "/api/ddns/record/delete" && r.Method == "POST" {
		a.deleteDNSRecord(w, r)
		return
	}
	if p == "/api/ddns/detect" && r.Method == "POST" {
		var q struct {
			ID       string `json:"id"`
			RecordID string `json:"recordId"`
		}
		if !decode(w, r, &q) {
			return
		}
		for _, d := range a.store.snapshot().DDNS {
			if d.ID == q.ID {
				ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
				defer cancel()
				results := a.dns.detectRecords(ctx, d, q.RecordID)
				if q.RecordID != "" && len(results) == 0 {
					fail(w, 404, "解析记录不存在")
					return
				}
				respond(w, 200, map[string]any{"ok": true, "records": results})
				return
			}
		}
		fail(w, 404, "任务不存在")
		return
	}
	if p == "/api/wake" && r.Method == "POST" {
		var q struct {
			ID string `json:"id"`
		}
		if !decode(w, r, &q) {
			return
		}
		for _, d := range a.store.snapshot().Devices {
			if d.ID == q.ID {
				if e := wake(d); e != nil {
					fail(w, 502, e.Error())
					return
				}
				a.event("info", "已向 "+d.Name+" 发送唤醒包；不代表设备已开机")
				respond(w, 200, map[string]bool{"ok": true})
				return
			}
		}
		fail(w, 404, "设备不存在")
		return
	}
	if p == "/api/certificates/download" {
		a.downloadCertificate(w, r)
		return
	}
	if p == "/api/certificates/import" && r.Method == "POST" {
		var q struct {
			ID          string `json:"id"`
			Certificate string `json:"certificate"`
			Key         string `json:"key"`
		}
		if !decode(w, r, &q) {
			return
		}
		if e := a.certs.importPair(q.ID, []byte(q.Certificate), []byte(q.Key)); e != nil {
			fail(w, 400, e.Error())
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
		return
	}
	if p == "/api/certificates/issue" && r.Method == "POST" {
		var q CertRequest
		if !decode(w, r, &q) {
			return
		}
		if e := a.certs.start(q); e != nil {
			fail(w, 400, e.Error())
			return
		}
		respond(w, 202, map[string]bool{"ok": true})
		return
	}
	if p == "/api/certificates/task" && r.Method == "PUT" {
		var q CertRequest
		if !decode(w, r, &q) {
			return
		}
		if e := a.certs.saveTask(q); e != nil {
			fail(w, 400, e.Error())
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
		return
	}
	if (p == "/api/certificates/run" || p == "/api/certificates/delete") && r.Method == "POST" {
		var q struct {
			ID string `json:"id"`
		}
		if !decode(w, r, &q) {
			return
		}
		var e error
		if p == "/api/certificates/run" {
			e = a.certs.runSaved(q.ID)
		} else {
			a.updateMu.Lock()
			e = a.certs.remove(q.ID)
			a.updateMu.Unlock()
		}
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
		return
	}
	if p == "/api/terminal" && r.Method == "GET" {
		a.terminal(w, r)
		return
	}
	if p == "/api/ssh/probe" && r.Method == "POST" {
		a.sshProbe(w, r)
		return
	}
	if p == "/api/ssh/trust" && r.Method == "POST" {
		a.sshTrust(w, r)
		return
	}
	if p == "/api/devices/check" && r.Method == "POST" {
		a.checkDevices(w, r)
		return
	}
	fail(w, 404, "接口不存在或请求方法不正确")
}
func Run() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		addr := env("LINKNEST_ADMIN_ADDR", "127.0.0.1:17880")
		host, port, e := hostPort(addr)
		if e != nil {
			os.Exit(1)
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		c := http.Client{Timeout: 3 * time.Second}
		res, e := c.Get("http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/api/health")
		if e != nil {
			os.Exit(1)
		}
		res.Body.Close()
		if res.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}
	addr := env("LINKNEST_ADMIN_ADDR", "127.0.0.1:17880")
	if _, _, e := hostPort(addr); e != nil {
		log.Fatal(e)
	}
	a, e := newApp(env("LINKNEST_DATA_DIR", "./data"), addr, os.Getenv("LINKNEST_FIREWALL") == "enabled")
	if e != nil {
		log.Fatal(e)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	server := &http.Server{Addr: addr, Handler: a.handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	a.queueApply()
	a.diagnostics.refresh(a.engine.fw)
	defer a.engine.close()
	defer a.closeApply()
	defer a.terminals.revoke("")
	accessDone := make(chan struct{})
	defer func() { cancel(); <-accessDone }()
	go func() {
		defer close(accessDone)
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		a.engine.access.Tick(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				a.engine.access.Tick(ctx)
			}
		}
	}()
	defer a.certs.close()
	defer a.dns.close()
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		ddns := time.NewTicker(time.Second)
		defer ddns.Stop()
		a.certs.tickRenewals()
		renew := time.NewTicker(time.Minute)
		defer renew.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				_ = a.engine.access.Flush()
				a.queueApply()
			case <-ddns.C:
				a.dns.tick(time.Now())
			case <-renew.C:
				a.certs.tickRenewals()
			}
		}
	}()
	go func() {
		<-ctx.Done()
		deadline, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		server.Shutdown(deadline)
	}()
	log.Printf("LinkNest %s 管理入口 http://%s；初始化口令文件：%s", version, addr, filepath.Join(a.store.dir, "bootstrap.token"))
	listener, e := a.adminListener()
	if e != nil {
		log.Fatal(e)
	}
	if e = server.Serve(listener); e != nil && !errors.Is(e, http.ErrServerClosed) {
		log.Fatal(e)
	}
}
