package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type portalSession struct {
	Route, Hash string
	Expires     time.Time
}
type Portal struct {
	mu            sync.Mutex
	store         *Store
	sessions      map[string]portalSession
	attempts      map[string]attempt
	log           func(string, string)
	publicKey     []byte
	probeMu       sync.Mutex
	probedDevices []Device
	probeResults  []DeviceStatus
	probedAt      time.Time
}

func newPortal(s *Store, log func(string, string)) *Portal {
	return &Portal{store: s, sessions: map[string]portalSession{}, attempts: map[string]attempt{}, log: log, publicKey: []byte(token(32))}
}

// Anonymous WOL still needs a route-bound, expiring cookie and a CSRF token.
// Sign tokens instead of consuming protected-login session slots for every visitor.
func (p *Portal) publicSignature(route, value string) string {
	m := hmac.New(sha256.New, p.publicKey)
	m.Write([]byte(route + "\x00" + value))
	return hex.EncodeToString(m.Sum(nil))
}
func (p *Portal) publicToken(route string, now time.Time) string {
	v := strconv.FormatInt(now.Add(8*time.Hour).Unix(), 10) + "." + token(24)
	return v + "." + p.publicSignature(route, v)
}
func (p *Portal) validPublicToken(route, value string, now time.Time) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || len(value) > 200 {
		return false
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	return err == nil && expires > now.Unix() && expires <= now.Add(8*time.Hour).Unix() &&
		hmac.Equal([]byte(parts[2]), []byte(p.publicSignature(route, parts[0]+"."+parts[1])))
}
func portalOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	s := r.Header.Get("Origin")
	if s == "" {
		s = r.Header.Get("Referer")
	}
	if s == "" {
		return r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	u, err := url.Parse(s)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return err == nil && u.User == nil && u.Scheme == scheme && strings.EqualFold(u.Host, r.Host)
}

type panelChoice struct{ Key, Name string }

var portalPage = template.Must(template.New("portal.html").Funcs(template.FuncMap{
	"panelColor": func(preset string) string {
		colors := map[string]string{"aurora": "#6125db", "sunset": "#dc586d", "ocean": "#1b69b1", "forest": "#087d62", "dusk": "#672a70", "slate": "#293442", "mist": "#c8dafa"}
		if color := colors[preset]; color != "" {
			return color
		}
		return colors["aurora"]
	},
	"version": func() string { return version },
	"inc":     func(v int) int { return v + 1 },
	"layouts": func() []panelChoice {
		return []panelChoice{{"cards", "卡片"}, {"compact", "紧凑"}, {"list", "列表"}, {"minimal", "极简"}}
	},
	"backgrounds": func() []panelChoice {
		return []panelChoice{{"aurora", "极光"}, {"sunset", "日落"}, {"ocean", "海洋"}, {"forest", "森林"}, {"dusk", "暮色"}, {"slate", "石墨"}, {"mist", "晨雾"}}
	},
	"engines": func() []panelChoice {
		return []panelChoice{{"bing", "Bing"}, {"baidu", "百度"}, {"google", "Google"}, {"duckduckgo", "DuckDuckGo"}}
	},
	"networks": func() []panelChoice {
		return []panelChoice{{"auto", "自动"}, {"internal", "内网"}, {"external", "外网"}, {"mixed", "混合"}}
	},
}).ParseFS(assets, "portal.html"))

func (p *Portal) serve(route WebRoute, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// no-referrer can turn a native form POST Origin into "null". Keep origin
	// information for same-origin forms, without leaking it to external links.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https: http:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if strings.HasPrefix(r.URL.Path, iconPrefix) {
		serveCachedIcon(p.store.dir, w, r)
		return
	}
	for _, f := range []string{"portal.css", "scrollbars.css", "button-feedback.css", "portal.js", "panel-logo.svg", "grain.svg"} {
		if r.URL.Path == "/__linknest/"+f && r.Method == "GET" {
			b, _ := assets.ReadFile(f)
			mime := "text/css"
			if f == "portal.js" {
				mime = "application/javascript"
			}
			if strings.HasSuffix(f, ".svg") {
				mime = "image/svg+xml"
			}
			w.Header().Set("Content-Type", mime+"; charset=utf-8")
			w.Write(b)
			return
		}
	}
	if !route.PublicAccess && route.AccessPassword == "" {
		http.Error(w, "尚未设置访问密码", 503)
		return
	}
	now := time.Now()
	cookieName := "ln_portal_" + route.ID
	cookie, _ := r.Cookie(cookieName)
	sid := ""
	if cookie != nil {
		sid = cookie.Value
	}
	p.mu.Lock()
	for k, v := range p.sessions {
		if now.After(v.Expires) {
			delete(p.sessions, k)
		}
	}
	for k, v := range p.attempts {
		if now.After(v.until) {
			delete(p.attempts, k)
		}
	}
	sess, ok := p.sessions[sid]
	logged := ok && sess.Route == route.ID && sess.Hash == route.AccessPassword
	p.mu.Unlock()
	if route.PublicAccess {
		logged = p.validPublicToken(route.ID, sid, now)
		if r.Method == "GET" && r.URL.Path == "/" && !logged {
			sid = p.publicToken(route.ID, now)
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sid, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 28800})
			logged = true
		}
	}
	message := ""
	if r.Method == "POST" {
		if !portalOrigin(r) {
			http.Error(w, "请求来源无效", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if r.ParseForm() != nil {
			http.Error(w, "请求无效", 400)
			return
		}
		if r.URL.Path == "/__linknest/login" {
			if route.PublicAccess {
				http.NotFound(w, r)
				return
			}
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			key := route.ID + ":" + ip
			p.mu.Lock()
			at := p.attempts[key]
			limited := at.n >= 6 || len(p.attempts) > 1024
			at.n++
			at.until = now.Add(5 * time.Minute)
			p.attempts[key] = at
			p.mu.Unlock()
			if limited {
				http.Error(w, "尝试过多，请 5 分钟后重试", 429)
				return
			}
			if bcrypt.CompareHashAndPassword([]byte(route.AccessPassword), []byte(r.Form.Get("password"))) == nil {
				sid = token(32)
				p.mu.Lock()
				if len(p.sessions) >= 128 {
					p.mu.Unlock()
					http.Error(w, "会话过多", 429)
					return
				}
				p.sessions[sid] = portalSession{Route: route.ID, Hash: route.AccessPassword, Expires: now.Add(8 * time.Hour)}
				delete(p.attempts, key)
				p.mu.Unlock()
				http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sid, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: 28800})
				http.Redirect(w, r, "/", 303)
				return
			}
			message = "访问密码不正确"
		} else {
			if !logged || subtle.ConstantTimeCompare([]byte(r.Form.Get("csrf")), []byte(sid)) != 1 {
				http.Error(w, "请重新登录", 403)
				return
			}
			if r.URL.Path == "/__linknest/logout" {
				p.mu.Lock()
				delete(p.sessions, sid)
				p.mu.Unlock()
				http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
				http.Redirect(w, r, "/", 303)
				return
			}
			if route.Backend == "wol" && r.URL.Path == "/__linknest/wake" {
				for _, d := range p.store.snapshot().Devices {
					if d.ID == r.Form.Get("id") {
						if err := wake(d); err != nil {
							fail(w, 502, "唤醒包发送失败")
							return
						}
						p.log("info", "WOL 入口已向 "+d.Name+" 发送唤醒包")
						respond(w, 200, map[string]any{"ok": true, "message": "已发送，请确认设备是否开机"})
						return
					}
				}
			}
			if route.Backend == "wol" && r.URL.Path == "/__linknest/devices/check" {
				p.checkDevices(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}
	} else if r.Method != "GET" || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := struct {
		Title, Error, CSRF string
		LoggedIn, WOL      bool
		PublicAccess       bool
		Devices            []Device
		Groups             []panelGroup
		Panel              PanelConfig
		Network            string
	}{Title: route.Name, Error: message, CSRF: sid, LoggedIn: logged, WOL: route.Backend == "wol", PublicAccess: route.PublicAccess}
	if data.WOL {
		data.Title = "网络唤醒"
	}
	if logged {
		c := p.store.snapshot()
		if data.WOL {
			data.Devices = c.Devices
		} else {
			data.Panel = c.Panel
			mode := c.Panel.NetworkMode
			if mode == "" {
				mode = "external"
			}
			if chosen := r.URL.Query().Get("network"); oneOf(chosen, "auto", "internal", "external", "mixed") {
				mode = chosen
			}
			data.Panel.NetworkMode = mode
			data.Groups = panelGroupsForNetwork(c, r.RemoteAddr, mode)
			if c.Panel.Title != "" {
				data.Title = c.Panel.Title
			}
			data.Network = map[string]string{"auto": "自动", "internal": "内网", "external": "外网", "mixed": "混合"}[mode]
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	portalPage.Execute(w, data)
}

// Access is checked by serve before reaching this endpoint. Only configured
// devices are probed; callers cannot supply arbitrary IPs or ports. One batch
// per portal, with a short shared cache, bounds work on public WOL entrances.
func (p *Portal) checkDevices(w http.ResponseWriter, r *http.Request) {
	if !p.probeMu.TryLock() {
		fail(w, 429, "正在检测，请稍后刷新")
		return
	}
	defer p.probeMu.Unlock()
	devices := p.store.snapshot().Devices
	if time.Since(p.probedAt) >= 3*time.Second || !slices.Equal(devices, p.probedDevices) {
		out := make([]DeviceStatus, len(devices))
		var wg sync.WaitGroup
		slots := make(chan struct{}, 8)
		for i, d := range devices {
			select {
			case slots <- struct{}{}:
			case <-r.Context().Done():
				wg.Wait()
				return
			}
			wg.Add(1)
			go func(i int, d Device) {
				defer wg.Done()
				defer func() { <-slots }()
				out[i] = checkDevice(r.Context(), d)
			}(i, d)
		}
		wg.Wait()
		if r.Context().Err() != nil {
			return
		}
		p.probeResults, p.probedDevices, p.probedAt = out, devices, time.Now()
	}
	respond(w, 200, map[string]any{"ok": true, "devices": p.probeResults})
}
