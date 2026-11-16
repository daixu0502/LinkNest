package app

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

const browserTrustLifetime = 24 * time.Hour
const maxTrustedBrowsers = 32

// A trust token is only a second-factor proof, never a login session.
// Raw tokens live exclusively in host-only HttpOnly cookies.
type trustedBrowser struct {
	Hash    string    `json:"hash"`
	Host    string    `json:"host"`
	Secure  bool      `json:"secure"`
	Expires time.Time `json:"expires"`
}

func trustCookieName(r *http.Request) string {
	if r.TLS != nil {
		return "__Host-linknest_trust_v1"
	}
	return "linknest_http_trust_v1"
}

func trustHash(value string) string {
	if len(value) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func requestTrustHash(r *http.Request) string {
	ck, err := r.Cookie(trustCookieName(r))
	if err != nil {
		return ""
	}
	return trustHash(ck.Value)
}

func trustedUntil(auth authConfig, r *http.Request, now time.Time) time.Time {
	if auth.TwoFactor == nil {
		return time.Time{}
	}
	hash := requestTrustHash(r)
	if hash == "" {
		return time.Time{}
	}
	for _, b := range auth.TrustedBrowsers {
		if b.Secure == (r.TLS != nil) && b.Host == strings.ToLower(r.Host) && now.Before(b.Expires) &&
			b.Expires.Sub(now) <= browserTrustLifetime && subtle.ConstantTimeCompare([]byte(b.Hash), []byte(hash)) == 1 {
			return b.Expires
		}
	}
	return time.Time{}
}

func clearTrustCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: trustCookieName(r), Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.Header().Set("X-LinkNest-Trusted-Until", "0")
}

// Called under a.mu only after a successful password and second-factor proof.
// Persist consumed codes and new trust together, before emitting any cookie.
// remember must be false for a reused trust proof, even if it expires while saving.
func (a *App) saveSecurityProofLocked(w http.ResponseWriter, r *http.Request, auth authConfig, remember bool) bool {
	now := time.Now()
	until := trustedUntil(auth, r, now)
	var cookie *http.Cookie
	if remember && auth.TwoFactor != nil && until.IsZero() {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			fail(w, 500, "无法创建浏览器信任，请稍后重试")
			return false
		}
		value := hex.EncodeToString(raw[:])
		kept := make([]trustedBrowser, 0, maxTrustedBrowsers)
		for _, b := range auth.TrustedBrowsers {
			if now.Before(b.Expires) && b.Expires.Sub(now) <= browserTrustLifetime {
				kept = append(kept, b)
			}
		}
		for len(kept) >= maxTrustedBrowsers {
			oldest := 0
			for i := range kept {
				if kept[i].Expires.Before(kept[oldest].Expires) {
					oldest = i
				}
			}
			kept = append(kept[:oldest], kept[oldest+1:]...)
		}
		until = now.UTC().Add(browserTrustLifetime)
		auth.TrustedBrowsers = append(kept, trustedBrowser{Hash: trustHash(value), Host: strings.ToLower(r.Host), Secure: r.TLS != nil, Expires: until})
		cookie = &http.Cookie{Name: trustCookieName(r), Value: value, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: int(browserTrustLifetime.Seconds()), Expires: until}
	}
	if err := a.saveAuthLocked(auth); err != nil {
		fail(w, 500, "无法保存验证状态，请稍后重试")
		return false
	}
	if cookie != nil {
		http.SetCookie(w, cookie)
	}
	if !until.IsZero() {
		w.Header().Set("X-LinkNest-Trusted-Until", until.Format(time.RFC3339Nano))
	}
	return true
}

// Revocation must reach disk before we acknowledge logout/cancellation.
func (a *App) revokeBrowserTrustLocked(w http.ResponseWriter, r *http.Request) bool {
	hash, now := requestTrustHash(r), time.Now()
	auth := a.auth
	kept := make([]trustedBrowser, 0, len(auth.TrustedBrowsers))
	for _, b := range auth.TrustedBrowsers {
		matches := hash != "" && b.Secure == (r.TLS != nil) && b.Host == strings.ToLower(r.Host) && subtle.ConstantTimeCompare([]byte(b.Hash), []byte(hash)) == 1
		if !matches && now.Before(b.Expires) {
			kept = append(kept, b)
		}
	}
	if len(kept) != len(auth.TrustedBrowsers) {
		auth.TrustedBrowsers = kept
		if err := a.saveAuthLocked(auth); err != nil {
			fail(w, 500, "无法撤销浏览器信任，请重试")
			return false
		}
	}
	clearTrustCookie(w, r)
	return true
}

func (a *App) cancelBrowserTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "仅支持 POST")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.revokeBrowserTrustLocked(w, r) {
		respond(w, 200, map[string]bool{"ok": true})
	}
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "仅支持 POST")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.revokeBrowserTrustLocked(w, r) {
		return
	}
	if ck, err := r.Cookie(adminCookieName(r)); err == nil {
		delete(a.sessions, ck.Value)
		a.terminals.revoke(ck.Value)
	}
	clearAdminCookie(w, r)
	respond(w, 200, map[string]bool{"ok": true})
}
