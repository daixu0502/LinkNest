package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

// RFC 6238: SHA-1, six digits, 30 seconds; compatible with Microsoft Authenticator.
// Only ciphertext and one-way recovery-code hashes are persisted.
type twoFactorConfig struct {
	Secret         string   `json:"secret"`
	LastStep       int64    `json:"lastStep"`
	RecoveryHashes []string `json:"recoveryHashes"`
}
type twoFactorEnrollment struct {
	secret  string
	session string
	expires time.Time
}

func twoFactorState(auth authConfig) map[string]any {
	n := 0
	if auth.TwoFactor != nil {
		n = len(auth.TwoFactor.RecoveryHashes)
	}
	return map[string]any{"enabled": auth.TwoFactor != nil, "recoveryCodesRemaining": n}
}
func (a *App) validateTwoFactor() error {
	if a.auth.TwoFactor == nil {
		return nil
	}
	secret, err := a.store.unseal(a.auth.TwoFactor.Secret)
	key, decodeErr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || decodeErr != nil || len(key) != 20 || a.auth.PasswordHash == "" {
		return errors.New("两步验证密钥无效，请恢复原 auth.json 与 master.key；不会自动关闭验证")
	}
	return nil
}
func totpCode(secret string, step int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || step < 0 {
		return ""
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(step))
	h := hmac.New(sha1.New, key)
	h.Write(b[:])
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 15
	n := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1000000)
}
func totpStep(secret, code string, now time.Time, last int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, false
	}
	step := now.Unix() / 30
	// Check the current step first, then allow one step of clock skew.
	for _, n := range []int64{step, step - 1, step + 1} {
		if n > last && subtle.ConstantTimeCompare([]byte(totpCode(secret, n)), []byte(code)) == 1 {
			return n, true
		}
	}
	return 0, false
}
func recoveryHash(code string) string {
	code = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if len(code) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(code); err != nil {
		return ""
	}
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}
func newRecoveryCodes() ([]string, []string, error) {
	codes, hashes := []string{}, []string{}
	for i := 0; i < 10; i++ {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, nil, err
		}
		s := strings.ToUpper(hex.EncodeToString(b[:]))
		code := s[:8] + "-" + s[8:16] + "-" + s[16:24] + "-" + s[24:]
		codes = append(codes, code)
		hashes = append(hashes, recoveryHash(code))
	}
	return codes, hashes, nil
}

// Caller holds a.mu. Mutate a copy; only saveAuthLocked commits consumption.
func (a *App) consumeSecondFactor(auth *authConfig, code string, now time.Time) bool {
	if auth.TwoFactor == nil {
		return false
	}
	next := *auth.TwoFactor
	secret, err := a.store.unseal(next.Secret)
	if err != nil {
		return false
	}
	if step, ok := totpStep(secret, code, now, next.LastStep); ok {
		next.LastStep = step
		auth.TwoFactor = &next
		return true
	}
	hash := recoveryHash(code)
	if hash == "" {
		return false
	}
	for i, v := range next.RecoveryHashes {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(v)) == 1 {
			next.RecoveryHashes = append(append([]string{}, next.RecoveryHashes[:i]...), next.RecoveryHashes[i+1:]...)
			auth.TwoFactor = &next
			return true
		}
	}
	return false
}
func (a *App) saveAuthLocked(auth authConfig) error {
	b, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	if err = writeAtomic(filepath.Join(a.store.dir, "auth.json"), b); err != nil {
		return err
	}
	a.auth = auth
	return nil
}

// Sensitive authenticated operations have their own bounded, session-keyed limiter.
func (a *App) securityProofLocked(w http.ResponseWriter, r *http.Request, auth *authConfig, password, code string, requireSecond bool) (authorized, freshFactor bool) {
	ck, err := r.Cookie(adminCookieName(r))
	if err != nil {
		fail(w, 401, "请重新登录")
		return false, false
	}
	s, ok := a.sessions[ck.Value]
	if !ok || !time.Now().Before(s.expires) || s.secure != (r.TLS != nil) {
		fail(w, 401, "请重新登录")
		return false, false
	}
	key := "security:" + ck.Value
	now := time.Now()
	for k, v := range a.failures {
		if now.After(v.until) {
			delete(a.failures, k)
		}
	}
	at := a.failures[key]
	if at.n >= 6 || len(a.failures) > 1024 {
		fail(w, 429, "验证尝试过多，请 5 分钟后重试")
		return false, false
	}
	valid := bcrypt.CompareHashAndPassword([]byte(auth.PasswordHash), []byte(password)) == nil
	if valid && requireSecond && auth.TwoFactor != nil && trustedUntil(*auth, r, now).IsZero() {
		if strings.TrimSpace(code) == "" {
			respond(w, 403, map[string]any{"error": "请补充动态验证码或恢复码", "errorCode": "two_factor_required", "twoFactorRequired": true})
			return false, false
		}
		valid = a.consumeSecondFactor(auth, code, now)
		freshFactor = valid
	}
	if !valid {
		at.n++
		at.until = now.Add(5 * time.Minute)
		a.failures[key] = at
		fail(w, 403, "密码或动态验证码 / 恢复码不正确（验证码不可重复使用）")
		return false, false
	}
	return true, freshFactor
}
func (a *App) twoFactorAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "仅支持 POST")
		return
	}
	var q struct {
		Password    string `json:"password"`
		Code        string `json:"code"`
		TrustDevice bool   `json:"trustDevice"`
	}
	if !decode(w, r, &q) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	auth := a.auth
	if ok, _ := a.securityProofLocked(w, r, &auth, q.Password, q.Code, r.URL.Path != "/api/2fa/begin"); !ok {
		return
	}
	ck, _ := r.Cookie(adminCookieName(r))
	switch r.URL.Path {
	case "/api/2fa/begin":
		if auth.TwoFactor != nil {
			fail(w, 409, "已开启两步验证，请先关闭再重新绑定")
			return
		}
		var b [20]byte
		if _, err := rand.Read(b[:]); err != nil {
			fail(w, 500, "无法生成绑定密钥")
			return
		}
		secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
		uri := url.URL{Scheme: "otpauth", Host: "totp", Path: "/LinkNest:" + auth.Username}
		query := url.Values{"secret": {secret}, "issuer": {"LinkNest"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
		uri.RawQuery = query.Encode()
		png, err := qrcode.Encode(uri.String(), qrcode.Medium, 256)
		if err != nil {
			fail(w, 500, "无法生成二维码")
			return
		}
		a.twoFactorPending = &twoFactorEnrollment{secret: secret, session: ck.Value, expires: time.Now().Add(10 * time.Minute)}
		respond(w, 200, map[string]any{"ok": true, "secret": secret, "qrDataURL": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), "expiresIn": 600})
		return
	case "/api/2fa/enable":
		pending := a.twoFactorPending
		if auth.TwoFactor != nil || pending == nil || pending.session != ck.Value || time.Now().After(pending.expires) {
			fail(w, 409, "绑定已过期，请重新开始")
			return
		}
		step, ok := totpStep(pending.secret, q.Code, time.Now(), -1)
		if !ok {
			key := "security:" + ck.Value
			at := a.failures[key]
			at.n++
			at.until = time.Now().Add(5 * time.Minute)
			a.failures[key] = at
			fail(w, 403, "验证码不正确，请确认手机时间自动同步")
			return
		}
		secret, err := a.store.seal(pending.secret)
		if err != nil {
			fail(w, 500, "无法加密绑定密钥")
			return
		}
		codes, hashes, err := newRecoveryCodes()
		if err != nil {
			fail(w, 500, "无法生成恢复码")
			return
		}
		auth.TwoFactor = &twoFactorConfig{Secret: secret, LastStep: step, RecoveryHashes: hashes}
		auth.TrustedBrowsers = nil
		if !a.saveSecurityProofLocked(w, r, auth, q.TrustDevice) {
			return
		}
		a.twoFactorPending = nil
		delete(a.failures, "security:"+ck.Value)
		a.revokeOtherSessionsLocked(ck.Value)
		respond(w, 200, map[string]any{"ok": true, "recoveryCodes": codes})
	case "/api/2fa/disable", "/api/2fa/recovery":
		if auth.TwoFactor == nil {
			fail(w, 409, "尚未开启两步验证")
			return
		}
		var codes []string
		if r.URL.Path == "/api/2fa/disable" {
			auth.TwoFactor = nil
		} else {
			var hashes []string
			var err error
			codes, hashes, err = newRecoveryCodes()
			if err != nil {
				fail(w, 500, "无法生成恢复码")
				return
			}
			next := *auth.TwoFactor
			next.RecoveryHashes = hashes
			auth.TwoFactor = &next
		}
		auth.TrustedBrowsers = nil
		if a.saveAuthLocked(auth) != nil {
			fail(w, 500, "无法保存验证设置")
			return
		}
		a.twoFactorPending = nil
		delete(a.failures, "security:"+ck.Value)
		a.revokeOtherSessionsLocked(ck.Value)
		clearTrustCookie(w, r)
		respond(w, 200, map[string]any{"ok": true, "recoveryCodes": codes})
	default:
		fail(w, 404, "接口不存在")
	}
}
func (a *App) revokeOtherSessionsLocked(keep string) {
	a.terminals.revoke("")
	for id := range a.sessions {
		if id != keep {
			delete(a.sessions, id)
		}
	}
}
