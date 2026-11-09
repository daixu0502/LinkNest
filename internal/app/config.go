package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"linknest/internal/access"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const version = "1.2.5"
const configSchema = 5

type Rule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Kind             string     `json:"kind"`
	Enabled          bool       `json:"enabled"`
	Listen           string     `json:"listen"`
	Target           string     `json:"target"`
	Domain           string     `json:"domain"`
	TLS              bool       `json:"tls"`
	RedirectHTTP     bool       `json:"redirectHttp,omitempty"`
	Certificate      string     `json:"certificate"`
	OpenFirewall     bool       `json:"openFirewall"`
	Network          string     `json:"network,omitempty"`
	ForwardMode      string     `json:"forwardMode,omitempty"`
	PreserveClientIP bool       `json:"preserveClientIp,omitempty"`
	Routes           []WebRoute `json:"routes,omitempty"`
}
type WebRoute struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Enabled        bool     `json:"enabled"`
	Domains        []string `json:"domains"`
	PathPrefix     string   `json:"pathPrefix"`
	Target         string   `json:"target"`
	SkipTLSVerify  bool     `json:"skipTlsVerify"`
	PreserveHost   bool     `json:"preserveHost,omitempty"`
	RewriteOrigin  bool     `json:"rewriteOrigin,omitempty"`
	Backend        string   `json:"backend"`
	AccessPassword string   `json:"accessPassword"`
	PublicAccess   bool     `json:"publicAccess,omitempty"`
}
type DNSAccount struct {
	AccessKeyID string `json:"accessKeyId"`
	Secret      string `json:"secret"`
}
type DDNSRule struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	Zone          string       `json:"zone"`
	RR            string       `json:"rr"`
	Type          string       `json:"type"`
	SourceURL     string       `json:"sourceUrl"`
	Enabled       bool         `json:"enabled"`
	Account       DNSAccount   `json:"account"`
	CredentialRef string       `json:"credentialRef"`
	Records       []DDNSRecord `json:"records"`
	IPv4          IPSource     `json:"ipv4"`
	IPv6          IPSource     `json:"ipv6"`
	Interval      int          `json:"interval"`
	StartDelay    int          `json:"startDelay"`
}
type IPSource struct {
	Mode      string `json:"mode"`
	Interface string `json:"interface"`
	URL       string `json:"url"`
}
type DDNSRecord struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Zone     string   `json:"zone"`
	Domain   string   `json:"domain"`
	Type     string   `json:"type"`
	Value    string   `json:"value"`
	TTL      int      `json:"ttl"`
	Line     string   `json:"line"`
	Priority int      `json:"priority,omitempty"`
	Source   IPSource `json:"source"`
}
type Bookmark struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	URL           string   `json:"url"`
	Group         string   `json:"group"`
	Description   string   `json:"description,omitempty"`
	URLs          []string `json:"urls,omitempty"`
	InternalURLs  []string `json:"internalUrls,omitempty"`
	Icon          string   `json:"icon,omitempty"`
	IconSourceURL string   `json:"iconSourceUrl,omitempty"`
	SameTab       bool     `json:"sameTab,omitempty"`
	Disabled      bool     `json:"disabled,omitempty"`
}
type Device struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	Broadcast string `json:"broadcast"`
	IP        string `json:"ip,omitempty"`
	CheckPort int    `json:"checkPort,omitempty"`
}
type SSHHost struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	Username    string `json:"username"`
	Fingerprint string `json:"fingerprint"`
}
type Config struct {
	Access          access.Config  `json:"access"`
	AdminTLS        AdminTLSConfig `json:"adminTls"`
	Schema          int            `json:"schema"`
	Rules           []Rule         `json:"rules"`
	DNS             DNSAccount     `json:"dns"`
	DDNS            []DDNSRule     `json:"ddns"`
	Bookmarks       []Bookmark     `json:"bookmarks"`
	Panel           PanelConfig    `json:"panel,omitempty"`
	Devices         []Device       `json:"devices"`
	SSHHosts        []SSHHost      `json:"sshHosts"`
	Blacklist       []string       `json:"blacklist"`
	Whitelist       []string       `json:"whitelist"`
	TerminalEnabled bool           `json:"terminalEnabled"`
}
type Store struct {
	mu  sync.RWMutex
	dir string
	key []byte
	cfg Config
}

func token(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".linknest-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}
func newStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, cfg: Config{Schema: 1, Rules: []Rule{}, DDNS: []DDNSRule{}, Bookmarks: []Bookmark{}, Devices: []Device{}, SSHHosts: []SSHHost{}, Blacklist: []string{}, Whitelist: []string{}}}
	kp := filepath.Join(dir, "master.key")
	b, err := os.ReadFile(kp)
	if errors.Is(err, os.ErrNotExist) {
		if auth, e := os.ReadFile(filepath.Join(dir, "auth.json")); e == nil && strings.Contains(string(auth), "enc:") {
			return nil, errors.New("已有加密两步验证密钥，但 master.key 缺失；请恢复原密钥")
		}
		metas, _ := filepath.Glob(filepath.Join(dir, "certificates", "*.renew.json"))
		for _, p := range metas {
			if b, e := os.ReadFile(p); e == nil && strings.Contains(string(b), "enc:") {
				return nil, errors.New("已有加密证书凭据，但 master.key 缺失；请恢复原密钥")
			}
		}
		if old, e := os.ReadFile(filepath.Join(dir, "config.json")); e == nil && strings.Contains(string(old), "enc:") {
			return nil, errors.New("已有加密配置，但 master.key 缺失；请恢复原密钥")
		}
		b = make([]byte, 32)
		if _, err = rand.Read(b); err != nil {
			return nil, err
		}
		err = writeAtomic(kp, b)
	}
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("master.key 长度错误，拒绝生成新密钥覆盖")
	}
	s.key = b
	b, err = os.ReadFile(filepath.Join(dir, "config.json"))
	existingConfig := err == nil
	if err == nil {
		err = json.Unmarshal(b, &s.cfg)
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	if s.cfg.Schema > configSchema {
		return nil, errors.New("配置来自更新版本，请勿直接降级")
	}
	previousSchema := s.cfg.Schema
	migrateConfig(&s.cfg)
	if existingConfig && previousSchema < configSchema {
		// Persist the migrated representation atomically. Do not run credential
		// replacement logic: existing encrypted secrets and password hashes must
		// remain byte-for-byte unchanged during a schema upgrade.
		data, e := json.MarshalIndent(s.cfg, "", "  ")
		if e != nil {
			return nil, e
		}
		if e = writeAtomic(filepath.Join(dir, "config.json"), data); e != nil {
			return nil, fmt.Errorf("保存迁移后的配置失败：%w", e)
		}
	}
	return s, nil
}
func (s *Store) snapshot() Config {
	c, _ := s.snapshotRevision()
	return c
}
func (s *Store) snapshotRevision() (Config, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := json.Marshal(s.cfg)
	var c Config
	_ = json.Unmarshal(b, &c)
	return c, fmt.Sprintf("\"%x\"", sha256.Sum256(b))
}

// Packet hot path: never JSON-copy credentials, certificates, and bookmarks.
func (s *Store) blockedIP(ip net.IP) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return blocked(ip, s.cfg)
}
func (s *Store) save(c Config) error {
	return s.saveExpected(c, "")
}

var errCredentialChange = errors.New("更换 AccessKey ID 时必须重新填写 Secret")

var errConfigConflict = errors.New("配置已被其他页面修改；请保留草稿并重新核对")

func (s *Store) saveExpected(c Config, expected string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != "" {
		b, _ := json.Marshal(s.cfg)
		if expected != fmt.Sprintf("\"%x\"", sha256.Sum256(b)) {
			return errConfigConflict
		}
	}
	if c.Schema > configSchema {
		return errors.New("配置来自更新版本，请勿直接降级")
	}
	migrateConfig(&c)
	for i := range c.Rules {
		for j := range c.Rules[i].Routes {
			r := &c.Rules[i].Routes[j]
			if r.PublicAccess && (r.Backend == "bookmarks" || r.Backend == "wol") {
				r.AccessPassword = "" // Explicit opt-out; an empty password alone still preserves protection.
				continue
			}
			previous := ""
			for _, old := range s.cfg.Rules {
				for _, sub := range old.Routes {
					if sub.ID == r.ID {
						previous = sub.AccessPassword
					}
				}
			}
			if r.AccessPassword == "" || r.AccessPassword == previous {
				for _, old := range s.cfg.Rules {
					for _, sub := range old.Routes {
						if sub.ID == r.ID {
							r.AccessPassword = sub.AccessPassword
						}
					}
				}
			} else {
				if len(r.AccessPassword) < 12 || len(r.AccessPassword) > 72 {
					return errors.New("内置页面访问密码需为 12—72 字节")
				}
				hash, err := bcrypt.GenerateFromPassword([]byte(r.AccessPassword), bcrypt.DefaultCost)
				if err != nil {
					return err
				}
				r.AccessPassword = string(hash)
			}
			if c.Rules[i].Enabled && r.Enabled && (r.Backend == "bookmarks" || r.Backend == "wol") && r.AccessPassword == "" {
				return errors.New("请设置入口访问密码，或明确开启免密码访问")
			}
		}
	}
	for i := range c.DDNS {
		r := &c.DDNS[i]
		previous := ""
		for _, old := range s.cfg.DDNS {
			if old.ID == r.ID {
				if r.Account.AccessKeyID != old.Account.AccessKeyID && r.Account.Secret == "" && r.Account.AccessKeyID != "" {
					return errCredentialChange
				}
				previous = old.Account.Secret
			}
		}
		if r.Account.Secret == "" || r.Account.Secret == previous {
			for _, old := range s.cfg.DDNS {
				if old.ID == r.ID {
					r.Account.Secret = old.Account.Secret
				}
			}
		} else {
			sealed, err := s.seal(r.Account.Secret)
			if err != nil {
				return err
			}
			r.Account.Secret = sealed
		}
	}
	if c.DNS.AccessKeyID != s.cfg.DNS.AccessKeyID && c.DNS.Secret == "" && c.DNS.AccessKeyID != "" {
		return errCredentialChange
	}
	if c.DNS.Secret == "" || c.DNS.Secret == s.cfg.DNS.Secret {
		c.DNS.Secret = s.cfg.DNS.Secret
	} else {
		v, e := s.seal(c.DNS.Secret)
		if e != nil {
			return e
		}
		c.DNS.Secret = v
	}
	c.Schema = configSchema
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	if e = writeAtomic(filepath.Join(s.dir, "config.json"), b); e != nil {
		return e
	}
	s.cfg = c
	return nil
}
func (s *Store) seal(v string) (string, error) {
	b, e := aes.NewCipher(s.key)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return "", e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return "", e
	}
	return "enc:" + base64.RawStdEncoding.EncodeToString(g.Seal(n, n, []byte(v), nil)), nil
}
func (s *Store) secret() (string, error) {
	return s.unseal(s.snapshot().DNS.Secret)
}
func (s *Store) unseal(v string) (string, error) {
	if v == "" {
		return "", errors.New("尚未设置阿里云 AccessKey Secret")
	}
	if !strings.HasPrefix(v, "enc:") {
		return "", errors.New("不支持的密钥格式")
	}
	b, e := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(v, "enc:"))
	if e != nil {
		return "", e
	}
	a, _ := aes.NewCipher(s.key)
	g, _ := cipher.NewGCM(a)
	if len(b) < g.NonceSize() {
		return "", errors.New("密钥损坏")
	}
	p, e := g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], nil)
	return string(p), e
}

var validID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,48}$`)
var domainRE = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)

func hostPort(v string) (string, int, error) {
	h, p, e := net.SplitHostPort(v)
	if e != nil {
		return "", 0, e
	}
	n, e := strconv.Atoi(p)
	if e != nil || n < 1 || n > 65535 {
		return "", 0, errors.New("端口需为 1—65535")
	}
	return h, n, nil
}
func validate(c Config, admin string) error {
	if err := validatePanel(c); err != nil {
		return err
	}
	if c.Schema > configSchema {
		return errors.New("配置来自更新版本，请勿直接降级")
	}
	migrateConfig(&c)
	if len(c.Rules) > 64 || len(c.DDNS) > 32 || len(c.Blacklist) > 256 || len(c.Whitelist) > 64 || len(c.Bookmarks) > 128 || len(c.Devices) > 64 || len(c.SSHHosts) > 32 {
		return errors.New("超出首版规则数量限制")
	}
	if err := access.Validate(c.Access); err != nil {
		return err
	}
	ids := map[string]bool{}
	seen := map[string][]Rule{}
	_, ap, _ := hostPort(admin)
	checkID := func(id string) error {
		if !validID.MatchString(id) || ids[id] {
			return errors.New("规则 ID 无效或重复")
		}
		ids[id] = true
		return nil
	}
	for _, r := range c.Rules {
		if e := checkID(r.ID); e != nil {
			return e
		}
		if strings.TrimSpace(r.Name) == "" {
			return errors.New("规则名称不能为空")
		}
		if r.Kind != "web" && r.Kind != "tcp" && r.Kind != "udp" && r.Kind != "tcpudp" {
			return errors.New("未知规则类型")
		}
		if r.ForwardMode != "" && r.ForwardMode != "proxy" && r.ForwardMode != "kernel" {
			return errors.New("未知转发模式")
		}
		if r.PreserveClientIP && (r.Kind == "web" || r.ForwardMode != "kernel") {
			return errors.New("保留客户端原始 IP 仅支持内核转发；兼容转发会重新建立连接")
		}
		if r.ForwardMode == "kernel" {
			if err := validateKernelRule(r); err != nil {
				return err
			}
		}
		h, p, e := hostPort(r.Listen)
		if e != nil {
			return fmt.Errorf("%s：监听地址需为 IP:端口", r.Name)
		}
		if h != "" && net.ParseIP(h) == nil {
			return errors.New("监听地址必须为 IP，不能是域名")
		}
		if r.OpenFirewall && (p < 1024 || p == ap || p == 3964 || p == 16601) {
			return errors.New("自动放行拒绝低端口、管理端口及保留端口")
		}
		if r.Enabled {
			for _, proto := range ruleProtocols(r) {
				k := proto + ":" + strconv.Itoa(p)
				if p == ap {
					return errors.New("监听端口与管理入口冲突")
				}
				for _, prev := range seen[k] {
					if listenersOverlap(prev, r) && (prev.Kind != "web" || r.Kind != "web" || webListenKey(prev) != webListenKey(r)) {
						return fmt.Errorf("%s 与 %s 监听冲突：同一协议、地址族及监听地址不能重叠；可分别使用仅 IPv4 和仅 IPv6 创建同端口规则", r.Name, prev.Name)
					}
				}
				seen[k] = append(seen[k], r)
			}
		}
		if r.Kind == "web" {
			if err := validateWeb(r, checkID); err != nil {
				return err
			}
		} else {
			th, tp, e := hostPort(r.Target)
			if e != nil || th == "" {
				return errors.New("转发目标需为主机:端口")
			}
			if r.Enabled && tp == p {
				for _, v6 := range []bool{false, true} {
					listenIP, ok := listenerAddress(r, v6)
					if !ok {
						continue
					}
					targetIP := net.ParseIP(th)
					if th == "localhost" || targetIP != nil && (targetIP.To4() == nil) == v6 && (targetIP.Equal(listenIP) || listenIP.IsUnspecified() && targetIP.IsLoopback()) {
						return errors.New("目标不能指向自身监听端口")
					}
				}
			}
		}
		if r.TLS && (r.Kind != "web" || !validID.MatchString(r.Certificate)) {
			return errors.New("TLS 仅用于 Web 规则，并需选择证书")
		}
		if r.RedirectHTTP && (!r.TLS || r.Kind != "web") {
			return errors.New("HTTP 自动跳转仅用于已启用 TLS 的反向代理")
		}
		if err := validateNetwork(r); err != nil {
			return err
		}
	}
	if err := validateSharedWebRules(c.Rules); err != nil {
		return err
	}
	if c.AdminTLS.Redirect && !c.AdminTLS.Enabled {
		return errors.New("请先启用管理 HTTPS，再开启 HTTP 跳转")
	}
	if c.AdminTLS.Enabled && !validID.MatchString(c.AdminTLS.Certificate) {
		return errors.New("管理 HTTPS 需要选择有效证书")
	}
	for _, r := range c.DDNS {
		if e := checkID(r.ID); e != nil {
			return e
		}
		if err := validateDDNSTask(r, c, checkID); err != nil {
			return err
		}
	}
	for _, b := range c.Bookmarks {
		if e := checkID(b.ID); e != nil {
			return e
		}
		u, e := url.Parse(b.URL)
		if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return errors.New("导航链接必须为 HTTP/HTTPS")
		}
	}
	for _, d := range c.Devices {
		if e := checkID(d.ID); e != nil {
			return e
		}
		if _, e := parseWOLMAC(d.MAC); e != nil {
			return fmt.Errorf("设备 %q：%w", d.Name, e)
		}
		if net.ParseIP(d.Broadcast).To4() == nil {
			return errors.New("WOL 广播地址需为 IPv4")
		}
		if d.IP != "" && net.ParseIP(d.IP).To4() == nil {
			return errors.New("在线检测地址需为 IPv4，不是广播地址")
		}
		if d.CheckPort < 0 || d.CheckPort > 65535 {
			return errors.New("在线检测 TCP 端口需为 1—65535；留空使用 Ping")
		}
	}
	for _, h := range c.SSHHosts {
		if e := checkID(h.ID); e != nil {
			return e
		}
		a, _, e := hostPort(h.Address)
		if e != nil || a == "" || h.Username == "" {
			return errors.New("SSH 地址或用户名不完整")
		}
		if h.Fingerprint != "" && !strings.HasPrefix(h.Fingerprint, "SHA256:") {
			return errors.New("SSH 指纹需以 SHA256: 开头；可留空，在连接时获取并确认")
		}
	}
	for _, s := range append(append([]string{}, c.Blacklist...), c.Whitelist...) {
		if net.ParseIP(s) == nil {
			if _, _, e := net.ParseCIDR(s); e != nil {
				return fmt.Errorf("无效 IP/CIDR：%s", s)
			}
		}
	}
	return nil
}
func blocked(ip net.IP, c Config) bool {
	match := func(v string) bool {
		if x := net.ParseIP(v); x != nil {
			return x.Equal(ip)
		}
		_, n, e := net.ParseCIDR(v)
		return e == nil && n.Contains(ip)
	}
	for _, s := range c.Whitelist {
		if match(s) {
			return false
		}
	}
	for _, s := range c.Blacklist {
		if match(s) {
			return true
		}
	}
	return false
}
