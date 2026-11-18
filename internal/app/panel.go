package app

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

type PanelConfig struct {
	Title            string       `json:"title,omitempty"`
	Subtitle         string       `json:"subtitle,omitempty"`
	Logo             string       `json:"logo,omitempty"`
	Favicon          string       `json:"favicon,omitempty"`
	Background       string       `json:"background,omitempty"`
	BackgroundPreset string       `json:"backgroundPreset,omitempty"`
	Theme            string       `json:"theme,omitempty"`
	Layout           string       `json:"layout,omitempty"`
	NetworkMode      string       `json:"networkMode,omitempty"`
	InternalCIDRs    []string     `json:"internalCidrs,omitempty"`
	Groups           []string     `json:"groups,omitempty"`
	HideDescription  bool         `json:"hideDescription,omitempty"`
	HideHeader       bool         `json:"hideHeader,omitempty"`
	HideSearch       bool         `json:"hideSearch,omitempty"`
	ShowClock        bool         `json:"showClock,omitempty"`
	ClockStyle       string       `json:"clockStyle,omitempty"`
	HideWebSearch    bool         `json:"hideWebSearch,omitempty"`
	SearchEngine     string       `json:"searchEngine,omitempty"`
	IconSources      []IconSource `json:"iconSources"`
}

type IconSource struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	URL      string `json:"url"`
	Disabled bool   `json:"disabled,omitempty"`
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func defaultPanelCIDRs() []string {
	return []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7"}
}

func webURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil && len(value) <= 4096
}
func validatePanel(c Config) error {
	p := c.Panel
	if !oneOf(p.ClockStyle, "", "vector", "simple", "digital", "stacked") {
		return errors.New("未知时间日期样式")
	}
	if !oneOf(p.SearchEngine, "", "bing", "baidu", "duckduckgo", "google") {
		return errors.New("未知搜索引擎")
	}
	for _, v := range []string{p.Logo, p.Favicon, p.Background} {
		if v != "" && !webURL(v) {
			return errors.New("面板图片地址必须为不带账号的 HTTP/HTTPS 地址")
		}
	}
	if len(p.Title) > 120 || len(p.Subtitle) > 500 || len(p.Groups) > 64 || len(p.InternalCIDRs) > 64 {
		return errors.New("面板设置超出长度或数量限制")
	}
	if p.Theme != "" && p.Theme != "auto" && p.Theme != "light" && p.Theme != "dark" {
		return errors.New("未知面板主题")
	}
	if !oneOf(p.Layout, "", "cards", "compact", "list", "minimal") {
		return errors.New("未知面板布局")
	}
	if !oneOf(p.NetworkMode, "", "external", "internal", "auto", "mixed") {
		return errors.New("未知面板网络模式")
	}
	if !oneOf(p.BackgroundPreset, "", "aurora", "sunset", "ocean", "forest", "dusk", "slate", "mist", "spectrum") {
		return errors.New("未知面板背景")
	}
	if len(p.IconSources) > 12 {
		return errors.New("最多配置 12 个图标源")
	}
	sourceIDs := map[string]bool{}
	for _, source := range p.IconSources {
		u, err := url.Parse(source.URL)
		if len(source.ID) == 0 || len(source.ID) > 100 || sourceIDs[source.ID] || strings.TrimSpace(source.Name) == "" || len(source.Name) > 100 || !oneOf(source.Kind, "iconify", "selfhst", "json") || !webURL(source.URL) || err != nil || u.Scheme != "https" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("图标源需唯一标识、名称及不带查询参数的 HTTPS 地址，类型为 Iconify、selfh.st 或 JSON")
		}
		sourceIDs[source.ID] = true
	}
	seen := map[string]bool{}
	for _, g := range p.Groups {
		if strings.TrimSpace(g) == "" || len(g) > 100 || seen[g] {
			return errors.New("分组名不能为空、重复或超过 100 字节")
		}
		seen[g] = true
	}
	for _, cidr := range p.InternalCIDRs {
		if _, _, e := net.ParseCIDR(cidr); e != nil {
			return errors.New("内网识别网段需要 CIDR 格式")
		}
	}
	for _, b := range c.Bookmarks {
		if strings.TrimSpace(b.Name) == "" || len(b.Name) > 160 || len(b.Description) > 500 || len(b.Group) > 100 || len(b.URLs) > 16 || len(b.InternalURLs) > 16 {
			return errors.New("站点名称不能为空，或站点字段超出限制")
		}
		for _, u := range append(append([]string{}, b.URLs...), b.InternalURLs...) {
			if !webURL(u) {
				return errors.New("站点链接必须为不带账号的 HTTP/HTTPS 地址")
			}
		}
		if b.Icon != "" && !webURL(b.Icon) && !localIconURL(b.Icon) {
			return errors.New("站点图标必须为 HTTP/HTTPS 地址或本地图标缓存")
		}
		if b.IconSourceURL != "" && (!webURL(b.IconSourceURL) || !strings.HasPrefix(b.IconSourceURL, "https://") || !localIconURL(b.Icon)) {
			return errors.New("高清缓存原图地址必须为不带账号的 HTTPS 地址，且与本地图标缓存一起保存")
		}
	}
	return nil
}

// Direct socket peer only: forwarded headers must not expose internal URLs to a
// visitor spoofing X-Forwarded-For. Auto is a convenience, never authorization.
func panelInternal(p PanelConfig, peer string) bool {
	if p.NetworkMode == "internal" {
		return true
	}
	if p.NetworkMode != "auto" {
		return false
	}
	host, _, _ := net.SplitHostPort(peer)
	ip := net.ParseIP(host)
	ranges := p.InternalCIDRs
	if len(ranges) == 0 {
		ranges = defaultPanelCIDRs()
	}
	for _, cidr := range ranges {
		_, n, e := net.ParseCIDR(cidr)
		if e == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

type panelLink struct {
	Name, Description, Icon, Target string
	URLs                            []string
	Labels                          []string
}
type panelGroup struct {
	Name  string
	Links []panelLink
}

func panelGroups(c Config, peer string) []panelGroup {
	return panelGroupsForNetwork(c, peer, c.Panel.NetworkMode)
}

func panelGroupsForNetwork(c Config, peer, mode string) []panelGroup {
	c.Panel.NetworkMode = mode
	names := append([]string{}, c.Panel.Groups...)
	names = append(names, "")
	for _, b := range c.Bookmarks {
		found := false
		for _, g := range names {
			if g == b.Group {
				found = true
			}
		}
		if !found {
			names = append(names, b.Group)
		}
	}
	groups := []panelGroup{}
	for _, name := range names {
		group := panelGroup{Name: name, Links: []panelLink{}}
		if name == "" {
			group.Name = "未分组"
		}
		for _, b := range c.Bookmarks {
			if b.Disabled || b.Group != name {
				continue
			}
			urls := b.URLs
			if len(urls) == 0 {
				urls = []string{b.URL}
			}
			labels := make([]string, len(urls))
			for i := range labels {
				labels[i] = "外网"
			}
			if panelInternal(c.Panel, peer) && len(b.InternalURLs) > 0 {
				urls = b.InternalURLs
				labels = make([]string, len(urls))
				for i := range labels {
					labels[i] = "内网"
				}
			} else if mode == "mixed" {
				urls = append([]string{}, urls...)
				for _, u := range b.InternalURLs {
					if !oneOf(u, urls...) {
						urls = append(urls, u)
						labels = append(labels, "内网")
					}
				}
			}
			target := "_blank"
			if b.SameTab {
				target = "_self"
			}
			group.Links = append(group.Links, panelLink{Name: b.Name, Description: b.Description, Icon: b.Icon, Target: target, URLs: urls, Labels: labels})
		}
		if len(group.Links) > 0 {
			groups = append(groups, group)
		}
	}
	return groups
}
