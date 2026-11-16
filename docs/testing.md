# LinkNest 1.2.0 测试

## 浏览器信任与手机轻面板

- 本地 `trusted_devices_test.go` 覆盖 24 小时固定到期、8 小时会话隔离、重启、多标签页、HTTP/HTTPS 与 Host 隔离、伪造令牌、UPnP 验证复用、安全设置全局撤销、过期会话主动退出、限额及原子保存失败。原有 TOTP、防重放、恢复码与限流测试继续执行。
- 本地 `scripts/test-trust-mobile.cjs` 启动隔离的真实程序，使用临时数据目录和容器回环端口；覆盖真实登录信任、重启免动态码、跨标签页撤销后原弹窗补验和字段保留。Chromium / WebKit 检查 320–430px、横屏、短视口和桌面，包含四种布局、深浅主题、菜单、触控尺寸及背景加载 / 失败。
- 在本机 WSL Docker 中构建测试二进制后设置 `LINKNEST_QA_BINARY`，或使用默认本地路径 `.tools/trust-mobile-20261116/linknest`；依赖沿用 `.tools/qa-node/node_modules`。测试记录与截图保存在被忽略的 `.tools/trust-mobile-20261116/`，不进入源码包。
- iPhone Safari 真机需另行记录 iOS/Safari 版本，验收地址栏展开 / 收起、状态栏、底部安全区、回弹与真实软键盘；WebKit 自动测试不等同于此项通过。

接口兼容：登录及二次验证请求新增可选布尔值 `trustDevice`；`GET /api/state` 的 `twoFactor.trustedUntil` 仅在当前信任有效时提供。需要补验时，管理操作返回 HTTP 403、`errorCode: "two_factor_required"` 和 `twoFactorRequired: true`；登录继续沿用原有的验证码挑战响应。`POST /api/2fa/trust/revoke` 仅撤销当前浏览器信任；与退出接口一样，登录过期后仍可调用，但继续要求同源及 `X-LinkNest-Request` 校验。服务端认证文件新增可选 `trustedBrowsers`，旧文件无需迁移，原子保存最多 32 条哈希记录；旧版本不认识此字段时恢复原有逐次验证码行为。

## 运行

```sh
go test ./...
go vet ./...
node scripts/test-ui.mjs
node scripts/test-workflows.mjs
node scripts/test-panel.mjs
node scripts/test-security.mjs
node scripts/test-twofactor.mjs
node scripts/test-notices.mjs
node scripts/test-interaction.mjs
node scripts/test-upnp.mjs
go build -trimpath -o bin/linknest ./cmd/linknest
```

可选 `go test -race ./...` 需支持的 CGO 工具链。ARM64 交叉编译使用 `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`；编译成功不等于在设备运行成功。

新增转发回归可运行 `go test ./internal/app -run 'TestForward|TestKernelFamily|TestKernelIPv6'` 和 `node scripts/test-forward-families.mjs`。本地 `.tools/test-forward-netns.py` 在 Linux 新建独立客户端、路由器和后端网络命名空间，使用 `.tools/forward-tests-linux-amd64`，实测 IPv4 / IPv6 TCP、UDP 同端口内核转发、来源地址转换开关和单地址族清理；需 root、`unshare`、`nsenter`、`ip` 及 legacy iptables/ip6tables，不连接生产网络。该脚本和测试代码只在本地保留。

## 自动回归范围

- UPnP 服务发现、同地址控制 URL、无代理/跳转、SOAP 错误、映射增删改与竞争保护、失败恢复；与 LinkNest 规则冲突、登录/CSRF、并发拒绝和独立数据保存。
- UPnP 刷新保留旧内容、后台状态轮询不重建页面、相同内容保留 DOM 与焦点；慢请求合并、失败保留上次结果、会话失效清空缓存及丢弃过期响应；桌面与手机验证卡片高度稳定。
- UPnP 原厂黑名单仅操作自有 UCI / INPUT 规则；模拟预检查失败、应用失败、并发写与回滚。跨设备管理开关模拟开启、关闭、取消及 EOF 回滚；SSH 指纹校验与两阶段确认、现有映射保留检查。原厂模式切换不在生产自动触发。
- 原厂 UPnP 启动、停止及回滚路径显式关闭子进程锁描述符；模拟服务拒绝继承事务锁，避免守护进程持续占锁导致后续黑名单应用失败。
- 原厂 UCI 自定义增量通过显式 export 物化、独立空增量上下文校验后再原子替换；模拟 commit 成功但不合并增量及导出失败。覆盖端口保护、安全模式、黑名单三条路径。原厂只读预检还使用真实权限 renderer 确认拒绝规则在 allow 之前，不改配置、不重启服务。
- 端口保护位于 LinkNest 转发页，直接读取主状态摘要，不必先打开 UPnP 页；提示、说明、状态、确认和错误分类见 [界面规范](ui-guidelines.md)。桌面 / 窄窗口 / 手机验证说明间距。
- UPnP 转发端口保护：IPv4 / 双栈筛选、去重排序、TCP+UDP 原厂兼容保护、已有冲突不写入、不自动删除；UCI 自有节优先级、解除保留其他权限、运行时校验、失败 / EOF 回滚、租约竞态保留；接口二次验证、CSRF、禁止普通配置绕过、待同步和持久化。

- 旧配置迁移、加密密钥、账户、HTTPS 会话与 CSRF。
- 两步验证：RFC 6238 向量、本地二维码、密码单独不能登录、时钟偏差与防重放、一次性恢复码及并发消费、绑定有效期 / 会话限制、限流、重启与账号变更保留、恢复码轮换与关闭、密钥缺失拒绝启动、分步弹窗切换。
- 共享端口域名路由、TLS、HTTP 跳转、来源适配、TCP/UDP、内核 NAT 自有链边界。
- 端口转发地址族与监听地址重叠校验；IPv4 / IPv6 同端口、双栈冲突、IPv4 映射地址及多规则检查。TCP / UDP 实际验证 IPv4 ↔ IPv6、同族及同端口独立监听；IPv4 / IPv6 内核 NAT 生成、原 IP 选项、地址族独立失败清理、规则解析预检查与持久化。前端验证两种模式文案、IPv6 地址保存与原 IP 选项。
- 反代 HTTP/HTTPS 自动来源头及伪造头清除；WS/WSS 与 HTTP/HTTPS 后端、证书校验、子协议、服务端推送、文本/二进制大帧、Ping/Pong、路径查询、来源保护及停用入口断开升级连接。
- DDNS 类型、删除远端确认、更新与凭据；证书长期任务及保护。证书 ZIP 下载覆盖登录 / CSRF、非法标识、缺失 / 损坏 / 不匹配文件、完整证书链及私钥、排除 DNS / ACME 凭据、续期中读取与过期证书导出；前端覆盖下载入口、二进制响应、错误提示和会话失效。
- 路由器公网 IPv4 / IPv6 非阻塞读取、单次共享刷新、冷却、独立失败与旧值标记；服务状态文案统一。
- 说明提示会话隐藏、持久不提示、恢复仅清理自身设置、存储不可用降级；故障警告不可隐藏。
- 操作确认使用独立、不可隐藏的说明，即使同文帮助已被隐藏仍显示；桌面和手机反代条件区域不占隐藏空间、不横向溢出，末尾开关保持紧凑间距。可选 `node scripts/test-dialog-layout.cjs` 使用 Playwright（可用 `EDGE_PATH` 指定浏览器）。
- 开关分隔线覆盖条件区域末尾、反代、转发、证书、DDNS、轻面板、访问过滤、UPnP 和确认弹窗；本地 `node scripts/test-switch-separators.cjs` 在深浅主题与桌面、窄窗口、手机宽度检查可见分隔线及横向边界，并确认目标主机字段不再显示示例说明。
- 端口转发核对本机监听及路由器可达的 NAT / UPnP / PCP 映射，按 IPv4/IPv6、协议、地址与端口范围区分；排除自有链、未挂接链与 OUTPUT 映射；读取失败不误报正常。冲突出现时撤下兼容监听，移除外部冲突后自动重试；不改外部映射。
- 总览统计卡片直达、布局与快捷操作移除；下拉菜单独立浮层、上下展开与边界限制、不撑大弹窗或挤动字段，关闭后恢复归属；圆形刷新及错误恢复、页面切换动画与减少动态效果支持。
- 单箭头刷新图标；后台与公共轻面板 / WOL 共用按钮反馈，悬停、键盘焦点、触屏按下、禁用状态与危险操作辨识，边框不改变尺寸。
- 轻面板、图标缓存、WOL、SSH 指纹确认、终端；前端布局 / 滚动 / 登录语义。
- 异常响应时间窗、阈值、白名单、内网豁免、IPv6、到期解封、单独解封 / 清空自动记录、保存及重启恢复。
- 不信任 X-Forwarded-For；代理 404 达阈值后的拒绝，WebSocket / 流式响应保留。
- 纯文本 / Spamhaus JSON、去重、非法 / 空内容、HTTPS / DNS / 保留地址防护、更新冷却及重启、各源独立更新、失败保留旧缓存、改 URL 不复用旧列表、停用 / 删除退出过滤。
- 访问过滤 API 登录与 CSRF；前端 IPv6 解封、输入转义、预设与策略表单。

## 设备隔离验证

`scripts/smoke-container.py <容器名>` 只操作具有 `linknest.test=true` 标签、无附加权限、仅绑定本机的临时容器和新数据卷。检查初始化、鉴权、版本、schema、代理、TCP、前端资源及停用 / 退出。

## 限制

未代替第三方安全审计、DDoS 压测、真实 iOS / Android WebView 验证。自动封禁 / 订阅不用于内核 NAT；大名单不展开成数万条宿主 iptables 规则。不在生产制造异常请求、启用名单或删除真实 DNS 来测试。

## 1.2.0 发布验收要求

构建和测试都在本机 WSL Docker 内执行，Windows 工作区是唯一源码来源。禁止使用其他 NAS 构建、验证。ARM64 镜像必须通过 QEMU 实际启动及恢复验收，不能仅以交叉编译成功代替。

新增本地回归覆盖配置 428/412/202、非阻塞状态读取、域名与最长路径段、原始编码 URI、升级连接释放、证书队列失败和退避、DNS 缓存更新、登录会话撤销及单侧防火墙失败。浏览器覆盖 78 个页面/主题/宽度组合以及焦点、草稿、晚返回、冲突、离线恢复和登录失效。现有 WS/WSS 测试继续验证子协议、二进制帧、来源和 TLS。

Go 测试及前端回归代码按工作区规则仅保留本地；发布只包含源码、资源、脚本和说明，不包含测试数据、截图或凭据。验收结果必须注明镜像摘要、源码摘要、架构和实际执行的项目。路由器内核与 WSL 不同；生产部署后的真实转发检查不能省略。
