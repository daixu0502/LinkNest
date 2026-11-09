# 栖网 LinkNest

## 简介

LinkNest 是单容器网络服务控制台，提供反向代理、TCP / UDP 端口转发、阿里云动态域名与证书申请、轻面板、网络唤醒、访问过滤和 SSH Web 终端。

当前版本 **1.2.5**，发布镜像支持 **Linux amd64 / ARM64**，适用于对应架构的 NAS / 路由器。前端为内嵌 HTML / CSS / JavaScript，无需 Node 构建。第三方资源与许可见 [THIRD_PARTY.md](THIRD_PARTY.md)。

**2026-11-09 同版本重新发布**：证书、域名行的高亮已与网络服务行统一完整圆角描边和内外留白，总览样式修订标记为 `row-outline-2`。若已拉取早期 1.2.5，请重新拉取并用原参数重建容器，保留原数据卷；仅重启旧容器不会更新镜像。详见 [1.2.5 更新记录](docs/changelog-1.2.5.md)。

镜像使用经过 ARM64 实机验证的精简 Debian 运行环境，保留 IPv4/IPv6 内核转发、证书、时区与现有前端功能。裁剪与发布入口见 [镜像构建与发布](docs/image-build.md)，验证范围见 [精简镜像验证](docs/minimal-image-validation.md)。

本项目尚未经独立安全审计，管理入口建议仅在受信局域网或 SSH 隧道中访问。自动封禁与名单订阅默认关闭，详见 [访问过滤](docs/access-filter.md)。

轻面板右上角「选择背景」菜单可设置卡片动效：默认跟随系统；系统关闭动画时，可为当前浏览器单独选择「开启」，不修改 Windows 设置。选择保存在当前浏览器中。

## 如何构建、导入与使用

### 获取镜像

从 Docker Hub 拉取（Linux ARM64）：

```sh
docker pull jacoyyyy/linknest:1.2.5
```

在源码目录构建，默认构建宿主机架构，期间执行 Go 测试：

```sh
docker build -t jacoyyyy/linknest:1.2.5 .
```

依赖下载困难时可追加 `--build-arg GOPROXY=https://goproxy.cn,direct`。源码测试方法见 [测试说明](docs/testing.md)。独立运行环境、离线构建及禁止叠加旧应用镜像的发布流程见 [镜像构建与发布](docs/image-build.md)。

离线导出、导入镜像：

```sh
# 在已有镜像的设备上导出
docker save jacoyyyy/linknest:1.2.5 | gzip > linknest-1.2.5-linux-arm64.tar.gz
# 复制到另一台 ARM64 设备后导入
gzip -dc linknest-1.2.5-linux-arm64.tar.gz | docker load
```

### 路由器 / NAS 部署

以下适用于 Linux host 网络与 legacy iptables。将 `192.168.1.1` 替换成真实 LAN IP。无需自动防火墙时，删除两个 `--cap-add`、锁挂载，并将 `LINKNEST_FIREWALL` 改为 `disabled`。

```sh
touch /run/xtables.lock
docker run -d --name linknest \
  --network host --restart unless-stopped \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW \
  --security-opt no-new-privileges:true \
  --read-only --tmpfs /tmp:size=8m \
  --memory 192m --pids-limit 128 --stop-timeout 40 \
  --log-opt max-size=5m --log-opt max-file=2 \
  -e LINKNEST_ADMIN_ADDR=192.168.1.1:17880 \
  -e LINKNEST_FIREWALL=enabled \
  --mount type=bind,source=/run/xtables.lock,target=/run/xtables.lock \
  -v linknest-data:/data \
  jacoyyyy/linknest:1.2.5
```

自动放行与内核转发需要较高网络权限，仅管理 LinkNest 自有规则，不清空宿主防火墙；不需要独立权限助手。不要使用 `--privileged` 或挂载 Docker Socket。WOL 广播建议使用 host 网络；公网可达仍取决于上级路由、运营商和防火墙。

反向代理自动设置来源请求头并支持 WebSocket/WSS，无需单独开启；Host 保留方式、显式 WS/WSS 后端和 Motrix 配置见 [反向代理说明](docs/reverse-proxy.md)。

端口转发内的“路由器 UPnP”可查看和管理原厂映射、设置设备黑名单，并通过显式授权开关切换原厂安全模式。默认不接管规则或降低安全限制，详见 [UPnP 管理](docs/upnp.md)。

端口转发支持「内核加速（IPv4 + IPv6）」和「兼容转发（IPv4 + IPv6 + 域名）」。同端口可分别建立仅 IPv4、仅 IPv6 规则；兼容模式支持两种地址族互转，内核模式支持同地址族转发及可选的原始客户端 IP 保留。内核能力取决于宿主系统，详见 [转发方式与原 IP](docs/port-forwarding.md)。

在「证书管理」中，已签发或已导入的证书可点击「下载证书」，下载 `linknest-<证书标识>.zip`。ZIP 包含完整证书链 `fullchain.pem` 和对应私钥 `privkey.pem`（PEM 格式）；不包含 DNS 凭据、续期任务或 ACME 账户密钥。压缩包包含私钥，请妥善保管。续期期间仍可下载当前已保存的证书；尚未签发或文件损坏时无法下载。

首次初始化读取一次性口令：

```sh
docker exec linknest cat /data/bootstrap.token
```

在页面输入口令，创建管理员用户名与 12—72 字节密码；没有默认账号密码，初始化后口令文件删除。随后配置业务规则、DNS 凭据和证书。管理 HTTPS 需在设置中选择有效证书并开启，不会在申请成功后自动开启。

两步验证可在「设置 → 两步验证（2FA）」开启。验证管理员密码后，用 Microsoft Authenticator 添加「其他账户」扫描本地生成的二维码，再输入 6 位动态验证码确认。启用前不会改变登录方式。请保存仅显示一次的 10 个恢复码；丢失手机时，使用账号、密码与一个恢复码登录，再关闭或重新绑定。恢复码只能使用一次，也可在设置中重新生成；验证码同一轮不可重复使用，手机与服务器需自动同步时间。建议通过 HTTPS 或 SSH 隧道绑定。启用后不要降级到不支持 2FA 的旧程序，否则旧程序不会要求动态验证码。

升级前备份，拉取新镜像后用原参数重建容器，保留原数据卷。同名容器需先停止并移除；**不要删除数据卷**。

## 项目结构

```text
cmd/linknest/       程序入口
internal/app/       配置、代理、DNS、证书、面板、WOL、终端与回归测试
internal/access/    访问过滤、封禁、订阅与单元测试
web/                页面、样式、脚本、图标和第三方终端资源
scripts/            构建、界面回归与隔离容器验证
docs/               功能和测试说明
Dockerfile          源码构建镜像
Dockerfile.runtime  预编译程序与许可文件构建镜像
compose.yaml        仅开放本机的试用部署
go.mod / go.sum     Go 依赖
THIRD_PARTY.md      第三方资源与许可说明
```

`bin/`、`dist/` 为本地构建 / 交付目录，不进入 Git 或 Docker 构建上下文。测试代码仅保留本地，不上传 GitHub；测试说明等 Markdown 文档继续分发。`local/` 中的配置和密钥不进入源码或镜像。

## 数据位置与备份

持久数据位于容器 `/data`，上述 `docker run` 使用命名卷 `linknest-data`。用 `docker volume inspect linknest-data` 查看实际位置，不要直接修改 Docker 内部目录。

```text
/data/
  config.json           规则与加密凭据
  master.key            解密密钥，必须随配置备份
  auth.json             管理账号、密码哈希、加密 2FA 密钥与恢复码哈希
  bootstrap.token       仅初始化前存在
  access/               封禁状态、名单缓存与更新状态
  icons/                已选择的本地图标缓存
  certificate-jobs.json 证书任务过程
  certificates/         证书、私钥、续期参数与 ACME 密钥
```

**配置导出不是完整备份**，不包含全部凭据、账号和证书。迁移需备份整个数据卷；丢失 `master.key` 后无法解密原凭据。备份含敏感信息，不要上传仓库或镜像。

完整备份不依赖镜像内的 `tar`（精简镜像不包含它）：

```sh
# 使用新的空目录，容器停止期间禁止其他进程写这个数据卷。
backup_dir="$PWD/linknest-backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir/data"
docker stop --time 40 linknest
docker cp -a linknest:/data/. "$backup_dir/data/"
# 核对 config.json、master.key、auth.json、certificates/ 等内容后再继续。
docker start linknest
```

恢复到新的空数据卷，再用原来的网络、权限、环境变量和挂载参数创建正式容器：

```sh
docker volume create linknest-restored
docker create --name linknest-restore -v linknest-restored:/data jacoyyyy/linknest:1.2.5
docker cp -a "$backup_dir/data/." linknest-restore:/data/
docker rm linknest-restore
# 此处按原部署参数启动，数据卷改为 linknest-restored；登录并检查业务。
```

1.2.5 使用 schema 5。回滚到 1.1.5 时必须同时恢复升级前的数据，不要让旧程序读取新版数据卷。完整验收和部署步骤见 [构建与发布](docs/image-build.md)。
