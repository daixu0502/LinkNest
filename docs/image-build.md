# 镜像构建与发布

发布镜像分为独立的精简运行环境和当前程序。禁止使用 `jacoyyyy/linknest:<旧版本>` 或 `latest` 作为后续发布的基础镜像，也不通过追加程序层更新旧应用镜像。源码、预编译及离线发布三种入口均使用同一套精简逻辑。

## 常规源码构建

仓库根目录的 `Dockerfile` 使用 Go 构建阶段、独立 Debian 依赖阶段及 scratch 最终阶段。`scripts/minimal-runtime.py` 按 ELF 动态依赖递归保留 glibc、legacy iptables/ip6tables 和全部 xtables 插件，并保留 CA、完整时区、NSS、协议/服务数据库、shell、读取初始化口令所需的 cat 与发行版许可。Python、包管理器和 Go SDK 只存在于构建阶段：

```sh
docker build --platform linux/arm64 -t jacoyyyy/linknest:1.2.0 .
```

## 离线交叉编译发布

运行环境只包含 Debian、CA 证书、iptables 和时区数据，不包含 LinkNest 程序、许可目录或配置。先独立构建并保存，更新系统依赖时再重建：

```sh
mkdir -p .tools/runtime-base
docker build --platform linux/arm64 -f Dockerfile.runtime-base -t linknest-runtime:minimal-bookworm-arm64 .
docker image save -o .tools/runtime-base/minimal-bookworm-arm64.tar linknest-runtime:minimal-bookworm-arm64
python scripts/release-image.py runtime-lock
```

`runtime-lock` 只接受带 `debian-minimal-v1` 标识的单层精简运行环境；发现任一层包含 LinkNest 程序、许可目录或完整 Debian 的 apt/perl/python 命令即拒绝，随后记录归档 SHA-256。每次 `prepare` 都重新检查内容和锁定哈希，防止误用旧应用或完整系统镜像。

离线场景也可从独立的、完全不含 LinkNest 的 Debian 依赖归档生成相同运行环境：

```sh
python scripts/minimal-runtime.py --input .tools/runtime-base/bookworm-arm64.tar --output .tools/runtime-base/minimal-bookworm-arm64.tar
python scripts/release-image.py runtime-lock
```

输入的任一历史层中出现 LinkNest 程序或许可目录都会被拒绝，即使它在后续层被覆盖或删除也一样。初始输入只复用了此前核对过的 Debian 与系统依赖层，后续发布不读取旧应用镜像。系统依赖更新需要重新裁剪、锁定和验证。

离线归档工具保留用于历史材料核对。正式发布使用下面的 WSL 流程，避免把未经过容器验收的交叉编译程序当作发布包。

脚本读取本地 Go SDK 与模块缓存中的依赖许可证，以及工作树中的第三方说明；所有文件缺失均会停止。生成镜像固定为精简运行环境一层、当前程序与许可证一层，后续发布不会逐版累积。`Dockerfile.runtime` 默认使用独立的 `linknest-runtime:minimal-bookworm-arm64`，并拒绝含旧程序或 apt 的基础镜像。

镜像顶层 `created`、当前程序层历史与 `org.opencontainers.image.created` 使用同一个 UTC 时间，默认取源码提交时间；可用非负 Unix 秒值 `SOURCE_DATE_EPOCH` 显式覆盖。这样既保留可重现的构建，也能让 Docker 正确显示镜像日期；`TZ=Asia/Shanghai` 只影响容器内时区，不能补全镜像创建时间。

旧版 `release-image.py` 仅保留历史归档核对；1.2.0 起的 prepare / publish 会拒绝执行，统一使用下方的 WSL 验收与发布入口。发布产物、日志、备份及凭据均不得提交到源码仓库。

ARM64 实机验证范围见 [精简镜像验证](minimal-image-validation.md)。

## WSL 验收和生产替换（1.2.0 起）

源码来自 Windows 工作区，构建、Go/race、Chromium、ARM64 仿真、内核命名空间和备份恢复检查都在 WSL 的本地 Docker 执行。脚本拒绝远程 Docker context；不用 NAS 充当构建机。按工作区约定，本地测试文件和依赖不提交，缺少验收文件时脚本会停止。

```powershell
python scripts/release-wsl.py --node-modules C:/path/to/node_modules
```

也可直接从该 Windows 工作区的 WSL 挂载目录运行（不使用旧的 Linux 源码副本）：

```sh
python3 scripts/release-wsl.py --node-modules .tools/qa-node/node_modules
```

默认 Go 与 Debian 下载镜像可分别用 `--goproxy` 和 `--debian-mirror` 指定。脚本加载 WSL 已安装的 IPv6 NAT 模块并注册 ARM64 binfmt；不修改宿主防火墙规则。内核转发流量只经过新建的隔离网络命名空间。生成的两种架构镜像均不超过 64 MiB，超限会中止。

验收通过后，`.tools/validation-1.2.5/accepted.json` 记录源码摘要、不可变镜像 ID、归档哈希及全部检查；`candidate-arm64.tar` 为路由器候选镜像，`rollback-helper-arm64.tar` 仅用于完整备份哈希与回滚清理。任一失败不会留下可复用的通过标记，源码变化后必须重新验收。

部署先做只读检查，`known_hosts` 必须是此前已经核对的主机密钥文件：

```powershell
python scripts/deploy-router.py --known-hosts C:/path/to/verified-known-hosts --preflight
python scripts/deploy-router.py --known-hosts C:/path/to/verified-known-hosts
```

脚本仅接受验收过且源码未变的归档。固定流程为：只读能力检查 → 导入候选及备份工具 → 记录业务基线 → 保存旧镜像 → 停止旧容器 → Docker 复制全部数据并核对哈希 → 通过 Docker API 完整保留容器参数及原数据卷创建新容器 → 核对版本、schema、已有业务入口和内核 NAT 规则。

检测失败时停止候选、保存失败现场、清空并恢复原数据卷，核对升级前哈希，再启动保留的旧容器。升级前镜像、数据和旧容器均保留，不自动删除 1.1.5 回滚材料。手动回滚使用本次生成的记录：

```powershell
python scripts/deploy-router.py --known-hosts C:/path/to/verified-known-hosts --rollback .tools/validation-1.2.5/deployment-YYYYMMDD-HHMMSS.json
```

HTTP 检查使用真实域名和路径；TCP 检查验证已有监听链路，不能替代应用协议的业务断言。IPv6 反代另从路由器回环连接检查，不能据此承诺公网 IPv6 可达。未配置的 IPv6 NAT 不在生产环境额外创建测试规则；能力检测与 WSL 流量验收分别记录。


发布始终使用与候选源码完全一致的干净提交工作树。若本次只编译、同步源码及镜像，不部署设备，显式使用「仅发布」模式：

```sh
# 在本机 WSL 终端登录，令牌不放进命令参数或聊天记录。
docker login -u jacoyyyy
python3 scripts/publish-wsl.py --source-worktree .tools/release-1.2.5-source --release-only --use-existing-login
```

此模式仍要求完整 WSL 验收、两种架构的本地/远端一致性、归档摘要及干净源码核对；`published.json` 明确记录 `release-only`，不声称已在路由器部署。不会操作生产容器或数据卷。默认工作区及提交工作树与验收源码不一致时拒绝发布。

如果已获得部署授权并完成生产验收，则继续使用部署验证模式：

```powershell
python scripts/publish-wsl.py --source-worktree .tools/release-1.2.5-source --deployment .tools/validation-1.2.5/deployment-YYYYMMDD-HHMMSS.json
```

未指定 `--use-existing-login` 时，发布脚本从终端读取 Docker Hub 令牌，使用临时登录目录，完成后退出并删除该目录。指定该参数时复用当前 WSL Docker 登录，不读取令牌参数、不登出用户已有会话。先推送、回拉核对 amd64 和 ARM64 镜像，再生成当前版本的多架构索引；核对完成后才更新 `latest`。`published.json` 保存远端摘要和对应源码提交。旧离线 `release-image.py` 不作为 1.2.0 及以后版本的正式发布入口。

1.2.1 起，验收目录默认跟随源码版本。需要代理访问 Docker Hub 时，可为 `publish-wsl.py` 追加 `--registry-proxy http://代理地址:端口`，显式传给 WSL 中的仓库命令及 Buildx；不切换 Docker context 或构建主机。

安全门禁使用 Go 1.26.10 和官方 `govulncheck v1.9.0`，扫描失败时不得部署。可在 WSL Go 容器中执行 `go install golang.org/x/vuln/cmd/govulncheck@v1.9.0` 提前准备模块缓存；扫描仍需联网查询模块声明和漏洞库。`release-wsl.py --proxy http://代理地址:端口` 可指定代理。检查结果仅覆盖 Go 漏洞数据库与已识别调用路径，不代表宿主 Linux 内核或全部系统包没有漏洞。
