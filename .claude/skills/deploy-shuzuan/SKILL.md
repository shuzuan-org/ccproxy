---
name: deploy-shuzuan
description: 把本地 ccproxy 改动部署到生产服务器 shuzuan_gia(root@89.208.252.173)。binary-drop + systemd:测试门禁→编 VERSION=dev linux binary→备份→原子替换→重启→健康+端到端验证→失败自动回滚。当用户要部署 ccproxy、更新生产服务器、上线伪装层改动(cch/TLS指纹/header)时使用。
---

# deploy-shuzuan —— 部署 ccproxy 到生产服务器

把本地 ccproxy 改动(伪装层 cch/TLS/header 等)编成 linux binary 部署到 **shuzuan_gia**。

## 一键部署

```bash
bash .claude/skills/deploy-shuzuan/scripts/deploy.sh
```

脚本按序做(任一步失败即中止/回滚):
1. **preflight** — ssh 连通 + `ccproxy.service` 在跑
2. **测试门禁** — `go test ./...` 全绿才继续
3. **编译** — `make build-linux`(**VERSION=dev**,见下)
4. **上传+备份+替换** — scp 到 `.new` → `cp` 当前到 `.bak.<时间戳>` → `mv` 原子替换
5. **重启+验证** — `systemctl restart` → `systemctl is-active`=active + `/health`=ok;**失败自动回滚到备份**
6. **端到端** — 用 config 里的 client key 经 proxy 发一个最小请求 → 期望 `HTTP 200`(证明 cch/TLS 伪装被 Anthropic 接受)

## 目标环境(事实)

| 项 | 值 |
|----|----|
| 服务器 | shuzuan_gia,`root@89.208.252.173:22`(免密) |
| 部署方式 | binary-drop(非 git/docker) |
| binary | `/opt/ccproxy/bin/ccproxy`(root:root 755) |
| 配置 | `/opt/ccproxy/etc/config.toml` |
| 服务 | systemd `ccproxy.service`(User=ccproxy, Restart=always) |
| 监听 | `127.0.0.1:3000`(`/health`, `/v1/messages`) |
| 上游 | `https://api.anthropic.com`(OAuth account `ceshi25`) |

## ⚠️ 关键约束:必须 VERSION=dev

`make build-linux` 默认 `VERSION=dev`,**绝不要传 `VERSION=x.y.z`**。原因:
- ccproxy 自动更新器默认开启(`config auto_update` 默认 true)
- 但 `dev` 版本在运行时禁用它(`updater.go`: `if !AutoUpdate || u.isDev || u.isDocker`)
- 若部署真版本号,更新器会从 GitHub 拉 release **覆盖掉这个手改的 binary**(丢失 cch/TLS 伪装改动)

部署后日志应有 `auto-update disabled: dev version` 确认。

## 回滚

脚本结尾打印回滚命令。手动:
```bash
ssh root@89.208.252.173 'ls /opt/ccproxy/bin/ | grep bak'   # 找备份
ssh root@89.208.252.173 'mv /opt/ccproxy/bin/ccproxy.bak.<TS> /opt/ccproxy/bin/ccproxy && systemctl restart ccproxy'
```

## 部署后额外验证(可选,伪装层改动建议做)

- **TLS 指纹**:抓出口 ClientHello 确认匹配真 Bun 客户端(无 ECH-GREASE 0xfe0d、padding 到记录体 512)。
  方法见 `internal/tls/fingerprint.go` 注释 + 之前的捕获脚本思路(本地起 TCP 捕获服务器,
  指 base_url 到它读 ClientHello)。
- **cch**:端到端 HTTP 200 即证明 cch 算对(服务端会重算比对)。日志看 account `ceshi25` success 递增。

## 参数化

`CCPROXY_SERVER` 环境变量可换目标(默认 `root@89.208.252.173`)。路径/服务名在脚本顶部常量。
