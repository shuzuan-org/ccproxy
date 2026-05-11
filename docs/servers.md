# ccproxy 服务器清单

> 最后更新：2026-05-11

## 服务器一览

| 别名 | 主机名 | IP | 城市 | 运营商 | ASN | OS | ccproxy |
|------|--------|----|------|--------|-----|-----|---------|
| ccp3 | ubuntu-s-1vcpu-1gb-sfo3 | 159.223.192.113 | 美国·加州·圣克拉拉 | DigitalOcean | AS14061 | Ubuntu 24.04 LTS | 0.1.16 |
| ccp4 | stockholm-2c4g | 70.34.220.108 | 瑞典·斯德哥尔摩 | Vultr (Constant Company) | AS20473 | Ubuntu 24.04 LTS | 0.1.16 |
| ccp5 | ubuntu-s-2vcpu-4gb-sgp1 | 167.172.89.103 | 新加坡 | DigitalOcean | AS14061 | Ubuntu 24.04 LTS | 0.1.16 |
| ccp6 | aichat | 23.185.200.18 | 美国·加州·洛杉矶 | FASTNET DATA INC | AS8796 | Debian 12 (bookworm) | 0.1.16 |
| zz | vital-baud-5 | 89.208.252.173 | 美国·加州·洛杉矶 | IT7 Networks (16clouds) | AS25820 | Ubuntu 24.04 LTS | 0.1.16 |

## 安装方式

所有服务器使用统一的安装结构，通过 OTA 自动升级（`ccproxy upgrade`）保持版本同步。

### 目录结构

```
/opt/ccproxy/
├── bin/
│   └── ccproxy          # 二进制主体（OTA 升级原子替换此文件）
├── etc/
│   └── config.toml      # 主配置（权限 0600 或 0700 目录）
└── data/                # 运行时数据（accounts.json、oauth_tokens.json 等）

/usr/local/bin/ccproxy  -> /opt/ccproxy/bin/ccproxy   # 全局符号链接
```

### 用户与权限

```bash
# 专用系统用户（无登录 shell）
useradd -r -s /sbin/nologin -d /opt/ccproxy ccproxy

# 目录归属
chown -R ccproxy:ccproxy /opt/ccproxy
chmod 700 /opt/ccproxy/etc          # 配置目录仅 ccproxy 可读
```

### systemd 服务

所有服务器服务文件内容完全一致：

```ini
# /etc/systemd/system/ccproxy.service
[Unit]
Description=ccproxy - Claude API Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ccproxy
Group=ccproxy
ExecStart=/opt/ccproxy/bin/ccproxy -c /opt/ccproxy/etc/config.toml
WorkingDirectory=/opt/ccproxy
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启用与启动：

```bash
systemctl daemon-reload
systemctl enable --now ccproxy
```

### 安装新服务器（完整流程）

```bash
# 1. 创建用户和目录
useradd -r -s /sbin/nologin ccproxy
mkdir -p /opt/ccproxy/{bin,etc,data}
chown -R ccproxy:ccproxy /opt/ccproxy
chmod 700 /opt/ccproxy/etc

# 2. 下载二进制（替换为最新 release tag）
VERSION=0.1.16
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fL "https://github.com/binn/ccproxy/releases/download/v${VERSION}/ccproxy-linux-${ARCH}" \
  -o /opt/ccproxy/bin/ccproxy
chmod 755 /opt/ccproxy/bin/ccproxy

# 3. 全局符号链接
ln -sf /opt/ccproxy/bin/ccproxy /usr/local/bin/ccproxy

# 4. 写配置（基于 config.toml.example）
cp config.toml.example /opt/ccproxy/etc/config.toml
chown ccproxy:ccproxy /opt/ccproxy/etc/config.toml
chmod 600 /opt/ccproxy/etc/config.toml

# 5. 写服务文件（见上方 systemd 内容）
vim /etc/systemd/system/ccproxy.service

# 6. 启动
systemctl daemon-reload
systemctl enable --now ccproxy
systemctl status ccproxy
```

## 常用运维命令

```bash
# 查看状态
systemctl status ccproxy
journalctl -u ccproxy -f          # 实时日志
journalctl -u ccproxy -n 100      # 最近 100 行

# 重启
systemctl restart ccproxy

# 手动触发更新检查
ccproxy upgrade --check

# 强制升级到最新版
ccproxy upgrade --force

# 查看版本
ccproxy version
```

## SSH 登录别名

以下别名已配置在本地 `~/.ssh/config`（或 `/etc/hosts` / SSH config）：

| 别名 | 实际 IP |
|------|---------|
| ccp3 | 159.223.192.113 |
| ccp4 | 70.34.220.108 |
| ccp5 | 167.172.89.103 |
| ccp6 | 23.185.200.18 |
| zz   | 89.208.252.173 |

## 备注

- **OTA 自动升级**：服务内置升级器，每小时检查 GitHub Releases，发现新版本后自动下载、SHA256 校验、原子替换二进制并发 SIGTERM 重启。无需手动介入。
- **zz** 服务器存在 `data.bak.20260409231531` 备份目录，为 2026-04-09 数据迁移留存，可按需清理。
- **ccp6** 运行在 `America/Los_Angeles` 时区（UTC-7/8），日志时间戳与其他服务器（UTC）不同，对比日志时注意换算。
- 所有服务器当前版本均为 **0.1.16**，运行状态 active (running)。
