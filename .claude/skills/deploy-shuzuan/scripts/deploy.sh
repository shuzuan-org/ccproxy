#!/usr/bin/env bash
# 部署 ccproxy 到 shuzuan_gia(binary-drop + systemd)。
# 测试门禁 → 编 VERSION=dev linux binary → 备份 → 原子替换 → 重启 → 验证 → 失败自动回滚 → 端到端。
set -euo pipefail

export PATH="$PATH:/opt/homebrew/bin:/usr/local/go/bin"

SERVER="${CCPROXY_SERVER:-root@89.208.252.173}"
SSH_OPTS=(-o ServerAliveInterval=60 -o ServerAliveCountMax=5 -o ConnectTimeout=15)
REMOTE_BIN="/opt/ccproxy/bin/ccproxy"
SERVICE="ccproxy"
HEALTH_URL="http://127.0.0.1:3000/health"
MESSAGES_URL="http://127.0.0.1:3000/v1/messages"
CONFIG="/opt/ccproxy/etc/config.toml"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"

sshx() { command ssh "${SSH_OPTS[@]}" "$@"; }
log()  { printf '\n\033[1;36m[deploy]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[deploy] ✗ %s\033[0m\n' "$*"; exit 1; }

cd "$REPO_ROOT"

# 1. preflight ----------------------------------------------------------------
log "preflight: ssh 连通 + 当前服务状态"
sshx "$SERVER" "systemctl is-active $SERVICE && ls -la $REMOTE_BIN" \
  || die "服务端不可达或 $SERVICE 未运行"

# 2. 测试门禁 -----------------------------------------------------------------
log "测试门禁: go test ./..."
if ! go test ./... >/tmp/ccproxy_deploy_test.log 2>&1; then
  tail -25 /tmp/ccproxy_deploy_test.log
  die "测试失败,中止部署"
fi
echo "✓ 全套测试通过"

# 3. 编译(VERSION=dev 是硬约束)---------------------------------------------
# dev 版本让运行时禁用自动更新器(updater.go: u.isDev);否则 GitHub release 会
# 覆盖掉这个手改的 binary。绝不传 VERSION=x.y.z。
log "编译 linux/amd64 (VERSION=dev)"
make build-linux >/dev/null
BIN="bin/ccproxy-linux-amd64"
file "$BIN" | grep -q "ELF 64-bit.*x86-64" || die "$BIN 不是 linux x86-64 ELF"
strings "$BIN" | grep -qF "claude-cli/2.1.185" \
  && echo "✓ 含 2.1.185 伪装标识" || echo "⚠ 未找到 2.1.185 UA(确认伪装版本)"

# 4. 上传 + 备份 + 原子替换 ---------------------------------------------------
TS="$(date +%Y%m%d%H%M%S)"
BAK="$REMOTE_BIN.bak.$TS"
log "上传 → 备份($BAK)→ 原子替换"
scp "${SSH_OPTS[@]}" "$BIN" "$SERVER:$REMOTE_BIN.new"
sshx "$SERVER" "
  set -e
  cp -p $REMOTE_BIN $BAK
  chown root:root $REMOTE_BIN.new && chmod 755 $REMOTE_BIN.new
  $REMOTE_BIN.new version
  mv $REMOTE_BIN.new $REMOTE_BIN
"

# 5. 重启 + 验证(失败自动回滚)----------------------------------------------
log "重启 $SERVICE + 健康验证"
sshx "$SERVER" "systemctl restart $SERVICE; sleep 3"
ACTIVE="$(sshx "$SERVER" "systemctl is-active $SERVICE" || true)"
HEALTH="$(sshx "$SERVER" "curl -s -m 5 $HEALTH_URL" || true)"

if [ "$ACTIVE" != "active" ] || [ "$HEALTH" != "ok" ]; then
  log "⚠ 验证失败 (active=$ACTIVE health=$HEALTH) — 自动回滚到 $BAK"
  sshx "$SERVER" "mv $BAK $REMOTE_BIN; systemctl restart $SERVICE; sleep 3
                  echo 回滚后: \$(systemctl is-active $SERVICE) \$(curl -s -m5 $HEALTH_URL)"
  die "部署失败已回滚"
fi
echo "✓ active + /health=ok"

log "启动日志关键行(auto-update 禁用 / 指纹 rebase / 错误)"
sshx "$SERVER" "journalctl -u $SERVICE --since '1 min ago' --no-pager \
  | grep -iE 'auto-update disabled|rebased to whitelist head|level\":\"ERROR|panic' | head -6" || true

# 6. 端到端(真实请求,确认 cch/TLS 伪装被 Anthropic 接受)--------------------
log "端到端: 经 proxy → Anthropic 发最小请求"
sshx "$SERVER" "
  KEY=\$(grep -E '^key *= *\"sk-' $CONFIG | head -1 | sed -E 's/.*\"(sk-[^\"]+)\".*/\1/')
  curl -s -m 60 -o /dev/null -w 'HTTP %{http_code} in %{time_total}s\n' $MESSAGES_URL \
    -H 'Content-Type: application/json' -H \"x-api-key: \$KEY\" -H 'anthropic-version: 2023-06-01' \
    -d '{\"model\":\"claude-haiku-4-5-20251001\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"ok\"}]}'
"

log "✓ 部署完成"
echo "回滚命令: ssh $SERVER 'mv $BAK $REMOTE_BIN && systemctl restart $SERVICE'"
