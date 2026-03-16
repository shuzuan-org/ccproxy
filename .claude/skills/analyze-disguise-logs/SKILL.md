---
name: analyze-disguise-logs
description: Analyze ccproxy runtime logs to evaluate disguise engine effectiveness. Use when user asks to analyze logs, check disguise status, review proxy logs, evaluate camouflage quality, or diagnose detection/fingerprint issues. Triggers on keywords like "analyze logs", "disguise effect", "log analysis", "camouflage review", "check fingerprint".
---

# Analyze Disguise Logs

Evaluate ccproxy disguise engine effectiveness from Docker/runtime logs.

## Log Format

Logs may be in two formats:
- **Plain JSON** (`docker logs ccproxy`) — one JSON object per line
- **Docker JSON wrapper** (`logs/*.log`) — nested escaped JSON: `{"log":"{\"time\":...}\n","stream":"stderr","time":"..."}`

For Docker wrapper format, use `sed 's/\\"/~/g'` before grep extraction to handle nested escaping.

## Analysis Workflow

### 1. Overview Metrics

Extract from `metrics summary` and `metrics account` logs:
- Time range, uptime, total/success/error requests
- Accounts count, health state, budget state, concurrency

### 2. Per-Layer Disguise Analysis

#### 2a. Client Detection

Log: `disguise/detect: multi-signal validation`

Fields: `is_cc`, `score`, `x_app_cli`, `has_cc_beta`, `has_user_id`, `has_system_prompt`, `has_anthropic_version`, `user_agent`

Threshold: UA gate + score >= 2/5. Score 4-5 is healthy. Break down by client version.

#### 2b. System Prompt Detection

Log: `disguise/detect: system prompt did not match any known prefix`

Fields: `best_dice`, `system_preview`

**Action required**: If `has_system_prompt` is `false` for newer CC versions (>= 2.1.66), this likely means the system prompt prefix list in the detector is outdated and needs updating. Low Dice scores (e.g., ~0.19) indicate the detector is NOT recognizing the current system prompt format. **Flag this as medium risk** and recommend checking `internal/disguise/detector.go` to update the known system prompt prefixes for newer CC versions. While other signals compensate (score still >= 2), losing an entire detection signal degrades defense-in-depth.

#### 2c. TLS Fingerprint

Log: `tls: handshake success`

Fields: `proto`, `via_proxy`, `elapsed`

**Known behavior**: `proto: "http/1.1"` is correct — official Claude CLI also negotiates HTTP/1.1. Typical SOCKS5 handshake: 300-400ms.

#### 2d. Beta Header Supplementation

Log: `disguise: beta header supplemented`

Fields: `before`, `after`

Verify: `oauth-2025-04-20` appended, original tokens preserved, no duplicates.

#### 2e. User ID Rewrite

Log: `disguise: user_id rewritten (CC pass-through)`

Fields: `before`, `after`

Count unique `before` (= client sessions) and unique `after` suffixes (= session mask periods).

#### 2f. Session Mask

Log: `disguise/session_mask: created new mask`

Fields: `mask_uuid`, `ttl`

**Known behavior**: TTL 15 min with **sliding renewal** — each request extends it. Few creations over long periods is normal if requests are continuous. New mask only after 15+ min idle. Unique `after` suffixes in 2e should equal mask count.

#### 2g. Fingerprint Learning

Log: `disguise/fingerprint: learned from CC client (new)`

Fires once per new client fingerprint. Low count is normal for few-client setups.

#### 2h. Disguise Application

Log: `disguise applied` — `disguised` should be true for all proxied requests.

`disguise: native Claude Code client detected, lightweight pass-through` confirms CC clients skip full 8-layer disguise.

### 3. Upstream Health

Log: `upstream success` — extract `status`, `elapsed`, `model`, `retries`, `failovers`. Calculate success rate and response time stats.

### 4. Throttle & Budget

- `throttle: request throttled` with `accepts=0` on cold start is normal
- `budget: headers updated` — `state: "normal"` is healthy

### 5. Security Events

Scan for: `auth rejected`, 404 on `/.env*`/`/robots.txt`/`/`, non-200 on `/v1/messages`.

## Report Template

1. **Overview** — uptime, requests, success rate, accounts
2. **Per-Layer Assessment** — each layer with status and evidence
3. **Risk Table** — layer | status | risk (low/medium/high)
4. **Security Events** — probes, auth failures
5. **Recommendations** — only for real issues

## Key Principles

- Do NOT flag known behaviors as issues: h/1.1 proto, cold-start throttle, few session masks with sliding TTL
- DO flag `has_system_prompt: false` on newer CC versions as medium risk — it means the detector's known prefix list is outdated and should be updated
- The ultimate metric: 0 blocks/429s from Anthropic = disguise is effective
- Compare across client versions when multiple are present
