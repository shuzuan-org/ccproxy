# cch / 3hex 验证 — 2.1.181（2026-06-18，抓包确认）

> ⚠️ **2026-06-21 修正**：本文**结论 2「ccproxy 应停发 cch」是错的**，已被
> `FINDINGS-2.1.185.md` 推翻。真因是 cch 受 **base_url 门控**（host 必须=
> api.anthropic.com），当时只抓到第三方/localhost 样本（base_url≠官方）才无
> cch，被错误外推成"firstParty 不发 cch"。firstParty 直连抓包证明 cch **确实
> 会发**，ccproxy 出口（OAuth→api.anthropic.com）**应发 cch**，只是 keys 轮换了
> 需抽新值。以 `FINDINGS-2.1.185.md` 为准。

## TL;DR

| 项 | 结论 | 证据等级 |
|----|------|---------|
| **3hex 算法 + salt** | **未变**，仍 `SHA256("59cf53e54c78"+msg[4,7,20]+version)[:3]` | ✅ 抓包确认 |
| **cch（第三方/OAuth 流量）** | **2.1.181 根本不发 cch** | ✅ 抓包确认 |
| **ATTEST_KEYS** | 旧 V1..V4 已从 binary 消失（轮换或重排） | ✅ 静态确认 |
| **新 ATTEST_KEYS** | 未抽出（且对当前部署**可能无需抽**，见下） | — |

## 抓包方法（无需 mitmproxy / 无需证书）

本机 `claude` CLI 已通过 env 走可配置上游
（`ANTHROPIC_BASE_URL=https://napi.origintask.cn` + `ANTHROPIC_AUTH_TOKEN`），
故不需要 TLS 拦截。新增零依赖透传代理 `capture_passthrough.py`：监听
`127.0.0.1:8788`，落盘 `/v1/messages` body 到 `captured/`，原样转发到真上游。

启动：`python3 capture_passthrough.py`
抓样：`ANTHROPIC_BASE_URL=http://127.0.0.1:8788 claude -p "say hi briefly"`

抓到真 `claude-cli/2.1.181 (external, sdk-cli)` 样本（111 KB）。

## 1. 3hex：未变，抓包验证通过 ✅

wire 真值 `cc_version=2.1.181.3c1`：

```
version       = 2.1.181
first non-meta = "say hi briefly"
chars[4,7,20] = "hb0"
3hex computed = SHA256("59cf53e54c78"+"hb0"+"2.1.181")[:3] = "3c1"
3hex observed = 3c1   →  MATCH
```

salt、字符索引 `[4,7,20]`、isMeta 前缀表对此样本全部正确。**ccproxy 的 3hex
代码对 2.1.181 不需要改。**

## 2. cch：2.1.181 第三方流量不发 cch（设计行为）

抓到的 billing block 完整内容：

```
x-anthropic-billing-header: cc_version=2.1.181.3c1; cc_entrypoint=sdk-cli;
```

**没有 `cch=` 段。** 这不是 bug——cc-probe 对 2.1.181 cli.js 的分析显示 billing
模板是 `cc_version=${n}; cc_entrypoint=${r};${s}${a}${l}`，cch 在条件段里，门控为：

```
provider==="firstParty" && Gu()  ||  provider==="vertex"
```

即 **cch 只对 firstParty / vertex provider 生成**（cc-probe
`billing_header_template.cch.gate_kind = provider_inclusion`）。第三方 token /
OAuth 上游的 provider 不在此列 → cch 段为空。

### 对 ccproxy 的影响（重要，可能颠覆现有做法）

ccproxy 服务的客户端走 OAuth / 第三方 provider。按 2.1.181 新逻辑，**真 2.1.181
客户端在这种场景下不发 cch**。那么 ccproxy 现在仍计算并注入 cch，会让出口流量
**比真客户端多一个本不该存在的 cch 字段** → 反成指纹破绽。

**待团队决策**：对 2.1.181+ 的 UA，正确行为很可能是
**billing header 不带 cch**，而不是"算对 cch"。需抓一个 firstParty 场景样本
确认 cch 在该 provider 下是否仍生成、算法是否仍是旧 keyed-xxhash64。

## 3. ATTEST_KEYS：旧 keys 已消失（静态确认）

旧 V1..V4（`0xAE4FBA0790EAE83E` 等）小端字节在 2.1.181 binary 中全部缺失；
xxhash PRIME64 对照实验（各出现 1 次）证明搜索法有效、cch 代码仍在 →
**keys 确已轮换或重排**。新值未抽出：不在 PRIME64 常量池旁，arm64 上很可能以
`MOVZ/MOVK` 立即数拼接、无连续裸字节 → 需反汇编。

**但抽取优先级现在存疑**：若结论 2 成立（第三方流量本就不发 cch），则
ccproxy 出口在该场景下根本不需要 cch，也就不需要新 keys。只有要伪装
firstParty/vertex 场景才需要。

## verify_captured.py 的修复

原脚本两处都**硬假设 billing block 含 cch=**，2.1.181 无-cch 样本会被整条 skip
（连 3hex 都验不了）：
- `find_billing_text`：锚点从 `billing+cch=` 改为只认 `x-anthropic-billing-header:`
- 主循环：无 cch → 记为 `absent`（非 skip/非 fail），继续验 3hex

修复后输出：`cch: 0/0 match (1 absent)`、`3hex: 1/1 match`。

## 下一步（按价值）

1. **决策 cch 策略**：对 2.1.181 UA 的第三方流量，ccproxy 应停发 cch（对齐真
   客户端）而非算 cch。需要 firstParty 抓样佐证后再动 `disguise` 代码。
2. **白名单 UA**：`version_whitelist.go` 仍 pin 2.1.150（落后 31 版）。3hex 已验证
   可用，可安全追加 2.1.181 三元组（UA/SDK/Runtime 从 `.meta` 抄）。
   - ⚠️ 本次抓样是 `-p`（print）触发的 **`sdk-cli` 入口**，UA=`claude-cli/2.1.181
     (external, sdk-cli)`，且首版 `capture_passthrough.py` 的 `.meta` 未记
     `x-stainless-*` headers。白名单要的是**交互 `cli` 入口**的三元组。脚本已
     补记 stainless headers；重抓一个**交互式**样本（不带 `-p`）再填白名单。

## 附：metadata.user_id 结构确认（cc-probe 预测 ✅）

抓到的真值与 cc-probe 对 2.1.181 的预测完全吻合：

```
metadata.user_id = "{\"device_id\":\"06fd...\",\"account_uuid\":\"\",\"session_id\":\"b5fd...\"}"
```

- user_id 现在是 **JSON.stringify 后的字符串**（cc-probe 探针测得 `user_id:Oe(r)`，
  wrapper=`Dg\`JSON.stringify(...)\``），非旧版裸对象。
- 字段顺序 `device_id, account_uuid, session_id` 一致；`account_uuid` 为空（第三方
  auth 无 Anthropic 账户，符合预期）。
- ccproxy 端 `metadata.go` 的 `isNewMetadataFormatVersion + json.Marshal` 已正确
  按此新格式产出 → **metadata 层对 2.1.181 无需改**。

