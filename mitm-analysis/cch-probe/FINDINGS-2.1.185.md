# cch / 3hex 验证 — 2.1.185（2026-06-21，firstParty 直连抓包确认）

> **本文修正 `FINDINGS-2.1.181.md` 的结论 2。** 之前"ccproxy 应停发 cch"是
> **错的**，根因是把 base_url 门控误判成 provider 门控。详见下文「门控真相」。

## TL;DR

| 项 | 结论 | 证据等级 |
|----|------|---------|
| **3hex 算法 + salt** | **未变**，2 样本复算全 match（b68 / 11a） | ✅ 抓包确认 |
| **cch 门控** | `firstParty/vertex` **且** `base_url 未设或=api.anthropic.com` | ✅ 反编译 + 抓包确认 |
| **ccproxy 是否该发 cch** | **该发**（出口=OAuth firstParty→api.anthropic.com，真客户端此位置发 cch） | ✅ 推翻旧结论 |
| **ATTEST_KEYS** | **已轮换**，旧 keys 算 `cf0b9` ≠ 真值 `0c516` | ✅ 动态 ground truth 确认 |
| **新 ATTEST_KEYS** | 未抽出（cch 是**原生码**，JS bundle 无字面量，需 arm64 反汇编） | — |

## 抓包方法（firstParty 直连 + 强制 cch）

本机 `claude` 用 **Max 订阅 OAuth**（keychain `Claude Code-credentials`，
`subscriptionType=max`）。零依赖透传代理 `capture_passthrough.py` 上游指
**官方 `api.anthropic.com`**：

```
python3 capture_passthrough.py --port 8788 --upstream https://api.anthropic.com
env -u ANTHROPIC_AUTH_TOKEN -u ANTHROPIC_API_KEY \
    _CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL=1 \
    ANTHROPIC_BASE_URL=http://127.0.0.1:8788 \
    claude -p "say hi briefly"
```

- `-u ANTHROPIC_AUTH_TOKEN`：去掉本 session 继承的第三方 token，强制走订阅 OAuth。
- `_CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL=1`：**关键旁路**。否则代理把 base_url
  改成 localhost → 触发 base_url 门控 → cch 被抑制（见下）。设此 env 直接让
  `Pu()` 短路返 true，强制发 cch，即便走 localhost 代理也能抓到真 cch。

确认是 firstParty：`metadata.user_id.account_uuid` **非空**（`bb8a6dcd-...`）；
第三方/无账户场景该字段为空。

## 门控真相（反编译 2.1.185 cli.js）

cch 段生成代码：

```js
s = o==="firstParty" && Pu() || o==="vertex" ? " cch=00000;" : ""
// o = xr() = provider; 默认 "firstParty"（无 USE_BEDROCK/VERTEX/... env）

function Pu(){ if(je._CLAUDE_CODE_ASSUME_FIRST_PARTY_BASE_URL) return true; return Zln() }
function Zln(){ let e=process.env.ANTHROPIC_BASE_URL; if(!e) return true; return Vze(e) }
function Vze(e){ try{ return ["api.anthropic.com"].includes(new URL(e).host) }catch{ return false } }
```

> 注：minify 名每 build 轮换。2.1.181 是 `Gu()`，2.1.185 是 `Pu()`，同一逻辑。

**等价于**：cch 发出 ⟺
`(provider∈{firstParty,vertex})` **AND** `(ANTHROPIC_BASE_URL 未设 OR host===api.anthropic.com)`。

这解释了之前所有"抓不到 cch"：
- 第三方样本（`napi.origintask.cn`）：host≠api.anthropic.com → `Vze`=false → 无 cch。
- localhost 代理样本：host=127.0.0.1 → `Vze`=false → 无 cch（**测量假象**）。
- 旧 FINDINGS 把这归因为"firstParty 不发 cch"是错的——真因是 **base_url 门控**。

## 对 ccproxy 的影响（推翻旧结论）

ccproxy 的**出口**：用 OAuth 订阅 token（provider=firstParty）转发到
**`api.anthropic.com`**。一个真 claude 客户端处在**完全相同的位置**
（firstParty + base_url=api.anthropic.com）**会发 cch**。

故 **ccproxy 应该发 cch** 以对齐真客户端——这与 `FINDINGS-2.1.181.md` 结论 2
相反。当时只抓到第三方无-cch 样本，错误外推成"停发"。

但 ccproxy 当前用**旧 ATTEST_KEYS**，算出的 cch 是**错的**：

```
ground truth (2.1.185 firstParty):
  样本1 body → cch=0c516   ccproxy 旧 keys 复算 → cf0b9  ❌
  样本2 body → cch=c2724   旧 keys → 失配          ❌
  3hex: 2/2 match（b68/11a）✅
```

→ ccproxy 现在出口带着**错误的 cch**，这才是真指纹破绽。
**修法 = 抽新 ATTEST_KEYS 算对 cch，不是停发。**

## 新 ATTEST_KEYS 抽取（待办，已具备 ground truth）

cch 是 keyed-xxhash64，v1..v4=4 个 ATTEST_KEYS，输入=整个请求体（cch 段替成
`cch=00000`）。算法（`cch_compute.py`）未变，只缺新 keys。

- **JS bundle 无线索**：PRIME64 常量 + BigInt 字面量在 17MB cli.js 中**0 次** →
  cch 实现在**原生码**（编进 Mach-O arm64），非 JS。
- **静态 grep 失败**：旧 key 小端字节在 binary 中消失（轮换）；新 key 很可能以
  arm64 `MOVZ/MOVK` 立即数拼接、无连续裸字节 → 需**反汇编** cch 原生函数，读
  init 常量旁的 4 个 u64。
- **优势**：现有 2 个 ground-truth 样本（body→cch）可**验证**任何候选 key——
  抽出 4 个 u64 后跑 `verify_captured.py`，2/2 match 即确认。

样本留在 `captured/`（gitignore 不提交；prompt 是 "say hi"/"2+2" 无敏感数据）。

## 附：3hex / metadata 无需改（与 2.1.181 一致）

- 3hex：salt `59cf53e54c78` + 字符索引 `[4,7,20]` + isMeta 前缀表，2 样本全对。
- metadata.user_id：JSON.stringify 字符串，`account_uuid` 在 firstParty 下非空；
  ccproxy `metadata.go` 已正确处理。

---

## 附录:2.1.185 cch native 逆向深挖(2026-06-22,Frida + dtrace + Ghidra)

历经 ~40 种技术的深度逆向。**已确定的架构事实** vs **仍未闭环的三要素**。

### 已确凿(实证)

| 项 | 结论 | 方法 |
|----|------|------|
| **输入结构** | cch 输入 = 请求 body(JSON)把 cch 字段→`00000`。billing 是 body **第一个 system block**(`"system":[{"text":"x-anthropic-billing-header:...cch=00000;"},...]`)。回填偏移确定(小请求 body+1372,大请求 body+8301) | 抓包 + lldb |
| **确定性** | cch 是**确定性 keyed-MAC**(服务端按内容+固定key复算验证,**无随机数**),低20位→5小写hex。固定配置→固定cch | 抓包复现 |
| **计算位置** | cch 在**原生 HTTP 请求 finalization** 计算(函数 `0x101415968`,其 `+0x22f8`=`0x101417c60` 在 send 之前),HTTP Client 线程 | dtrace ustack + Frida backtrace + LC_FUNCTION_STARTS |
| **buffer 架构** | hash 输入 buffer(含cch=00000)与发送 body B(含真cch)**是不同 buffer**;B 由 JS 序列化(非 memmove),回填非原地 | Frida memmove 链追踪 + watchpoint |

### 算法排除(整 body,所有格式/key)

wyhash、rapidhash(=Bun HashMap 默认,seed 0xca81,一次请求277万次,**非cch**)、SipHash、XXH3(默认secret+各seed)、XXH64-withSeed、旧 keyed-XXH64(旧keys)、keyed-XXH64(扫整binary连续u64四元组 + 5150个MOVZ/MOVK四元组,全不中)。**结论:cch hash 是内联的自定义 hash(无标准常量),输入很可能是 body 的抽取(非整 body)**。

### 仍未闭环的三要素

1. **确切输入范围**:确认含 cch=00000 的 body,但整 body 全算法测试全失败 → 强烈指向**抽取**("几个固定位置"),具体哪些字段/字节未定。
2. **算法**:确认非任何标准 hash;自定义 native hash,无可识别常量。
3. **native 函数符号/地址**:缩小到 `0x101415968` 子树(send 前调用 `0x10142cfe4`异步调度/`0x101420c60`/`0x1007a4c98`),但精确的内联 hash 指令未定。

### 技术壁垒(为何卡住)

- **SIP 阻止 destructive dtrace**(`stop()` Permission denied)→ 无法暂停在热点设 lldb watchpoint。
- **lldb 断热函数**(memmove 百万次/请求)陷阱开销太大,跑不到目标。
- **Frida HW watchpoint 可用**(线程对象 `setHardwareWatchpoint` + 单步跨过机制已跑通,能抓写/读+backtrace),但 cch 输入 buffer **瞬态 + JS 写(非 memmove)+ 多层 copy**,无法在回填前定位到正确 buffer。
- cch hash **内联 + 自定义**,Ghidra 反编译子树无标准常量可锚定。

### 可复现工具链(全部就绪)

- 重签名可调试 binary `/tmp/claude-dbg`(get-task-allow + disable-library-validation)
- Frida spawn/attach 脚本 `/tmp/cchhw*.py`(HW watchpoint + 单步)、`cchchain.py`(cch 传播链)、`cchdiag.py`
- dtrace 非破坏性 `bmm.d`(可靠抓 billing memmove dst)
- Ghidra 12.1.2 headless 反编译(raw __TEXT @ base 0x100000b00)
- 验证过的 rapidhash 实现(`/tmp/rapid.c`,13/13 test vector)、keyed-XXH64 全binary扫描器(`/tmp/keyscan.c`)
- ground truth:`captured/*.pre`(body→cch);确定性复现 `--session-id <uuid> --no-session-persistence` + 固定 CONFIG_DIR

### 下一步(需单进程、谨慎 CPU)

最有希望:在 **`0x101415968` 异步 send 执行期间**,定位序列化输出的 body-with-cch=00000 buffer(用 Frida MemoryAccessMonitor 或在 `0x101415968` 入口后扫描大 JSON buffer),设 HW watchpoint 抓回填写 → backtrace → cch 函数 → Ghidra 读算法。或:Frida Stalker 追踪单次 `0x101415968` 调用找写 cch 的指令。

---

## 附录2:差分实验确认输入 ≈ 整 body(2026-06-22)

零调试、低CPU的黑盒差分(同 session/config/日期,只改一处,经代理抓 cch):

| 实验 | 结果 | 推论 |
|------|------|------|
| prompt 第9字符 t→X | cch 06b10→b8e64 | prompt 早位置在输入 |
| prompt 末字符 x→Q | cch 06b10→d12fa | prompt 晚位置在输入(雪崩) |
| 重复完全相同 | cch 06b10(不变) | **确定性确认** |
| 改工作目录(改 system prompt env 段) | cch 06b10→1ad90 | **system prompt 在输入** |

**结论:cch 输入 ≈ 整个请求 body(含 system prompt + messages + metadata,cch字段=00000),与旧 keyed-MAC 设计的输入一致。** 不是"几个固定位置"的抽取——整 body 雪崩敏感。

### 算法:更彻底的排除(整 body,候选key,所有格式,5种归一化变体)

新增排除:FNV1a-64、CRC32、MD5/SHA1/SHA256/SHA512/SHA3、Blake2b/Blake2s(含 keyed 各 digest_size)、Murmur3(32/x64-128)、CityHash64(含 seed)、xxh3-128。
归一化变体(均测试):cch→00000 / +3hex→000 / 删billing块 / 删cch字段 / 清空billing值。**全部不中。**

→ **cch 算法 = 自定义 keyed hash**(无标准算法在任何归一化下匹配)。与旧版(标准 keyed-XXH64)不同,2.1.185 换成了自定义算法。**唯一出路:从 native 反编译读出算法**(已知在 `0x101415968` 子树,内联,无标准常量锚点)。

---

## 附录3:Frida Stalker 指令级热点分析(2026-06-22)

对 `0x101415968`(请求 finalization)做 Stalker block 覆盖,找最热循环(假设 cch hash 读整 body = 最热块)。

**热点块**(exec count):
- JIT 块 `+0x7ca5xxxx`(9214/8914)= JS 序列化(JSON.stringify body,JIT 编译)
- native `+0x1408078`(1478)= **HTTP header 解析**(查空格/tab/冒号 + 字符类表),非 hash
- native `+0x86efe4`(1287)= **`fe25519_mul`**(Curve25519 域乘,×0x13 约简,5-limb);1287≈一次 X25519 scalar mult(255 ladder×5)= **TLS 握手密钥交换,非 cch**
- 其余:数字 int↔float 格式化、970项表查找

**结论:cch hash 没有作为显著 native 热点循环出现** → 要么是小输入循环(cch 输入可能是 body 的某种小型 canonical digest,非整 50KB),要么 cch 在 JIT/JS 里计算(但 bytecode dump 曾证伪)。两者矛盾,未解。

### Curve25519/Ed25519 发现(可能相关也可能是 TLS)
binary 含完整 Ed25519/X25519 实现(`0x100863000-0x10086f000`,`fe25519_mul`@`0x86efe4`)。本次出现的是 TLS X25519(已排除)。**但仍存疑**:cch 是 keyed-MAC,若旧 ATTEST_KEYS"轮换"实为改用签名方案,cch 可能 = 截断的 Ed25519/MAC——这能解释为何所有标准 hash 全不中。**未验证**(需找 cch 路径里非-TLS 的 Ed25519/MAC 调用 + key)。

### 总评:三要素状态
- **#1 输入**:✅ 确认 ≈ 整 body(差分实证)
- **#2 算法**:⚠️ 排除所有标准 hash(~14种×5归一化);确定自定义 keyed;具体逻辑**未拿到**
- **#3 函数**:⚠️ 在 `0x101415968` 子树;精确内联指令**未定**(Stalker 未使其显著浮现)

---

## 附录4:cli.js 源码 + SHA256 hook 确认(2026-06-22)

### cli.js 提取成功(dump_bundle.py,17MB 源码)
- **cch 完全是 native**:cli.js 里 `cch` 只作 `" cch=00000;"` 字面量出现(billing 模板),**无任何 JS 计算/replace**。billing 函数 `c=\`x-anthropic-billing-header: cc_version=${n}; cc_entrypoint=${r};${s}${a}${l}\``,其中 `s=" cch=00000;"`。3hex 由 JS 算(`SHA256(Zyp+chars+version)[:3]`,salt `Zyp="59cf53e54c78"`)并作参数传入。
- 即:JS 建 cch=00000 模板 → Bun fork native 在发送前回填真 cch。**cch 算法在 Bun fork native,不在 cli.js。**

### SHA256 实测排除(Frida hook native sha256_block)
找到唯一 SHA256 HW 函数 `0x1000dd2c0`(`sha256_block(state,data,num_blocks)`,12条 sha256h)。hook 请求全程:
- 所有调用 nb=21-31 块(~1.4KB)、二进制、**成对**(=TLS 1.3 HKDF/HMAC-SHA256 握手)
- **无 nb>31 调用** → body(50KB=780块)**从未经此 SHA256**
- 无任何调用数据含 `cch=`/`MARKERZZ`/billing

→ **cch 不用 SHA256/HMAC-SHA256**(实测,非推测)。结合 Stalker(无 body hash 热点)+ cli.js(native),cch 是 **Bun fork 里的自定义 keyed hash,不读整 body 于紧循环,不用 SHA**。这与"输入≈整body"的差分结论仍有张力——可能 cch 读 body 用 SIMD 宽循环(64-128字节/轮→390-780轮,未在 Stalker top 中明确识别),或对 body 做了某种 native 摘要后再 keyed-hash。**未最终解出。**

### 累计排除的算法(~16种,多数实测)
wyhash, rapidhash(=HashMap), SipHash, XXH3/XXH64(各seed), 旧keyed-XXH64(连续key+5150 MOVZ/MOVK四元组), FNV1a, CRC32, MD5/SHA1/SHA256/SHA512/SHA3, Blake2b/Blake2s(含keyed), Murmur3, CityHash, xxh3-128, **HMAC-SHA256/512/SHA1/Blake2(实测)**, keyed-prefix/suffix。× 5种归一化变体。**全不中。**

---

## 附录5:张力解开 + cli.js hash 排查(2026-06-22,最终)

### body-size 差分解开"张力"(关键)
跑两个不同 body 大小的请求(小 vs +31KB),Stalker diff 找随 body 线性增长的块:全是**对象管理**(0x8bd0c4=对象释放、0x85e464=递归遍历/缓存比对、0x8b1214=对象比较、0x8af=trampoline)。**无一是 hash 循环。**

→ **确证:不存在 hash 整 body 的 native 循环。** "差分说整body" + "Stalker无body-hash热点"自洽:cch hash 的是 body 解析/序列化时的**小型派生摘要**,或流式累加,非原始 50KB body 跑独立循环。

### cli.js hash 函数排查(均非 cch)
- FNV-1a 32位(`t=2166136261;t^=c;t=imul(t,16777619)`)→ 5字符(25字母表)= ID生成器
- systemHash/perBlockHashes/extraBodyHash = **prompt 缓存系统**(cacheDiagnosis),非 cch
- 54处 Math.imul = 各种缓存/ID hash,**cch 全不在 JS**(cli.js 仅 cch=00000 字面量)
- 实测 keyed-FNV1a(32/64,自定义init/prime)over body:不中

### 最终诚实结论(~55 种技术后)
cch = Anthropic **定制 Bun fork 里的 native 自定义 keyed hash**,特征:① 输入≈整body(派生摘要,非原始)② 无标准算法匹配(穷尽~16种)③ 不在 JS ④ 不用 SHA ⑤ 非独立热点循环(内联在序列化/解析)⑥ 无标准常量锚点。**这六条叠加 + 算法和key双未知 + buffer瞬态 + SIP限制,使其在常规逆向(lldb/dtrace/Frida-watchpoint/Stalker/Ghidra/差分/穷举)下无法精确切出。**

需定制 Bun fork 源码 或 内部信息 才能闭环。三要素:#1性质+张力已解,#2/#3精确逻辑未得。

---

## 附录6:完整 buffer 流 + 主线程分析(2026-06-22,最终)

### Buffer 流彻底澄清(Frida 双源对比)
| buffer | 地址例 | 内容 | 角色 |
|--------|--------|------|------|
| Y (billing 串) | 0x2e9d427704cf | `x-anthropic-billing-header:...cch=00000;`(85B) | JS 建的 billing 字符串 |
| B (send body) | 0x2e9d450a178 | 完整请求 body,含**真 cch**(2218B) | JS 序列化的最终 body,被发送 |

**Y ≠ B(差 ~8.6MB)** → 回填发生在 **B(send body)里**,不在 Y。这解释了为何之前所有监 Y(billing memmove dst)的 watchpoint 全失败。

### B 的特性(双跑对比)
- cch 在 **B+0x178**(=billing 在 body 的偏移),B 基址**页对齐**(0x...a000)
- 全址随 mmap ASLR 变,但**低16位稳定**(0x...a178);cch 值**确定**(329d9 两跑一致)
- B 是 arena 内页对齐 slot(JS 逐字段序列化写入,**无 memmove 写 cch=00000 进 B** → cchhw8 全扫确认),回填前地址不可知

### 主线程 Stalker(tid 259,序列化线程)
热点:HashMap rehash(rapidhash 内联 @0x1d99f50,secret 0x2d358dcc/0x8bb84b93,迭代表项)、字节拷贝(序列化 @0x297d5f0)、bitset(分配器 @0x305d360)。**cch hash 在主线程也不作为热点出现** → 与序列化交织 或 hash 小派生摘要。

### 最终(~62 种技术)
数据流已完整理清:JS 建 cch=00000 模板 → 序列化进 B → **Bun fork native 在 B 内回填真 cch** → 发送。但回填是对**瞬态、JS逐字段构建、地址回填前不可知的 B** 的原地写,且 cch hash 无独立循环/无标准常量/不用SHA/不在JS。**这使精确算法(#2)和精确指令(#3)在常规逆向下不可达。** #1 输入性质(≈整body派生)+ 完整buffer流已解。

---

## ★★★ 附录7:cch 算法彻底破解 + 双样本验证通过(2026-06-22)★★★

经 ~75 个实验,**三要素全部清晰浮现并验证**。突破路径:静态搜 XXH/wyhash secret 常量 → 在请求 finalization 区(0x101424bac)发现 XXH64 init 用旧 ATTEST_V3 作 seed → hook XXH64 函数抓真实输入字节 → 双 ground-truth 验证。

### 算法(已验证)
```
cch = XXH64(normalized_body, seed=0x4d659218e32a3268) & 0xFFFFF  → 5 位小写 hex
```
- **算法**:标准 XXH64(非旧版 4-key keyed-xxhash64)
- **seed**:`0x4d659218e32a3268` = 旧 ATTEST_V3(单 key)
- 铁证:init 函数常量 = seed+0x60EA27EEADC0B5D6(=seed+P1+P2)、seed+0xC2B2AE3D27D4EB4F(=seed+P2)、seed+0(=v3)、seed+0x61C8864E7A143579(=seed−P1),即标准 XXH64 累加器初始化

### 确切输入(已验证)
normalized_body = **整个 wire 请求体 JSON**,做 4 处规范化:
1. `"model":"..."` → `"model":""`(model 值置空)
2. 删除 `max_tokens` 字段(含逗号)
3. 删除 `fallbacks` 字段(若存在)
4. `cch=XXXXX;` → `cch=00000;`(占位符,hash 在回填前算)

### native 函数(符号/地址,module base 0x100000000)
| 函数 | 地址 | 作用 |
|------|------|------|
| XXH64_reset | **0x1005feabc** | init 累加器(v1=seed+P1+P2, v2=seed+P2, v3=seed, v4=seed−P1) |
| XXH64_update | **0x1005feb20** | 流式喂数据(x0=state,x1=ptr,x2=len) |
| cch 编排器 | **0x101424bac** | 提取body+规范化(model=""/删max_tokens/fallbacks)+XXH64 |
| body JSON 字段解析器 | **0x10142ca80** | 搜 `"model":`/`"fallbacks":[`/`"max_tokens":` 做括号匹配 |

### 验证
- runtime hook XXH64_reset(过滤 seed=ATTEST_V3)+ update,抓到真实输入 2156B → xxh64 low20 = **b91bb** = 真 cch **b91bb** ✓
- 离线重建 2 个独立 ground-truth:063→**4eb53**✓、064→**a63f5**✓
- 实现:`cch_compute_185.py`(双样本 OK)

### 为何之前 70 个实验没破
① 输入不是原始 body(model 被置空、max_tokens 删除)→ 所有"over 原始 body"测试注定失败;② seed=ATTEST_V3 但需配合规范化输入;③ 算法是 XXH64 不是 wyhash/rapidhash(那俩是 HashMap 用);④ 关键突破=**静态搜 XX H64 init 常量(seed+P1+P2 等)定位函数,再 hook 抓真实输入**,而非黑盒猜。

### ccproxy 落地
出口流量(OAuth→api.anthropic.com,firstParty)**应发 cch**,用上述算法计算。注意:seed 是 baked key,未来版本可能再轮换(从 binary 搜 XXH64 init 常量重抽)。
