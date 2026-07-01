# probe — covert client-fingerprint discovery

`ccproxy probe` finds hidden steganographic fingerprints that a client (e.g.
Claude Code) embeds in its outbound requests, using **differential testing**
instead of disassembly.

## The idea

A covert fingerprint's implementation can be arbitrarily obfuscated and
scattered across the client binary — but its *purpose* is convergent: it must
make the outbound bytes differ according to some hidden environment signal
(proxy hostname, timezone, locale). So we set the trap at the point it cannot
avoid — the outbound HTTP body — and:

1. hold the semantic input fixed (a single deterministic prompt),
2. flip **one** environment dimension at a time,
3. diff each variant's outbound body against a clean baseline.

Any byte that drifts is a suspected fingerprint bit. No reverse engineering
required; RE only confirms *how* a drift we already found is triggered.

## `ccproxy probe env`

Runs the local environment matrix:

- starts a **sink** (`sink.go`) that stands in for `api.anthropic.com`, records
  every outbound `/v1/messages` body, and returns a minimal valid response so
  the client completes normally. It never contacts a real upstream and never
  needs a real credential.
- drives the real `claude` once per **variant** (`matrix.go`): baseline (UTC /
  en_US), `tz_cn`, `tz_urumqi`, `lang_zh`, and the host-dimension variants
  `host_cn` / `host_reseller` / `host_labkw` (+ a combination).
- **normalizes** each body (`normalize.go`): canonical key order, dynamic ids
  masked — but deliberately **no** Unicode folding, so homoglyph carriers
  survive to be seen.
- **diffs** the covert date line rune-by-rune (`diff.go`) and **scans** it for
  confusable / invisible characters (`scan.go`).
- prints a report (`report.go`) with a per-variant breakdown and a summary of
  which environment dimension changes which bytes.

```
ccproxy probe env                          # tz/locale dimensions (no sudo)
ccproxy probe env --out /tmp/probe-out     # also persist raw/normalized captures
ccproxy probe env --variants tz_cn         # a single dimension (+ baseline)
ccproxy probe env --allow-hosts-edit       # also drive host_* (needs sudo, see below)
```

### The host dimension needs loopback name resolution

The client classifies on `new URL(ANTHROPIC_BASE_URL).hostname`. To exercise
the `.cn` / reseller / AI-lab-keyword signals, that hostname must both *be*
`something.cn` **and** resolve back to the local sink. The only clean way is a
temporary `/etc/hosts` entry, which is root-owned — so `--allow-hosts-edit`
shells out through `sudo tee` (`hosts.go`), wrapping its additions in a marker
block and restoring the original file byte-for-byte on exit.

Without `--allow-hosts-edit`, the `host_*` variants are **skipped and honestly
reported as "not driven"** — never faked from the known classifier logic.

Note: a client may refuse plain `http://` to a non-loopback hostname or upgrade
it to `https`. If the host variants can't be driven for that reason, the report
says so; use a TLS-capable capture path (see `../cch-probe`) for that case.

## What it found (2.1.197)

Confirms the observed fingerprint from the black-box side:

- `tz_cn` / `tz_urumqi` → date separator `-` → `/` (cnTZ signal), pinpointed to
  the two separator positions.
- `lang_zh` → identical to baseline (locale is **not** a signal — a clean
  negative control).
- host variants (when driven) → the `Today's` apostrophe swaps to its homoglyph
  (U+2019 for known domains, U+02BC for AI-lab keywords).

The observed build injects the date line into a `<system-reminder>` inside
`messages[]`, not into `system[]` — `DateLine` (`normalize.go`) locates it
wherever it lives.
