# cch-probe — cch / 3hex maintenance toolkit

Scripts for verifying that ccproxy's `cch` and `cc_version.<3hex>` algorithms
still match what real Claude Code clients emit on the wire. Used when bumping
`internal/disguise/version_whitelist.go` or after any Claude CLI release that
might have rotated `ATTEST_KEYS` or added new `isMeta` injection prefixes.

The full procedure is documented in `CLAUDE.md` under
"Maintaining the cch / 3hex version whitelist". This README covers what each
script does so you can pick the right one without re-reading the procedure.

## Reference implementations

- **`cch_compute.py`** — Python reference of the keyed-xxhash64 algorithm in
  `internal/disguise/cch.go`. Uses the same `ATTEST_KEYS` constants. Run
  standalone to sanity-check Go output against a known-good Python baseline.

## Capture (mitmproxy reverse-proxy)

These run as mitmdump scripts (`mitmdump -s SCRIPT`) and dump intercepted
`/v1/messages` requests to disk. The wrapper at `~/.claude/cccc-mitm` routes
the official `claude` CLI through `https://localhost:8443` so traffic flows
through whichever script is loaded.

- **`capture_one.py`** — captures the first request only, then stops.
  Useful for grabbing a single ground-truth sample without an ever-growing
  on-disk pile.
- **`capture_continuous.py`** — captures every request to a timestamped
  file under `captured/`. Use this when you want to exercise multiple
  scenarios (tool calls, multi-turn, slash commands) in one session.
- **`capture_reverse.py`** — older variant kept for reference; behaves
  similarly to `capture_one.py`.

## Verify

- **`verify_captured.py`** — main verification driver. Walks every `*.bin`
  under `captured/`, extracts the billing block from `system[]` (NOT a
  free-form regex on body — that catches user-pasted code as false
  positives), then for each sample checks:
    1. Re-computes cch with `cch_compute.py`'s keyed-xxhash64 and compares
       against the wire value.
    2. Re-computes 3hex with the same `isMetaTextPrefixes` table as
       `internal/disguise/three_hex.go` and compares against the wire value.
  Prints aggregate pass/fail counts plus first few failures with
  diagnostic detail (chars, computed vs observed, first non-meta text).
- **`verify_cch.py`** — older single-purpose script that walks the
  larger `samples/` archive (1358 captures from 2.1.72/2.1.74). Kept
  because the historical cross-version data is useful when investigating
  whether `ATTEST_KEYS` changed between specific versions.

## Helpers

- **`extract_cch_samples.py`** — one-off conversion script: reads a
  mitmproxy `.flow` file (the binary export format) and explodes it into
  `samples/NNNN.bin` plus `index.tsv`. Used once to prepare the historical
  archive; rarely needed.

## What is NOT in version control

- `captured/` — accumulating runtime captures from `cccc-mitm`. Each file
  contains a real request body (potentially with prompts, tool inputs, file
  contents) so it stays local-only.
- `samples/` — historical 2.1.72/2.1.74 archive (~1358 files, several
  hundred MB). Keep on disk if you ever need to re-validate cross-version
  key rotation, but not in git.
- `fresh_sample.bin`, `*.meta` — single ground-truth captures used by the
  Go test suite (see `cch_test.go`, `three_hex_test.go`,
  `cch_e2e_test.go`). Tests use `t.Skipf` when missing, so CI passes
  without them; local maintainers grab one with `cccc-mitm "say hi"` to
  re-enable the ground-truth assertions.
