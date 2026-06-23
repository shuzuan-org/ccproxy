"""verify_captured.py — Validate cch + 3hex against all newly captured samples.

Reports per-sample match/fail and aggregates by failure mode.
"""
import os, json, re, hashlib
from cch_compute import cch_token

CAPTURED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captured")
SALT = "59cf53e54c78"

# Same 25 prefixes as Go's three_hex.go (post-2026-05-11: <command-name>
# removed after binary analysis showed it is NOT isMeta in the slash-command
# A6 call path).
ISMETA_PREFIXES = [
    "<system-reminder>", "<local-command-caveat>",
    "<local-command-stdout>",
    "Result of calling the ", "Called the ",
    "## Exited Plan Mode", "## Exited Auto Mode",
    "Continue from where you left off.",
    "This session is being continued from another machine",
    "The date has changed.",
    "The PermissionDenied hook indicated", "Your tool call was malformed",
    "Output token limit hit. Resume directly",
    "Auto mode still active", "The user has asked you to work without stopping",
    "The user opened the file ", "The user selected the lines ",
    "The user has expressed a desire to invoke the agent",
    "Note: The file ", "Note: ", "Contents of ",
    "A plan file exists from plan mode at:",
    "The following skills are available for use",
    "<mcp-resource server=", "File snapshot",
]


def is_meta(text):
    t = text.lstrip()
    return any(t.startswith(p) for p in ISMETA_PREFIXES)


def first_non_meta_text(parsed):
    for msg in parsed.get("messages", []):
        if msg.get("role") != "user":
            continue
        c = msg.get("content")
        if isinstance(c, str):
            if not is_meta(c):
                return c
            continue
        if isinstance(c, list):
            for block in c:
                if isinstance(block, dict) and block.get("type") == "text":
                    if not is_meta(block.get("text", "")):
                        return block.get("text", "")
    return ""


def char_at(s, i):
    return s[i] if i < len(s) else "0"


def find_billing_text(parsed):
    """Return the billing-header text from parsed['system'][*].text, or None.

    Must be extracted strictly from system[]: a regex over the raw body
    catches user-pasted code containing 'cch=...' substrings (very common
    when chatting *about* this codebase) and produces wrong matches.

    Anchor on the 'x-anthropic-billing-header:' prefix only. The cch token is
    NOT a reliable anchor: since 2.1.181 it is gated by provider inclusion
    (firstParty/vertex), so legitimate third-party/OAuth traffic carries a
    billing block with no cch= at all.
    """
    for s in parsed.get("system", []):
        if not isinstance(s, dict):
            continue
        text = s.get("text", "")
        if "x-anthropic-billing-header:" in text:
            return text
    return None


def main():
    files = sorted(f for f in os.listdir(CAPTURED) if f.endswith(".bin"))
    cch_ok = cch_fail = cch_absent = 0
    hex_ok = hex_fail = 0
    skip = 0
    failures = []

    for fname in files:
        path = os.path.join(CAPTURED, fname)
        with open(path, "rb") as f:
            body = f.read()

        # filter out non-claude requests (our curl test was 7 bytes)
        if len(body) < 100:
            skip += 1
            continue
        try:
            parsed = json.loads(body)
        except Exception:
            skip += 1
            continue
        billing = find_billing_text(parsed)
        if billing is None:
            skip += 1
            continue

        # ---- cch (operate on the body, but locate the cch token via the
        # billing block to avoid hitting a user-pasted 'cch=XXXXX' first)
        #
        # NOTE: since 2.1.181 the cch token is gated by provider inclusion
        # (firstParty/vertex only — see cc-probe billing_header_template probe).
        # Requests through a third-party/OAuth upstream legitimately carry NO
        # cch. Treat "no cch" as an ABSENT observation, not a skip — we still
        # want to verify 3hex (which is always present) on these samples.
        cch_m = re.search(r'cch=([0-9a-f]{5})', billing)
        if not cch_m:
            cch_absent += 1
            cch_match = None
            observed_cch = "<absent>"
            computed_cch = ""
        else:
            observed_cch = cch_m.group(1)
            # Build the byte string we know is unique in body: the billing line
            # with the real cch. Replace exactly that occurrence with the
            # placeholder, then re-hash.
            observed_cch_bytes = ("cch=" + observed_cch).encode()
            # Find the SAME cch token, but only inside the billing line in body
            billing_bytes = billing.encode()
            billing_idx = body.find(billing_bytes)
            if billing_idx < 0:
                skip += 1
                continue
            # Locate the cch= within the billing block region
            cch_off = body.find(observed_cch_bytes, billing_idx,
                                billing_idx + len(billing_bytes))
            if cch_off < 0:
                skip += 1
                continue
            pre = body[:cch_off] + b"cch=00000" + body[cch_off + len(observed_cch_bytes):]
            computed_cch = cch_token(pre)
            cch_match = observed_cch == computed_cch

        # ---- 3hex (extract version from billing block, not raw body)
        cv_m = re.search(r'cc_version=(\d+\.\d+\.\d+)\.([0-9a-f]{3})', billing)
        if cv_m:
            version = cv_m.group(1)
            observed_3hex = cv_m.group(2)
            try:
                text = first_non_meta_text(parsed)
                chars = char_at(text, 4) + char_at(text, 7) + char_at(text, 20)
                computed_3hex = hashlib.sha256(
                    (SALT + chars + version).encode()).hexdigest()[:3]
                hex_match = observed_3hex == computed_3hex
            except Exception as e:
                hex_match = False
                computed_3hex = f"ERR:{e}"
                text = ""
                chars = ""
        else:
            hex_match = None
            observed_3hex = "<none>"
            computed_3hex = ""
            text = ""
            chars = ""
            version = "?"

        if cch_match is True:
            cch_ok += 1
        elif cch_match is False:
            cch_fail += 1
        # cch_match is None → cch absent (provider not firstParty/vertex);
        # already counted in cch_absent, not a failure.
        if hex_match is True:
            hex_ok += 1
        elif hex_match is False:
            hex_fail += 1

        if cch_match is False or hex_match is False:
            failures.append({
                "file": fname,
                "size": len(body),
                "cch_obs": observed_cch,
                "cch_comp": computed_cch,
                "cch_match": cch_match,
                "version": version if cv_m else "?",
                "3hex_obs": observed_3hex,
                "3hex_comp": computed_3hex,
                "3hex_match": hex_match,
                "first_text_60": text[:60],
                "chars": chars,
            })

    print(f"Total samples: {len(files)} (skipped {skip} non-claude)")
    print(f"cch:  {cch_ok}/{cch_ok+cch_fail} match  ({cch_absent} absent — provider not firstParty/vertex)")
    print(f"3hex: {hex_ok}/{hex_ok+hex_fail} match")
    if failures:
        print(f"\n=== {len(failures)} failures ===")
        for f in failures:
            print(f"\n  {f['file']} ({f['size']}b)")
            print(f"    cch:  obs={f['cch_obs']} comp={f['cch_comp']} match={f['cch_match']}")
            print(f"    3hex: v{f['version']} obs={f['3hex_obs']} comp={f['3hex_comp']} match={f['3hex_match']}")
            print(f"    first non-meta text (60b): {f['first_text_60']!r}")
            print(f"    chars: {f['chars']!r}")


if __name__ == "__main__":
    main()
