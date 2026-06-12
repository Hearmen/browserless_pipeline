"""
collect_builder.py — browserless reconstruction of the `collect` verify field.

`collect = encodeURIComponent( base64( XTEA_ECB( serialize({cd, sd}) ) ) )`.

We have the XTEA cipher + the per-build key (xtea.py) and a REAL captured `{cd, sd}`
template per build (vendored in browserless_pipeline/groundtruth/<build>.real.json). This
module loads the template, patches the session-variable fields (timestamps + the
slider behavior trail derived from the solved gap), re-serializes, and re-encrypts.

── Fidelity limits (be honest) ─────────────────────────────────────────────────
* The groundtruth is the *parsed* {cd, sd}; the VM's exact serialization carries
  fixed-width whitespace padding (SERIALIZE_FORMAT.md §"Whitespace padding") that is
  reproduced byte-exact only for tdc1 (tdc-clean/serialize.js). For builds 2..10 we
  emit compact JSON — structurally faithful, NOT guaranteed byte-identical to the VM.
* The device fingerprint (canvas/WebGL/UA/screen) is template-borrowed from the
  capture machine, not generated for the caller's environment.
=> A server-accepted browserless `collect` cannot be END-TO-END validated here,
   because the same request also needs `eks`/`vData`, which are unsolved. What IS
   validated: XTEA round-trip + structural round-trip (encrypt->decrypt->parse).
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse

from . import xtea

# Vendored into the package (browserless_pipeline/groundtruth/) so it runs standalone.
_GT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "groundtruth")

# Plausible unix-epoch window for spotting timestamp fields (seconds & millis).
_TS_SEC_LO, _TS_SEC_HI = 1_500_000_000, 2_000_000_000
_TS_MS_LO, _TS_MS_HI = 1_500_000_000_000, 2_000_000_000_000


def load_template(build_label: str) -> dict:
    path = os.path.join(_GT_DIR, f"{build_label}.real.json")
    if not os.path.exists(path):
        raise FileNotFoundError(f"no collect template for {build_label}: {path}")
    return json.load(open(path))


def _refresh_timestamps(value, now_s: int, now_ms: int):
    """Recursively bump epoch-looking ints to the current time (preserve everything else)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if _TS_MS_LO <= value <= _TS_MS_HI:
            return now_ms
        if _TS_SEC_LO <= value <= _TS_SEC_HI:
            return now_s
        return value
    if isinstance(value, list):
        return [_refresh_timestamps(v, now_s, now_ms) for v in value]
    if isinstance(value, dict):
        return {k: _refresh_timestamps(v, now_s, now_ms) for k, v in value.items()}
    return value


def build_collect(build_label: str, ans: str | None = None, *, refresh_time: bool = True) -> tuple[str, int]:
    """Return (collect_token, tlg) for the given build.

    collect_token is `encodeURIComponent(base64(XTEA(serialized)))` — drop straight
    into the verify `collect` field; tlg is len(collect_token).
    """
    blob = load_template(build_label)
    if refresh_time:
        now_s, now_ms = int(time.time()), int(time.time() * 1000)
        blob = _refresh_timestamps(blob, now_s, now_ms)
    # NOTE: ans currently rides in the verify `ans` field, not re-injected into the
    # trail here (trail tampering risks structural mismatch); the template trail is a
    # real human-like trail. Hook for future trail synthesis:
    _ = ans
    serialized = json.dumps(blob, separators=(",", ":"), ensure_ascii=False)
    token_b64 = xtea.challenge_encrypt(serialized, build_label)
    # Return RAW base64 — http_client._post_form (urlencode) does the single wire
    # encode (== browser's encodeURIComponent). The server decodes once → raw base64.
    # Pre-quoting here would DOUBLE-encode (server sees %2F… → invalid base64).
    # tlg = length of the raw base64 (matches the HAR: tlg == len(decoded collect)).
    return token_b64, len(token_b64)


if __name__ == "__main__":
    import glob

    files = sorted(glob.glob(os.path.join(_GT_DIR, "tdc*.real.json")))
    ok = 0
    for f in files:
        label = os.path.basename(f).replace(".real.json", "")
        collect, tlg = build_collect(label, ans="488,70;", refresh_time=True)
        # structural round-trip: decrypt the token we just produced -> parse -> same shape
        plain = xtea.decrypt_token(collect, label)  # collect is raw base64 now
        parsed = json.loads(plain)
        same_shape = set(parsed) == {"cd", "sd"} and len(parsed["cd"]) == len(load_template(label)["cd"])
        ok += same_shape
        print(f"{label}: collect {tlg} chars | round-trip+shape {'OK' if same_shape else 'FAIL'}")
    print(f"SELFTEST {ok}/{len(files)} builds round-trip structurally")
    assert ok == len(files)
