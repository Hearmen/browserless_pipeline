"""
trail_collect.py — build a `collect` whose behavior-trail is consistent with the
CV gap (ans), so the server's slide-consistency check passes.

Why: the browser passes because its real drag writes a trail into `collect` that ends
at the gap. A template trail from a different solve ends elsewhere → errorCode 12.

How: we captured REAL, server-accepted passing collects (one per build) in
`trail_templates/<build>.json`, each with a known winning `ans`. Empirically the
trail's total type-1 dx is linear in ans:  trail_dx ≈ 2.10 * ans  (the device scale
`coordinate[2]`≈2.0912). So to retarget a template to a new gap `cv_gx`:

    factor = cv_gx / template_ans          (≈ 1, since both are ~450–520)

scale every type-1 dx in cd[trail] and every dx in sd.slideValue by `factor`, refresh
timestamps, re-encrypt with the build's XTEA key. The submitted ans is `cv_gx`.

Validated empirically: trail_dx/ans ratio was 2.037–2.046 across 15 real passes.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse

from . import xtea
from .collect_builder import _refresh_timestamps

_TPL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trail_templates")


def has_template(build: str) -> bool:
    return os.path.exists(os.path.join(_TPL_DIR, f"{build}.json"))


def _trail_index(cd: list) -> int | None:
    for i, v in enumerate(cd):
        if (isinstance(v, list) and v and isinstance(v[0], list)
                and len(v[0]) >= 4 and v[0][0] in (1, 2, 3, 4)):
            return i
    return None


def build_collect_with_trail(build: str, gap_x: int, gap_y: int = 30) -> tuple[str, int, str]:
    """Return (collect_token, tlg, ans) for `build` retargeted to gap_x.

    ans is returned so the caller submits exactly what the trail encodes.
    """
    tpl = json.load(open(os.path.join(_TPL_DIR, f"{build}.json")))
    blob = tpl["blob"]
    tpl_ans = tpl["ans"]
    factor = gap_x / float(tpl_ans)

    now_ms = int(time.time() * 1000)
    blob = _refresh_timestamps(blob, int(time.time()), now_ms)
    cd, sd = blob["cd"], blob["sd"]

    ti = _trail_index(cd)
    if ti is not None:
        new_trail = []
        for samp in cd[ti]:
            s = list(samp)
            if s[0] == 1:                       # type-1 move: scale dx
                s[1] = int(round(s[1] * factor))
            elif s[0] == 4:                     # idle: refresh absolute ts
                s[3] = now_ms
            new_trail.append(s)
        cd[ti] = new_trail

    sv = sd.get("slideValue")
    if isinstance(sv, list) and sv:
        sv[0] = [int(round(sv[0][0] * factor))] + list(sv[0][1:])  # header start-x
        for i in range(1, len(sv)):
            sv[i] = [int(round(sv[i][0] * factor))] + list(sv[i][1:])
        sd["slideValue"] = sv

    serialized = json.dumps(blob, separators=(",", ":"), ensure_ascii=False)
    token_b64 = xtea.challenge_encrypt(serialized, build)
    # RAW base64 — _post_form (urlencode) single-encodes for the wire; server decodes
    # once → raw base64. Pre-quoting double-encodes (server sees %2F → XTEA fails).
    # tlg = len(raw) (HAR: tlg == len(decoded collect)).
    ans = f"{gap_x},{gap_y};"
    return token_b64, len(token_b64), ans


def graft_trail_into(fresh_blob: dict, build: str, gap_x: int, gap_y: int = 30) -> tuple[str, int, str]:
    """Graft a real (scaled-to-gap_x) trail from build's template into a FRESH blob.

    fresh_blob = a freshly headless-generated collect blob (fresh tokenid, real-ish
    fingerprint, but empty trail). We copy the template's trail/slideValue/coordinate
    (scaled to gap_x) into it, so the collect is both fresh (no replay) AND has a
    human-like drag ending at the gap. Re-encrypt with the build key.
    """
    tpl = json.load(open(os.path.join(_TPL_DIR, f"{build}.json")))
    tb = tpl["blob"]
    factor = gap_x / float(tpl["ans"])
    now_ms = int(time.time() * 1000)

    cd, sd = fresh_blob["cd"], fresh_blob["sd"]
    tcd = tb["cd"]
    ti_tpl = _trail_index(tcd)
    ti = _trail_index(cd)
    if ti_tpl is not None and ti is not None:
        scaled = []
        for samp in tcd[ti_tpl]:
            s = list(samp)
            if s[0] == 1:
                s[1] = int(round(s[1] * factor))
            elif s[0] == 4:
                s[3] = now_ms
            scaled.append(s)
        cd[ti] = scaled
    # copy slideValue (scaled) + coordinate from template
    sv = [list(x) for x in tb["sd"].get("slideValue", [])]
    if sv:
        sv[0] = [int(round(sv[0][0] * factor))] + list(sv[0][1:])
        for i in range(1, len(sv)):
            sv[i] = [int(round(sv[i][0] * factor))] + list(sv[i][1:])
        sd["slideValue"] = sv
    if "coordinate" in tb["sd"]:
        sd["coordinate"] = list(tb["sd"]["coordinate"])
    for k in ("dragobj", "ft", "trycnt", "refreshcnt"):
        if k in tb["sd"]:
            sd[k] = tb["sd"][k]

    serialized = json.dumps(fresh_blob, separators=(",", ":"), ensure_ascii=False)
    token_b64 = xtea.challenge_encrypt(serialized, build)  # RAW base64; see build_collect_with_trail
    return token_b64, len(token_b64), f"{gap_x},{gap_y};"


if __name__ == "__main__":
    import glob
    for f in sorted(glob.glob(os.path.join(_TPL_DIR, "*.json"))):
        build = os.path.basename(f).replace(".json", "")
        collect, tlg, ans = build_collect_with_trail(build, 480, 30)
        # verify round-trip + trail total ≈ 2.10*480
        plain = json.loads(xtea.decrypt_token(collect, build))  # collect is raw base64 now
        ti = _trail_index(plain["cd"])
        dx = sum(s[1] for s in plain["cd"][ti] if s[0] == 1)
        print(f"{build}: collect {tlg}c ans={ans} trail_dx={dx} (target≈{int(2.10*480)})")
