#!/usr/bin/env python3
"""
compare_params.py — capture the REAL verify wire body from both the browserless and
the browser paths, then diff every parameter field-by-field (and deep-diff the
decrypted `collect`).

Why: browser passes (errorCode 0) but browserless near-misses (errorCode 12) with
the same CV. The crypto is server-accepted, so the residual difference must be a
concrete wire-level discrepancy. This tool surfaces it with REAL captured values
only — no stubs, no fabricated params.

  * browserless wire: monkeypatch HttpClient._post_form to record the exact
    urllib.parse.urlencode(body) string it is about to POST.
  * browser wire: drive Kimi WebBridge -> Chrome, install the XHR `send` hook
    (window.__vb) that records the full verify request body, do a real drag.

The server URL-decodes each form value exactly once. `urllib.parse.parse_qs` does
the same. So: parse_qs each wire, then try to XTEA-decrypt the resulting `collect`.
If the browser's decrypts but the browserless one does not, the browserless collect
is DOUBLE-encoded on the wire (trail_collect already url-quotes it, then
_post_form url-encodes again) and the server sees garbage base64.

    python3 -m browserless_pipeline.compare_params [url]
"""
from __future__ import annotations

import base64
import json
import re
import sys
import time
import urllib.parse
import urllib.request

from . import build_detect, http_client, xtea
from .signatures import BrowserlessSolver, _DRAG_JS, _HOOK_JS

_WEBBRIDGE_API = "http://127.0.0.1:10086/command"
_SESS = "cmpparams"

# Fields whose values are long blobs — show length + head instead of full value.
_BLOB = {"collect", "eks", "vData", "ua"}


# ── decryption helper ─────────────────────────────────────────────────────────
def decrypt_any(collect_value: str):
    """collect_value is exactly what parse_qs returned (server-visible, decoded once).

    Returns (build_label, plaintext_dict, note). Tries every per-build XTEA key.
    Does NOT pre-unquote — the point is to test what the server actually decodes.
    """
    pct = "%" in collect_value
    for label in xtea.KEYS:
        try:
            plain = xtea.decrypt_token(collect_value, label)
            obj = json.loads(plain)
            if isinstance(obj, dict) and "cd" in obj and "sd" in obj:
                return label, obj, ("pct-escaped!" if pct else "")
        except Exception:
            continue
    return None, None, ("STILL %-ESCAPED -> not valid base64" if pct else "no key decrypts")


def _trail_dx(blob: dict):
    cd = blob.get("cd", [])
    for v in cd:
        if (isinstance(v, list) and v and isinstance(v[0], list)
                and len(v[0]) >= 4 and v[0][0] in (1, 2, 3, 4)):
            return sum(s[1] for s in v if s[0] == 1), len(v)
    return None, 0


def _summ_collect(tag: str, raw_collect: str):
    """Print a detailed view of one path's collect: decode-once test + structure."""
    print(f"\n  ── {tag} collect ──")
    print(f"     wire value: {len(raw_collect)}c  head={raw_collect[:48]!r}")
    has_pct = "%" in raw_collect
    print(f"     contains '%': {has_pct}  (server decodes the wire ONCE before reading this)")
    label, blob, note = decrypt_any(raw_collect)
    if not blob:
        print(f"     XTEA decrypt: FAIL — {note}")
        # show what one more unquote would do
        once = urllib.parse.unquote(raw_collect)
        if once != raw_collect:
            l2, b2, _ = decrypt_any(once)
            print(f"     after ONE extra unquote -> {'DECRYPTS as '+l2 if b2 else 'still fails'}"
                  f"  (proves the wire was double-encoded)" if b2 else "")
        return None, None
    dx, n = _trail_dx(blob)
    sd = blob.get("sd", {})
    ans_field = sd.get("slideValue")
    coord = sd.get("coordinate")
    print(f"     XTEA decrypt: OK as {label} {('['+note+']') if note else ''}")
    print(f"     trail: {n} samples, Σtype1-dx={dx}")
    print(f"     sd.coordinate={coord}  slideValue[0:2]={ans_field[:2] if isinstance(ans_field,list) else ans_field}")
    return label, blob


def _parse_wire(wire: str) -> dict:
    """parse_qs the wire body the way the server does (decode each value once)."""
    return {k: v[0] for k, v in urllib.parse.parse_qs(wire, keep_blank_values=True).items()}


# ── browserless capture ───────────────────────────────────────────────────────
def capture_browserless(max_tries: int = 1) -> dict:
    print("=" * 78)
    print("CAPTURE: browserless path (pure HTTP + CV + XTEA + headless vData)")
    print("=" * 78)
    solver = BrowserlessSolver(max_tries=max_tries)
    captured = {}

    orig_post = solver.client._post_form

    def spy(url, data):
        if "new_verify" in url:
            wire = urllib.parse.urlencode(data)
            captured["wire"] = wire
            captured["sent_dict"] = dict(data)
            print("\n[browserless] verify body the pipeline is about to POST:")
            for k in sorted(data):
                v = str(data[k])
                if k in _BLOB:
                    print(f"   {k:14s} = ({len(v)}c) {v[:40]}…")
                else:
                    print(f"   {k:14s} = {v!r}")
            print(f"\n[browserless] exact wire string ({len(wire)}c) head:\n   {wire[:160]}…")
        return orig_post(url, data)

    solver.client._post_form = spy
    try:
        ec, res, build, conf, eks_n, vd_n = solver._attempt()
        print(f"\n[browserless] result: errorCode={ec} build={build} conf={conf:.3f} "
              f"eks={eks_n}c vData={vd_n}c")
        captured["errorCode"] = str(ec)
        captured["resp"] = res
    except Exception as e:
        print(f"[browserless] _attempt raised: {e}")
    return captured


# ── browser capture ───────────────────────────────────────────────────────────
def _cmd(action, args, timeout=45):
    body = json.dumps({"action": action, "args": args, "session": _SESS}).encode()
    req = urllib.request.Request(_WEBBRIDGE_API, body, {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=timeout)).get("data", {})


def _nlist(f):
    return _cmd("network", {"cmd": "list", "filter": f}).get("requests", [])


def _ndet(r):
    return _cmd("network", {"cmd": "detail", "requestId": r})


_VB_HOOK = (
    "(function(){if(!window.__vh){var s=XMLHttpRequest.prototype.send;"
    "XMLHttpRequest.prototype.send=function(b){try{if((this.__u||'').indexOf('new_verify')>=0"
    "||(b&&String(b).indexOf('collect=')>=0)){window.__vb=String(b);"
    "this.addEventListener('load',function(){try{window.__vresp=this.responseText;}catch(e){}});}}catch(e){}"
    "return s.apply(this,arguments);};var o=XMLHttpRequest.prototype.open;"
    "XMLHttpRequest.prototype.open=function(m,u){this.__u=u;return o.apply(this,arguments);};window.__vh=1;}return 1;})()"
)


def capture_browser(url: str, max_tries: int = 6) -> dict:
    print("\n" + "=" * 78)
    print("CAPTURE: browser path (real Chrome via WebBridge — engine mints everything)")
    print("=" * 78)
    import cv2  # noqa
    from .gap_detector import detect_gap_multiscale

    captured = {}
    for k in range(1, max_tries + 1):
        try:
            _cmd("navigate", {"url": "https://urlsec.qq.com/check.html", "newTab": (k == 1)})
            time.sleep(2.4)
            _cmd("network", {"cmd": "start"})
            trig = ("(function(){var i=document.querySelector('input');var b=[].slice.call("
                    "document.querySelectorAll('a,button')).find(function(e){return (e.innerText||'')"
                    ".indexOf('立即检测')>=0;});if(i){i.value=%s;i.dispatchEvent(new Event('input',{bubbles:true}));}"
                    "if(b)b.click();return !!b;})()" % json.dumps(url))
            _cmd("evaluate", {"code": trig})
            time.sleep(3.4)
            shows = _nlist("new_show")
            if not shows:
                print(f"  [browser] try {k}: no show; retry")
                continue
            show = shows[-1]["url"]
            imgs = {}
            ok = True
            for idx in (1, 2):
                rs = [r for r in _nlist("index=%d" % idx) if "hycdn" in r["url"]]
                if not rs:
                    ok = False
                    break
                d = _ndet(rs[-1]["requestId"])
                imgs[idx] = "/tmp/cmp_hy%d.png" % idx
                open(imgs[idx], "wb").write(base64.b64decode(d["body"]))
            if not ok:
                print(f"  [browser] try {k}: missing image; retry")
                continue
            bg = cv2.imread(imgs[1])
            sl = cv2.imread(imgs[2], cv2.IMREAD_UNCHANGED)
            gap_x, gap_y, conf = detect_gap_multiscale(bg, sl)

            _cmd("navigate", {"url": show, "newTab": False})
            _cmd("network", {"cmd": "start"})
            time.sleep(3.2)
            build = _cmd("evaluate", {"code": "window.TDC_NAME||''"}).get("value", "")
            _cmd("evaluate", {"code": _VB_HOOK})
            _cmd("evaluate", {"code": _HOOK_JS})  # getData hook -> window.__cap
            _cmd("evaluate", {"code": _DRAG_JS % (bg.shape[1], gap_x)})
            time.sleep(2.6)

            vb = _cmd("evaluate", {"code": "window.__vb||''"}).get("value", "")
            vresp = _cmd("evaluate", {"code": "window.__vresp||''"}).get("value", "")
            ec = "?"
            m = re.search(r'"errorCode"\s*:\s*"?(\d+)"?', vresp or "")
            if m:
                ec = m.group(1)
            print(f"  [browser] try {k}: build={build} cv_gx={gap_x} conf={conf:.3f} "
                  f"-> errorCode={ec}  vb={len(vb)}c")
            if not vb:
                continue
            captured["wire"] = vb
            captured["errorCode"] = ec
            captured["cv_gx"] = gap_x
            captured["build"] = build
            if ec == "0":  # we want a passing reference; keep going otherwise
                print("\n[browser] verify body the ENGINE sent (errorCode 0 reference):")
                fields = _parse_wire(vb)
                for kk in sorted(fields):
                    v = fields[kk]
                    if kk in _BLOB:
                        print(f"   {kk:14s} = ({len(v)}c) {v[:40]}…")
                    else:
                        print(f"   {kk:14s} = {v!r}")
                break
        except Exception as e:
            print(f"  [browser] try {k}: error {e}")
            continue
    try:
        _cmd("close_session", {})
    except Exception:
        pass
    return captured


# ── diff ──────────────────────────────────────────────────────────────────────
def diff(bl: dict, br: dict):
    print("\n" + "=" * 78)
    print("DIFF: browserless wire vs browser wire (server-visible, decoded once)")
    print("=" * 78)
    bl_wire = bl.get("wire", "")
    br_wire = br.get("wire", "")
    if not bl_wire or not br_wire:
        print(f"  missing wire(s): browserless={bool(bl_wire)} browser={bool(br_wire)}")
        if bl_wire:
            _summ_collect("browserless", _parse_wire(bl_wire).get("collect", ""))
        if br_wire:
            _summ_collect("browser", _parse_wire(br_wire).get("collect", ""))
        return

    bf = _parse_wire(bl_wire)
    rf = _parse_wire(br_wire)
    keys = sorted(set(bf) | set(rf))
    print(f"\n  browserless errorCode={bl.get('errorCode')}  "
          f"browser errorCode={br.get('errorCode')}")
    print(f"\n  {'field':14s} | {'browserless':>26s} | {'browser':>26s}")
    print("  " + "-" * 74)
    for k in keys:
        a = bf.get(k, "∅")
        b = rf.get(k, "∅")
        if k in _BLOB:
            sa = f"{len(a)}c" if a != "∅" else "∅"
            sb = f"{len(b)}c" if b != "∅" else "∅"
            mark = "" if sa == sb else "  <-- LEN DIFF"
            print(f"  {k:14s} | {sa:>26s} | {sb:>26s}{mark}")
        else:
            mark = "" if a == b else "  <-- DIFF"
            print(f"  {k:14s} | {str(a)[:26]:>26s} | {str(b)[:26]:>26s}{mark}")

    # deep collect comparison — the crux
    print("\n" + "-" * 78)
    print("DEEP collect decode (this is exactly what the server XTEA-decrypts):")
    lbl_bl, blob_bl = _summ_collect("browserless", bf.get("collect", ""))
    lbl_br, blob_br = _summ_collect("browser", rf.get("collect", ""))

    print("\n" + "=" * 78)
    print("VERDICT")
    print("=" * 78)
    if blob_br and not blob_bl:
        print("  ✗ browserless collect does NOT decrypt from the wire, browser DOES.")
        print("    => browserless collect is DOUBLE-ENCODED on the wire.")
        print("    Fix: do NOT urllib.parse.quote() collect in trail_collect.py —")
        print("    let http_client._post_form (urlencode) do the single encode.")
    elif blob_bl and blob_br:
        print("  ✓ both collects decrypt from the wire (no double-encode).")
        print("    Residual diff is structural — compare the field table + trail above.")
    else:
        print(f"  browserless decrypts={bool(blob_bl)} browser decrypts={bool(blob_br)}")


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "www.baidu.com"
    bl = capture_browserless()
    br = capture_browser(url)
    diff(bl, br)


if __name__ == "__main__":
    main()
