"""
build_detect.py — identify which of the 10 rotating tdc.js builds the server served.

The server rotates a fixed pool of 10 obfuscated builds (tdc1..tdc10), each with its
own XTEA key (xtea.KEYS). Each build is identified by a stable 32-char global name
(`window.<NAME>` / `window.TDC_NAME`), which maps 1:1 to the tdcN label.

NAME2LABEL is the verified mapping (source of truth:
tdc_deobfuscate/tdc-clean/capture_all_real.py).
"""
from __future__ import annotations

import re

# Verified build-name -> label (tdc_deobfuscate/tdc-clean/capture_all_real.py NAME2LABEL).
NAME2LABEL = {
    "XRQGGFeNgDMiCOVjDlRNZXUUUAQCjHYk": "tdc1",
    "EiCaaiheRYWRFnnmCJClhmUHiYhBVQnb": "tdc2",
    "lFMSEjDhQXagacghaZGKVHMYFSgahXJe": "tdc3",
    "CbVdaENkemmXEjEeXfFOVfZiOVaAdNnO": "tdc4",
    "BRgJZVKZmQbSidBCBfgAihBiXBJOKMgE": "tdc5",
    "XBAMTQQHMlehiUfCOJJejJFZaJcFmmaf": "tdc6",
    "TjAnUHGNjjdRPUNYJUlGZCYcSbdGeXRh": "tdc7",
    "KaTFhXGKdghFEOYMPgEcEgEcZjQKQNbY": "tdc8",
    "GWGWMGBkVmQXYdVHeaPeCUPSEPlYREFc": "tdc9",
    "AiRDcTSmeRXFERjAPgCmNiWBCdOelPUn": "tdc10",
}


class UnknownBuildError(Exception):
    pass


def extract_build_name(tdc_js: str) -> str | None:
    """Pull the build's global name from the served tdc.js body.

    Live builds start with `window.TDC_NAME = "<name>";`. The local beautified
    copies instead expose the name as a `window.<name>` property — handle both.
    """
    m = re.search(r'TDC_NAME\s*=\s*["\']([A-Za-z]{20,40})["\']', tdc_js)
    if m:
        return m.group(1)
    for m in re.finditer(r"window\.([A-Za-z]{28,34})\b", tdc_js):
        if m.group(1) in NAME2LABEL:
            return m.group(1)
    # fallback: any known build name present anywhere in the body
    for name in NAME2LABEL:
        if name in tdc_js:
            return name
    m = re.search(r"window\.([A-Za-z]{28,34})\b", tdc_js)
    return m.group(1) if m else None


def extract_eks(tdc_js: str) -> str:
    """Recover `eks` browserless from the served tdc.js.

    eks is NOT computed — it is the server seed `window[TDC_NAME]`, a string literal
    the server bakes into the tdc.js it serves for the session, which the page just
    echoes back into the verify POST (eks === window.TDC.getInfo().info ===
    window[TDC_NAME]). Verified byte-exact vs the HAR (352-char seed, build tdc6).

    Must be called on the *live session's* tdc.js (its URL carries the session
    js_data/app_data); a stale build's seed will be rejected by the server.
    """
    name = extract_build_name(tdc_js)
    if not name:
        raise UnknownBuildError("cannot find TDC_NAME → cannot extract eks seed")
    m = re.search(re.escape("window." + name) + r"""\s*=\s*['"]([^'"]+)['"]""", tdc_js)
    if not m:
        raise UnknownBuildError(f"TDC_NAME {name} found but no baked window[{name}] seed (eks)")
    return m.group(1)


def detect_build(tdc_js: str) -> str:
    """Return the tdcN label for the served tdc.js, or raise UnknownBuildError."""
    name = extract_build_name(tdc_js)
    label = NAME2LABEL.get(name) if name else None
    if not label:
        raise UnknownBuildError(
            f"served build name {name!r} not in NAME2LABEL — add its mapping/key "
            f"(see tdc_deobfuscate/recover_key.js)"
        )
    return label


if __name__ == "__main__":
    import glob, os

    # Optional fixtures: the raw tdc*.js builds are NOT shipped with the standalone
    # package (the runtime fetches tdc.js live). If they exist alongside the repo,
    # run the build-id selftest; otherwise skip gracefully.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    fixtures = sorted(glob.glob(os.path.join(root, "tdc_deobfuscate", "tdc*.js")))
    if not fixtures:
        print("no local tdc*.js fixtures — skipping build-id selftest "
              "(runtime fetches tdc.js live).")
    else:
        ok = 0
        for f in fixtures:
            src = open(f, encoding="utf-8", errors="replace").read()
            label = detect_build(src)
            exp = os.path.basename(f).replace(".js", "")
            match = "OK" if label == exp else f"MISMATCH (exp {exp})"
            print(f"{os.path.basename(f)} -> {label}  {match}")
            ok += label == exp
        print(f"SELFTEST {ok}/{len(fixtures)} local builds identified")
        assert ok == len(fixtures)
