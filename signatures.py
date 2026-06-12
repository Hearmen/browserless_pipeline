"""
signatures.py — pluggable captcha solvers.

A solver turns a target URL into a verified captcha `(ticket, randstr)`, which the
pipeline then redeems at `gw_check`. The split exists because `collect`/`eks`/`vData`
are bound to the session that produced them — so a solver owns its whole captcha
exchange and returns the ticket, rather than handing raw signatures to a foreign
session.

  * BrowserEngineSolver — drives the real page engine (Kimi WebBridge -> Chrome):
    CV gap + simulated drag; the site's own engine mints collect/eks/vData/ans and
    the browser's own verify yields the ticket. Works end-to-end TODAY.

  * BrowserlessSolver — runs every browserless-capable stage (prehandle/show/CV/
    collect-via-XTEA) and then RAISES NotReversedError at eks/vData. It exists to
    prove the skeleton is complete and to mark the exact remaining RE gap; it will
    return a real ticket the moment eks/vData are reversed (no rewiring).
"""
from __future__ import annotations

import abc
import base64
import json
import os
import subprocess
import time
import urllib.request

from . import build_detect, collect_builder, http_client


class NotReversedError(NotImplementedError):
    """Raised when a stage depends on an unsolved signature (eks / vData)."""


class SolveResult:
    def __init__(self, ticket: str, randstr: str, build: str = "", meta: dict | None = None):
        self.ticket, self.randstr, self.build, self.meta = ticket, randstr, build, meta or {}

    def __repr__(self):
        return f"SolveResult(build={self.build!r}, ticket={self.ticket[:16]}..., randstr={self.randstr!r})"


class CaptchaSolver(abc.ABC):
    name = "abstract"

    @abc.abstractmethod
    def solve(self, url: str) -> SolveResult:
        ...


# ── Browserless solver ──────────────────────────────────────────────────────────
_NODE_VDATA_CLI = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "node_engine", "getvdata_cli.js")


class BrowserlessSolver(CaptchaSolver):
    """Fully browserless: pure HTTP + CV + reversed signatures (no browser at all).

    Every signature is generated without a browser:
      - ans    : CV gap detection (cv_pipeline)         [ans.x == gap_x, verified]
      - collect: XTEA-ECB rebuild (collect_builder)      [recovered keys]
      - eks    : server seed extracted from live tdc.js  [build_detect.extract_eks]
      - vData  : real Chaos VM run headless in Node       [node_engine/getvdata_cli.js]

    Status: the server ACCEPTS these signatures (verify is evaluated, not
    signature-rejected). Passing (errorCode:0) additionally requires a `collect`
    behavior-trail consistent with `ans`; the current collect reuses a template
    trail, so the slide answer is judged inconsistent (errorCode 12) until a
    matching trail is synthesized. See README "Remaining work".
    """
    name = "browserless"

    def __init__(self, ua: str = http_client.DEFAULT_UA, max_tries: int = 12):
        self.client = http_client.HttpClient(ua=ua)
        self.ua = ua
        self.max_tries = max_tries

    def _vdata(self, param_string, captcha_config, slide_bg_src, tdc_data=""):
        payload = json.dumps({"paramString": param_string, "captchaConfig": captcha_config,
                              "slideBgSrc": slide_bg_src, "tdcData": tdc_data})
        p = subprocess.run(["node", _NODE_VDATA_CLI], input=payload,
                           capture_output=True, text=True, timeout=90)
        out = json.loads(p.stdout or "{}")
        if "error" in out:
            raise RuntimeError(f"vData node engine: {out['error']} :: {p.stderr[:200]}")
        return out["vData"]

    def _attempt(self):
        import cv2
        import numpy as np
        from .gap_detector import detect_gap_multiscale

        import re
        s = http_client.CaptchaSession(ua=self.ua)
        self.client.prehandle(s)
        self.client.show(s)
        html = self.client._get(s.show_url)  # full captchaConfig (for vData)
        cfg = dict(re.findall(r'(\w+):"((?:[^"\\]|\\.)*)"',
                   re.search(r"window\.captchaConfig=\{(.*?)\};", html, re.S).group(1)))

        bg = cv2.imdecode(np.frombuffer(self.client.fetch_image(s, 1), np.uint8), cv2.IMREAD_COLOR)
        sl = cv2.imdecode(np.frombuffer(self.client.fetch_image(s, 2), np.uint8), cv2.IMREAD_UNCHANGED)
        gap_x, gap_y, conf = detect_gap_multiscale(bg, sl)

        tdc_js = self.client.fetch_tdc_js(s)
        build = build_detect.detect_build(tdc_js)
        eks = build_detect.extract_eks(tdc_js)          # reversed: server seed
        # collect with a behavior-trail consistent with the CV gap (shared ans),
        # so the slide passes when the gap is correct; fall back to template trail.
        from . import trail_collect
        if trail_collect.has_template(build):
            collect, tlg, ans = trail_collect.build_collect_with_trail(build, gap_x, gap_y)
        else:
            ans = f"{gap_x},{gap_y};"
            collect, tlg = collect_builder.build_collect(build, ans=ans)

        # vData: real Chaos VM headless, over the verify body
        body = {"aid": http_client.AID, "ans": ans, "collect": collect, "eks": eks,
                "nonce": s.nonce, "sess": s.sess, "sid": s.sid}
        param_string = "&".join(f"{k}={v}" for k, v in body.items())
        # NOTE: passing a synthetic slideBgSrc drove getCaptchaData into a wrong
        # branch (vData 108c); omitting it yields the real 152c length (matches HAR).
        vData = self._vdata(param_string, cfg, "", tdc_data="")

        res = self.client.verify(s, {"ans": ans, "collect": collect, "tlg": tlg,
                                     "eks": eks, "vData": vData, "vlg": s.vlg})
        ec = str(res.get("errorCode", "?"))
        return ec, res, build, conf, len(eks), len(vData)

    def solve(self, url: str) -> SolveResult:
        last_ec = None
        for k in range(1, self.max_tries + 1):
            ec, res, build, conf, eks_n, vd_n = self._attempt()
            print(f"  [browserless] try {k}: build={build} conf={conf:.3f} "
                  f"eks={eks_n}c vData={vd_n}c -> errorCode={ec}")
            last_ec = ec
            if ec == "0":
                print(f"  [browserless] PASSED build={build}")
                return SolveResult(res["ticket"], res["randstr"], build)
        raise RuntimeError(
            f"browserless solver: {self.max_tries} tries, last errorCode={last_ec}. "
            f"All signatures (collect/eks/vData/ans) were generated and ACCEPTED "
            f"(verify evaluated, not signature-rejected). Remaining gap: a collect "
            f"behavior-trail consistent with ans (errorCode 12 = slide judged wrong)."
        )


# ── Browser-engine solver (works today) ─────────────────────────────────────────
_WEBBRIDGE_API = "http://127.0.0.1:10086/command"

_HOOK_JS = (
    "(function(){if(window.TDC&&window.TDC.getData&&!window.__hk){window.__cap=null;"
    "var o=window.TDC.getData;window.TDC.getData=function(){var r=o.apply(this,arguments);"
    "try{window.__cap=r;}catch(e){}return r;};window.__hk=1;}"
    "return !!(window.TDC&&window.TDC.getData);})()"
)

# Eased simulated drag to the CV gap (from tdc-clean/solve_live.py DRAG_JS).
_DRAG_JS = ("(async function(){var thumb=document.querySelector('.tc-drag-thumb');"
    "var bg=document.querySelector('#slideBg')||document.querySelector('.tc-bg');"
    "var piece=[].slice.call(document.querySelectorAll('img')).find(function(i){return /img_index=2/.test(i.src);});"
    "if(!thumb||!bg)return 'NO_ELEMENTS';var tb=thumb.getBoundingClientRect(),bb=bg.getBoundingClientRect();"
    "var scale=bb.width/%d;var gapNat=%d;var pieceRel=piece?(piece.getBoundingClientRect().left-bb.left):0;"
    "var D=gapNat*scale-pieceRel;var sx=tb.left+tb.width/2,sy=tb.top+tb.height/2;"
    "function fire(type,x,y){var t=type==='down'?thumb:document;var mt=type==='down'?'mousedown':(type==='up'?'mouseup':'mousemove');"
    "t.dispatchEvent(new MouseEvent(mt,{bubbles:true,cancelable:true,clientX:x,clientY:y,view:window,button:0}));"
    "var pt=type==='down'?'pointerdown':(type==='up'?'pointerup':'pointermove');"
    "t.dispatchEvent(new PointerEvent(pt,{bubbles:true,cancelable:true,clientX:x,clientY:y,pointerId:1,pointerType:'mouse',isPrimary:true,button:0}));}"
    "var sleep=function(ms){return new Promise(function(r){setTimeout(r,ms);});};"
    "fire('down',sx,sy);await sleep(90);var steps=46;"
    "for(var i=1;i<=steps;i++){var t=i/steps;var ease=1-Math.pow(1-t,3);"
    "var over=(t>0.85)?Math.sin((t-0.85)/0.15*Math.PI)*6*scale:0;var x=sx+D*ease+over;"
    "var y=sy+Math.sin(t*Math.PI)*2+(Math.random()-0.5)*1.2;fire('move',x,y);await sleep(8+Math.floor(Math.random()*16));}"
    "await sleep(120);fire('move',sx+D,sy);await sleep(60);fire('up',sx+D,sy);"
    "return JSON.stringify({D:Math.round(D),scale:Math.round(scale*100)/100});})()")


class BrowserEngineSolver(CaptchaSolver):
    """Drives real Chrome via Kimi WebBridge; the page engine mints all signatures."""
    name = "browser"

    def __init__(self, session: str = "blpipe", max_tries: int = 15):
        self.session = session
        self.max_tries = max_tries

    def _cmd(self, action: str, args: dict, timeout: int = 45) -> dict:
        body = json.dumps({"action": action, "args": args, "session": self.session}).encode()
        req = urllib.request.Request(_WEBBRIDGE_API, body, {"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=timeout)).get("data", {})

    def _net_list(self, filt):
        return self._cmd("network", {"cmd": "list", "filter": filt}).get("requests", [])

    def _net_detail(self, rid):
        return self._cmd("network", {"cmd": "detail", "requestId": rid})

    def _attempt(self, url: str, first: bool):
        import cv2
        from .gap_detector import detect_gap_multiscale

        self._cmd("navigate", {"url": "https://urlsec.qq.com/check.html", "newTab": first}); time.sleep(2.4)
        self._cmd("network", {"cmd": "start"})
        trig = ("(function(){var i=document.querySelector('input');var b=[].slice.call("
                "document.querySelectorAll('a,button')).find(function(e){return (e.innerText||'')"
                ".indexOf('立即检测')>=0;});if(i){i.value=%s;i.dispatchEvent(new Event('input',{bubbles:true}));}"
                "if(b)b.click();return !!b;})()" % json.dumps(url))
        self._cmd("evaluate", {"code": trig}); time.sleep(3.4)

        shows = self._net_list("new_show")
        if not shows:
            return None
        show = shows[-1]["url"]
        imgs = {}
        for idx in (1, 2):
            rs = [r for r in self._net_list("index=%d" % idx) if "hycdn" in r["url"]]
            if not rs:
                return None
            d = self._net_detail(rs[-1]["requestId"])
            imgs[idx] = "/tmp/blpipe_hy%d.png" % idx
            open(imgs[idx], "wb").write(base64.b64decode(d["body"]))
        bg = cv2.imread(imgs[1]); sl = cv2.imread(imgs[2], cv2.IMREAD_UNCHANGED)
        gap_x, gap_y, conf = detect_gap_multiscale(bg, sl)

        self._cmd("navigate", {"url": show, "newTab": False}); self._cmd("network", {"cmd": "start"}); time.sleep(3.4)
        build = self._cmd("evaluate", {"code": "window.TDC_NAME||''"}).get("value", "")
        self._cmd("evaluate", {"code": _HOOK_JS})
        self._cmd("evaluate", {"code": _DRAG_JS % (bg.shape[1], gap_x)})
        time.sleep(2.4)

        vr = self._net_list("cap_union_new_verify")
        if not vr:
            return ("noverify", None, None, build)
        vbody = self._net_detail(vr[-1]["requestId"]).get("body", "")
        try:
            vj = json.loads(vbody.replace("'", '"')) if isinstance(vbody, str) else vbody
        except Exception:
            vj = {}
        from .build_detect import NAME2LABEL
        return (str(vj.get("errorCode", "?")), vj.get("ticket"), vj.get("randstr"),
                NAME2LABEL.get(build, build[:6]))

    def solve(self, url: str) -> SolveResult:
        for k in range(1, self.max_tries + 1):
            print(f"  [browser] try {k}")
            r = self._attempt(url, first=(k == 1))
            if not r:
                continue
            ec, ticket, randstr, build = r
            if ec == "0":
                print(f"  [browser] PASSED (build={build}) ticket={ticket[:20]}...")
                self._cmd("close_session", {})
                return SolveResult(ticket, randstr, build)
            print(f"  [browser] errorCode={ec} (retry)")
        self._cmd("close_session", {})
        raise RuntimeError(f"browser solver exhausted {self.max_tries} tries without errorCode:0")


def get_solver(provider: str, **kw) -> CaptchaSolver:
    if provider == "browser":
        return BrowserEngineSolver(**kw)
    if provider == "browserless":
        return BrowserlessSolver(**{k: v for k, v in kw.items() if k == "ua"})
    raise ValueError(f"unknown provider {provider!r}; use 'browser' or 'browserless'")
