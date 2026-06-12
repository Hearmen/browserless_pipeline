"""
http_client.py — pure-HTTP client for the urlsec.qq.com / Tencent 防水墙 check flow.

Stdlib only (urllib). Covers every browserless-capable stage:
  prehandle -> show (+ parse captchaConfig) -> hycdn images -> verify -> gw_check.

Endpoint facts are grounded in ../urlsec.qq.com.har (see selftest in __main__,
which parses the HAR offline and asserts the field extraction).
"""
from __future__ import annotations

import base64
import gzip
import json
import random
import re
import time
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field

CAP_HOST = "https://t.captcha.qq.com"
GW_URL = "https://cgi.urlsec.qq.com/index.php"

AID = "2046626881"
ENTRY_URL = "https://urlsec.qq.com/check.html"
DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

# Hard-coded init params shared across prehandle/show/verify (full_flow.md §global).
BASE_PARAMS = {
    "aid": AID, "protocol": "https", "accver": "1", "showtype": "popup",
    "noheader": "1", "fb": "1", "aged": "0", "enableAged": "0",
    "enableDarkMode": "0", "grayscale": "1", "dyeid": "0", "clientype": "2",
    "lang": "zh-cn",
}


def _rand_callback() -> str:
    return "_aq_" + str(random.random())[2:8]


def _jsonp(text: str) -> dict:
    """Extract the JSON argument from a `cb({...})` JSONP body."""
    m = re.search(r"\((.*)\)\s*;?\s*$", text.strip(), re.S)
    payload = m.group(1) if m else text
    return json.loads(payload)


def parse_captcha_config(html: str) -> dict:
    """Pull the flat window.captchaConfig={...} object from the show HTML.

    The refreshed `sess`, `nonce`, image id and tdc.js URL are all server-embedded
    here (NOT computed by JS at runtime), so a browserless client can read them.
    """
    m = re.search(r"window\.captchaConfig\s*=\s*\{(.*?)\};", html, re.S)
    if not m:
        raise ValueError("captchaConfig not found in show HTML")
    body = m.group(1)
    cfg = dict(re.findall(r'(\w+)\s*:\s*"((?:[^"\\]|\\.)*)"', body))
    out = {
        "nonce": cfg.get("nonce", ""),
        "sess": cfg.get("sess", ""),          # the upgraded session
        "dcFileName": cfg.get("dcFileName", ""),  # tdc.js?app_data=...&js_data=...
        "vmByteCode": cfg.get("vmByteCode", ""),
        "vmAvailable": cfg.get("vmAvailable", ""),
        "uip": cfg.get("uip", ""),
        "spt": cfg.get("spt", ""),
    }
    img = re.search(r"image=(\d+)", cfg.get("cdnPic1", "") + cfg.get("cdnPic2", ""))
    out["image_id"] = img.group(1) if img else ""
    out["cdnPic1"] = cfg.get("cdnPic1", "")
    out["cdnPic2"] = cfg.get("cdnPic2", "")
    return out


def vlg_from_config(cfg: dict) -> str:
    """vlg = [vmAvailable?1:0, vmByteCode?1:0, 1].join('_')  (full_flow.md §⑦.38)."""
    return "%d_%d_1" % (1 if cfg.get("vmAvailable") else 0, 1 if cfg.get("vmByteCode") else 0)


@dataclass
class CaptchaSession:
    """Mutable state carried across the flow."""
    ua: str = DEFAULT_UA
    sess: str = ""
    sid: str = ""
    nonce: str = ""
    image_id: str = ""
    dc_file: str = ""
    vlg: str = "0_0_1"
    rnd: int = field(default_factory=lambda: random.randint(0, 999999))
    create_iframe_start: int = field(default_factory=lambda: int(time.time() * 1000))
    prehandle_load_time: int = 224
    _subsid: int = 0
    show_url: str = ""

    @property
    def ua_b64(self) -> str:
        return base64.b64encode(self.ua.encode()).decode()

    def next_subsid(self) -> str:
        self._subsid += 1
        return str(self._subsid)


class HttpClient:
    def __init__(self, ua: str = DEFAULT_UA, timeout: int = 25):
        self.timeout = timeout
        self.ua = ua

    @staticmethod
    def _decompress(raw: bytes, encoding: str | None) -> bytes:
        enc = (encoding or "").lower()
        if enc == "gzip" or raw[:2] == b"\x1f\x8b":
            return gzip.decompress(raw)
        if enc == "deflate":
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -15)
        return raw

    def _get(self, url: str, binary: bool = False):
        req = urllib.request.Request(url, headers={
            "User-Agent": self.ua, "Referer": ENTRY_URL,
            "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.9",
        })
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            raw = self._decompress(r.read(), r.headers.get("Content-Encoding"))
        return raw if binary else raw.decode("utf-8", "replace")

    def _post_form(self, url: str, data: dict) -> str:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, body, headers={
            "User-Agent": self.ua, "Referer": "https://t.captcha.qq.com/",
            "Origin": "https://t.captcha.qq.com",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        })
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return r.read().decode("utf-8", "replace")

    # ---- stages ----------------------------------------------------------------
    def prehandle(self, s: CaptchaSession) -> CaptchaSession:
        params = dict(BASE_PARAMS)
        params.update({
            "ua": s.ua_b64, "cap_cd": "", "uid": "", "entry_url": ENTRY_URL,
            "elder_captcha": "0", "js": "/tcaptcha-frame.1e14192e.js",
            "login_appid": "", "support_media": "jpeg,png,gif,mp4,webm",
            "wb": "2", "version": "1.1.0", "subsid": s.next_subsid(),
            "callback": _rand_callback(), "sess": "", "agent_id": "", "agent_auth_sign": "",
        })
        url = f"{CAP_HOST}/cap_union_prehandle?" + urllib.parse.urlencode(params)
        j = _jsonp(self._get(url))
        s.sess, s.sid = j["sess"], j["sid"]
        return s

    def show(self, s: CaptchaSession) -> CaptchaSession:
        params = dict(BASE_PARAMS)
        params.update({
            "ua": s.ua_b64, "sess": s.sess, "fwidth": "0", "sid": s.sid,
            "wxLang": "", "tcScale": "1", "uid": "", "cap_cd": "", "rnd": str(s.rnd),
            "prehandleLoadTime": str(s.prehandle_load_time),
            "createIframeStart": str(s.create_iframe_start),
            "global": "0", "subsid": s.next_subsid(),
        })
        s.show_url = f"{CAP_HOST}/cap_union_new_show?" + urllib.parse.urlencode(params)
        cfg = parse_captcha_config(self._get(s.show_url))
        s.sess = cfg["sess"] or s.sess           # session upgrade
        s.nonce = cfg["nonce"]
        s.image_id = cfg["image_id"]
        s.dc_file = cfg["dcFileName"]
        s.vlg = vlg_from_config(cfg)
        return s

    def fetch_image(self, s: CaptchaSession, index: int) -> bytes:
        params = {
            "index": str(index),
            "image": f"{s.image_id}?aid={AID}",
            "sess": s.sess, "sid": s.sid, "img_index": str(index),
            "subsid": s.next_subsid(),
        }
        return self._get(f"{CAP_HOST}/hycdn?" + urllib.parse.urlencode(params), binary=True)

    def fetch_tdc_js(self, s: CaptchaSession) -> str:
        """The tdc.js URL (with app_data/js_data) is embedded as dcFileName."""
        if not s.dc_file:
            raise ValueError("no dcFileName — call show() first")
        return self._get(f"{CAP_HOST}/{s.dc_file.lstrip('/')}")

    def verify(self, s: CaptchaSession, sig: dict) -> dict:
        """POST cap_union_new_verify. `sig` carries collect/tlg/eks/vData/ans."""
        body = dict(BASE_PARAMS)
        body.update({
            "ua": s.ua_b64, "sess": s.sess, "fwidth": "0", "sid": s.sid,
            "wxLang": "", "tcScale": "1", "uid": "", "cap_cd": "", "rnd": str(s.rnd),
            "prehandleLoadTime": str(s.prehandle_load_time),
            "createIframeStart": str(s.create_iframe_start), "global": "0",
            "subsid": "2", "cdata": "0",
            "ans": sig["ans"], "vsig": "", "websig": "", "subcapclass": "",
            "pow_answer": "", "pow_calc_time": "0",
            "collect": sig["collect"], "tlg": str(sig.get("tlg", len(sig["collect"]))),
            "fpinfo": "", "eks": sig["eks"], "nonce": s.nonce,
            "vlg": sig.get("vlg", s.vlg), "vData": sig["vData"],
        })
        return _jsonp_or_json(self._post_form(f"{CAP_HOST}/cap_union_new_verify", body))

    def gw_check(self, url: str, ticket: str, randstr: str) -> dict:
        params = {
            "m": "check", "a": "gw_check",
            "callback": "jQuery%d_%d" % (random.randint(10**20, 10**21), int(time.time() * 1000)),
            "url": url, "ticket": ticket, "randstr": randstr,
            "_": str(int(time.time() * 1000)),
        }
        raw = self._get(GW_URL + "?" + urllib.parse.urlencode(params))
        return _jsonp(raw)


def _jsonp_or_json(text: str) -> dict:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return _jsonp(text)


if __name__ == "__main__":
    # Offline selftest: parse the 3 key responses straight out of the HAR.
    # The HAR is NOT shipped with the standalone package; skip if absent.
    import os, sys

    har_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "urlsec.qq.com.har")
    if not os.path.exists(har_path):
        print(f"no HAR fixture at {har_path} — skipping offline parse selftest "
              "(runtime hits the live endpoints).")
        sys.exit(0)
    har = json.load(open(har_path))
    got = {}
    for e in har["log"]["entries"]:
        u = e["request"]["url"]
        txt = e["response"]["content"].get("text", "")
        if "cap_union_prehandle" in u and "prehandle" not in got:
            j = _jsonp(txt); got["prehandle"] = (j["sess"][:10], j["sid"])
        elif "cap_union_new_show" in u and "show" not in got:
            got["show"] = parse_captcha_config(txt)
        elif "gw_check" in u:
            got["gw"] = _jsonp(txt)["data"]["results"]

    p = got["prehandle"]; assert p[1] == "7468947454248751104", p
    c = got["show"]
    assert c["nonce"] == "eda1152f11f1daf0", c["nonce"]
    assert c["sess"].startswith("s10COFhf"), c["sess"][:12]
    assert c["image_id"] == "937370472877611264", c["image_id"]
    assert "tdc.js?app_data=" in c["dcFileName"], c["dcFileName"][:30]
    assert vlg_from_config(c) == "0_0_1", vlg_from_config(c)
    g = got["gw"]; assert g["url"] == "45677.vip", g
    print("prehandle:", p)
    print("show.nonce:", c["nonce"], "| sess:", c["sess"][:12] + "...", "| image:", c["image_id"])
    print("show.vlg:", vlg_from_config(c), "| tdc.js embedded:", "app_data=" in c["dcFileName"])
    print("gw_check verdict:", g)
    print("SELFTEST OK")
