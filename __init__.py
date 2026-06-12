"""
browserless_pipeline — full-chain urlsec.qq.com URL-safety checker.

A single orchestrator that runs the entire check flow:
  prehandle -> show -> (tdc.js/images) -> CV ans -> collect -> verify -> gw_check.

Every browserless-capable stage runs over pure HTTP/CV here. The two unsolved,
per-session server-validated signatures (`eks`, `vData`) are isolated behind a
pluggable captcha solver:

  * BrowserEngineSolver — solves via the real page engine (Kimi WebBridge -> Chrome);
    the site mints eks/vData/collect/ans and returns a ticket. Works end-to-end TODAY.
  * BrowserlessSolver   — collect (XTEA) + ans (CV) browserless; raises
    NotReversedError at eks/vData (the remaining reverse-engineering gap).

See README.md for the browserless/blocked breakdown and the exact RE work left.
"""
from .signatures import (
    BrowserEngineSolver,
    BrowserlessSolver,
    CaptchaSolver,
    NotReversedError,
    get_solver,
)


def __getattr__(name):  # lazy so `python -m ...pipeline` doesn't double-import
    if name == "check_url":
        from .pipeline import check_url
        return check_url
    raise AttributeError(name)

__all__ = [
    "check_url",
    "CaptchaSolver",
    "BrowserEngineSolver",
    "BrowserlessSolver",
    "get_solver",
    "NotReversedError",
]
