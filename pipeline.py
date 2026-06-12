"""
pipeline.py — full-chain urlsec.qq.com URL-safety check.

    check_url(url, provider="browser") -> verdict dict

Flow:
    1. solver.solve(url)  -> (ticket, randstr)   [captcha: provider-specific]
    2. http.gw_check(url, ticket, randstr) -> URL safety verdict

Both providers reach errorCode:0 today:
  `provider="browserless"` — pure HTTP + CV + XTEA collect + extracted eks + real
    headless-VM vData; no browser. Gated only by CV gap quality (retries on miss).
  `provider="browser"` — drives real Chrome via Kimi WebBridge (:10086); the page
    engine mints all four signatures. Reference path.
See signatures.py / README.md.

CLI:  python3 -m browserless_pipeline.pipeline <url> [--provider browser|browserless]
"""
from __future__ import annotations

import argparse
import json
import sys

from . import http_client, signatures


def check_url(url: str, provider: str = "browser", **solver_kw) -> dict:
    """Run the full chain for `url` and return the gw_check verdict dict."""
    solver = signatures.get_solver(provider, **solver_kw)
    print(f"[*] checking url={url!r} via provider={solver.name!r}")
    result = solver.solve(url)
    print(f"[*] captcha solved: {result}")

    client = http_client.HttpClient()
    verdict = client.gw_check(url, result.ticket, result.randstr)
    return verdict


def _print_verdict(url: str, verdict: dict) -> int:
    print("\n================ FINAL CHECK RESULT ================")
    print(json.dumps(verdict, ensure_ascii=False, indent=2))
    res = verdict.get("data", {}).get("results", {})
    if res:
        evil = res.get("eviltype")
        safe = str(evil) in ("0", "", "None")
        print(f"\nURL: {res.get('url')}  eviltype={evil}  "
              f"{'SAFE' if safe else 'FLAGGED'}  "
              f"title={res.get('WordingTitle')!r}  wording={res.get('Wording')!r}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="urlsec.qq.com full-chain URL safety check")
    ap.add_argument("url", help="target URL/domain to check, e.g. 4444.vip")
    ap.add_argument("--provider", choices=["browser", "browserless"], default="browser",
                    help="captcha solver (default: browser — works end-to-end today)")
    ap.add_argument("--max-tries", type=int, default=15, help="browser solver retries")
    args = ap.parse_args(argv)

    kw = {"max_tries": args.max_tries} if args.provider == "browser" else {}
    try:
        verdict = check_url(args.url, provider=args.provider, **kw)
    except signatures.NotReversedError as e:
        print(f"\n[!] browserless chain blocked:\n{e}", file=sys.stderr)
        return 3
    except signatures.build_detect.UnknownBuildError as e:
        print(f"\n[!] build detection failed: {e}", file=sys.stderr)
        return 3
    except (ConnectionError, OSError) as e:
        print(f"\n[!] network/transport error: {e}", file=sys.stderr)
        return 2
    return _print_verdict(args.url, verdict)


if __name__ == "__main__":
    sys.exit(main())
