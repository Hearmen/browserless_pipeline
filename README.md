# browserless_pipeline — urlsec.qq.com URL-safety checker

> 🌐 [中文版本](README.zh-CN.md)

`browserless_pipeline` is a self-contained orchestrator for the urlsec.qq.com slide-captcha URL-safety check. It can produce a safety verdict without Chrome or WebBridge.

```
prehandle → show → download images → CV gap detection → ans
          → tdc.js build detect → generate collect (XTEA) → verify → gw_check → verdict
```

## Usage

### CLI

```bash
python3 -m browserless_pipeline.pipeline <url> [--provider browser|browserless]

# Browserless mode
python3 -m browserless_pipeline.pipeline huawei.com --provider browserless

# Real-browser mode (requires WebBridge + Chrome)
python3 -m browserless_pipeline.pipeline 4444.vip --provider browser
```

### Python API

```python
from browserless_pipeline import check_url

verdict = check_url("huawei.com", provider="browserless")
print(verdict)
```

### Install dependencies

```bash
pip install -r browserless_pipeline/requirements.txt   # opencv-python-headless, numpy
# Node.js must be on PATH (for node_engine/getvdata_cli.js)
```

## Architecture

How a URL flows through the pipeline:

```
 check_url(url)                                       pipeline.py
      │
      ▼
 BrowserlessSolver.solve → _attempt()                 signatures.py
      │
      ├─► prehandle  ───────────────────► sess, sid          http_client.py
      ├─► show       ───────────────────► nonce, image_id    http_client.py
      ├─► fetch_image ×2 ───────────────► bg, slider         http_client.py
      ├─► detect_gap_multiscale ────────► gap_x, gap_y       gap_detector.py
      ├─► fetch_tdc_js ─────────────────► tdc.js             http_client.py
      │        ├─ detect_build ─────────► build (tdc1–10)    build_detect.py
      │        └─ extract_eks ──────────► eks                build_detect.py
      │
      ├─► collect ── trail template?                        trail_collect.py / collect_builder.py
      │       yes (tdc2–10): trail_templates/<build>.json + xtea.py
      │       no  (tdc1)    : groundtruth/<build>.real.json + xtea.py
      │
      ├─► vData ── subprocess → node_engine/getvdata_cli.js  signatures.py
      │
      └─► verify(POST) ◄── {ans, collect, eks, vData}        http_client.py
              │
              ▼ errorCode 0 → ticket, randstr
              ▼ 9/12 → retry

 gw_check(url, ticket, randstr) ────────────────────────► VERDICT  http_client.py
```

### Module dependency graph

```
                         pipeline.py
                          │ imports
                  ┌───────┴───────┐
                  ▼               ▼
            signatures.py      http_client.py
                  │ imports
   ┌──────┬───────┼───────────┬──────────────┐
   ▼      ▼       ▼           ▼              ▼
http_   build_  collect_    trail_         gap_detector.py
client  detect  builder ◄── collect         (cv2, numpy)
.py     .py     .py    imports  .py
                  │              │
                  └──────┬───────┘
                         ▼
                       xtea.py

  signatures.py ── spawns ─► node_engine/getvdata_cli.js
                                  │ require
                                  ▼
                              getvdata.js ── require ─► browser_env.js
                                  │ runs (vm context)
                                  ▼
                              vm-slide.enc.js
```

### Core files

| File | Purpose |
|---|---|
| `pipeline.py` | Entry / CLI: orchestrates the whole check flow |
| `signatures.py` | BrowserlessSolver + BrowserEngineSolver |
| `http_client.py` | stdlib-only Tencent HTTP client (prehandle/show/verify/gw_check) |
| `build_detect.py` | Identify tdc build and extract eks |
| `collect_builder.py` | Collect generator for tdc1 / fallback |
| `trail_collect.py` | Collect generator for tdc2–10 |
| `gap_detector.py` | CV slider-gap detection |
| `xtea.py` | XTEA-ECB cipher |
| `node_engine/` | Headless Node VM used to generate vData |

> Authorized security research use only.
