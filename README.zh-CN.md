# browserless_pipeline — urlsec.qq.com URL 安全检测链路

> 🌐 [English version](README.md)

`browserless_pipeline` 是一个自包含的 urlsec.qq.com 滑动验证码检测 orchestrator，
无需 Chrome/WebBridge 即可完成 URL 安全判定。

```
prehandle → show → 下载图片 → CV 缺口检测 → ans
          → tdc.js 检测 build → 生成 collect (XTEA) → verify → gw_check → 安全判定
```

## 使用方式

### CLI

```bash
python3 -m browserless_pipeline.pipeline <url> [--provider browser|browserless]

# 无浏览器模式
python3 -m browserless_pipeline.pipeline huawei.com --provider browserless

# 真实浏览器模式（需要 WebBridge + Chrome）
python3 -m browserless_pipeline.pipeline 4444.vip --provider browser
```

### Python API

```python
from browserless_pipeline import check_url

verdict = check_url("huawei.com", provider="browserless")
print(verdict)
```

### 安装依赖

```bash
pip install -r browserless_pipeline/requirements.txt   # opencv-python-headless, numpy
# 需要 Node.js 在 PATH 中（用于 node_engine/getvdata_cli.js）
```

## 架构

URL 在主流程中的流转：

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
              ▼ 9/12 → 重试

 gw_check(url, ticket, randstr) ────────────────────────► VERDICT  http_client.py
```

### 模块依赖

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

### 核心文件

| 文件 | 作用 |
|---|---|
| `pipeline.py` | 入口 / CLI：编排整个检测流程 |
| `signatures.py` | BrowserlessSolver + BrowserEngineSolver |
| `http_client.py` | 纯 HTTP 腾讯客户端（prehandle/show/verify/gw_check） |
| `build_detect.py` | 识别 tdc build 并提取 eks |
| `collect_builder.py` | tdc1 / fallback 的 collect 生成 |
| `trail_collect.py` | tdc2–10 的 collect 生成 |
| `gap_detector.py` | CV 滑块缺口检测 |
| `xtea.py` | XTEA-ECB 加密 |
| `node_engine/` | 无头 Node VM，用于生成 vData |

> 仅用于授权的安全研究。
