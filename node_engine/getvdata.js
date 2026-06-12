'use strict';
/*
 * getvdata.js — Headless Tencent 防水墙 (tcaptcha slide) vData generator.
 *
 * Runs the REAL obfuscated "Chaos VM" (vm-slide.e201876f.enc.js) in pure Node
 * (no browser) and uses the VM's own XMLHttpRequest interceptor to produce a
 * valid `vData` string, exactly the way the page does.
 *
 * HOW IT WORKS (the driver mechanism, reverse-engineered):
 *   - vm-slide.enc.js is `__TENCENT_CHAOS_VM(0, <bytecode>, window)`. The string
 *     table arg `U` IS the window object; the VM resolves globals via U[name].
 *   - On plain load the VM only runs webpack module-init (~9700 ops) and exports
 *     a set of CommonJS module objects: getCaptchaData, encryptData, encrypt,
 *     base64 encode/decode (custom alphabet), init, and proxyXHR/open/send.
 *   - It does NOT set window.getVData (that name was a red herring; the lowIE
 *     path in tcaptcha-slide.js only calls window.getVData as a fallback).
 *   - The real mechanism: calling proxyXHR() monkey-patches
 *     XMLHttpRequest.prototype.open/send. When a POST to /cap_union_new_verify
 *     is sent, the patched send() collects page data (getCaptchaData),
 *     encrypts it (encryptData), custom-base64-encodes it, and appends
 *     `&vData=<...>` to the request body.
 *   - So we drive it by: load enc.js with a browser shim -> call proxyXHR() ->
 *     fire a verify XHR carrying the paramString -> read vData back out.
 *
 * The vData is intentionally non-deterministic (a per-call Math.random key is
 * baked into the ciphertext), matching real browser behaviour.
 *
 * Public API:
 *   const { getVData, createSession } = require('./getvdata.js');
 *   const vData = getVData(paramString, captchaConfig);
 *   // or, to amortise VM load across many calls:
 *   const sess = createSession({ captchaConfig, profile, TDC });
 *   const vData = sess.getVData(paramString);
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { install } = require('./browser_env.js');

const ENC_PATH = path.join(__dirname, 'vm-slide.enc.js');

// Locate the SET_PROP opcode handler so we can sniff which webpack exports
// objects the VM creates (it never touches `window` directly).
const SETPROP_NEEDLE =
  'function(){var A=n[n.length-2];A[0][A[1]]=n[n.length-1]}';
const SETPROP_PATCH =
  'function(){var A=n[n.length-2];if(globalThis.__CHAOS_SETPROP)globalThis.__CHAOS_SETPROP(A[0],A[1]);A[0][A[1]]=n[n.length-1]}';

function loadInstrumentedSrc() {
  let src = fs.readFileSync(ENC_PATH, 'utf8');
  if (!src.includes(SETPROP_NEEDLE)) {
    throw new Error('getvdata: SET_PROP handler not found — enc.js changed?');
  }
  return src.replace(SETPROP_NEEDLE, SETPROP_PATCH);
}

/**
 * Create a long-lived VM session. Loads + drives the Chaos VM once; the returned
 * object can generate many vData strings cheaply.
 *
 * @param {object} opts
 * @param {object} opts.captchaConfig - window.captchaConfig (38-field object from
 *        the cap_union_new_show response). Required for a realistic fingerprint.
 * @param {object} [opts.profile] - device profile passed to browser_env.install.
 * @param {object} [opts.TDC] - object exposing getData()/getInfo() (Tencent
 *        device collector). If omitted a minimal stub is installed.
 * @param {string} [opts.slideBgSrc] - the slideBg image src (carries &sid=).
 * @param {string} [opts.verifyUrl] - URL the page POSTs to (default
 *        /cap_union_new_verify).
 */
function createSession(opts = {}) {
  const captchaConfig = opts.captchaConfig || {};
  const verifyUrl = opts.verifyUrl || '/cap_union_new_verify';

  const win = install({ profile: opts.profile, captchaConfig });
  win.window = win;

  // window.TDC: device fingerprint collector. The VM reads TDC.getData().
  win.TDC = opts.TDC || {
    getData() { return ''; },
    getInfo() { return {}; },
    clearTickStore() {},
    setData() {},
  };

  // document.getElementById('slideBg').src carries &sid= which feeds the data.
  if (opts.slideBgSrc) {
    const slideBg = { src: opts.slideBgSrc };
    const og = win.document.getElementById;
    win.document.getElementById = (id) =>
      id === 'slideBg' ? slideBg : og.call(win.document, id);
  }

  // Provide a real, proxy-able XMLHttpRequest the VM can monkey-patch.
  let lastSent = null;
  class ChaosXHR {
    constructor() {
      this.readyState = 0; this.status = 0; this.responseText = '';
      this._headers = {}; this._listeners = {};
    }
    open(method, url) { this.method = method; this.url = url; }
    setRequestHeader(k, v) { this._headers[k] = v; }
    send(body) {
      // After proxyXHR has patched the prototype, the VM's wrapper mutates
      // `body` (appending &vData=...) and then calls this original send.
      this._sentBody = body;
      lastSent = { url: this.url, body: body };
    }
    abort() {}
    getResponseHeader() { return null; }
    getAllResponseHeaders() { return ''; }
    addEventListener(t, f) { (this._listeners[t] = this._listeners[t] || []).push(f); }
    removeEventListener() {}
  }
  ChaosXHR.prototype.toString = () =>
    'function XMLHttpRequest() { [native code] }';
  win.XMLHttpRequest = ChaosXHR;

  const ctx = vm.createContext(win);
  win.window = win;

  const modules = [];
  global.__CHAOS_SETPROP = (obj, prop) => {
    if (String(prop) === '__esModule') modules.push(obj);
  };
  ctx.__CHAOS_SETPROP = global.__CHAOS_SETPROP;
  win.__CHAOS_SETPROP = global.__CHAOS_SETPROP;

  const src = loadInstrumentedSrc();
  vm.runInContext(src, ctx, { filename: 'vm-slide.enc.js' });

  function findModule(pred) {
    for (const m of modules) { try { if (pred(m)) return m; } catch (_) {} }
    return null;
  }
  const mProxy = findModule((m) => typeof m.proxyXHR === 'function');
  const mInit = findModule((m) => typeof m.init === 'function');
  if (!mProxy) throw new Error('getvdata: proxyXHR export not found');

  // Drive the VM: install the XHR interceptor (the real page does this).
  try { if (mInit) mInit.init(); } catch (_) { /* init is optional */ }
  mProxy.proxyXHR();

  function getVData(paramString) {
    if (typeof paramString !== 'string') {
      throw new TypeError('getVData(paramString): paramString must be a string');
    }
    // Strip any pre-existing vData so we measure what the VM appends.
    let body = paramString
      .replace(/(^|&)vData=[^&]*/g, '')
      .replace(/^&/, '');

    lastSent = null;
    const x = new win.XMLHttpRequest();
    x.open('POST', verifyUrl);
    x.send(body);

    const sent = (lastSent && lastSent.body) != null
      ? String(lastSent.body)
      : String(x._sentBody || '');
    const m = /[&?]vData=([^&]*)/.exec(sent);
    if (!m) {
      throw new Error('getvdata: VM did not inject vData into the request body');
    }
    return m[1];
  }

  return { getVData, window: win, modules };
}

/**
 * One-shot convenience: build a session and produce one vData.
 * @param {string} paramString - `&`-joined key=value pairs (the verify body).
 * @param {object} [captchaConfig] - window.captchaConfig.
 * @param {object} [opts] - extra createSession options (profile, TDC, slideBgSrc).
 * @returns {string} vData
 */
function getVData(paramString, captchaConfig, opts = {}) {
  const sess = createSession(Object.assign({ captchaConfig }, opts));
  return sess.getVData(paramString);
}

module.exports = { getVData, createSession };
