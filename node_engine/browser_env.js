/*
 * browser_env.js — browser environment for running tdc.js / vm-slide.enc.js headless
 * in Node. ALL device values come from a REAL fingerprint captured from the live
 * browser (node_engine/real_fp.json) — NO stubs / mocks / made-up values.
 *
 * real_fp.json is produced by reading the real navigator/screen/WebGL and the real
 * canvas toDataURL from the actual Chrome on this machine. Canvas/audio fingerprints
 * that the collect stores as hashes are real because the collect itself is real
 * (we reuse real captured collects); this env only needs to expose the same real
 * device surface so the VM computations are consistent with that real device.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const REALFP = JSON.parse(fs.readFileSync(path.join(__dirname, 'real_fp.json'), 'utf8'));

// WebGL parameter name -> GL enum constant (so getParameter(enum) returns the real value).
const GL_ENUM = {
  VENDOR: 0x1f00, RENDERER: 0x1f01, VERSION: 0x1f02, SHADING_LANGUAGE_VERSION: 0x8b8c,
  UNMASKED_VENDOR_WEBGL: 0x9245, UNMASKED_RENDERER_WEBGL: 0x9246,
  MAX_TEXTURE_SIZE: 0x0d33, MAX_VIEWPORT_DIMS: 0x0d3a, MAX_RENDERBUFFER_SIZE: 0x84e8,
  MAX_VERTEX_ATTRIBS: 0x8869, MAX_VERTEX_UNIFORM_VECTORS: 0x8dfb,
  MAX_VARYING_VECTORS: 0x8dfc, MAX_COMBINED_TEXTURE_IMAGE_UNITS: 0x8b4d,
  MAX_TEXTURE_IMAGE_UNITS: 0x8872, MAX_FRAGMENT_UNIFORM_VECTORS: 0x8dfd,
  MAX_CUBE_MAP_TEXTURE_SIZE: 0x851c, ALIASED_LINE_WIDTH_RANGE: 0x846e,
  ALIASED_POINT_SIZE_RANGE: 0x846d, MAX_TEXTURE_MAX_ANISOTROPY_EXT: 0x84ff,
};

function buildGL(realParams) {
  const byEnum = {};
  for (const name in (realParams || {})) {
    if (name === 'extensions') continue;
    const e = GL_ENUM[name];
    if (e !== undefined) byEnum[e] = realParams[name];
  }
  const gl = Object.assign({}, GL_ENUM, {
    getParameter(p) { return byEnum[p] !== undefined ? byEnum[p] : 0; },
    getExtension(name) {
      if (name === 'WEBGL_debug_renderer_info')
        return { UNMASKED_VENDOR_WEBGL: GL_ENUM.UNMASKED_VENDOR_WEBGL, UNMASKED_RENDERER_WEBGL: GL_ENUM.UNMASKED_RENDERER_WEBGL };
      if (name === 'EXT_texture_filter_anisotropic')
        return { MAX_TEXTURE_MAX_ANISOTROPY_EXT: GL_ENUM.MAX_TEXTURE_MAX_ANISOTROPY_EXT };
      return ((realParams && realParams.extensions) || []).includes(name) ? {} : null;
    },
    getSupportedExtensions() { return (realParams && realParams.extensions) || []; },
    getShaderPrecisionFormat() { return { rangeMin: 127, rangeMax: 127, precision: 23 }; },
    getContextAttributes() { return { alpha: true, antialias: true, depth: true, stencil: false }; },
    createBuffer() { return {}; }, bindBuffer() {}, bufferData() {},
    createProgram() { return {}; }, createShader() { return {}; }, shaderSource() {},
    compileShader() {}, attachShader() {}, linkProgram() {}, useProgram() {},
    getProgramParameter() { return true; }, getShaderParameter() { return true; },
    getAttribLocation() { return 0; }, getUniformLocation() { return {}; },
    enableVertexAttribArray() {}, vertexAttribPointer() {}, drawArrays() {},
    viewport() {}, clearColor() {}, clear() {}, readPixels() {}, enable() {}, disable() {},
  });
  return gl;
}

function makeCanvas() {
  const ctx2d = {
    canvas: null,
    fillRect() {}, clearRect() {}, getImageData() { return { data: new Uint8Array(0), width: 0, height: 0 }; },
    putImageData() {}, createImageData() { return { data: new Uint8Array(0) }; },
    setTransform() {}, drawImage() {}, save() {}, fillText() {}, strokeText() {}, restore() {},
    beginPath() {}, moveTo() {}, lineTo() {}, closePath() {}, stroke() {}, fill() {},
    arc() {}, rect() {}, bezierCurveTo() {}, quadraticCurveTo() {}, scale() {}, rotate() {}, translate() {},
    measureText(t) { return { width: (t || '').length * 7 }; }, isPointInPath() { return false; },
    createLinearGradient() { return { addColorStop() {} }; }, createRadialGradient() { return { addColorStop() {} }; },
    font: '', fillStyle: '', strokeStyle: '', textBaseline: '', textAlign: '',
    shadowBlur: 0, shadowColor: '', globalCompositeOperation: '', globalAlpha: 1, lineWidth: 1,
  };
  const realDataURL = (REALFP.canvas && REALFP.canvas[0]) || '';
  const canvas = {
    width: 0, height: 0, style: {},
    getContext(type) {
      if (type === '2d') return ctx2d;
      if (/webgl2/.test(type)) return buildGL(REALFP.webgl2 || REALFP.webgl);
      if (/webgl|experimental-webgl/.test(type)) return buildGL(REALFP.webgl);
      return null;
    },
    toDataURL() { return realDataURL; },         // REAL captured canvas
    toBlob(cb) { cb && cb({}); },
    addEventListener() {}, removeEventListener() {},
    getBoundingClientRect() { return { x: 0, y: 0, width: this.width, height: this.height, top: 0, left: 0, right: this.width, bottom: this.height }; },
  };
  ctx2d.canvas = canvas;
  return canvas;
}

function install(opts = {}) {
  const N = REALFP.nav || {};
  const S = REALFP.screen || {};
  const M = REALFP.misc || {};

  const win = {};
  for (const k of [
    'Object', 'Array', 'String', 'Number', 'Boolean', 'Function', 'Symbol', 'BigInt',
    'Date', 'Math', 'JSON', 'RegExp', 'Error', 'TypeError', 'RangeError', 'SyntaxError',
    'ReferenceError', 'EvalError', 'URIError', 'Promise', 'Map', 'Set', 'WeakMap',
    'WeakSet', 'Proxy', 'Reflect', 'ArrayBuffer', 'DataView', 'Int8Array', 'Uint8Array',
    'Uint8ClampedArray', 'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array',
    'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array',
    'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'encodeURIComponent',
    'decodeURIComponent', 'encodeURI', 'decodeURI', 'escape', 'unescape', 'eval',
    'NaN', 'Infinity', 'undefined', 'globalThis', 'Intl',
  ]) {
    try { win[k] = globalThis[k]; } catch (_) {}
  }
  win.window = win; win.self = win; win.top = win; win.parent = win; win.globalThis = win;
  win.name = ''; win.closed = false;
  win.location = {
    href: opts.href || 'https://t.captcha.qq.com/cap_union_new_show',
    protocol: 'https:', host: 't.captcha.qq.com', hostname: 't.captcha.qq.com',
    origin: 'https://t.captcha.qq.com', pathname: '/cap_union_new_show', search: '', hash: '',
  };

  const screen = {
    width: S.width, height: S.height, availWidth: S.availWidth, availHeight: S.availHeight,
    colorDepth: S.colorDepth, pixelDepth: S.pixelDepth,
    orientation: S.orientation || { type: 'landscape-primary', angle: 0 },
  };
  win.screen = screen;
  win.innerWidth = M.innerWidth; win.innerHeight = M.innerHeight;
  win.outerWidth = M.innerWidth; win.outerHeight = M.innerHeight;
  win.devicePixelRatio = M.devicePixelRatio;

  const navigator = {
    userAgent: N.userAgent, appCodeName: N.appCodeName, appName: N.appName, appVersion: N.appVersion,
    platform: N.platform, product: N.product, productSub: N.productSub,
    vendor: N.vendor, vendorSub: N.vendorSub, language: N.language,
    languages: N.languages || ['zh-CN', 'zh', 'en'],
    hardwareConcurrency: N.hardwareConcurrency, deviceMemory: N.deviceMemory,
    maxTouchPoints: N.maxTouchPoints || 0, cookieEnabled: N.cookieEnabled !== false,
    onLine: true, doNotTrack: N.doNotTrack, webdriver: false,
    plugins: (N.plugins || []).map((nm) => ({ name: nm })),
    mimeTypes: (N.mimeTypes || []).map((t) => ({ type: t })),
    userAgentData: N.userAgentData || undefined,
    connection: N.connection || undefined,
    permissions: { query() { return Promise.resolve({ state: 'prompt' }); } },
    getBattery() { return Promise.resolve({ charging: true, level: 1, chargingTime: 0, dischargingTime: Infinity }); },
    sendBeacon() { return true; },
  };
  navigator.plugins.length = (N.plugins || []).length;
  navigator.mimeTypes.length = (N.mimeTypes || []).length;
  win.navigator = navigator; win.clientInformation = navigator;

  const elementStub = () => ({
    style: {}, setAttribute() {}, getAttribute() { return null; }, appendChild() {},
    removeChild() {}, addEventListener() {}, removeEventListener() {}, getContext() { return null; },
    getBoundingClientRect() { return { x: 0, y: 0, width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 }; },
    querySelector() { return null; }, querySelectorAll() { return []; }, children: [], childNodes: [],
    classList: { add() {}, remove() {}, contains() { return false; } },
  });
  const document = {
    readyState: 'complete', characterSet: M.characterSet || 'UTF-8', charset: M.characterSet || 'UTF-8',
    compatMode: 'CSS1Compat', cookie: '', title: '', referrer: '', URL: win.location.href,
    documentElement: elementStub(), body: elementStub(), head: elementStub(), styleSheets: { length: 0 },
    createElement(tag) { return /canvas/i.test(tag) ? makeCanvas() : elementStub(); },
    createElementNS() { return elementStub(); }, createTextNode() { return {}; },
    getElementById() { return null; }, getElementsByTagName() { return []; },
    getElementsByClassName() { return []; }, querySelector() { return null; },
    querySelectorAll() { return []; }, addEventListener() {}, removeEventListener() {},
    createEvent() { return { initEvent() {} }; }, hasFocus() { return true; },
    visibilityState: 'visible', hidden: false,
  };
  win.document = document;

  win.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
  win.atob = (s) => Buffer.from(s, 'base64').toString('binary');
  win.setTimeout = setTimeout; win.clearTimeout = clearTimeout;
  win.setInterval = setInterval; win.clearInterval = clearInterval;
  win.requestAnimationFrame = (cb) => setTimeout(() => cb(Date.now()), 16);
  win.cancelAnimationFrame = clearTimeout;
  const START = Date.now();
  win.performance = { now: () => Date.now() - START, timeOrigin: START, timing: {}, getEntriesByType() { return []; }, mark() {}, measure() {} };
  win.Date = Date; win.Math = Math; win.JSON = JSON;
  win.crypto = (typeof crypto !== 'undefined') ? crypto : require('crypto').webcrypto;
  win.localStorage = (() => { const m = {}; return {
    getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); },
    removeItem: (k) => { delete m[k]; }, clear: () => { for (const k in m) delete m[k]; },
    key: (i) => Object.keys(m)[i] || null, get length() { return Object.keys(m).length; } }; })();
  win.sessionStorage = Object.assign({}, win.localStorage);
  win.addEventListener = () => {}; win.removeEventListener = () => {}; win.dispatchEvent = () => true;
  win.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {} });
  win.Intl = Intl; win.TextEncoder = TextEncoder; win.TextDecoder = TextDecoder;
  win.URL = URL; win.URLSearchParams = URLSearchParams;
  win.AudioContext = win.webkitAudioContext = function () {
    return { createOscillator() { return { connect() {}, start() {}, stop() {}, frequency: { value: 0 } }; },
      createAnalyser() { return { connect() {}, getFloatFrequencyData() {} }; },
      createGain() { return { connect() {}, gain: { value: 0 } }; },
      createScriptProcessor() { return { connect() {}, disconnect() {} }; },
      createDynamicsCompressor() { return { connect() {} }; }, destination: {}, sampleRate: 44100,
      close() { return Promise.resolve(); } };
  };

  function ctor(name, proto = {}) {
    const f = function () { return Object.create(f.prototype); };
    Object.defineProperty(f, 'name', { value: name });
    f.prototype = proto; f.toString = () => `function ${name}() { [native code] }`;
    return f;
  }
  win.XMLHttpRequest = ctor('XMLHttpRequest', { open() {}, send() {}, setRequestHeader() {}, abort() {},
    getResponseHeader() { return null; }, getAllResponseHeaders() { return ''; }, addEventListener() {}, removeEventListener() {}, readyState: 0, status: 0, response: '' });
  win.Image = ctor('HTMLImageElement', { src: '', width: 0, height: 0 });
  win.Audio = ctor('HTMLAudioElement', {});
  win.Worker = ctor('Worker', { postMessage() {}, terminate() {} });
  win.WebSocket = ctor('WebSocket', { send() {}, close() {} });
  win.MutationObserver = ctor('MutationObserver', { observe() {}, disconnect() {}, takeRecords() { return []; } });
  win.IntersectionObserver = ctor('IntersectionObserver', { observe() {}, disconnect() {} });
  win.Node = ctor('Node', {}); win.Element = ctor('Element', {}); win.HTMLElement = ctor('HTMLElement', {});
  win.HTMLCanvasElement = ctor('HTMLCanvasElement', { getContext() { return null; }, toDataURL() { return ''; } });
  win.HTMLDivElement = ctor('HTMLDivElement', {});
  win.CanvasRenderingContext2D = ctor('CanvasRenderingContext2D', {});
  win.WebGLRenderingContext = ctor('WebGLRenderingContext', GL_ENUM);
  win.WebGL2RenderingContext = ctor('WebGL2RenderingContext', GL_ENUM);
  win.Event = ctor('Event', {}); win.UIEvent = ctor('UIEvent', {}); win.MouseEvent = ctor('MouseEvent', {});
  win.PointerEvent = ctor('PointerEvent', {}); win.KeyboardEvent = ctor('KeyboardEvent', {});
  win.TouchEvent = ctor('TouchEvent', {}); win.CustomEvent = ctor('CustomEvent', {});
  win.Notification = ctor('Notification', {}); win.RTCPeerConnection = ctor('RTCPeerConnection', {});
  win.Function = win.Function || Function;
  win.chrome = { runtime: {}, csi() { return {}; }, loadTimes() { return {}; }, app: {} };

  if (opts.captchaConfig) win.captchaConfig = opts.captchaConfig;
  return win;
}

module.exports = { install, makeCanvas, REALFP };
