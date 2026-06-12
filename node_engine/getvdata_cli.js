#!/usr/bin/env node
'use strict';
/*
 * getvdata_cli.js — stdin/stdout bridge so the Python pipeline can get vData from
 * the headless Chaos VM (getvdata.js).
 *
 * Input (stdin JSON): { paramString, captchaConfig, slideBgSrc, tdcData }
 *   - paramString : the verify request body (the `&`-joined fields, minus vData)
 *   - captchaConfig: window.captchaConfig (38-field object from cap_union_new_show)
 *   - slideBgSrc  : optional bg image src carrying &sid= (feeds getCaptchaData)
 *   - tdcData     : optional real TDC.getData() token (so vData embeds real collect)
 * Output (stdout JSON): { vData } or { error }
 */
const { createSession } = require('./getvdata.js');

let raw = '';
process.stdin.on('data', (d) => (raw += d));
process.stdin.on('end', () => {
  try {
    const inp = JSON.parse(raw || '{}');
    const opts = { captchaConfig: inp.captchaConfig || {} };
    if (inp.slideBgSrc) opts.slideBgSrc = inp.slideBgSrc;
    if (typeof inp.tdcData === 'string') {
      opts.TDC = { getData: () => inp.tdcData, getInfo: () => ({}), clearTickStore() {}, setData() {} };
    }
    const sess = createSession(opts);
    const vData = sess.getVData(inp.paramString || '');
    process.stdout.write(JSON.stringify({ vData }));
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: e.message }));
  }
});
