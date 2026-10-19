(function () {
  'use strict';

  var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  function h(tag, cls, txt) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt != null) e.textContent = txt;
    return e;
  }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, reduce ? Math.min(ms, 60) : ms); }); }
  function icons() { if (window.lucide && window.lucide.createIcons) { try { window.lucide.createIcons(); } catch (e) { /* icons are decoration only */ } } }
  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  function stamp() { var d = new Date(); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); }
  function lerp(a, b, t) { return a + (b - a) * t; }
  function until(fn, ms) {
    return new Promise(function (res) {
      var t0 = Date.now();
      (function tick() { if (fn() || Date.now() - t0 > (ms || 15000)) return res(); setTimeout(tick, 60); })();
    });
  }

  var voice = { level: 0, target: 0 };

  /* ---------- toast + modal ---------- */
  function toast(msg, kind) {
    var t = h('div', 'toast ' + (kind || ''));
    t.appendChild(h('span', 'dot'));
    t.appendChild(h('span', '', msg));
    $('#toasts').appendChild(t);
    requestAnimationFrame(function () { t.classList.add('on'); });
    setTimeout(function () { t.classList.remove('on'); setTimeout(function () { t.remove(); }, 400); }, 3600);
  }
  var lastFocus = null;
  function openModal(title, node) {
    var m = $('#modal');
    $('.m-title', m).textContent = title;
    var b = $('.m-body', m);
    b.innerHTML = '';
    b.appendChild(node);
    m.classList.add('open');
    m.setAttribute('aria-hidden', 'false');
    lastFocus = document.activeElement;
    $('.m-close', m).focus();
  }
  function closeModal() {
    var m = $('#modal');
    m.classList.remove('open');
    m.setAttribute('aria-hidden', 'true');
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }
  $('#modal').addEventListener('click', function (e) { if (e.target.closest('[data-close]')) closeModal(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && $('#modal').classList.contains('open')) closeModal(); });

  /* ---------- hashing + audit log ---------- */
  function hex(u8) { var s = ''; for (var i = 0; i < u8.length; i++) s += (u8[i] < 16 ? '0' : '') + u8[i].toString(16); return s; }
  function hasCrypto() { return !!(window.crypto && crypto.subtle && window.TextEncoder); }
  function sha(str) {
    if (hasCrypto()) {
      return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then(function (b) { return hex(new Uint8Array(b)); });
    }
    var x = 5381;
    for (var i = 0; i < str.length; i++) x = ((x << 5) + x + str.charCodeAt(i)) >>> 0;
    return Promise.resolve(x.toString(16) + '00000000');
  }
  function hmac(secret, msg) {
    if (!hasCrypto()) return Promise.resolve('unsigned');
    var enc = new TextEncoder();
    return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
      .then(function (k) { return crypto.subtle.sign('HMAC', k, enc.encode(msg)); })
      .then(function (s) { return hex(new Uint8Array(s)); });
  }

  var LOG_KEY = 'callbackdesk.log.v1';
  var logs = [];
  var chain = 'genesis';
  var chainQ = Promise.resolve();
  var logView = 'audit';

  function saveLogs() { try { localStorage.setItem(LOG_KEY, JSON.stringify(logs.slice(-80))); } catch (e) { /* storage may be blocked */ } }
  function loadLogs() {
    try {
      var raw = JSON.parse(localStorage.getItem(LOG_KEY) || '[]');
      if (Array.isArray(raw)) { logs = raw.slice(-80); if (logs.length) chain = logs[logs.length - 1].hash || chain; }
    } catch (e) { logs = []; }
  }
  function log(level, code, msg) {
    var e = { t: stamp(), level: level, code: code, msg: msg, hash: '........' };
    logs.push(e);
    if (logs.length > 80) logs.shift();
    renderLogs();
    chainQ = chainQ.then(function () { return sha(chain + '|' + e.t + '|' + code + '|' + msg); }).then(function (hh) {
      e.hash = hh.slice(0, 10);
      chain = e.hash;
      renderLogs();
      saveLogs();
    });
  }
  function renderLogs() {
    var box = $('#logs');
    if (!box) return;
    var errs = logs.filter(function (l) { return l.level !== 'info'; });
    $('#errCount').textContent = errs.length;
    var rows = (logView === 'errors' ? errs : logs).slice(-40).reverse();
    box.innerHTML = '';
    if (!rows.length) { var li0 = h('li'); li0.style.display = 'block'; li0.appendChild(h('span', 'dim', 'Nothing here yet.')); box.appendChild(li0); return; }
    rows.forEach(function (l) {
      var li = h('li');
      li.appendChild(h('span', 'tm', l.t));
      li.appendChild(h('span', 'lv ' + l.level, l.level));
      var tx = h('span', 'tx', l.code + ' - ' + l.msg);
      tx.appendChild(h('small', '', 'chain ' + l.hash));
      li.appendChild(tx);
      box.appendChild(li);
    });
  }

  /* ---------- vault (AES-GCM, key kept non-exportable in IndexedDB) ---------- */
  var LEAD_KEY = 'callbackdesk.leads.v1';
  var vaultKey = null;
  var leads = [];
  var memOnly = {};

  function b64(buf) { var a = new Uint8Array(buf), s = ''; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
  function unb64(s) { var b = atob(s), a = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }
  function openDb() {
    return new Promise(function (res, rej) {
      var r = indexedDB.open('callbackdesk-vault', 1);
      r.onupgradeneeded = function () { r.result.createObjectStore('k'); };
      r.onsuccess = function () { res(r.result); };
      r.onerror = function () { rej(r.error); };
    });
  }
  function initVault() {
    try { leads = JSON.parse(localStorage.getItem(LEAD_KEY) || '[]'); if (!Array.isArray(leads)) leads = []; } catch (e) { leads = []; }
    var idbOk = false;
    try { idbOk = !!window.indexedDB; } catch (e) { idbOk = false; }
    if (!(hasCrypto() && idbOk)) {
      log('warn', 'VAULT_OFF', 'Crypto or IndexedDB unavailable; records stay in memory only');
      return Promise.resolve();
    }
    return openDb().then(function (db) {
      return new Promise(function (res, rej) {
        var rq = db.transaction('k').objectStore('k').get('main');
        rq.onsuccess = function () { res(rq.result); };
        rq.onerror = function () { rej(rq.error); };
      }).then(function (k) {
        if (k) return k;
        return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']).then(function (nk) {
          return new Promise(function (res, rej) {
            var tx = db.transaction('k', 'readwrite');
            tx.objectStore('k').put(nk, 'main');
            tx.oncomplete = function () { res(nk); };
            tx.onerror = function () { rej(tx.error); };
          });
        });
      });
    }).then(function (k) {
      vaultKey = k;
      log('info', 'VAULT_READY', 'AES-GCM key loaded, not exportable');
    }).catch(function (err) {
      vaultKey = null;
      log('error', 'VAULT_INIT', 'Vault init failed (' + ((err && err.name) || 'unknown') + '); memory only');
    });
  }
  function encryptObj(obj) {
    if (!vaultKey) return Promise.resolve(null);
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, vaultKey, new TextEncoder().encode(JSON.stringify(obj)))
      .then(function (ct) { return { iv: b64(iv), ct: b64(ct) }; });
  }
  function decryptRec(rec) {
    if (memOnly[rec.id]) return Promise.resolve(memOnly[rec.id]);
    if (!vaultKey || !rec.blob) return Promise.resolve(null);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(rec.blob.iv) }, vaultKey, unb64(rec.blob.ct))
      .then(function (pt) { return JSON.parse(new TextDecoder().decode(pt)); })
      .catch(function () { log('error', 'DECRYPT_FAIL', 'Record ' + rec.id + ' could not be decrypted'); return null; });
  }
  function saveLeads() {
    try { localStorage.setItem(LEAD_KEY, JSON.stringify(leads.slice(-50))); } catch (e) { log('error', 'STORE_FAIL', 'Local storage write blocked'); }
  }

  /* ---------- roles ---------- */
  var role = 'agent';
  function can(a) {
    if (a === 'read') return role !== 'viewer';
    return role === 'admin';
  }
  function maskName(n) { return n.split(' ').map(function (p) { return p.charAt(0) + '***'; }).join(' '); }
  function maskPhone(p) { return '***' + p.slice(-3); }
  function maskEmail(e) { var i = e.indexOf('@'); return e.charAt(0) + '***' + (i > -1 ? e.slice(i) : ''); }

  /* ---------- domain: steps + validation ---------- */
  var SERVICES = [
    { id: 'install', name: 'New installation', note: 'survey + fitting' },
    { id: 'repair', name: 'Repair visit', note: 'fault diagnosis' },
    { id: 'plan', name: 'Maintenance plan', note: 'yearly service' },
    { id: 'quote', name: 'Free quote', note: 'site estimate' },
    { id: 'urgent', name: 'Urgent call-out', note: 'same-day dispatch' }
  ];
  var TIMES = [];
  for (var hh = 9; hh < 17; hh++) { TIMES.push(pad(hh) + ':00'); TIMES.push(pad(hh) + ':30'); }

  function bizDays() {
    var out = [], d = new Date();
    d.setHours(0, 0, 0, 0);
    var now = new Date();
    if (now.getHours() >= 16) d.setDate(d.getDate() + 1);
    while (out.length < 5) {
      var w = d.getDay();
      if (w !== 0 && w !== 6) out.push(new Date(d.getTime()));
      d.setDate(d.getDate() + 1);
    }
    return out;
  }
  function isoDay(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); }
  function dayLabel(d) { return d.toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short' }); }
  function isBusy(d, time) {
    var key = isoDay(d) + time, x = 7;
    for (var i = 0; i < key.length; i++) x = (x * 31 + key.charCodeAt(i)) >>> 0;
    if (x % 5 === 0) return true;
    var now = new Date();
    if (isoDay(d) === isoDay(now)) {
      var p = time.split(':');
      if (+p[0] * 60 + +p[1] <= now.getHours() * 60 + now.getMinutes() + 60) return true;
    }
    return false;
  }

  function checkName(v) {
    v = String(v || '').replace(/\s+/g, ' ').trim();
    if (v.length > 80 || !/^\p{L}[\p{L}'.-]*(\s+\p{L}[\p{L}'.-]*)+$/u.test(v)) {
      return { ok: false, code: 'NAME_FORMAT', msg: 'I need a first and last name to file this. Could you say it again?' };
    }
    return { ok: true, value: v, display: v };
  }
  function checkPhone(v) {
    var raw = String(v || '').replace(/[\s().-]/g, '');
    if (!/^\+?\d{8,15}$/.test(raw)) {
      return { ok: false, code: 'PHONE_FORMAT', msg: 'That number looks off. Give me 8 to 15 digits, with the country code if you have one.' };
    }
    return { ok: true, value: raw, display: raw };
  }
  function checkEmail(v) {
    v = String(v || '').trim();
    if (v.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v)) {
      return { ok: false, code: 'EMAIL_FORMAT', msg: 'That email is not complete. Something like name@company.com?' };
    }
    return { ok: true, value: v, display: v };
  }
  function checkService(v) {
    var s = SERVICES.filter(function (x) { return x.id === v; })[0];
    if (!s) return { ok: false, code: 'SERVICE_UNKNOWN', msg: 'Pick one of the services on the list and I will book it.' };
    return { ok: true, value: s, display: s.name };
  }
  function checkSlot(v) {
    if (!v || !v.iso || TIMES.indexOf(v.time) < 0) return { ok: false, code: 'SLOT_MISSING', msg: 'Choose a day and a free time and I will hold it.' };
    var d = bizDays().filter(function (x) { return isoDay(x) === v.iso; })[0];
    if (!d) return { ok: false, code: 'SLOT_RANGE', msg: 'We only call back on the next five working days.' };
    if (isBusy(d, v.time)) return { ok: false, code: 'SLOT_TAKEN', msg: 'That slot just filled up. Pick another one?' };
    return { ok: true, value: { iso: v.iso, time: v.time, label: dayLabel(d) + ', ' + v.time }, display: dayLabel(d) + ' ' + v.time };
  }

  var STEPS = [
    { key: 'name', label: 'Name', icon: 'user', type: 'text', ph: 'First and last name', check: checkName,
      ask: function () { return 'Callback Desk, good to hear you. Who am I speaking with?'; } },
    { key: 'phone', label: 'Phone', icon: 'phone', type: 'text', ph: '+1 415 555 0100', mode: 'tel', check: checkPhone,
      ask: function (s) { return 'Thanks, ' + s.data.name.split(' ')[0] + '. What is the best number to reach you on?'; } },
    { key: 'email', label: 'Email', icon: 'mail', type: 'text', ph: 'name@company.com', mode: 'email', check: checkEmail,
      ask: function () { return 'And an email for the confirmation?'; } },
    { key: 'service', label: 'Service', icon: 'wrench', type: 'select', check: checkService,
      ask: function () { return 'Which service would you like to book?'; } },
    { key: 'slot', label: 'Callback time', icon: 'calendar-clock', type: 'slots', check: checkSlot,
      ask: function () { return 'Last one. When should we call you back? Pick a free slot and I will hold it.'; } }
  ];

  /* ---------- session state + chat ---------- */
  var S = null;
  function newState() {
    return { id: 'S-' + Math.random().toString(36).slice(2, 8).toUpperCase(), i: 0, data: {}, state: {}, active: false, busy: false, ready: false, t0: 0, timer: null, secret: Math.random().toString(36).slice(2) + Date.now(), outputs: null, dock: null };
  }
  S = newState();

  function chatEl() { return $('#chat'); }
  function scrollChat() { var c = chatEl(); c.scrollTop = c.scrollHeight; }
  function addMsg(who, text) {
    var c = chatEl();
    var empty = $('.chat-empty', c);
    if (empty) empty.remove();
    var m = h('div', 'msg ' + who, text);
    c.appendChild(m);
    scrollChat();
    return m;
  }
  function agentSay(text) {
    var c = chatEl();
    var empty = $('.chat-empty', c);
    if (empty) empty.remove();
    var tp = h('div', 'typing');
    tp.appendChild(h('i')); tp.appendChild(h('i')); tp.appendChild(h('i'));
    c.appendChild(tp);
    scrollChat();
    voice.target = 1;
    $('#wave').classList.add('talk');
    var myId = S.id;
    return sleep(450 + text.length * 14).then(function () {
      if (S.id !== myId) { tp.remove(); return; }
      tp.remove();
      addMsg('agent', text);
      return sleep(300).then(function () {
        voice.target = 0;
        $('#wave').classList.remove('talk');
      });
    });
  }

  function setCallUI(live) {
    $('#call').classList.toggle('live', live);
    $('#callState').textContent = live ? 'Live - listening' : 'Call ended';
    var chip = $('#leadChip');
    if (live) { chip.textContent = 'live'; chip.className = 'chip live'; }
    if (S.timer) { clearInterval(S.timer); S.timer = null; }
    if (live) {
      S.t0 = Date.now();
      S.timer = setInterval(function () {
        var s = Math.floor((Date.now() - S.t0) / 1000);
        $('#timer').textContent = pad(Math.floor(s / 60)) + ':' + pad(s % 60);
      }, 500);
    }
  }

  /* ---------- lead card ---------- */
  var CHECK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>';
  var CROSS = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';

  function buildFields() {
    var ul = $('#fields');
    ul.innerHTML = '';
    STEPS.forEach(function (st) {
      var li = h('li', 'field');
      li.dataset.k = st.key;
      var ico = h('span', 'ico');
      var i = document.createElement('i');
      i.setAttribute('data-lucide', st.icon);
      ico.appendChild(i);
      var t = h('span', 't');
      t.appendChild(h('small', '', st.label));
      t.appendChild(h('b', 'empty', 'waiting'));
      li.appendChild(ico); li.appendChild(t); li.appendChild(h('span', 'st'));
      ul.appendChild(li);
    });
    icons();
  }
  function okCount() { return STEPS.filter(function (s) { return S.state[s.key] === 'ok'; }).length; }
  function setField(key, state, text) {
    var li = $('.field[data-k="' + key + '"]');
    if (!li) return;
    li.classList.remove('cur', 'ok', 'bad', 'skip');
    if (state) li.classList.add(state);
    var b = $('b', li);
    if (state === 'ok') { b.textContent = text; b.className = ''; }
    else if (state === 'bad') { b.textContent = 'rejected - asking again'; b.className = 'empty'; }
    else if (state === 'skip') { b.textContent = 'skipped'; b.className = 'empty'; }
    else if (state === 'cur') { b.textContent = 'listening...'; b.className = 'empty'; }
    $('.st', li).innerHTML = state === 'ok' ? CHECK : (state === 'bad' ? CROSS : '');
    S.state[key] = state;
    var n = okCount();
    $('#ringFg').style.strokeDashoffset = String(100 - n * 20);
    $('#ringN').textContent = n + '/5';
  }
  function resetCard() {
    buildFields();
    $('#ringFg').style.strokeDashoffset = '100';
    $('#ringN').textContent = '0/5';
    $('#leadId').textContent = S.id;
    var chip = $('#leadChip'); chip.textContent = 'waiting'; chip.className = 'chip';
    $$('#pipe li').forEach(function (li) { li.className = ''; });
    var st = $('#stamp'); st.className = 'stamp';
    ['#btnEmail', '#btnPayload', '#btnFlip'].forEach(function (s) { $(s).disabled = true; });
    $('#flip').classList.remove('back');
    $('#cipher').textContent = 'Nothing stored yet.';
  }

  /* ---------- dock (custom inputs, no native pickers) ---------- */
  function clearDock() { $('#dock').innerHTML = ''; S.dock = null; S.ready = false; }
  function dockIdle() {
    var d = $('#dock');
    d.innerHTML = '';
    var w = h('div', 'dock-idle');
    var a = h('button', 'btn magnet', ' Start call'); a.type = 'button'; a.id = 'btnStart';
    var ai = document.createElement('i'); ai.setAttribute('data-lucide', 'phone-call'); a.insertBefore(ai, a.firstChild);
    var b = h('button', 'btn btn-ghost', ' Sample call'); b.type = 'button'; b.id = 'btnAuto';
    var bi = document.createElement('i'); bi.setAttribute('data-lucide', 'play'); b.insertBefore(bi, b.firstChild);
    w.appendChild(a); w.appendChild(b); d.appendChild(w);
    a.addEventListener('click', startCall);
    b.addEventListener('click', autoplay);
    icons();
  }
  function skipRow(st) {
    var row = h('div', 'dock-row');
    row.appendChild(h('span', '', 'Step ' + (S.i + 1) + ' of 5'));
    var sk = h('button', 'link', 'Skip this one');
    sk.type = 'button';
    sk.addEventListener('click', function () { skip(st); });
    row.appendChild(sk);
    return row;
  }
  function renderDock(st) {
    var d = $('#dock');
    d.innerHTML = '';
    S.ready = false;
    if (st.type === 'text') {
      var f = h('form');
      f.autocomplete = 'off';
      var inp = document.createElement('input');
      inp.type = 'text'; inp.placeholder = st.ph; inp.setAttribute('aria-label', st.label);
      if (st.mode) inp.inputMode = st.mode;
      inp.maxLength = 120;
      var go = h('button', 'btn', 'Send'); go.type = 'submit';
      f.appendChild(inp); f.appendChild(go);
      f.addEventListener('submit', function (e) { e.preventDefault(); submit(st, inp.value); });
      d.appendChild(f); d.appendChild(skipRow(st));
      S.dock = { setText: function (v) { inp.value = v; }, send: function () { submit(st, inp.value); } };
      if (!S.auto) inp.focus({ preventScroll: true });
    } else if (st.type === 'select') {
      S.dock = buildSelect(st, d);
    } else {
      S.dock = buildSlots(st, d);
    }
    S.ready = true;
  }

  function buildSelect(st, d) {
    var row = h('div'); row.style.display = 'flex'; row.style.gap = '10px';
    var dd = h('div', 'dd');
    var btn = h('button', 'dd-btn'); btn.type = 'button';
    btn.setAttribute('aria-haspopup', 'listbox'); btn.setAttribute('aria-expanded', 'false');
    var val = h('span', 'dd-val ph', 'Choose a service');
    btn.appendChild(val);
    var chev = document.createElement('i'); chev.setAttribute('data-lucide', 'chevrons-up-down'); btn.appendChild(chev);
    var list = h('ul', 'dd-list'); list.setAttribute('role', 'listbox');
    var chosen = null, act = -1;
    var opts = SERVICES.map(function (s, idx) {
      var li = h('li', 'dd-opt');
      li.setAttribute('role', 'option'); li.setAttribute('aria-selected', 'false');
      li.appendChild(h('span', '', s.name)); li.appendChild(h('small', '', s.note));
      li.addEventListener('click', function () { pick(idx); close(); });
      list.appendChild(li);
      return li;
    });
    function paint() { opts.forEach(function (o, i) { o.classList.toggle('act', i === act); }); }
    function pick(i) {
      chosen = SERVICES[i].id; act = i;
      val.textContent = SERVICES[i].name; val.classList.remove('ph');
      opts.forEach(function (o, k) { o.setAttribute('aria-selected', k === i ? 'true' : 'false'); });
      paint();
    }
    function open() { dd.classList.add('open'); btn.setAttribute('aria-expanded', 'true'); if (act < 0) act = 0; paint(); }
    function close() { dd.classList.remove('open'); btn.setAttribute('aria-expanded', 'false'); }
    btn.addEventListener('click', function () { dd.classList.contains('open') ? close() : open(); });
    btn.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') { e.preventDefault(); if (!dd.classList.contains('open')) open(); else { act = (act + 1) % opts.length; paint(); } }
      else if (e.key === 'ArrowUp') { e.preventDefault(); if (!dd.classList.contains('open')) open(); else { act = (act - 1 + opts.length) % opts.length; paint(); } }
      else if (e.key === 'Enter' && dd.classList.contains('open')) { e.preventDefault(); pick(act); close(); }
      else if (e.key === 'Escape') close();
    });
    document.addEventListener('click', function away(e) {
      if (!document.body.contains(dd)) { document.removeEventListener('click', away); return; }
      if (!dd.contains(e.target)) close();
    });
    dd.appendChild(btn); dd.appendChild(list);
    var go = h('button', 'btn', 'Book it'); go.type = 'button';
    go.addEventListener('click', function () { close(); submit(st, chosen); });
    row.appendChild(dd); row.appendChild(go);
    d.appendChild(row); d.appendChild(skipRow(st));
    icons();
    return {
      open: open, close: close,
      hover: function (i) { act = i; paint(); },
      pick: function (i) { pick(i); },
      send: function () { close(); submit(st, chosen); }
    };
  }

  function buildSlots(st, d) {
    var wrap = h('div', 'slots');
    var days = bizDays(), di = 0, chosen = null;
    var dayRow = h('div', 'days');
    var grid = h('div', 'times');
    var dbtn = days.map(function (dt, i) {
      var b = h('button', 'day' + (i === 0 ? ' on' : ''), dayLabel(dt)); b.type = 'button';
      b.addEventListener('click', function () { setDay(i); });
      dayRow.appendChild(b);
      return b;
    });
    var tbtn = [];
    function drawTimes() {
      grid.innerHTML = ''; tbtn = []; chosen = null;
      TIMES.forEach(function (t) {
        var b = h('button', 'time', t); b.type = 'button';
        if (isBusy(days[di], t)) b.disabled = true;
        b.addEventListener('click', function () { setTime(t); });
        grid.appendChild(b); tbtn.push(b);
      });
    }
    function setDay(i) { di = i; dbtn.forEach(function (b, k) { b.classList.toggle('on', k === i); }); drawTimes(); }
    function setTime(t) { chosen = t; tbtn.forEach(function (b) { b.classList.toggle('on', b.textContent === t); }); }
    var go = h('button', 'btn go', 'Hold this slot'); go.type = 'button';
    function send() { submit(st, chosen ? { iso: isoDay(days[di]), time: chosen } : null); }
    go.addEventListener('click', send);
    drawTimes();
    wrap.appendChild(dayRow); wrap.appendChild(grid); wrap.appendChild(go);
    d.appendChild(wrap);
    var sk = skipRow(st); sk.style.marginTop = '8px'; d.appendChild(sk);
    return {
      setDay: setDay, setTime: setTime, send: send,
      firstFree: function (after) {
        for (var i = 0; i < TIMES.length; i++) { if (TIMES[i] >= after && !tbtn[i].disabled) return TIMES[i]; }
        for (var j = 0; j < TIMES.length; j++) { if (!tbtn[j].disabled) return TIMES[j]; }
        return null;
      }
    };
  }

  /* ---------- conversation engine ---------- */
  function startCall() {
    if (S.active) return Promise.resolve();
    S = newState();
    resetCard();
    chatEl().innerHTML = '';
    $('#timer').textContent = '00:00';
    S.active = true;
    setCallUI(true);
    log('info', 'CALL_START', 'Session ' + S.id + ' opened');
    addMsg('sys', 'call connected - ' + S.id);
    clearDock();
    var me = S.id;
    return agentSay('Connecting you now. I will ask five quick things.').then(function () { if (S.id === me) return nextStep(); });
  }
  function nextStep() {
    if (S.i >= STEPS.length) return finish();
    var st = STEPS[S.i];
    var me = S.id;
    setField(st.key, 'cur');
    return agentSay(st.ask(S)).then(function () { if (S.id === me && S.active) renderDock(st); });
  }
  function submit(st, raw) {
    if (!S.active || S.busy || !S.ready) return;
    S.busy = true;
    var me = S.id;
    var r = st.check(raw);
    var shown = r.ok ? r.display : ((raw && raw.iso) ? raw.iso + ' ' + raw.time : (st.type === 'select' ? '' : String(raw || '')));
    addMsg('you', shown || '...');
    S.ready = false;
    if (!r.ok) {
      setField(st.key, 'bad');
      log('warn', 'E_VALIDATION', 'Field ' + st.key + ' rejected (' + r.code + ')');
      toast(st.label + ' did not pass: ' + r.code, 'err');
      return agentSay(r.msg).then(function () {
        if (S.id !== me) return;
        S.busy = false;
        setField(st.key, 'cur');
        renderDock(st);
      });
    }
    S.data[st.key] = r.value;
    setField(st.key, 'ok', r.display);
    log('info', 'FIELD_OK', st.key + ' accepted');
    S.i++;
    clearDock();
    var follow = st.key === 'slot' ? agentSay('Done. I am holding ' + r.value.label + ' and will call that number then.') : Promise.resolve();
    return follow.then(function () { if (S.id !== me) return; S.busy = false; return nextStep(); });
  }
  function skip(st) {
    if (!S.active || S.busy) return;
    S.busy = true;
    addMsg('you', '(skipped)');
    setField(st.key, 'skip');
    log('warn', 'FIELD_SKIPPED', 'Field ' + st.key + ' left empty');
    S.i++;
    clearDock();
    var me = S.id;
    return sleep(200).then(function () { if (S.id !== me) return; S.busy = false; return nextStep(); });
  }

  function missingList() { return STEPS.filter(function (s) { return S.state[s.key] !== 'ok'; }).map(function (s) { return s.label.toLowerCase(); }); }

  function finish() {
    var me = S.id;
    S.active = false;
    setCallUI(false);
    clearDock();
    var miss = missingList();
    var q = miss.length === 0;
    var msg = q ? 'All five details check out. I am filing you as qualified, and a confirmation email is on its way.'
      : 'Thanks. I am missing ' + miss.join(', ') + ', so this goes to a person who will follow up.';
    return agentSay(msg).then(function () { if (S.id === me) return pipeline(q, miss); });
  }

  function buildOutputs(q, id) {
    var d = S.data;
    var payload = {
      event: q ? 'lead.qualified' : 'lead.needs_review',
      id: id,
      score: okCount(),
      service: d.service ? { id: d.service.id, name: d.service.name } : null,
      callback: d.slot ? { date: d.slot.iso, time: d.slot.time } : null,
      contact: { name: d.name || null, phone: d.phone || null, email: d.email || null }
    };
    var first = d.name ? d.name.split(' ')[0] : 'there';
    var email = q
      ? 'To: ' + d.email + '\nSubject: Callback booked - ' + d.slot.label + '\n\nHi ' + first + ',\n\nThanks for calling. Here is what we have:\n\n  Service:  ' + d.service.name + '\n  Callback: ' + d.slot.label + '\n  Number:   ' + d.phone + '\n\nIf anything is wrong, just reply to this email and we will fix it.\n\nCallback Desk'
      : 'No email sent. A review task was created for a person to complete the missing details.';
    return { payload: payload, email: email };
  }

  function pipeline(q, miss) {
    var me = S.id;
    var lis = $$('#pipe li');
    var id = 'L-' + Date.now().toString(36).toUpperCase();
    var out = buildOutputs(q, id);
    S.outputs = out;
    function mark(i, ok, label) { var li = lis[i]; li.className = ok ? 'on' : 'off'; if (label) li.textContent = label; }
    var rec = { id: id, ts: Date.now(), status: q ? 'qualified' : 'review', service: S.data.service ? S.data.service.name : '-', slot: S.data.slot ? S.data.slot.label : '-', missing: miss };
    var plain = { name: S.data.name || '', phone: S.data.phone || '', email: S.data.email || '' };
    return sleep(350).then(function () {
      mark(0, true, 'Validated ' + okCount() + '/5');
      return sleep(350);
    }).then(function () {
      mark(1, q, q ? 'Scored - qualified' : 'Scored - review');
      return encryptObj(plain);
    }).then(function (blob) {
      rec.blob = blob;
      if (blob) { mark(2, true); $('#cipher').textContent = 'id: ' + id + '\niv: ' + blob.iv + '\nct: ' + blob.ct + '\n\nstatus: ' + rec.status + '\nservice: ' + rec.service; }
      else { memOnly[id] = plain; mark(2, false, 'Memory only'); $('#cipher').textContent = 'Vault unavailable in this browser. Record kept in memory for this tab only.'; }
      return sleep(350);
    }).then(function () {
      leads.push(rec);
      saveLeads();
      mark(3, true, 'Stored ' + id);
      log('info', 'LEAD_STORED', id + ' ' + rec.status + (blob_ok(rec) ? ' (encrypted)' : ' (memory only)'));
      renderLeads();
      return sleep(350);
    }).then(function () {
      mark(4, q, q ? 'Email + webhook queued' : 'Review task created');
      log('info', q ? 'FOLLOWUP_QUEUED' : 'REVIEW_TASK', id + (q ? ' confirmation email and webhook queued' : ' missing ' + miss.join(',')));
      var chip = $('#leadChip');
      chip.textContent = q ? 'qualified' : 'needs review';
      chip.className = 'chip ' + (q ? 'ok' : 'warn');
      var st = $('#stamp');
      st.textContent = q ? 'QUALIFIED' : 'REVIEW';
      st.className = 'stamp ' + (q ? '' : 'warn');
      void st.offsetWidth;
      st.classList.add('hit');
      ['#btnEmail', '#btnPayload', '#btnFlip'].forEach(function (s) { $(s).disabled = false; });
      toast(q ? 'Lead qualified and stored' : 'Saved for human review', q ? '' : 'warn');
      if (S.id === me) { dockIdle(); }
    });
  }
  function blob_ok(rec) { return !!rec.blob; }

  /* ---------- sample call ---------- */
  function typeInto(text) {
    return new Promise(function (res) {
      var i = 0;
      (function step() {
        if (!S.dock || !S.dock.setText) return res();
        S.dock.setText(text.slice(0, i));
        if (i++ < text.length) setTimeout(step, reduce ? 5 : 45 + Math.random() * 40); else res();
      })();
    });
  }
  function autoplay() {
    if (S.active) return;
    startCall().then(function () { return run(); });
    function run() {
      var me = S.id;
      S.auto = true;
      function live() { return S.id === me && S.active; }
      function ready() { return until(function () { return !live() || S.ready; }, 20000).then(function () { return live(); }); }
      function text(v) { return ready().then(function (ok) { if (!ok) return; return sleep(500).then(function () { return typeInto(v); }).then(function () { return sleep(350); }).then(function () { if (live() && S.dock) S.dock.send(); }); }); }
      return text('Maria Novak')
        .then(function () { return text('+1 415 555 0142'); })
        .then(function () { return text('maria.novak@brightpath'); })
        .then(function () { return text('maria.novak@brightpath.example'); })
        .then(function () { return ready(); })
        .then(function (ok) {
          if (!ok) return;
          return sleep(600).then(function () { S.dock.open(); return sleep(500); })
            .then(function () { S.dock.hover(1); return sleep(450); })
            .then(function () { S.dock.pick(1); return sleep(450); })
            .then(function () { S.dock.close(); return sleep(350); })
            .then(function () { if (live()) S.dock.send(); });
        })
        .then(function () { return ready(); })
        .then(function (ok) {
          if (!ok) return;
          return sleep(600).then(function () { S.dock.setDay(1); return sleep(500); })
            .then(function () { var t = S.dock.firstFree('11:00'); if (t) S.dock.setTime(t); return sleep(600); })
            .then(function () { if (live()) S.dock.send(); });
        })
        .then(function () { S.auto = false; });
    }
  }

  /* ---------- outputs modals ---------- */
  function showEmail() {
    if (!S.outputs) return;
    var pre = h('pre', '', S.outputs.email);
    openModal('Confirmation email (simulated)', pre);
    log('info', 'EMAIL_PREVIEW', 'Email preview opened');
  }
  function showPayload() {
    if (!S.outputs) return;
    var wrap = h('div');
    var body = JSON.stringify(S.outputs.payload, null, 2);
    var pre = h('pre', '', 'POST /hooks/leads\nContent-Type: application/json\nX-Desk-Signature: computing...\n\n' + body);
    wrap.appendChild(pre);
    wrap.appendChild(h('p', 'hint', 'Signed with a per-session secret so the receiving system can reject forged calls. Retries use the lead id as an idempotency key.'));
    openModal('Webhook payload (simulated)', wrap);
    hmac(S.secret, body).then(function (sig) { pre.textContent = 'POST /hooks/leads\nContent-Type: application/json\nX-Desk-Signature: sha256=' + sig + '\n\n' + body; });
  }

  /* ---------- vault table ---------- */
  var renderToken = 0;
  function fmtTime(ts) { var d = new Date(ts); return pad(d.getHours()) + ':' + pad(d.getMinutes()); }
  function renderLeads() {
    var box = $('#leads');
    var tok = ++renderToken;
    $('#btnExport').disabled = !can('export');
    $('#btnPurge').disabled = !can('purge');
    if (!leads.length) {
      box.innerHTML = '';
      box.appendChild(h('div', 'empty-note', 'No leads yet. Run a call above and the record lands here.'));
      return;
    }
    Promise.all(leads.slice().reverse().map(function (r) { return decryptRec(r).then(function (p) { return { r: r, p: p }; }); })).then(function (rows) {
      if (tok !== renderToken) return;
      box.innerHTML = '';
      rows.forEach(function (x) {
        var r = x.r, p = x.p;
        var row = h('div', 'trow');
        var nm = h('div', 'nm');
        var name = p && p.name ? (can('read') ? p.name : maskName(p.name)) : (p ? 'Unnamed' : 'Locked');
        nm.appendChild(h('b', '', name));
        var sub = p && p.phone ? (can('read') ? p.phone : maskPhone(p.phone)) : r.id;
        nm.appendChild(h('small', '', sub));
        row.appendChild(nm);
        var sv = h('div', 'sv', r.service);
        sv.appendChild(h('small', '', r.slot));
        row.appendChild(sv);
        var chip = h('span', 'chip ' + (r.status === 'qualified' ? 'ok' : 'warn'), r.status === 'qualified' ? 'qualified' : 'review');
        var cw = h('div'); cw.appendChild(chip); cw.appendChild(h('small', 'mono dim', ' ' + fmtTime(r.ts)));
        row.appendChild(cw);
        var act = h('div', 'act');
        var view = h('button', 'ibtn'); view.type = 'button'; view.title = 'Open record'; view.setAttribute('aria-label', 'Open record');
        var vi = document.createElement('i'); vi.setAttribute('data-lucide', 'eye'); view.appendChild(vi);
        view.addEventListener('click', function () { openRecord(r, p); });
        act.appendChild(view);
        var del = h('button', 'ibtn'); del.type = 'button'; del.title = 'Delete'; del.setAttribute('aria-label', 'Delete record');
        var di = document.createElement('i'); di.setAttribute('data-lucide', 'trash-2'); del.appendChild(di);
        del.addEventListener('click', function () {
          if (!can('purge')) { denied('delete ' + r.id); return; }
          leads = leads.filter(function (l) { return l.id !== r.id; }); delete memOnly[r.id]; saveLeads();
          log('info', 'RECORD_DELETE', r.id + ' deleted by ' + role); renderLeads();
        });
        act.appendChild(del);
        row.appendChild(act);
        box.appendChild(row);
      });
      icons();
    });
  }
  function denied(what) {
    log('warn', 'ACCESS_DENIED', role + ' tried to ' + what);
    toast('Blocked: ' + role + ' role cannot do that', 'err');
  }
  function openRecord(r, p) {
    var dl = h('dl');
    function add(k, v, mono) { dl.appendChild(h('dt', '', k)); dl.appendChild(h('dd', mono ? 'mono' : '', v)); }
    var rd = can('read');
    add('Record', r.id, true);
    add('Status', r.status);
    add('Name', p ? (rd ? p.name : maskName(p.name)) : '-');
    add('Phone', p ? (rd ? p.phone : maskPhone(p.phone)) : '-');
    add('Email', p ? (rd ? p.email : maskEmail(p.email)) : '-');
    add('Service', r.service);
    add('Callback', r.slot);
    var wrap = h('div'); wrap.appendChild(dl);
    wrap.appendChild(h('p', 'hint', rd ? 'Full details shown for the ' + role + ' role. This view was written to the audit log.' : 'Masked for the viewer role. Switch to Agent to see contact details.'));
    openModal('Lead ' + r.id, wrap);
    log('info', 'RECORD_VIEW', r.id + ' opened by ' + role + (rd ? ' (full)' : ' (masked)'));
  }
  function exportCsv() {
    if (!can('export')) { denied('export CSV'); return; }
    if (!leads.length) { toast('Nothing to export yet', 'warn'); return; }
    Promise.all(leads.map(function (r) { return decryptRec(r).then(function (p) { return { r: r, p: p || {} }; }); })).then(function (rows) {
      function q(v) { v = String(v == null ? '' : v); if (/^[=+\-@]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; }
      var lines = ['id,status,name,phone,email,service,callback'];
      rows.forEach(function (x) { lines.push([x.r.id, x.r.status, x.p.name, x.p.phone, x.p.email, x.r.service, x.r.slot].map(q).join(',')); });
      var csv = lines.join('\n');
      var wrap = h('div');
      var pre = h('pre', '', csv);
      var cp = h('button', 'btn btn-sm', 'Copy CSV'); cp.type = 'button'; cp.style.marginTop = '14px';
      cp.addEventListener('click', function () {
        var done = function () { toast('CSV copied'); };
        var fail = function () {
          var r = document.createRange(); r.selectNodeContents(pre);
          var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r);
          toast('Press Ctrl+C to copy', 'warn');
        };
        try { navigator.clipboard.writeText(csv).then(done, fail); } catch (e) { fail(); }
      });
      wrap.appendChild(pre); wrap.appendChild(cp);
      openModal('Export - ' + rows.length + ' records', wrap);
      log('info', 'EXPORT', rows.length + ' records exported by admin');
    });
  }
  function purgeAll() {
    if (!can('purge')) { denied('purge records'); return; }
    var wrap = h('div');
    wrap.appendChild(h('p', '', 'This permanently removes all ' + leads.length + ' stored records from this browser. The audit log keeps the event.'));
    var go = h('button', 'btn', 'Purge records'); go.type = 'button'; go.style.marginTop = '16px';
    go.addEventListener('click', function () {
      leads = []; memOnly = {}; saveLeads(); closeModal();
      log('info', 'PURGE', 'All records purged by admin'); renderLeads(); toast('Records purged');
    });
    wrap.appendChild(go);
    openModal('Purge all records?', wrap);
  }

  function pill(seg, btn) {
    var p = $('.seg-pill', seg);
    p.style.width = btn.offsetWidth + 'px';
    p.style.transform = 'translateX(' + (btn.offsetLeft - 4) + 'px)';
  }
  function initSeg(seg, attr, cb) {
    var btns = $$('button', seg);
    function sync() { var on = $('button.on', seg) || btns[0]; pill(seg, on); }
    btns.forEach(function (b) {
      b.addEventListener('click', function () {
        btns.forEach(function (x) { x.classList.toggle('on', x === b); });
        pill(seg, b); cb(b.getAttribute(attr));
      });
    });
    sync();
    window.addEventListener('resize', sync);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(sync);
  }

  /* ---------- orb ---------- */
  function initOrb() {
    var c = $('#orb');
    if (!c || !c.getContext) return;
    var ctx = c.getContext('2d');
    var W = 0, H = 0;
    var N = reduce ? 420 : 1100, pts = [], ga = Math.PI * (3 - Math.sqrt(5));
    for (var i = 0; i < N; i++) {
      var y = 1 - (i / (N - 1)) * 2, r = Math.sqrt(1 - y * y), th = ga * i;
      pts.push({ x: Math.cos(th) * r, y: y, z: Math.sin(th) * r, ph: Math.random() * 6.283 });
    }
    function size() {
      var b = c.getBoundingClientRect(), dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = b.width; H = b.height; c.width = W * dpr; c.height = H * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    size();
    window.addEventListener('resize', size);
    var t = 0, mx = 0, my = 0, tx = 0, ty = 0, looping = false, visible = true;
    window.addEventListener('pointermove', function (e) { tx = e.clientX / window.innerWidth - .5; ty = e.clientY / window.innerHeight - .5; });
    function frame() {
      if (!visible) { looping = false; return; }
      requestAnimationFrame(frame);
      t += reduce ? 0.002 : 0.008;
      mx += (tx - mx) * .05; my += (ty - my) * .05;
      voice.level += (voice.target - voice.level) * .07;
      ctx.clearRect(0, 0, W, H);
      var R = Math.min(W, H) * .34, cx = W / 2, cy = H / 2;
      var ay = t * .6 + mx * 1.3, ax = -.35 + my * .9;
      var sy = Math.sin(ay), cyy = Math.cos(ay), sx = Math.sin(ax), cxx = Math.cos(ax);
      var amp = .03 + voice.level * .1;
      for (var i = 0; i < N; i++) {
        var p = pts[i];
        var w = 1 + amp * Math.sin(p.ph * 2 + t * 6 + p.y * 5);
        var x = p.x * w, y = p.y * w, z = p.z * w;
        var x1 = x * cyy + z * sy, z1 = -x * sy + z * cyy;
        var y2 = y * cxx - z1 * sx, z2 = y * sx + z1 * cxx;
        var ps = 2.6 / (2.6 - z2);
        var d = (z2 + 1) / 2;
        var rr = Math.round(lerp(56, 255, d)), gg = Math.round(lerp(225, 178, d)), bb = Math.round(lerp(192, 74, d));
        ctx.fillStyle = 'rgba(' + rr + ',' + gg + ',' + bb + ',' + (.22 + d * .78).toFixed(3) + ')';
        ctx.beginPath();
        ctx.arc(cx + x1 * R * ps, cy + y2 * R * ps, (.7 + d * 1.7) * ps, 0, 6.283);
        ctx.fill();
      }
      ctx.lineWidth = 1;
      for (var k = 0; k < 2; k++) {
        ctx.strokeStyle = k ? 'rgba(56,225,192,.35)' : 'rgba(255,178,74,.28)';
        ctx.beginPath();
        ctx.ellipse(cx, cy, R * (1.28 + k * .2), R * (.34 + k * .08 + voice.level * .05), -.42 + k * .85 + mx * .3, 0, 6.283);
        ctx.stroke();
      }
    }
    function kick() { if (!looping) { looping = true; frame(); } }
    if ('IntersectionObserver' in window) {
      new IntersectionObserver(function (en) { visible = en[0].isIntersecting; if (visible) kick(); }).observe(c);
    }
    kick();
  }

  /* ---------- scroll, mouse, motion ---------- */
  function initMotion() {
    var progress = $('#progress'), nav = $('#nav'), copy = $('#heroCopy'), fill = $('#railFill'), railWrap = $('#railWrap');
    var cards = $$('.cards .card');
    var ticking = false;
    function onScroll() {
      ticking = false;
      var y = window.scrollY, max = document.documentElement.scrollHeight - window.innerHeight;
      progress.style.transform = 'scaleX(' + (max > 0 ? y / max : 0) + ')';
      nav.classList.toggle('solid', y > 40);
      if (!reduce && y < window.innerHeight * 1.2) copy.style.transform = 'translateY(' + (y * .12).toFixed(1) + 'px)';
      if (railWrap) {
        var b = railWrap.getBoundingClientRect();
        var p = Math.min(1, Math.max(0, (window.innerHeight * .8 - b.top) / (b.height + 120)));
        fill.style.transform = 'scaleX(' + p.toFixed(3) + ')';
        cards.forEach(function (c, i) { c.classList.toggle('lit', p > (i + .3) / cards.length); });
      }
    }
    window.addEventListener('scroll', function () { if (!ticking) { ticking = true; requestAnimationFrame(onScroll); } }, { passive: true });
    onScroll();

    if ('IntersectionObserver' in window) {
      var io = new IntersectionObserver(function (en) {
        en.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } });
      }, { threshold: .12 });
      $$('.rv').forEach(function (el) { io.observe(el); });
    } else { $$('.rv').forEach(function (el) { el.classList.add('in'); }); }

    var cur = $('#cursor');
    if (window.matchMedia && matchMedia('(pointer: fine)').matches && !reduce) {
      var cx = 0, cy = 0, tx = 0, ty = 0;
      window.addEventListener('pointermove', function (e) { tx = e.clientX; ty = e.clientY; cur.classList.add('on'); });
      document.addEventListener('pointerleave', function () { cur.classList.remove('on'); });
      (function loop() { cx += (tx - cx) * .2; cy += (ty - cy) * .2; cur.style.transform = 'translate(' + cx.toFixed(1) + 'px,' + cy.toFixed(1) + 'px)'; requestAnimationFrame(loop); })();
      document.addEventListener('pointerover', function (e) { cur.classList.toggle('big', !!e.target.closest('a, button, .dd-opt, .time, .day')); });

      document.addEventListener('pointermove', function (e) {
        var b = e.target.closest && e.target.closest('.magnet');
        $$('.magnet').forEach(function (m) { if (m !== b) m.style.transform = ''; });
        if (b) { var r = b.getBoundingClientRect(); b.style.transform = 'translate(' + ((e.clientX - r.left - r.width / 2) * .18).toFixed(1) + 'px,' + ((e.clientY - r.top - r.height / 2) * .28).toFixed(1) + 'px)'; }
      });

      var tl = $('#tilt'), flip = $('#flip');
      tl.addEventListener('pointermove', function (e) {
        var r = tl.getBoundingClientRect(), px = (e.clientX - r.left) / r.width, py = (e.clientY - r.top) / r.height;
        var flipped = flip.classList.contains('back');
        tl.style.transform = 'rotateX(' + ((.5 - py) * 7).toFixed(2) + 'deg) rotateY(' + ((px - .5) * 9).toFixed(2) + 'deg)';
        $$('.face', tl).forEach(function (f) { f.style.setProperty('--mx', (px * 100) + '%'); f.style.setProperty('--my', (py * 100) + '%'); });
        void flipped;
      });
      tl.addEventListener('pointerleave', function () { tl.style.transform = ''; });
      tl.style.transition = 'transform .25s var(--ease)';

      $$('.tilt-sm').forEach(function (c) {
        c.addEventListener('pointermove', function (e) {
          var r = c.getBoundingClientRect();
          c.style.transform = 'perspective(700px) rotateX(' + ((.5 - (e.clientY - r.top) / r.height) * 8).toFixed(2) + 'deg) rotateY(' + (((e.clientX - r.left) / r.width - .5) * 10).toFixed(2) + 'deg) translateY(-3px)';
        });
        c.addEventListener('pointerleave', function () { c.style.transform = ''; });
      });
    }

    $$('[data-count]').forEach(function (el) {
      var to = +el.getAttribute('data-count');
      if (reduce || to < 6) return;
      var t0 = null;
      function step(ts) { if (t0 == null) t0 = ts; var p = Math.min(1, (ts - t0) / 1400); el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3))); if (p < 1) requestAnimationFrame(step); }
      requestAnimationFrame(step);
    });
  }

  /* ---------- boot ---------- */
  function boot() {
    loadLogs();
    renderLogs();
    buildFields();
    $('#leadId').textContent = 'no session';
    dockIdle();
    initOrb();
    initMotion();
    initSeg($('#roleSeg'), 'data-role', function (r) { role = r; log('info', 'ROLE_SWITCH', 'Role set to ' + r); renderLeads(); });
    initSeg($('#logSeg'), 'data-log', function (v) { logView = v; renderLogs(); });
    $('#btnExport').addEventListener('click', exportCsv);
    $('#btnPurge').addEventListener('click', purgeAll);
    $('#btnEmail').addEventListener('click', showEmail);
    $('#btnPayload').addEventListener('click', showPayload);
    $('#btnFlip').addEventListener('click', function () { $('#flip').classList.add('back'); });
    $('#btnFlipBack').addEventListener('click', function () { $('#flip').classList.remove('back'); });
    $('#ctaStart').addEventListener('click', function () { setTimeout(startCall, 500); });
    $('#ctaAuto').addEventListener('click', function () { $('#desk').scrollIntoView({ behavior: reduce ? 'auto' : 'smooth' }); setTimeout(autoplay, 700); });
    initVault().then(function () { renderLeads(); });
    icons();
    window.addEventListener('load', icons);
    window.addEventListener('error', function (e) { log('error', 'JS_ERROR', String(e.message || 'script error').slice(0, 90)); });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
