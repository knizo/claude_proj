// ===== Knizo admin: auth + 2FA + control panel =====
(function(){
  // --- libs check ---
  function libsError(){
    if (typeof OTPAuth === 'undefined' && typeof qrcode === 'undefined')
      return 'Both 2FA and QR libraries failed to load. Check your network connection or disable any ad blocker, then reload.';
    if (typeof OTPAuth === 'undefined')
      return '2FA library (otpauth) failed to load. Check your network or ad blocker, then reload.';
    if (typeof qrcode === 'undefined')
      return 'QR library (qrcode-generator) failed to load. Check your network or ad blocker, then reload.';
    return null;
  }

  const AUTH_KEY    = 'knizo.auth.v1';          // legacy — wiped on load
  const TOTP_KEY    = 'knizo.totp.v1';          // { secret } when 2FA enabled
  const SESSION_KEY = 'knizo.session.v1';
  const TRUST_KEY   = 'knizo.trust.v1';         // [{ token, expires, addedAt, ua }]
  const SESSION_MS  = 1000 * 60 * 60 * 4;        // 4h
  const TRUST_MS    = 1000 * 60 * 60 * 24 * 30;  // 30d
  const DEFAULT_USER = 'admin';
  const DEFAULT_PASS = 'ThisIsMyPassword!@';
  // Drop any stale auth blob from earlier versions so the new flow is clean.
  localStorage.removeItem(AUTH_KEY);

  const THEMES = [
    { id:'midnight',  name:'Midnight',  desc:'Deep blue, soft purple', sw:['#0b0d12','#161a23','#6c8cff','#9b6cff','#3ddc97'] },
    { id:'solar',     name:'Solar',     desc:'Warm light theme',       sw:['#fdfaf3','#ffffff','#d97706','#b45309','#0d9488'] },
    { id:'matrix',    name:'Matrix',    desc:'Green on black',         sw:['#000000','#061a0f','#00ff66','#33ff99','#b8ff00'] },
    { id:'synthwave', name:'Synthwave', desc:'Neon retro',             sw:['#1a0a2e','#2c1146','#ff2bd6','#7b2bff','#00f0ff'] },
    { id:'forest',    name:'Forest',    desc:'Deep greens',            sw:['#0c1410','#152a22','#4ade80','#22c55e','#facc15'] },
    { id:'sunset',    name:'Sunset',    desc:'Orange & red',           sw:['#1a0d0a','#2c1a16','#ff6b35','#f7431f','#fcc419'] },
    { id:'mono',      name:'Mono',      desc:'Pure monochrome',        sw:['#000000','#141414','#ffffff','#cccccc','#fafafa'] },
    { id:'ocean',     name:'Ocean',     desc:'Teal & cyan',            sw:['#041f2e','#0a3a52','#22d3ee','#0ea5e9','#a3e635'] },
    { id:'coffee',    name:'Coffee',    desc:'Warm browns',            sw:['#1c1410','#2e221a','#d4a574','#a67855','#f5deb3'] },
    { id:'slate',     name:'Slate',     desc:'Pro gray',               sw:['#0f172a','#293449','#60a5fa','#3b82f6','#a78bfa'] },
  ];

  // ---- crypto ----
  const enc = new TextEncoder();
  function randBytes(n){ const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
  function toHex(buf){ return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join(''); }
  function fromHex(h){ const out = new Uint8Array(h.length/2); for (let i=0;i<out.length;i++) out[i]=parseInt(h.substr(i*2,2),16); return out; }
  async function pbkdf2(password, saltHex, iter=120000){
    const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name:'PBKDF2', salt: fromHex(saltHex), iterations: iter, hash:'SHA-256' },
      key, 256
    );
    return toHex(bits);
  }
  function base32Encode(bytes){
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits=0, val=0, out='';
    for (const b of bytes){ val=(val<<8)|b; bits+=8; while(bits>=5){ out+=A[(val>>>(bits-5))&31]; bits-=5; } }
    if (bits>0) out += A[(val<<(5-bits))&31];
    return out;
  }

  // ---- storage ----
  function getJSON(k, d=null){ try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } }
  function setJSON(k,v){ localStorage.setItem(k, JSON.stringify(v)); }

  function getTotp(){ return getJSON(TOTP_KEY); }
  function setTotp(secret){ setJSON(TOTP_KEY, { secret }); }
  function clearTotp(){ localStorage.removeItem(TOTP_KEY); }
  function isTotpEnabled(){ return !!getTotp(); }
  function clearAuth(){
    localStorage.removeItem(AUTH_KEY);
    localStorage.removeItem(TOTP_KEY);
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(TRUST_KEY);
  }

  function getSession(){
    const s = getJSON(SESSION_KEY);
    if (!s || s.expires < Date.now()) return null;
    return s;
  }
  function setSession(){ setJSON(SESSION_KEY, { expires: Date.now()+SESSION_MS }); }
  function endSession(){ localStorage.removeItem(SESSION_KEY); }

  // Trusted devices (per-browser)
  function getTrusted(){
    const arr = getJSON(TRUST_KEY, []) || [];
    const now = Date.now();
    const valid = arr.filter(t => t.expires > now);
    if (valid.length !== arr.length) setJSON(TRUST_KEY, valid);
    return valid;
  }
  function isTrusted(){
    const tok = localStorage.getItem('knizo.trust.token');
    if (!tok) return false;
    return getTrusted().some(t => t.token === tok);
  }
  function trustThisBrowser(){
    let tok = localStorage.getItem('knizo.trust.token');
    if (!tok){ tok = toHex(randBytes(16)); localStorage.setItem('knizo.trust.token', tok); }
    const list = getTrusted().filter(t => t.token !== tok);
    list.push({ token: tok, expires: Date.now()+TRUST_MS, addedAt: Date.now(), ua: navigator.userAgent.slice(0,80) });
    setJSON(TRUST_KEY, list);
  }
  function untrustToken(token){
    setJSON(TRUST_KEY, getTrusted().filter(t => t.token !== token));
  }
  function untrustAll(){ setJSON(TRUST_KEY, []); }

  // ---- TOTP ----
  function newSecret(){ return base32Encode(randBytes(20)); }
  function makeTOTP(secret, account='admin@knizo.com'){
    return new OTPAuth.TOTP({
      issuer: 'Knizo Admin', label: account,
      algorithm: 'SHA1', digits: 6, period: 30,
      secret: OTPAuth.Secret.fromBase32(secret),
    });
  }
  function verifyTOTP(secret, code){
    return makeTOTP(secret).validate({ token: code, window: 1 }) !== null;
  }

  // ===== view switching =====
  const overlay = document.getElementById('adminOverlay');
  if (!overlay){ console.error('[Knizo Admin] #adminOverlay missing'); return; }
  overlay.classList.remove('is-open');
  overlay.removeAttribute('hidden');
  overlay.style.removeProperty('display');
  const views = overlay.querySelectorAll('.admin-view');
  views.forEach(v => { v.removeAttribute('hidden'); v.classList.remove('is-show'); });

  function show(viewName){
    overlay.classList.add('is-open');
    views.forEach(v => v.classList.toggle('is-show', v.dataset.view === viewName));
  }
  function hide(){ overlay.classList.remove('is-open'); }

  function showLibError(msg){
    overlay.classList.add('is-open');
    views.forEach(v => v.classList.remove('is-show'));
    let box = overlay.querySelector('.lib-error');
    if (!box){
      box = document.createElement('div');
      box.className = 'admin-view lib-error';
      box.innerHTML = `<div class="auth-card"><h2 style="color:#ff8a8a">// Cannot start admin</h2>
        <p class="muted"></p>
        <p class="muted small">If on GitHub Pages, try Incognito mode or whitelist <code>cdn.jsdelivr.net</code>.</p></div>`;
      overlay.querySelector('.admin-modal').appendChild(box);
    }
    box.querySelector('p.muted').textContent = msg;
    box.classList.add('is-show');
  }

  // open / close (event delegation)
  document.addEventListener('click', e => {
    if (e.target.closest('#adminOpen')){ e.preventDefault(); openAdmin(); }
    if (e.target.closest('#adminClose')){ hide(); }
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && overlay.classList.contains('is-open')) hide();
  });
  function handleHash(){
    if (location.hash === '#reset'){
      clearAuth();
      localStorage.removeItem('knizo.trust.token');
      history.replaceState(null, '', location.pathname + location.search);
      alert('Session, 2FA, and trusted browsers wiped. Sign in with: ' + DEFAULT_USER + ' / ' + DEFAULT_PASS);
      openAdmin();
      return;
    }
    if (location.hash === '#admin') openAdmin();
  }
  handleHash();
  window.addEventListener('hashchange', handleHash);

  function openAdmin(){
    const err = libsError();
    if (err){ showLibError(err); return; }
    if (getSession()) return openPanel();
    showLogin();
  }

  function showLogin(){
    show('login');
    const needOtp = isTotpEnabled() && !isTrusted();
    const otpField = document.getElementById('otpField');
    const otpInput = document.getElementById('loginOtp');
    const trustRow = document.querySelector('.checkbox-row');
    if (needOtp){
      otpField.style.display = '';
      otpInput.setAttribute('required','required');
      if (trustRow) trustRow.style.display = '';
    } else {
      otpField.style.display = 'none';
      otpInput.removeAttribute('required');
      if (trustRow) trustRow.style.display = 'none';
    }
  }

  // ===== 2FA enrollment =====
  let pending = null;

  function showOtpSetup(user, secret){
    show('otpsetup');
    document.getElementById('otpAccount').textContent = user + '@knizo.com';
    document.getElementById('otpSecret').textContent = secret;
    drawQR('qrCanvas', makeTOTP(secret, user + '@knizo.com').toString());
  }

  document.getElementById('copySecret').addEventListener('click', () => {
    navigator.clipboard.writeText(document.getElementById('otpSecret').textContent);
  });

  document.getElementById('otpSetupForm').addEventListener('submit', e => {
    e.preventDefault();
    if (!getSession()){ alert('You must be signed in to enable 2FA.'); return showLogin(); }
    const code = document.getElementById('otpVerify').value.trim();
    if (!pending || !verifyTOTP(pending.secret, code)) return alert('Invalid code — try again.');
    setTotp(pending.secret);
    untrustAll(); // require fresh trust now that 2FA is on
    pending = null;
    document.getElementById('otpVerify').value = '';
    openPanel();
    switchPane('account');
    flash('2FA enabled ✓');
  });

  // ===== LOGIN =====
  document.getElementById('loginForm').addEventListener('submit', e => {
    e.preventDefault();
    const errEl = document.getElementById('loginErr');
    errEl.hidden = true;
    const u = document.getElementById('loginUser').value.trim();
    const p = document.getElementById('loginPass').value;
    const c = document.getElementById('loginOtp').value.trim();
    const trustChk = document.getElementById('trustDevice').checked;
    const fail = m => { errEl.textContent = m; errEl.hidden = false; };
    if (u !== DEFAULT_USER || p !== DEFAULT_PASS) return fail('Invalid credentials');
    if (isTotpEnabled() && !isTrusted()){
      const totp = getTotp();
      if (!c) return fail('2FA code required');
      if (!verifyTOTP(totp.secret, c)) return fail('Invalid 2FA code');
      if (trustChk) trustThisBrowser();
    }
    setSession();
    document.getElementById('loginForm').reset();
    openPanel();
  });

  // ===== PANEL =====
  let draft = null;
  function openPanel(){
    show('panel');
    draft = window.Knizo.loadContent();
    if (!Array.isArray(draft.lists.media)) draft.lists.media = [];
    switchPane('dashboard');
  }

  function switchPane(name){
    overlay.querySelectorAll('.panel-nav button').forEach(b => b.classList.toggle('active', b.dataset.pane === name));
    overlay.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.dataset.pane === name));
    const titles = { dashboard:'Dashboard', content:'Content', lists:'Lists', media:'Media library', theme:'Theme', account:'Account' };
    document.getElementById('panelTitle').textContent = titles[name] || name;
    if (name === 'dashboard') buildDashboard();
    if (name === 'content')   buildContentEditor();
    if (name === 'lists')     buildListsEditor();
    if (name === 'media')     buildMedia();
    if (name === 'theme')     buildThemePicker();
    if (name === 'account')   buildAccountEditor();
  }

  overlay.addEventListener('click', e => {
    const btn = e.target.closest('.panel-nav button');
    if (btn) switchPane(btn.dataset.pane);
  });

  // === DASHBOARD ===
  function buildDashboard(){
    const root = document.getElementById('dashboardView');
    const c = draft;
    const counts = {
      services: c.lists.services.length,
      work:     c.lists.work.length,
      tools:    c.lists.tools.length,
      media:    (c.lists.media||[]).length,
    };
    const totalText = Object.keys(c.text).length;
    const theme = window.Knizo.loadTheme();
    const themeName = (THEMES.find(t => t.id===theme)||{}).name || theme;
    const used = storageBytesUsed();
    root.innerHTML = `
      <div class="dash-grid">
        <div class="dash-card"><div class="label">Active theme</div><div class="val">${escapeHtml(themeName)}</div><div class="sub">${escapeHtml(theme)}</div></div>
        <div class="dash-card"><div class="label">Text fields</div><div class="val">${totalText}</div><div class="sub">across all sections</div></div>
        <div class="dash-card"><div class="label">List items</div><div class="val">${counts.services + counts.work + counts.tools}</div><div class="sub">${counts.services} services · ${counts.work} work · ${counts.tools} tools</div></div>
        <div class="dash-card"><div class="label">Media library</div><div class="val">${counts.media}</div><div class="sub">${(used/1024).toFixed(0)} KB used</div></div>
      </div>
      <div class="dash-section">
        <h3>Quick actions</h3>
        <div class="dash-actions">
          <button class="dash-action" data-go="content"><span class="ico">✎</span>Edit text content</button>
          <button class="dash-action" data-go="lists"><span class="ico">≡</span>Manage lists</button>
          <button class="dash-action" data-go="media"><span class="ico">▣</span>Upload images</button>
          <button class="dash-action" data-go="theme"><span class="ico">◐</span>Change theme</button>
          <button class="dash-action" data-go="account"><span class="ico">◉</span>Account & security</button>
          <button class="dash-action" id="dashViewSite"><span class="ico">↗</span>View live site</button>
        </div>
      </div>
      <div class="dash-section">
        <h3>Tips</h3>
        <ul style="color:var(--muted);font-size:13px;line-height:1.7;margin:0;padding-left:18px">
          <li>Click "Save changes" in the sidebar to persist edits.</li>
          <li>Press <kbd style="font-family:var(--mono);background:var(--surface);padding:1px 6px;border-radius:3px;border:1px solid var(--line)">Esc</kbd> to close the panel.</li>
          <li>Use the Media library to upload thumbnails for Work items.</li>
          <li>Trusted devices skip 2FA for 30 days.</li>
        </ul>
      </div>
    `;
    root.querySelectorAll('[data-go]').forEach(b => b.addEventListener('click', () => switchPane(b.dataset.go)));
    root.querySelector('#dashViewSite').addEventListener('click', () => { hide(); document.getElementById('top')?.scrollIntoView(); });
  }

  function storageBytesUsed(){
    let total = 0;
    for (const k in localStorage){
      if (!Object.prototype.hasOwnProperty.call(localStorage, k)) continue;
      total += (localStorage.getItem(k)||'').length;
    }
    return total;
  }

  // === CONTENT (text fields) ===
  function buildContentEditor(){
    const root = document.getElementById('contentEditor');
    const groups = {
      'Brand & Nav': ['brand.name','brand.tld','nav.0','nav.1','nav.2','nav.3','nav.4','nav.5'],
      'Hero': ['hero.eyebrow','hero.title','hero.lead','hero.cta1','hero.cta2','stats.0.n','stats.0.l','stats.1.n','stats.1.l','stats.2.n','stats.2.l'],
      'Services section': ['services.eyebrow','services.title','services.lead'],
      'Work section': ['work.eyebrow','work.title','work.lead'],
      'Streaming & Film': ['stream.eyebrow','stream.title','stream.lead','film.eyebrow','film.title','film.lead'],
      'Tools section': ['tools.eyebrow','tools.title','tools.lead'],
      'Contact / Footer': ['cta.title','cta.lead','cta.email','footer.copy','footer.text'],
    };
    root.innerHTML = `
      <div class="editor-search"><input type="search" id="contentSearch" placeholder="Search fields…"></div>
      <div id="contentGroups"></div>
    `;
    const out = root.querySelector('#contentGroups');
    for (const [title, keys] of Object.entries(groups)){
      const g = document.createElement('div');
      g.className = 'editor-group';
      g.innerHTML = `<h3>${title}</h3>` + keys.map(k => {
        const v = draft.text[k] ?? '';
        const long = v.length > 60 || k.endsWith('.lead') || k.endsWith('.title');
        return `<div class="editor-row" data-key="${k}">
          <label>${k}</label>
          ${long
            ? `<textarea data-k="${k}">${escapeAttr(v)}</textarea>`
            : `<input type="text" data-k="${k}" value="${escapeAttr(v)}">`}
        </div>`;
      }).join('');
      out.appendChild(g);
    }
    out.querySelectorAll('[data-k]').forEach(inp => {
      inp.addEventListener('input', () => { draft.text[inp.dataset.k] = inp.value; });
    });
    root.querySelector('#contentSearch').addEventListener('input', e => {
      const q = e.target.value.toLowerCase().trim();
      out.querySelectorAll('.editor-row').forEach(row => {
        const key = row.dataset.key;
        const val = (draft.text[key]||'').toLowerCase();
        const match = !q || key.includes(q) || val.includes(q);
        row.style.display = match ? '' : 'none';
      });
      out.querySelectorAll('.editor-group').forEach(g => {
        const any = [...g.querySelectorAll('.editor-row')].some(r => r.style.display !== 'none');
        g.style.display = any ? '' : 'none';
      });
    });
  }

  // === LISTS ===
  function buildListsEditor(){
    const root = document.getElementById('listsEditor');
    root.innerHTML = '';

    root.appendChild(makeListGroup('services', 'Services (icon, title, text)', i => `
      <div class="editor-row"><label>Icon</label><input data-f="icon" value="${escapeAttr(draft.lists.services[i].icon)}"></div>
      <div class="editor-row"><label>Title</label><input data-f="title" value="${escapeAttr(draft.lists.services[i].title)}"></div>
      <div class="editor-row"><label>Text</label><textarea data-f="text">${escapeAttr(draft.lists.services[i].text)}</textarea></div>
    `, () => ({ icon:'•', title:'New service', text:'Describe it here.' })));

    root.appendChild(makeListGroup('work', 'Work items (image, title, tags, link)', i => {
      const item = draft.lists.work[i];
      const opts = (draft.lists.media||[]).map(m => `<option value="${escapeAttr(m.id)}" ${item.image===m.id?'selected':''}>${escapeAttr(m.name)}</option>`).join('');
      return `
        <div class="editor-row"><label>Image (from Media library)</label>
          <select data-f="image"><option value="">— Use gradient —</option>${opts}</select>
        </div>
        <div class="editor-row"><label>Gradient style (t1–t4, used if no image)</label><input data-f="thumb" value="${escapeAttr(item.thumb||'t1')}"></div>
        <div class="editor-row"><label>Title</label><input data-f="title" value="${escapeAttr(item.title)}"></div>
        <div class="editor-row"><label>Tags</label><input data-f="tags" value="${escapeAttr(item.tags)}"></div>
        <div class="editor-row"><label>Link URL</label><input data-f="href" value="${escapeAttr(item.href||'#')}"></div>
      `;
    }, () => ({ thumb:'t1', title:'New project', tags:'Tag · Tag', href:'#', image:'' })));

    root.appendChild(makeStringList('stream', 'Streaming bullet points'));
    root.appendChild(makeStringList('film',   'Film bullet points'));

    root.appendChild(makeListGroup('tools', 'Tools / cool sites (label + link)', i => `
      <div class="editor-row"><label>Label</label><input data-f="label" value="${escapeAttr(draft.lists.tools[i].label)}"></div>
      <div class="editor-row"><label>Link URL</label><input data-f="href" value="${escapeAttr(draft.lists.tools[i].href||'#')}"></div>
    `, () => ({ label:'New link', href:'#' })));
  }

  function makeListGroup(key, title, rowHtml, makeNew){
    const g = document.createElement('div');
    g.className = 'editor-group';
    const items = draft.lists[key];
    g.innerHTML = `<h3>${title}</h3>` +
      items.map((_,i) => `
        <div class="list-item" data-i="${i}">
          <div class="list-item-head">
            <strong>#${i+1}</strong>
            <div class="list-actions">
              <button type="button" class="icon-btn" data-act="up">↑</button>
              <button type="button" class="icon-btn" data-act="down">↓</button>
              <button type="button" class="icon-btn danger" data-act="del">delete</button>
            </div>
          </div>
          ${rowHtml(i)}
        </div>`).join('') +
      `<button type="button" class="add-btn" data-act="add">+ Add item</button>`;
    g.addEventListener('input', e => {
      const item = e.target.closest('.list-item'); if (!item) return;
      const i = +item.dataset.i;
      const f = e.target.dataset.f; if (!f) return;
      draft.lists[key][i][f] = e.target.value;
    });
    g.addEventListener('change', e => {
      const item = e.target.closest('.list-item'); if (!item) return;
      const i = +item.dataset.i;
      const f = e.target.dataset.f; if (!f) return;
      draft.lists[key][i][f] = e.target.value;
    });
    g.addEventListener('click', e => {
      const btn = e.target.closest('button[data-act]'); if (!btn) return;
      const act = btn.dataset.act;
      if (act === 'add'){ draft.lists[key].push(makeNew()); buildListsEditor(); return; }
      const item = btn.closest('.list-item'); if (!item) return;
      const i = +item.dataset.i;
      const arr = draft.lists[key];
      if (act === 'del'){ arr.splice(i,1); }
      if (act === 'up' && i>0){ [arr[i-1],arr[i]]=[arr[i],arr[i-1]]; }
      if (act === 'down' && i<arr.length-1){ [arr[i+1],arr[i]]=[arr[i],arr[i+1]]; }
      buildListsEditor();
    });
    return g;
  }

  function makeStringList(key, title){
    const g = document.createElement('div');
    g.className = 'editor-group';
    const items = draft.lists[key];
    g.innerHTML = `<h3>${title}</h3>` +
      items.map((v,i) => `
        <div class="list-item" data-i="${i}">
          <div class="list-item-head">
            <strong>#${i+1}</strong>
            <div class="list-actions">
              <button type="button" class="icon-btn" data-act="up">↑</button>
              <button type="button" class="icon-btn" data-act="down">↓</button>
              <button type="button" class="icon-btn danger" data-act="del">delete</button>
            </div>
          </div>
          <div class="editor-row"><input data-f="v" value="${escapeAttr(v)}"></div>
        </div>`).join('') +
      `<button type="button" class="add-btn" data-act="add">+ Add bullet</button>`;
    g.addEventListener('input', e => {
      const item = e.target.closest('.list-item'); if (!item) return;
      const i = +item.dataset.i;
      if (e.target.dataset.f === 'v') draft.lists[key][i] = e.target.value;
    });
    g.addEventListener('click', e => {
      const btn = e.target.closest('button[data-act]'); if (!btn) return;
      const act = btn.dataset.act;
      if (act === 'add'){ draft.lists[key].push('New item'); buildListsEditor(); return; }
      const item = btn.closest('.list-item'); if (!item) return;
      const i = +item.dataset.i;
      const arr = draft.lists[key];
      if (act === 'del'){ arr.splice(i,1); }
      if (act === 'up' && i>0){ [arr[i-1],arr[i]]=[arr[i],arr[i-1]]; }
      if (act === 'down' && i<arr.length-1){ [arr[i+1],arr[i]]=[arr[i],arr[i+1]]; }
      buildListsEditor();
    });
    return g;
  }

  // === MEDIA LIBRARY ===
  function buildMedia(){
    const root = document.getElementById('mediaEditor');
    const items = draft.lists.media || [];
    const used = storageBytesUsed();
    root.innerHTML = `
      <div class="media-toolbar">
        <button class="btn btn-primary btn-sm" id="mediaUpload">+ Upload images</button>
        <div class="media-stats">${items.length} image${items.length===1?'':'s'} · ${(used/1024).toFixed(0)} KB used in browser storage</div>
      </div>
      ${items.length === 0 ? `
        <div class="media-empty">
          <p style="margin:0 0 6px">No images yet.</p>
          <p style="font-size:12px;margin:0">Click "Upload images" to add files. Images are stored in your browser and used as Work-item thumbnails.</p>
        </div>
      ` : `
        <div class="media-grid">
          ${items.map(m => `
            <div class="media-item" data-id="${escapeAttr(m.id)}">
              <div class="media-thumb" style="background-image:url('${escapeAttr(m.dataUrl)}')"></div>
              <div class="media-meta">
                <div class="media-name" title="${escapeAttr(m.name)}">${escapeHtml(m.name)}</div>
                <div class="media-actions">
                  <button class="icon-btn" data-act="rename">rename</button>
                  <button class="icon-btn danger" data-act="del">delete</button>
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      `}
    `;
    root.querySelector('#mediaUpload').addEventListener('click', () => {
      document.getElementById('imageUploadInput').click();
    });
    root.querySelectorAll('.media-item').forEach(it => {
      it.querySelector('[data-act="del"]')?.addEventListener('click', () => {
        if (!confirm('Delete this image?')) return;
        draft.lists.media = draft.lists.media.filter(m => m.id !== it.dataset.id);
        // also clear from work items referring to it
        draft.lists.work.forEach(w => { if (w.image === it.dataset.id) w.image = ''; });
        buildMedia();
      });
      it.querySelector('[data-act="rename"]')?.addEventListener('click', () => {
        const m = draft.lists.media.find(m => m.id === it.dataset.id);
        const name = prompt('New name:', m.name);
        if (name){ m.name = name; buildMedia(); }
      });
    });
  }

  document.getElementById('imageUploadInput').addEventListener('change', async e => {
    const files = [...e.target.files];
    e.target.value = '';
    if (!files.length) return;
    for (const f of files){
      try {
        const dataUrl = await resizeImage(f, 1200);
        const id = 'img_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2,7);
        draft.lists.media = draft.lists.media || [];
        draft.lists.media.push({ id, name: f.name, dataUrl, addedAt: Date.now() });
      } catch (err){ console.error(err); alert('Failed to process: ' + f.name); }
    }
    // try to save immediately so images persist even if the user forgets
    try { window.Knizo.saveContent(draft); flash('Uploaded ✓'); }
    catch { flash('Storage full — delete some images', true); }
    buildMedia();
  });

  function resizeImage(file, maxW=1200){
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        const scale = Math.min(1, maxW / img.width);
        const w = Math.round(img.width * scale);
        const h = Math.round(img.height * scale);
        const canvas = document.createElement('canvas');
        canvas.width = w; canvas.height = h;
        canvas.getContext('2d').drawImage(img, 0, 0, w, h);
        const mime = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
        resolve(canvas.toDataURL(mime, 0.85));
      };
      img.onerror = reject;
      img.src = URL.createObjectURL(file);
    });
  }

  // === THEME ===
  function buildThemePicker(){
    const root = document.getElementById('themeEditor');
    const current = window.Knizo.loadTheme();
    root.innerHTML = `
      <p class="muted" style="margin:0 0 16px;font-size:13px">Pick a theme — applied immediately, persisted on Save.</p>
      <div class="theme-grid">
        ${THEMES.map(t => `
          <button class="theme-card ${t.id===current?'active':''}" data-id="${t.id}">
            <div class="theme-swatches">${t.sw.map(c => `<div style="background:${c}"></div>`).join('')}</div>
            <div class="theme-name">${t.name}</div>
            <div class="theme-desc">${t.desc}</div>
          </button>`).join('')}
      </div>
    `;
    root.querySelectorAll('.theme-card').forEach(card => {
      card.addEventListener('click', () => {
        window.Knizo.applyTheme(card.dataset.id);
        root.querySelectorAll('.theme-card').forEach(c => c.classList.toggle('active', c===card));
      });
    });
  }

  // === ACCOUNT ===
  function buildAccountEditor(){
    const root = document.getElementById('accountEditor');
    const trusted = getTrusted();
    const myToken = localStorage.getItem('knizo.trust.token');
    const totpOn = isTotpEnabled();
    root.innerHTML = `
      <div class="editor-group">
        <h3>Account</h3>
        <p class="muted" style="font-size:13px;margin:0">Signed in as <code style="color:var(--accent)">${escapeHtml(DEFAULT_USER)}</code>.</p>
        <p class="muted" style="font-size:12px;margin:6px 0 0">Credentials are fixed in the site's source. To change them, edit <code>admin.js</code>.</p>
      </div>
      <div class="editor-group">
        <h3>Two-factor authentication</h3>
        ${totpOn ? `
          <p class="muted" style="font-size:13px;margin:0 0 12px">2FA is <strong style="color:var(--accent)">enabled</strong> on this browser. Future sign-ins will require a 6-digit code.</p>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button type="button" class="btn btn-ghost btn-sm" id="ac2faReissue">Re-issue secret (re-scan QR)</button>
            <button type="button" class="btn btn-ghost btn-sm" id="ac2faDisable" style="border-color:#ff6b6b;color:#ff8a8a">Disable 2FA</button>
          </div>
        ` : `
          <p class="muted" style="font-size:13px;margin:0 0 12px">2FA is <strong>off</strong>. Enable it to require an authenticator code on sign-in.</p>
          <button type="button" class="btn btn-primary btn-sm" id="ac2faEnable">Enable 2FA</button>
        `}
      </div>
      <div class="editor-group">
        <h3>Trusted browsers (skip 2FA for 30 days)</h3>
        ${!totpOn
          ? `<p class="muted" style="font-size:13px;margin:0">Enable 2FA first — trust only matters when 2FA is on.</p>`
          : trusted.length === 0
            ? `<p class="muted" style="font-size:13px;margin:0">No trusted browsers. On next sign-in, check "Trust this browser" to add this one.</p>`
            : trusted.map(t => `
              <div class="device-row">
                <div>
                  <div>${escapeHtml(t.ua)}${t.token===myToken?' <span style="color:var(--accent);font-size:11px">(this browser)</span>':''}</div>
                  <div class="muted" style="font-size:11px">expires ${new Date(t.expires).toLocaleString()}</div>
                </div>
                <button class="icon-btn danger" data-untrust="${escapeAttr(t.token)}">revoke</button>
              </div>`).join('')
        }
        ${totpOn && trusted.length ? `<button type="button" class="btn btn-ghost btn-sm" id="acUntrustAll" style="margin-top:8px">Revoke all</button>` : ''}
      </div>
      <div class="editor-group">
        <h3 style="color:#ff8a8a">Danger zone</h3>
        <button type="button" class="btn btn-ghost btn-sm" id="acReset" style="border-color:#ff6b6b;color:#ff8a8a">Reset all data (2FA + edits + media)</button>
      </div>
    `;
    root.querySelector('#ac2faEnable')?.addEventListener('click', () => {
      const secret = newSecret();
      pending = { secret };
      showOtpSetup(DEFAULT_USER, secret);
    });
    root.querySelector('#ac2faReissue')?.addEventListener('click', () => {
      if (!confirm('Re-issue 2FA secret? You will need to re-scan the QR.')) return;
      const secret = newSecret();
      pending = { secret };
      untrustAll();
      showOtpSetup(DEFAULT_USER, secret);
    });
    root.querySelector('#ac2faDisable')?.addEventListener('click', () => {
      if (!confirm('Disable 2FA? Sign-in will only require username + password.')) return;
      clearTotp();
      untrustAll();
      buildAccountEditor();
      flash('2FA disabled');
    });
    root.querySelectorAll('[data-untrust]').forEach(b => {
      b.addEventListener('click', () => { untrustToken(b.dataset.untrust); buildAccountEditor(); });
    });
    root.querySelector('#acUntrustAll')?.addEventListener('click', () => {
      if (!confirm('Revoke all trusted browsers?')) return;
      untrustAll(); buildAccountEditor();
    });
    root.querySelector('#acReset').addEventListener('click', () => {
      if (!confirm('Reset 2FA, saved edits, theme, AND uploaded images?')) return;
      clearAuth();
      localStorage.removeItem(window.Knizo.STORE_KEY);
      localStorage.removeItem(window.Knizo.THEME_KEY);
      localStorage.removeItem('knizo.trust.token');
      location.reload();
    });
  }

  // === SAVE / LOGOUT / EXPORT / IMPORT / PUBLISH ===
  function buildSiteJson(ts){
    return {
      updatedAt: ts,
      theme: window.Knizo.loadTheme(),
      content: { text: draft.text, lists: draft.lists },
    };
  }
  function downloadSiteJson(ts){
    const blob = new Blob([JSON.stringify(buildSiteJson(ts), null, 2)], { type:'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'site.json';
    a.click();
  }

  document.addEventListener('click', async e => {
    if (e.target.closest('#saveAllBtn')){
      try {
        const ts = Date.now();
        window.Knizo.saveContent(draft);
        window.Knizo.setUpdatedAt(ts);
        window.Knizo.renderAll();
        downloadSiteJson(ts);
        flash('Saved locally + site.json downloaded — commit it to /data/site.json on GitHub to publish');
      } catch (err){ flash('Save failed: ' + err.message, true); }
    }
    if (e.target.closest('#pullBtn')){
      const updated = await window.Knizo.syncFromRemote();
      if (updated){
        draft = window.Knizo.loadContent();
        if (!Array.isArray(draft.lists.media)) draft.lists.media = [];
        window.Knizo.renderAll();
        switchPane('dashboard');
        flash('Pulled latest from GitHub ✓');
      } else {
        flash('Already up to date');
      }
    }
    if (e.target.closest('#logoutBtn')){ endSession(); showLogin(); }
    if (e.target.closest('#exportBtn')){
      downloadSiteJson(window.Knizo.getUpdatedAt() || Date.now());
    }
    if (e.target.closest('#importBtn')){
      document.getElementById('importFile').click();
    }
  });

  document.getElementById('importFile').addEventListener('change', async e => {
    const f = e.target.files[0]; if (!f) return;
    try {
      const data = JSON.parse(await f.text());
      if (data.content){
        window.Knizo.saveContent({
          text: { ...window.Knizo.DEFAULT_CONTENT.text, ...(data.content.text||{}) },
          lists: { ...window.Knizo.DEFAULT_CONTENT.lists, ...(data.content.lists||{}) },
        });
      }
      if (data.theme) window.Knizo.applyTheme(data.theme);
      if (data.updatedAt) window.Knizo.setUpdatedAt(data.updatedAt);
      window.Knizo.renderAll();
      draft = window.Knizo.loadContent();
      if (!Array.isArray(draft.lists.media)) draft.lists.media = [];
      switchPane('dashboard');
      flash('Imported ✓');
    } catch { flash('Invalid file', true); }
    e.target.value = '';
  });

  function flash(msg, isErr=false){
    const el = document.getElementById('saveMsg');
    if (!el) return;
    el.textContent = msg;
    el.hidden = false;
    el.classList.toggle('err', isErr);
    clearTimeout(flash._t);
    flash._t = setTimeout(() => el.hidden = true, 2500);
  }

  // QR
  function drawQR(elId, text){
    const el = document.getElementById(elId);
    el.innerHTML = '';
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    el.innerHTML = qr.createImgTag(5, 0);
  }

  function escapeHtml(s){
    return String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
  }
  function escapeAttr(s){ return escapeHtml(s); }
})();
