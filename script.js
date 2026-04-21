// ===== Knizo public site bootstrap =====
const STORE_KEY = 'knizo.site.v1';
const THEME_KEY = 'knizo.theme.v1';
const TS_KEY    = 'knizo.updatedAt.v1';
const REMOTE_URL = 'data/site.json';

const DEFAULT_CONTENT = {
  text: {
    'brand.name': 'Knizo',
    'brand.tld': '.com',
    'nav.0': 'Work',
    'nav.1': 'Services',
    'nav.2': 'Streaming',
    'nav.3': 'Film',
    'nav.4': 'Tools',
    'nav.5': 'Contact',
    'hero.eyebrow': "// Hello, I'm Raanan",
    'hero.title': 'I build & design <span class="grad">websites</span> that work.',
    'hero.lead': 'Clean code, smart layouts, and reliable hosting — for personal pages, streaming sites, film projects, and small businesses.',
    'hero.cta1': 'Start a project',
    'hero.cta2': 'See my work →',
    'stats.0.n': '10+', 'stats.0.l': 'Years building',
    'stats.1.n': '50+', 'stats.1.l': 'Sites shipped',
    'stats.2.n': '24/7', 'stats.2.l': 'Support',
    'services.eyebrow': '// What I do',
    'services.title': 'Services',
    'services.lead': 'End-to-end website work — from the first sketch to the live URL.',
    'work.eyebrow': '// Selected projects',
    'work.title': 'Work Links',
    'work.lead': 'A small sample of recent and ongoing pages.',
    'stream.eyebrow': '// Streaming',
    'stream.title': 'Streaming Websites',
    'stream.lead': 'Custom pages for broadcasters, podcasters, and creators — clean players, schedules, and archives that load fast.',
    'film.eyebrow': '// Film',
    'film.title': 'My Film Work',
    'film.lead': 'Showcase pages built around trailers, stills, credits, and press kits — designed to make your film look its best online.',
    'tools.eyebrow': '// Resources',
    'tools.title': 'Tools & Cool Sites',
    'tools.lead': 'A growing collection of useful links, files, and small utilities.',
    'cta.title': "Have an idea? Let's build it.",
    'cta.lead': "Drop a line and I'll get back within a day.",
    'cta.email': 'support@knizo.com',
    'footer.copy': '© ',
    'footer.text': ' Knizo — build & design websites.',
  },
  lists: {
    services: [
      { icon: '◆', title: 'Web Design', text: 'Modern, responsive layouts that look great on every screen.' },
      { icon: '⟨/⟩', title: 'Development', text: 'Hand-crafted HTML, CSS, and JS — fast, accessible, and SEO-ready.' },
      { icon: '▶', title: 'Streaming Pages', text: 'Custom pages for live streams, video archives, and embeds.' },
      { icon: '★', title: 'Help & Support', text: 'Ongoing maintenance, fixes, and updates so your site keeps working.' },
    ],
    work: [
      { thumb: 't1', title: 'Personal Portfolio', tags: 'Design · Build', href: '#' },
      { thumb: 't2', title: 'Streaming Hub', tags: 'Live · Embeds', href: '#' },
      { thumb: 't3', title: 'Film Project Site', tags: 'Showcase · Trailer', href: '#' },
      { thumb: 't4', title: 'Small Business Page', tags: 'One-pager · Contact', href: '#' },
    ],
    stream: [
      'Embedded live players',
      'VOD and replay archives',
      'Schedule and chat integrations',
      'Mobile-first layouts',
    ],
    film: [
      'Hero trailer reels',
      'Cast & crew pages',
      'Press kit downloads',
      'Festival schedule',
    ],
    tools: [
      { label: 'Updates', href: '#' },
      { label: 'Files', href: '#' },
      { label: 'Accordion', href: '#' },
      { label: 'Cool Sites', href: '#' },
      { label: 'Help & Support', href: '#' },
      { label: 'Facebook', href: '#' },
    ],
    media: [],
  }
};

function loadContent(){
  try{
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return structuredClone(DEFAULT_CONTENT);
    const saved = JSON.parse(raw);
    return {
      text: { ...DEFAULT_CONTENT.text, ...(saved.text||{}) },
      lists: { ...DEFAULT_CONTENT.lists, ...(saved.lists||{}) },
    };
  } catch { return structuredClone(DEFAULT_CONTENT); }
}
function saveContent(c){ localStorage.setItem(STORE_KEY, JSON.stringify(c)); }

function getUpdatedAt(){ return parseInt(localStorage.getItem(TS_KEY) || '0', 10) || 0; }
function setUpdatedAt(ts){ localStorage.setItem(TS_KEY, String(ts || Date.now())); }

async function fetchRemoteSite(){
  try {
    const res = await fetch(REMOTE_URL + '?t=' + Date.now(), { cache: 'no-store' });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

async function syncFromRemote(){
  const remote = await fetchRemoteSite();
  if (!remote || !remote.content) return false;
  const remoteTs = remote.updatedAt || 0;
  if (remoteTs <= getUpdatedAt()) return false;
  const merged = {
    text: { ...DEFAULT_CONTENT.text, ...(remote.content.text || {}) },
    lists: { ...DEFAULT_CONTENT.lists, ...(remote.content.lists || {}) },
  };
  saveContent(merged);
  setUpdatedAt(remoteTs);
  if (remote.theme) applyTheme(remote.theme);
  return true;
}

function loadTheme(){ return localStorage.getItem(THEME_KEY) || 'midnight'; }
function applyTheme(name){
  document.documentElement.setAttribute('data-theme', name);
  localStorage.setItem(THEME_KEY, name);
}

function renderText(content){
  document.querySelectorAll('[data-edit]').forEach(el => {
    const key = el.dataset.edit;
    if (content.text[key] != null) el.innerHTML = content.text[key];
  });
}

function renderLists(content){
  // Services
  const services = document.querySelector('[data-list="services"]');
  if (services) {
    services.innerHTML = content.lists.services.map((s, i) => `
      <article class="card" data-idx="${i}">
        <div class="card-icon">${escapeHtml(s.icon)}</div>
        <h3>${escapeHtml(s.title)}</h3>
        <p>${escapeHtml(s.text)}</p>
      </article>`).join('');
  }
  // Work
  const work = document.querySelector('[data-list="work"]');
  if (work) {
    const media = content.lists.media || [];
    work.innerHTML = content.lists.work.map((w, i) => {
      const img = w.image ? media.find(m => m.id === w.image) : null;
      const thumb = img
        ? `<div class="work-thumb" style="background-image:url('${escapeAttr(img.dataUrl)}');background-size:cover;background-position:center"></div>`
        : `<div class="work-thumb ${escapeAttr(w.thumb||'t1')}"></div>`;
      return `
      <a class="work-item" href="${escapeAttr(w.href||'#')}" data-idx="${i}">
        ${thumb}
        <h3>${escapeHtml(w.title)}</h3>
        <span>${escapeHtml(w.tags)}</span>
      </a>`;
    }).join('');
  }
  // Stream ticks
  const stream = document.querySelector('[data-list="stream"]');
  if (stream) stream.innerHTML = content.lists.stream.map(t => `<li>${escapeHtml(t)}</li>`).join('');
  // Film ticks
  const film = document.querySelector('[data-list="film"]');
  if (film) film.innerHTML = content.lists.film.map(t => `<li>${escapeHtml(t)}</li>`).join('');
  // Tools
  const tools = document.querySelector('[data-list="tools"]');
  if (tools) {
    tools.innerHTML = content.lists.tools.map((t, i) => `
      <a class="tool" href="${escapeAttr(t.href||'#')}" data-idx="${i}">
        <span class="icon">↗</span>${escapeHtml(t.label)}
      </a>`).join('');
  }
}

function escapeHtml(s){
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}
function escapeAttr(s){ return escapeHtml(s); }

function renderAll(){
  const content = loadContent();
  renderText(content);
  renderLists(content);
  document.getElementById('year').textContent = new Date().getFullYear();
}

// ===== boot =====
applyTheme(loadTheme());
renderAll();
// Always pull the latest published data from GitHub; if newer than our cached
// copy, replace it and re-render. localStorage acts as a fast cache + admin draft.
syncFromRemote().then(updated => { if (updated) renderAll(); });

// nav toggle
const toggle = document.querySelector('.nav-toggle');
const links = document.querySelector('.nav-links');
toggle?.addEventListener('click', () => {
  const open = links.classList.toggle('open');
  toggle.setAttribute('aria-expanded', open);
});
links?.querySelectorAll('a').forEach(a => {
  a.addEventListener('click', () => links.classList.remove('open'));
});

// expose for admin.js
window.Knizo = {
  STORE_KEY, THEME_KEY, TS_KEY, REMOTE_URL,
  DEFAULT_CONTENT,
  loadContent, saveContent,
  loadTheme, applyTheme,
  getUpdatedAt, setUpdatedAt,
  fetchRemoteSite, syncFromRemote,
  renderAll,
};
