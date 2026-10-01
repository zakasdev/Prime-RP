// Prime RP web host: server-side admin login and persistent shared JSON storage.
const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

// Read local configuration without exposing secrets to the browser or requiring a dependency.
try {
  const envText = require('node:fs').readFileSync(path.join(__dirname, '.env'), 'utf8');
  for (const line of envText.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (match && process.env[match[1]] === undefined) process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
} catch {}

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'site.json');
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PANEL_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const sessions = new Map();
const loginAttempts = new Map();

const initialData = {
  status: 'online', players: 128,
  products: [
    { id: 1, name: 'عضوية VIP', description: 'مزايا حصرية ومكافآت يومية.', price: '500 نقطة', icon: '✦' },
    { id: 2, name: 'سيارة مميزة', description: 'اختر مركبتك ولفت الأنظار في المدينة.', price: '800 نقطة', icon: '🚘' },
    { id: 3, name: 'منزل الأحلام', description: 'مساحتك الخاصة في قلب Los Santos.', price: '1,200 نقطة', icon: '⌂' }
  ], suggestions: [],
  staff: [
    { id: '1012048571938476042', name: 'صهيب', role: 'إدارة عليا' },
    { id: '934851204758192640', name: 'يوسف', role: 'إدارة السيرفر' },
    { id: '812057349182043146', name: 'فريق الدعم', role: 'دعم فني' }
  ]
};

function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map(v => v.trim()).filter(Boolean).map(v => {
    const i = v.indexOf('='); return [v.slice(0, i), decodeURIComponent(v.slice(i + 1))];
  }));
}
function cookie(name, value, maxAge, secure = false) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
}
function signedId(id) { return `${id}.${crypto.createHmac('sha256', SESSION_SECRET).update(id).digest('hex')}`; }
function currentUser(req) {
  const value = parseCookies(req).prime_session || '';
  const [id, sig] = value.split('.');
  if (!id || !sig || sig.length !== 64 || !sessions.has(id)) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(id).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  return sessions.get(id);
}
function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(JSON.stringify(body));
}
function fail(res, status, message) { send(res, status, { error: message }); }
async function readBody(req, max = 16 * 1024 * 1024) {
  let raw = ''; for await (const chunk of req) { raw += chunk; if (raw.length > max) throw Object.assign(new Error('الطلب أكبر من الحد المسموح.'), { status: 413 }); }
  try { return raw ? JSON.parse(raw) : {}; } catch { throw Object.assign(new Error('صيغة البيانات غير صحيحة.'), { status: 400 }); }
}
async function readDb() {
  try { return JSON.parse(await fs.readFile(DB_FILE, 'utf8')); }
  catch (e) { if (e.code !== 'ENOENT') throw e; await fs.mkdir(DATA_DIR, { recursive: true }); await fs.writeFile(DB_FILE, JSON.stringify(initialData, null, 2)); return structuredClone(initialData); }
}
let writeQueue = Promise.resolve();
function writeDb(data) {
  writeQueue = writeQueue.catch(() => {}).then(async () => { await fs.mkdir(DATA_DIR, { recursive: true }); const tmp = DB_FILE + '.tmp'; await fs.writeFile(tmp, JSON.stringify(data, null, 2)); await fs.rename(tmp, DB_FILE); });
  return writeQueue;
}
function normalizeData(v) {
  const data = {
    status: ['online', 'offline', 'maintenance'].includes(v.status) ? v.status : 'offline',
    players: Math.max(0, Math.min(999999, Number(v.players) || 0)),
    products: Array.isArray(v.products) ? v.products.slice(0, 100).map(x => ({ id: Number(x.id) || Date.now(), name: String(x.name || '').slice(0, 80), description: String(x.description || '').slice(0, 300), price: String(x.price || '').slice(0, 50), icon: String(x.icon || '✦').slice(0, 12), image: validImage(x.image) })) : [],
    staff: Array.isArray(v.staff) ? v.staff.slice(0, 100).map(x => ({ id: String(x.id || '').slice(0, 32), name: String(x.name || '').slice(0, 80), role: String(x.role || '').slice(0, 80), image: validImage(x.image) })) : [],
    suggestions: Array.isArray(v.suggestions) ? v.suggestions.slice(-1000).map(x => ({ id: Number(x.id) || Date.now(), name: String(x.name || 'لاعب المدينة').slice(0, 32), text: String(x.text || '').slice(0, 400), status: ['pending', 'accepted', 'rejected'].includes(x.status) ? x.status : 'pending' })) : []
  };
  return data;
}
function validImage(value) { return typeof value === 'string' && /^data:image\/(jpeg|png|webp|gif);base64,/.test(value) && value.length < 1500000 ? value : ''; }
function publicUser(user) { return user ? { admin: user.admin === true } : null; }
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const proto = req.headers['x-forwarded-proto'] || 'http';
  return origin === `${proto}://${host}`;
}
function secureRequest(req) { return req.headers['x-forwarded-proto'] === 'https'; }

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname === '/api/state' && req.method === 'GET') return send(res, 200, await readDb());
    if (url.pathname === '/api/me' && req.method === 'GET') return send(res, 200, { user: publicUser(currentUser(req)) });
    if (url.pathname === '/auth/admin' && req.method === 'POST') {
      if (!sameOrigin(req)) return fail(res, 403, 'الطلب غير مسموح.');
      if (!ADMIN_PASSWORD || !SESSION_SECRET) return fail(res, 503, 'أكمل رمز الإدارة في ملف .env أولاً.');
      const ip = req.socket.remoteAddress || 'unknown'; const now = Date.now(); const attempt = loginAttempts.get(ip) || { count: 0, until: now + 10 * 60 * 1000 };
      if (attempt.until < now) { attempt.count = 0; attempt.until = now + 10 * 60 * 1000; }
      if (attempt.count >= 8) return fail(res, 429, 'محاولات كثيرة. انتظر قليلاً ثم أعد المحاولة.');
      const body = await readBody(req, 4000); const submitted = String(body.password || '');
      const good = crypto.timingSafeEqual(crypto.createHash('sha256').update(submitted).digest(), crypto.createHash('sha256').update(ADMIN_PASSWORD).digest());
      if (!good) { attempt.count++; loginAttempts.set(ip, attempt); return fail(res, 401, 'رمز الإدارة غير صحيح.'); }
      loginAttempts.delete(ip); const sid = crypto.randomBytes(32).toString('hex'); sessions.set(sid, { admin: true });
      res.writeHead(204, { 'Set-Cookie': cookie('prime_session', signedId(sid), 60 * 60 * 8, secureRequest(req)), 'Cache-Control': 'no-store' }); return res.end();
    }
    if (url.pathname === '/auth/logout' && req.method === 'POST') {
      const user = currentUser(req); if (user) { const sid = parseCookies(req).prime_session.split('.')[0]; sessions.delete(sid); }
      res.writeHead(204, { 'Set-Cookie': cookie('prime_session', '', 0, secureRequest(req)), 'Cache-Control': 'no-store' }); return res.end();
    }
    if (url.pathname === '/api/suggestions' && req.method === 'POST') {
      const b = await readBody(req, 24000); const text = String(b.text || '').trim();
      if (!text || text.length > 400) return fail(res, 400, 'اكتب اقتراحاً لا يتجاوز 400 حرف.');
      const db = await readDb(); db.suggestions.push({ id: Date.now(), name: String(b.name || 'لاعب المدينة').trim().slice(0, 32) || 'لاعب المدينة', text, status: 'pending' });
      await writeDb(db); return send(res, 201, { ok: true });
    }
    if (url.pathname === '/api/admin/state' && req.method === 'POST') {
      if (!sameOrigin(req)) return fail(res, 403, 'الطلب غير مسموح.');
      const user = currentUser(req); if (!user || user.admin !== true) return fail(res, 403, 'تحتاج إلى صلاحية إدارة الموقع.');
      const incoming = await readBody(req); await writeDb(normalizeData(incoming)); return send(res, 200, { ok: true });
    }
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/auth/')) return fail(res, 404, 'المسار غير موجود.');

    const requested = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
    const file = path.resolve(ROOT, '.' + requested);
    if (!file.startsWith(ROOT + path.sep)) return fail(res, 403, 'ممنوع.');
    const ext = path.extname(file).toLowerCase(); const types = { '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.webp':'image/webp', '.mp3':'audio/mpeg', '.md':'text/plain; charset=utf-8' };
    if (!types[ext] || requested.startsWith('/data/') || requested.endsWith('.env')) return fail(res, 404, 'الملف غير موجود.');
    const content = await fs.readFile(file); res.writeHead(200, { 'Content-Type': types[ext], 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600' }); return res.end(content);
  } catch (e) { console.error(e); return fail(res, e.status || 500, e.status ? e.message : 'حدث خطأ في الخادم.'); }
});

if ((!SESSION_SECRET || !ADMIN_PASSWORD) && process.env.NODE_ENV === 'production') { console.error('SESSION_SECRET and ADMIN_PANEL_PASSWORD are required in production.'); process.exit(1); }
server.listen(PORT, () => console.log(`Prime RP listening on http://localhost:${PORT}`));
