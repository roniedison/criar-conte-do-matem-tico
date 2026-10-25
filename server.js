const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);
const root = __dirname;
const dataDir = path.join(root, 'data');
const dbFile = path.join(dataDir, 'users.json');
const publicFiles = new Set(['index.html', 'app.js', 'styles.css']);
const sessions = new Map();
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };
fs.mkdirSync(dataDir, { recursive: true });
function loadDb() { try { return JSON.parse(fs.readFileSync(dbFile, 'utf8')); } catch { return { users: {} }; } }
function saveDb(db) { fs.writeFileSync(dbFile, JSON.stringify(db, null, 2), { mode: 0o600 }); }
function normalizeUsername(value) { return String(value || '').trim().replace(/\s+/g, ' ').toLocaleLowerCase('pt-BR'); }
function initialProgress() { return { xp: 0, levelBase: 1, streak: 0, record: 0, lastStudy: null, completedDaily: [], completedWeekly: [], history: [], areaXp: { 'Álgebra': 0, 'Geometria': 0, 'Cálculo': 0, 'Probabilidade': 0 }, badges: [], sessions: [] }; }
function json(res, status, data, extra = {}) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra }); res.end(JSON.stringify(data)); }
function readBody(req) { return new Promise((resolve, reject) => { let body = ''; req.on('data', chunk => { body += chunk; if (body.length > 16_384) { reject(new Error('Corpo muito grande')); req.destroy(); } }); req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch { reject(new Error('JSON inválido')); } }); req.on('error', reject); }); }
function tokenFrom(req) { const cookie = req.headers.cookie || ''; const item = cookie.split(';').map(s => s.trim()).find(s => s.startsWith('mathrpg_session=')); return item ? decodeURIComponent(item.split('=').slice(1).join('=')) : ''; }
function accountFor(req, db) { const token = tokenFrom(req); const name = sessions.get(token); const user = name && db.users[name]; return user && user.active ? { token, name, user } : null; }
function publicUser(name, user) { const xp = user.progress?.xp || 0; return { username: user.username, role: user.role, active: user.active, xp, level: (user.progress?.levelBase || 1) + Math.floor(xp / 200) }; }
function sessionCookie(token) { return `mathrpg_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`; }
function startSession(name, res) { const token = crypto.randomBytes(32).toString('hex'); sessions.set(token, name); res.setHeader('Set-Cookie', sessionCookie(token)); }
function clearSession(req, res) { const token = tokenFrom(req); sessions.delete(token); res.setHeader('Set-Cookie', 'mathrpg_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'); }
function safeEqual(a, b) { const aa = Buffer.from(a, 'hex'), bb = Buffer.from(b, 'hex'); return aa.length === bb.length && crypto.timingSafeEqual(aa, bb); }
async function handleApi(req, res, url) {
  const db = loadDb();
  if (url.pathname === '/api/register' && req.method === 'POST') {
    const body = await readBody(req); const username = String(body.username || '').trim().replace(/\s+/g, ' '); const key = normalizeUsername(username); const password = String(body.password || '');
    if (!/^[\p{L}\p{N}._ -]{3,24}$/u.test(username)) return json(res, 400, { error: 'Use de 3 a 24 letras, números, espaços, ponto, hífen ou sublinhado no usuário.' });
    if (password.length < 8 || password.length > 200) return json(res, 400, { error: 'A senha precisa ter pelo menos 8 caracteres.' });
    if (db.users[key]) return json(res, 409, { error: 'Esse nome de usuário já está em uso.' });
    const salt = crypto.randomBytes(16).toString('hex'); const passwordHash = await scrypt(password, salt, 64);
    const currentDb = loadDb(); if (currentDb.users[key]) return json(res, 409, { error: 'Esse nome de usuário já está em uso.' });
    Object.assign(db, currentDb);
    const role = Object.keys(db.users).length === 0 ? 'admin' : 'student';
    db.users[key] = { username, role, active: true, salt, passwordHash: passwordHash.toString('hex'), createdAt: new Date().toISOString(), progress: initialProgress() };
    saveDb(db); startSession(key, res); return json(res, 201, { user: publicUser(key, db.users[key]), progress: db.users[key].progress });
  }
  if (url.pathname === '/api/login' && req.method === 'POST') {
    const body = await readBody(req); const key = normalizeUsername(body.username); const password = String(body.password || ''); const user = db.users[key];
    if (!user || !user.active) return json(res, 401, { error: 'Usuário ou senha incorretos, ou acesso desativado.' });
    const attempted = await scrypt(password, user.salt, 64);
    if (!safeEqual(attempted.toString('hex'), user.passwordHash)) return json(res, 401, { error: 'Usuário ou senha incorretos, ou acesso desativado.' });
    startSession(key, res); return json(res, 200, { user: publicUser(key, user), progress: user.progress || null });
  }
  const account = accountFor(req, db);
  if (url.pathname === '/api/logout' && req.method === 'POST') { clearSession(req, res); return json(res, 200, { ok: true }); }
  if (url.pathname === '/api/me' && req.method === 'GET') return account ? json(res, 200, { user: publicUser(account.name, account.user), progress: account.user.progress || null }) : json(res, 401, { error: 'Faça login para continuar.' });
  if (!account) return json(res, 401, { error: 'Faça login para continuar.' });
  if (url.pathname === '/api/progress' && req.method === 'PUT') {
    const body = await readBody(req); if (!body.progress || typeof body.progress !== 'object' || Array.isArray(body.progress)) return json(res, 400, { error: 'Progresso inválido.' });
    db.users[account.name].progress = body.progress; saveDb(db); return json(res, 200, { ok: true });
  }
  if (url.pathname === '/api/ranking' && req.method === 'GET') {
    const ranking = Object.entries(db.users).filter(([, u]) => u.active).map(([name, u]) => ({ username: u.username, xp: u.progress?.xp || 0 })).sort((a, b) => b.xp - a.xp).slice(0, 20);
    return json(res, 200, { ranking });
  }
  if (url.pathname === '/api/admin/users' && req.method === 'GET') {
    if (account.user.role !== 'admin') return json(res, 403, { error: 'Apenas administradores podem gerenciar usuários.' });
    const users = Object.entries(db.users).map(([name, user]) => ({ key: name, ...publicUser(name, user), createdAt: user.createdAt })).sort((a, b) => a.username.localeCompare(b.username, 'pt-BR'));
    return json(res, 200, { users });
  }
  const match = url.pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
  if (match && req.method === 'PATCH') {
    if (account.user.role !== 'admin') return json(res, 403, { error: 'Apenas administradores podem gerenciar usuários.' });
    const key = normalizeUsername(decodeURIComponent(match[1])); const body = await readBody(req); const target = db.users[key];
    if (!target) return json(res, 404, { error: 'Usuário não encontrado.' });
    if (key === account.name && body.active === false) return json(res, 400, { error: 'Não é possível desativar a própria conta.' });
    if (typeof body.active !== 'boolean') return json(res, 400, { error: 'Informe o estado de acesso.' });
    target.active = body.active; saveDb(db);
    if (!target.active) for (const [token, name] of sessions) if (name === key) sessions.delete(token);
    return json(res, 200, { user: publicUser(key, target) });
  }
  return json(res, 404, { error: 'Rota não encontrada.' });
}
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') return res.writeHead(405).end('Method not allowed');
    const pathname = decodeURIComponent(url.pathname);
    const name = pathname === '/' ? 'index.html' : pathname.slice(1);
    if (!publicFiles.has(name)) return res.writeHead(404).end('Not found');
    fs.readFile(path.join(root, name), (error, data) => {
      if (error) return res.writeHead(404).end('Not found');
      res.writeHead(200, { 'Content-Type': types[path.extname(name)], 'Cache-Control': 'no-cache' });
      res.end(req.method === 'HEAD' ? undefined : data);
    });
  } catch (error) {
    if (!res.headersSent) json(res, 400, { error: error.message || 'Requisição inválida.' }); else res.destroy();
  }
});
server.listen(8766, '127.0.0.1');
