const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Load .env
const envPath = path.join(__dirname, '.env');
function loadEnv() {
  try {
    const envFile = fs.readFileSync(envPath, 'utf-8');
    envFile.split('\n').forEach(line => {
      const [key, ...vals] = line.split('=');
      if (key && vals.length) process.env[key.trim()] = vals.join('=').trim();
    });
  } catch (e) {}
}
loadEnv();

const app = express();
const PORT = process.env.PORT || 3001;

// ─── Authentication ───
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const sessions = new Map();
const usersPath = path.join(__dirname, 'data', 'users.json');

function hashPassword(password) {
  return crypto.createHash('sha256').update(password + 'wax-affairs-salt').digest('hex');
}

function getPasswordHash() {
  return process.env.CRM_PASSWORD_HASH;
}

function getUsers() {
  try { return JSON.parse(fs.readFileSync(usersPath, 'utf-8')); } catch(e) { return []; }
}

function saveUsers(users) {
  fs.writeFileSync(usersPath, JSON.stringify(users, null, 2), 'utf-8');
}

function createSession(userId) {
  const id = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 24 * 60 * 60 * 1000;
  sessions.set(id, { created: Date.now(), expires, userId });
  return id;
}

function isValidSession(sessionId) {
  if (!sessionId) return false;
  const session = sessions.get(sessionId);
  if (!session) return false;
  if (Date.now() > session.expires) { sessions.delete(sessionId); return false; }
  return true;
}

function getSessionUser(req) {
  const cookies = parseCookies(req.headers.cookie);
  const session = sessions.get(cookies.wax_session);
  if (!session) return null;
  const users = getUsers();
  return users.find(u => u.id === session.userId) || null;
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(c => {
    const [key, ...vals] = c.trim().split('=');
    if (key) cookies[key.trim()] = vals.join('=').trim();
  });
  return cookies;
}

function requireAuth(req, res) {
  const cookies = parseCookies(req.headers.cookie);
  if (!isValidSession(cookies.wax_session)) { res.status(401).json({ error: 'Niet ingelogd' }); return false; }
  return true;
}

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ─── Login Page ───
const loginCSS = `*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(135deg,#faf8f5 0%,#f3ede4 30%,#fdf5f3 70%,#fbe8e2 100%)}
.login-card{background:white;border-radius:20px;padding:48px 40px;box-shadow:0 20px 60px rgba(0,0,0,0.08);width:100%;max-width:420px;margin:20px}
.logo{text-align:center;margin-bottom:32px}
.logo-icon{width:64px;height:64px;background:linear-gradient(135deg,#a8875c,#c2a47e);border-radius:16px;display:inline-flex;align-items:center;justify-content:center;font-size:32px;margin-bottom:16px;color:white;font-weight:bold}
.logo h1{font-size:22px;color:#1f2937;font-weight:700}
.logo p{font-size:13px;color:#9ca3af;margin-top:4px}
label{display:block;font-size:13px;font-weight:600;color:#374151;margin-bottom:6px}
input[type="password"],input[type="text"],input[type="email"]{width:100%;padding:12px 16px;border:2px solid #e5e7eb;border-radius:12px;font-size:15px;outline:none;transition:border-color .2s;margin-bottom:12px}
input:focus{border-color:#a8875c}
select{width:100%;padding:12px 16px;border:2px solid #e5e7eb;border-radius:12px;font-size:15px;outline:none;margin-bottom:12px;background:white}
button{width:100%;padding:12px;background:linear-gradient(135deg,#a8875c,#c2a47e);color:white;border:none;border-radius:12px;font-size:15px;font-weight:600;cursor:pointer;margin-top:8px;transition:transform .1s,box-shadow .2s}
button:hover{transform:translateY(-1px);box-shadow:0 4px 15px rgba(168,135,92,0.4)}
.error{background:#fef2f2;color:#dc2626;padding:10px 14px;border-radius:10px;font-size:13px;margin-bottom:16px;border:1px solid #fee2e2}
.setup-info{background:#faf8f5;color:#755635;padding:10px 14px;border-radius:10px;font-size:13px;margin-bottom:16px;border:1px solid #e6d9c8}
.user-cards{display:flex;flex-direction:column;gap:10px;margin-bottom:20px}
.user-card{display:flex;align-items:center;gap:14px;padding:14px 16px;border:2px solid #e5e7eb;border-radius:14px;cursor:pointer;transition:all .2s}
.user-card:hover,.user-card.selected{border-color:#a8875c;background:#faf8f5}
.user-avatar{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:700;color:white;flex-shrink:0}
.user-info h3{font-size:15px;font-weight:600;color:#1f2937}
.user-info p{font-size:12px;color:#9ca3af}
.divider{text-align:center;color:#9ca3af;font-size:12px;margin:16px 0;position:relative}
.divider::before,.divider::after{content:'';position:absolute;top:50%;width:40%;height:1px;background:#e5e7eb}
.divider::before{left:0}.divider::after{right:0}`;

app.get('/login', (req, res) => {
  const error = req.query.error === '1' ? '<p class="error">Onjuist wachtwoord</p>' : req.query.error === '2' ? '<p class="error">Wachtwoorden komen niet overeen</p>' : req.query.error === '3' ? '<p class="error">Naam en wachtwoord zijn verplicht (min. 4 tekens)</p>' : '';
  const users = getUsers();
  const setup = users.length === 0;

  if (setup) {
    // First time: create two accounts (Lisanne + Simone)
    res.send(`<!DOCTYPE html><html lang="nl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Setup — Wax Affairs CRM</title><style>${loginCSS}</style></head><body>
<div class="login-card">
  <div class="logo"><div class="logo-icon">W</div><h1>Wax Affairs</h1><p>Team Setup</p></div>
  ${error}
  <div class="setup-info">Welkom! Maak accounts aan voor het team. Je kunt later meer toevoegen.</div>
  <form method="POST" action="/setup">
    <div style="background:#f9fafb;border-radius:12px;padding:16px;margin-bottom:16px">
      <p style="font-size:12px;font-weight:700;color:#6b7280;text-transform:uppercase;margin-bottom:10px">👩‍💼 Account 1</p>
      <input type="text" name="name1" placeholder="Naam (bijv. Lisanne)" required>
      <input type="email" name="email1" placeholder="E-mail (optioneel)">
      <select name="lang1"><option value="nl">🇳🇱 Nederlands</option><option value="de">🇩🇪 Deutsch</option></select>
      <input type="password" name="pass1" placeholder="Wachtwoord (min. 4 tekens)" required>
    </div>
    <div style="background:#f9fafb;border-radius:12px;padding:16px;margin-bottom:16px">
      <p style="font-size:12px;font-weight:700;color:#6b7280;text-transform:uppercase;margin-bottom:10px">👩‍💼 Account 2 (optioneel)</p>
      <input type="text" name="name2" placeholder="Naam (bijv. Simone)">
      <input type="email" name="email2" placeholder="E-mail (optioneel)">
      <select name="lang2"><option value="de">🇩🇪 Deutsch</option><option value="nl">🇳🇱 Nederlands</option></select>
      <input type="password" name="pass2" placeholder="Wachtwoord">
    </div>
    <button type="submit">🚀 Accounts aanmaken & starten</button>
  </form>
</div></body></html>`);
  } else {
    // Normal login: show user cards
    res.send(`<!DOCTYPE html><html lang="nl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Login — Wax Affairs CRM</title><style>${loginCSS}</style></head><body>
<div class="login-card">
  <div class="logo"><div class="logo-icon">W</div><h1>Wax Affairs</h1><p>CRM Login</p></div>
  ${error}
  <form method="POST" action="/login" id="loginForm">
    <input type="hidden" name="userId" id="selectedUser" value="">
    <div class="user-cards">
      ${users.map(u => `<div class="user-card" onclick="selectUser('${u.id}', this)">
        <div class="user-avatar" style="background:${u.color || '#a8875c'}">${u.naam[0]}${(u.naam.split(' ')[1]||'')[0]||''}</div>
        <div class="user-info"><h3>${u.naam}</h3><p>${u.rol} · ${u.taal==='de'?'🇩🇪':'🇳🇱'}</p></div>
      </div>`).join('')}
    </div>
    <div id="passField" style="display:none">
      <label id="passLabel">Wachtwoord</label>
      <input type="password" name="password" id="password" placeholder="••••••••">
      <button type="submit">Inloggen</button>
    </div>
  </form>
</div>
<script>
function selectUser(id, el) {
  document.getElementById('selectedUser').value = id;
  document.querySelectorAll('.user-card').forEach(c => c.classList.remove('selected'));
  el.classList.add('selected');
  document.getElementById('passField').style.display = 'block';
  document.getElementById('password').focus();
  const name = el.querySelector('h3').textContent.split(' ')[0];
  document.getElementById('passLabel').textContent = 'Wachtwoord voor ' + name;
}
</script></body></html>`);
  }
});

app.post('/setup', (req, res) => {
  const { name1, email1, lang1, pass1, name2, email2, lang2, pass2 } = req.body;
  if (!name1 || !pass1 || pass1.length < 4) return res.redirect('/login?error=3');

  const users = [];
  const colors = ['#a8875c', '#6366f1', '#059669', '#dc2626', '#8b5cf6'];

  users.push({
    id: crypto.randomBytes(8).toString('hex'),
    naam: name1.trim(),
    email: (email1||'').trim(),
    taal: lang1 || 'nl',
    rol: 'Founder / CEO',
    color: colors[0],
    passwordHash: hashPassword(pass1),
    isAdmin: true,
    aangemaakt: new Date().toISOString()
  });

  if (name2 && pass2 && pass2.length >= 4) {
    users.push({
      id: crypto.randomBytes(8).toString('hex'),
      naam: name2.trim(),
      email: (email2||'').trim(),
      taal: lang2 || 'de',
      rol: 'Founder / CEO',
      color: colors[1],
      passwordHash: hashPassword(pass2),
      isAdmin: true,
      aangemaakt: new Date().toISOString()
    });
  }

  saveUsers(users);

  // Auto-login as first user
  const sessionId = createSession(users[0].id);
  res.setHeader('Set-Cookie', `wax_session=${sessionId}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`);
  res.redirect('/');
});

app.post('/login', (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) return res.redirect('/login?error=1');

  const users = getUsers();
  const user = users.find(u => u.id === userId);
  if (!user) return res.redirect('/login?error=1');
  if (hashPassword(password) !== user.passwordHash) return res.redirect('/login?error=1');

  const sessionId = createSession(user.id);
  res.setHeader('Set-Cookie', `wax_session=${sessionId}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`);
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  if (cookies.wax_session) sessions.delete(cookies.wax_session);
  res.setHeader('Set-Cookie', 'wax_session=; Path=/; HttpOnly; Max-Age=0');
  res.redirect('/login');
});

// ─── Current User API ───
app.get('/api/me', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Niet ingelogd' });
  res.json({ id: user.id, naam: user.naam, email: user.email, taal: user.taal, rol: user.rol, color: user.color, isAdmin: user.isAdmin });
});

app.get('/api/users', (req, res) => {
  if (!requireAuth(req, res)) return;
  const users = getUsers();
  res.json(users.map(u => ({ id: u.id, naam: u.naam, email: u.email, taal: u.taal, rol: u.rol, color: u.color, isAdmin: u.isAdmin })));
});

app.post('/api/users', (req, res) => {
  if (!requireAuth(req, res)) return;
  const users = getUsers();
  const colors = ['#a8875c', '#6366f1', '#059669', '#dc2626', '#8b5cf6', '#0891b2', '#ca8a04'];
  const newUser = {
    id: crypto.randomBytes(8).toString('hex'),
    naam: req.body.naam,
    email: req.body.email || '',
    taal: req.body.taal || 'nl',
    rol: req.body.rol || 'Teamlid',
    color: colors[users.length % colors.length],
    passwordHash: hashPassword(req.body.password || 'welkom123'),
    isAdmin: req.body.isAdmin || false,
    aangemaakt: new Date().toISOString()
  };
  users.push(newUser);
  saveUsers(users);
  res.json({ id: newUser.id, naam: newUser.naam, email: newUser.email, taal: newUser.taal, rol: newUser.rol, color: newUser.color });
});

// ─── Public Booking Page ───
app.get('/boeken', (req, res) => {
  res.sendFile(path.join(__dirname, 'public-booking.html'));
});

app.get('/api/public/services', (req, res) => {
  const services = laadJSON('services.json');
  res.json(services.filter(s => s.actief !== false));
});

app.get('/api/public/beschikbaarheid', (req, res) => {
  const { datum } = req.query;
  const bookings = laadJSON('bookings.json');
  const bestaande = bookings.filter(b => b.datum === datum && b.status !== 'geannuleerd');
  const slots = [];
  for (let h = 9; h < 18; h++) {
    for (let m = 0; m < 60; m += 30) {
      const tijd = `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`;
      const bezet = bestaande.some(b => b.tijd === tijd);
      if (!bezet) slots.push(tijd);
    }
  }
  res.json(slots);
});

app.post('/api/public/boeken', (req, res) => {
  const bookings = laadJSON('bookings.json');
  const booking = {
    id: crypto.randomBytes(8).toString('hex'),
    ...req.body,
    status: 'bevestigd',
    bron: 'website',
    aangemaakt: new Date().toISOString()
  };
  bookings.push(booking);
  slaJSON('bookings.json', bookings);
  res.json(booking);
});

// ─── Static Files + Auth Protection ───
app.use((req, res, next) => {
  if (req.path === '/login' || req.path === '/logout') return next();
  const cookies = parseCookies(req.headers.cookie);
  if (!isValidSession(cookies.wax_session)) return res.redirect('/login');
  next();
});

app.use(express.static(__dirname));

// ─── Uploads ───
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
app.use('/uploads', express.static(uploadsDir));

// ─── Data Helpers ───
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

function laadJSON(bestand) {
  try { return JSON.parse(fs.readFileSync(path.join(dataDir, bestand), 'utf-8')); } catch(e) { return []; }
}
function slaJSON(bestand, data) {
  fs.writeFileSync(path.join(dataDir, bestand), JSON.stringify(data, null, 2));
}

// ─── API: Contacten ───
app.get('/api/contacts', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('contacts.json'));
});

app.post('/api/contacts', (req, res) => {
  if (!requireAuth(req, res)) return;
  const contacts = laadJSON('contacts.json');
  const contact = { id: crypto.randomBytes(8).toString('hex'), ...req.body, aangemaakt: new Date().toISOString(), gewijzigd: new Date().toISOString(), communicatie: [] };
  contacts.push(contact);
  slaJSON('contacts.json', contacts);
  res.json(contact);
});

app.put('/api/contacts/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const contacts = laadJSON('contacts.json');
  const idx = contacts.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  contacts[idx] = { ...contacts[idx], ...req.body, gewijzigd: new Date().toISOString() };
  slaJSON('contacts.json', contacts);
  res.json(contacts[idx]);
});

app.delete('/api/contacts/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  let contacts = laadJSON('contacts.json');
  contacts = contacts.filter(c => c.id !== req.params.id);
  slaJSON('contacts.json', contacts);
  res.json({ ok: true });
});

app.post('/api/contacts/:id/log', (req, res) => {
  if (!requireAuth(req, res)) return;
  const contacts = laadJSON('contacts.json');
  const contact = contacts.find(c => c.id === req.params.id);
  if (!contact) return res.status(404).json({ error: 'Niet gevonden' });
  if (!contact.communicatie) contact.communicatie = [];
  const entry = { id: crypto.randomBytes(6).toString('hex'), datum: new Date().toISOString(), ...req.body };
  contact.communicatie.unshift(entry);
  contact.gewijzigd = new Date().toISOString();
  slaJSON('contacts.json', contacts);
  res.json(entry);
});

// ─── API: Franchisees ───
app.get('/api/franchisees', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('franchisees.json'));
});

app.post('/api/franchisees', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('franchisees.json');
  const item = {
    id: crypto.randomBytes(8).toString('hex'),
    status: 'lead',
    onboarding: { locatieGoedgekeurd: false, huurcontract: false, trainingAfgerond: false, inrichtingCompleet: false, proefdag: false, grandOpening: false, systemen: false, eersteVoorraad: false },
    maandomzet: [],
    ...req.body,
    aangemaakt: new Date().toISOString(),
    gewijzigd: new Date().toISOString()
  };
  list.push(item);
  slaJSON('franchisees.json', list);
  res.json(item);
});

app.put('/api/franchisees/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('franchisees.json');
  const idx = list.findIndex(f => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  list[idx] = { ...list[idx], ...req.body, gewijzigd: new Date().toISOString() };
  slaJSON('franchisees.json', list);
  res.json(list[idx]);
});

app.delete('/api/franchisees/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  let list = laadJSON('franchisees.json');
  list = list.filter(f => f.id !== req.params.id);
  slaJSON('franchisees.json', list);
  res.json({ ok: true });
});

// ─── API: Studenten ───
app.get('/api/students', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('students.json'));
});

app.post('/api/students', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('students.json');
  const item = { id: crypto.randomBytes(8).toString('hex'), status: 'lead', ...req.body, aangemaakt: new Date().toISOString(), gewijzigd: new Date().toISOString() };
  list.push(item);
  slaJSON('students.json', list);
  res.json(item);
});

app.put('/api/students/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('students.json');
  const idx = list.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  list[idx] = { ...list[idx], ...req.body, gewijzigd: new Date().toISOString() };
  slaJSON('students.json', list);
  res.json(list[idx]);
});

app.delete('/api/students/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  let list = laadJSON('students.json');
  list = list.filter(s => s.id !== req.params.id);
  slaJSON('students.json', list);
  res.json({ ok: true });
});

// ─── API: Cohorten ───
app.get('/api/cohorts', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('cohorts.json'));
});

app.post('/api/cohorts', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('cohorts.json');
  const item = { id: crypto.randomBytes(8).toString('hex'), studentIds: [], status: 'gepland', ...req.body, aangemaakt: new Date().toISOString() };
  list.push(item);
  slaJSON('cohorts.json', list);
  res.json(item);
});

app.put('/api/cohorts/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('cohorts.json');
  const idx = list.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  list[idx] = { ...list[idx], ...req.body };
  slaJSON('cohorts.json', list);
  res.json(list[idx]);
});

app.delete('/api/cohorts/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  let list = laadJSON('cohorts.json');
  list = list.filter(c => c.id !== req.params.id);
  slaJSON('cohorts.json', list);
  res.json({ ok: true });
});

// ─── API: Producten ───
app.get('/api/products', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('products.json'));
});

app.post('/api/products', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('products.json');
  const item = { id: crypto.randomBytes(8).toString('hex'), actief: true, ...req.body, aangemaakt: new Date().toISOString() };
  list.push(item);
  slaJSON('products.json', list);
  res.json(item);
});

app.put('/api/products/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('products.json');
  const idx = list.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  list[idx] = { ...list[idx], ...req.body };
  slaJSON('products.json', list);
  res.json(list[idx]);
});

app.delete('/api/products/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  let list = laadJSON('products.json');
  list = list.filter(p => p.id !== req.params.id);
  slaJSON('products.json', list);
  res.json({ ok: true });
});

// ─── API: Voorraad ───
app.get('/api/inventory', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('inventory.json'));
});

app.put('/api/inventory/:productId', (req, res) => {
  if (!requireAuth(req, res)) return;
  let inv = laadJSON('inventory.json');
  if (!Array.isArray(inv)) inv = [];
  const idx = inv.findIndex(i => i.productId === req.params.productId);
  if (idx >= 0) { inv[idx] = { ...inv[idx], ...req.body }; }
  else { inv.push({ productId: req.params.productId, ...req.body }); }
  slaJSON('inventory.json', inv);
  res.json(inv.find(i => i.productId === req.params.productId));
});

// ─── API: Bestellingen ───
app.get('/api/orders', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('orders.json'));
});

app.post('/api/orders', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('orders.json');
  const nr = `WA-${String(list.length + 1).padStart(4, '0')}`;
  const item = { id: crypto.randomBytes(8).toString('hex'), ordernummer: nr, status: 'nieuw', ...req.body, aangemaakt: new Date().toISOString() };
  list.push(item);
  slaJSON('orders.json', list);
  res.json(item);
});

app.put('/api/orders/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('orders.json');
  const idx = list.findIndex(o => o.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  list[idx] = { ...list[idx], ...req.body };
  slaJSON('orders.json', list);
  res.json(list[idx]);
});

app.delete('/api/orders/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  let list = laadJSON('orders.json');
  list = list.filter(o => o.id !== req.params.id);
  slaJSON('orders.json', list);
  res.json({ ok: true });
});

// ─── API: Leveranciers ───
app.get('/api/suppliers', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('suppliers.json'));
});

app.post('/api/suppliers', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('suppliers.json');
  const item = { id: crypto.randomBytes(8).toString('hex'), ...req.body, aangemaakt: new Date().toISOString() };
  list.push(item);
  slaJSON('suppliers.json', list);
  res.json(item);
});

app.put('/api/suppliers/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('suppliers.json');
  const idx = list.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  list[idx] = { ...list[idx], ...req.body };
  slaJSON('suppliers.json', list);
  res.json(list[idx]);
});

// ─── API: Taken ───
app.get('/api/tasks', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('tasks.json'));
});

app.post('/api/tasks', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('tasks.json');
  const item = { id: crypto.randomBytes(8).toString('hex'), status: 'todo', prioriteit: 'normaal', ...req.body, aangemaakt: new Date().toISOString() };
  list.push(item);
  slaJSON('tasks.json', list);
  res.json(item);
});

app.put('/api/tasks/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('tasks.json');
  const idx = list.findIndex(t => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  list[idx] = { ...list[idx], ...req.body };
  slaJSON('tasks.json', list);
  res.json(list[idx]);
});

app.delete('/api/tasks/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  let list = laadJSON('tasks.json');
  list = list.filter(t => t.id !== req.params.id);
  slaJSON('tasks.json', list);
  res.json({ ok: true });
});

// ─── API: Financieel ───
app.get('/api/financials', (req, res) => {
  if (!requireAuth(req, res)) return;
  const data = laadJSON('financials.json');
  res.json(Array.isArray(data) ? data : data || {});
});

app.post('/api/financials', (req, res) => {
  if (!requireAuth(req, res)) return;
  slaJSON('financials.json', req.body);
  res.json({ ok: true });
});

// ─── API: Businessplan Data ───
app.get('/api/businessplan', (req, res) => {
  if (!requireAuth(req, res)) return;
  try { res.json(JSON.parse(fs.readFileSync(path.join(dataDir, 'businessplan.json'), 'utf-8'))); }
  catch(e) { res.json({}); }
});

app.post('/api/businessplan', (req, res) => {
  if (!requireAuth(req, res)) return;
  slaJSON('businessplan.json', req.body);
  res.json({ ok: true });
});

// ─── API: Meeting Notes ───
app.get('/api/notes', (req, res) => {
  if (!requireAuth(req, res)) return;
  try { res.json(JSON.parse(fs.readFileSync(path.join(dataDir, 'notes.json'), 'utf-8'))); }
  catch(e) { res.json({}); }
});

app.post('/api/notes', (req, res) => {
  if (!requireAuth(req, res)) return;
  slaJSON('notes.json', req.body);
  res.json({ ok: true });
});

// ─── API: Huddles (Communication Hub) ───
app.get('/api/huddles', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('huddles.json'));
});

app.post('/api/huddles', (req, res) => {
  if (!requireAuth(req, res)) return;
  const huddles = laadJSON('huddles.json');
  const user = getSessionUser(req);
  const huddle = {
    id: crypto.randomBytes(8).toString('hex'),
    ...req.body,
    auteur: user ? user.naam : 'Onbekend',
    auteurId: user ? user.id : null,
    aangemaakt: new Date().toISOString()
  };
  huddles.unshift(huddle);
  slaJSON('huddles.json', huddles);
  res.json(huddle);
});

app.put('/api/huddles/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const huddles = laadJSON('huddles.json');
  const idx = huddles.findIndex(h => h.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  Object.assign(huddles[idx], req.body, { bijgewerkt: new Date().toISOString() });
  slaJSON('huddles.json', huddles);
  res.json(huddles[idx]);
});

app.post('/api/huddles/:id/reacties', (req, res) => {
  if (!requireAuth(req, res)) return;
  const huddles = laadJSON('huddles.json');
  const huddle = huddles.find(h => h.id === req.params.id);
  if (!huddle) return res.status(404).json({ error: 'Niet gevonden' });
  const user = getSessionUser(req);
  if (!huddle.reacties) huddle.reacties = [];
  const reactie = {
    id: crypto.randomBytes(4).toString('hex'),
    tekst: req.body.tekst,
    auteur: user ? user.naam : 'Onbekend',
    auteurId: user ? user.id : null,
    aangemaakt: new Date().toISOString()
  };
  huddle.reacties.push(reactie);
  slaJSON('huddles.json', huddles);
  res.json(reactie);
});

// ─── API: Academy (LMS) ───
app.get('/api/academy', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('academy.json'));
});

app.post('/api/academy', (req, res) => {
  if (!requireAuth(req, res)) return;
  slaJSON('academy.json', req.body);
  res.json({ ok: true });
});

app.post('/api/academy/voortgang', (req, res) => {
  if (!requireAuth(req, res)) return;
  const { studentId, lesId, status } = req.body;
  if (!studentId || !lesId || !status) return res.status(400).json({ error: 'studentId, lesId en status zijn verplicht' });
  const academy = laadJSON('academy.json');
  if (!academy.voortgang) academy.voortgang = {};
  if (!academy.voortgang[studentId]) academy.voortgang[studentId] = {};
  academy.voortgang[studentId][lesId] = { status, datum: new Date().toISOString() };
  slaJSON('academy.json', academy);
  res.json({ ok: true, voortgang: academy.voortgang[studentId] });
});

// ─── API: Marketing ───
app.get('/api/marketing', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('marketing.json'));
});

app.post('/api/marketing', (req, res) => {
  if (!requireAuth(req, res)) return;
  const marketing = laadJSON('marketing.json');
  const user = getSessionUser(req);
  const { type } = req.body; // 'content', 'leads', 'campaigns'
  if (!type || !marketing[type]) return res.status(400).json({ error: 'Ongeldig type' });
  const item = {
    id: crypto.randomBytes(8).toString('hex'),
    ...req.body.item,
    auteur: user ? user.naam : 'Onbekend',
    auteurId: user ? user.id : null,
    aangemaakt: new Date().toISOString()
  };
  marketing[type].unshift(item);
  slaJSON('marketing.json', marketing);
  res.json(item);
});

app.put('/api/marketing/:type/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const marketing = laadJSON('marketing.json');
  const { type, id } = req.params;
  if (!marketing[type]) return res.status(400).json({ error: 'Ongeldig type' });
  const idx = marketing[type].findIndex(i => i.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  Object.assign(marketing[type][idx], req.body, { bijgewerkt: new Date().toISOString() });
  slaJSON('marketing.json', marketing);
  res.json(marketing[type][idx]);
});

app.delete('/api/marketing/:type/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const marketing = laadJSON('marketing.json');
  const { type, id } = req.params;
  if (!marketing[type]) return res.status(400).json({ error: 'Ongeldig type' });
  marketing[type] = marketing[type].filter(i => i.id !== id);
  slaJSON('marketing.json', marketing);
  res.json({ ok: true });
});

// ─── API: Settings ───
app.get('/api/settings', (req, res) => {
  if (!requireAuth(req, res)) return;
  try { res.json(JSON.parse(fs.readFileSync(path.join(dataDir, 'settings.json'), 'utf-8'))); }
  catch(e) { res.json({}); }
});

app.post('/api/settings', (req, res) => {
  if (!requireAuth(req, res)) return;
  slaJSON('settings.json', req.body);
  res.json({ ok: true });
});

// ─── API: Studios ───
app.get('/api/studios', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('studios.json'));
});

app.post('/api/studios', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('studios.json');
  const item = { id: crypto.randomBytes(8).toString('hex'), actief: true, ...req.body, aangemaakt: new Date().toISOString() };
  list.push(item);
  slaJSON('studios.json', list);
  res.json(item);
});

app.put('/api/studios/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('studios.json');
  const idx = list.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  list[idx] = { ...list[idx], ...req.body };
  slaJSON('studios.json', list);
  res.json(list[idx]);
});

app.delete('/api/studios/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  let list = laadJSON('studios.json');
  list = list.filter(s => s.id !== req.params.id);
  slaJSON('studios.json', list);
  res.json({ ok: true });
});

// ─── API: Services ───
app.get('/api/services', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('services.json'));
});

app.post('/api/services', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('services.json');
  const item = { id: crypto.randomBytes(8).toString('hex'), actief: true, ...req.body, aangemaakt: new Date().toISOString() };
  list.push(item);
  slaJSON('services.json', list);
  res.json(item);
});

app.put('/api/services/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('services.json');
  const idx = list.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  list[idx] = { ...list[idx], ...req.body };
  slaJSON('services.json', list);
  res.json(list[idx]);
});

app.delete('/api/services/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  let list = laadJSON('services.json');
  list = list.filter(s => s.id !== req.params.id);
  slaJSON('services.json', list);
  res.json({ ok: true });
});

// ─── API: Afspraken (Boekingen) ───
app.get('/api/bookings', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('bookings.json'));
});

app.post('/api/bookings', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('bookings.json');
  const nr = `B-${String(list.length + 1).padStart(4, '0')}`;
  const item = { id: crypto.randomBytes(8).toString('hex'), boekingnummer: nr, status: 'bevestigd', ...req.body, aangemaakt: new Date().toISOString() };
  list.push(item);
  slaJSON('bookings.json', list);
  res.json(item);
});

app.put('/api/bookings/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('bookings.json');
  const idx = list.findIndex(b => b.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  list[idx] = { ...list[idx], ...req.body };
  slaJSON('bookings.json', list);
  res.json(list[idx]);
});

app.delete('/api/bookings/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  let list = laadJSON('bookings.json');
  list = list.filter(b => b.id !== req.params.id);
  slaJSON('bookings.json', list);
  res.json({ ok: true });
});

// ─── API: Klanten (Clients) ───
app.get('/api/clients', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('clients.json'));
});

app.post('/api/clients', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('clients.json');
  const item = { id: 'client-' + crypto.randomBytes(8).toString('hex'), ...req.body, aangemaakt: new Date().toISOString() };
  list.push(item);
  slaJSON('clients.json', list);
  res.json(item);
});

app.put('/api/clients/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('clients.json');
  const idx = list.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  list[idx] = { ...list[idx], ...req.body };
  slaJSON('clients.json', list);
  res.json(list[idx]);
});

app.delete('/api/clients/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  let list = laadJSON('clients.json');
  list = list.filter(c => c.id !== req.params.id);
  slaJSON('clients.json', list);
  res.json({ ok: true });
});

// ─── API: Personeel (Urenregistratie) ───
app.get('/api/personeel', (req, res) => {
  if (!requireAuth(req, res)) return;
  const d = laadJSON('personeel.json');
  res.json(d && d.medewerkers ? d : { medewerkers: [], uren: [] });
});

app.post('/api/personeel', (req, res) => {
  if (!requireAuth(req, res)) return;
  slaJSON('personeel.json', req.body);
  res.json(req.body);
});

app.put('/api/personeel/medewerker/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const d = laadJSON('personeel.json') || { medewerkers: [], uren: [] };
  const idx = d.medewerkers.findIndex(m => m.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  d.medewerkers[idx] = { ...d.medewerkers[idx], ...req.body };
  slaJSON('personeel.json', d);
  res.json(d.medewerkers[idx]);
});

app.post('/api/personeel/uren', (req, res) => {
  if (!requireAuth(req, res)) return;
  const d = laadJSON('personeel.json') || { medewerkers: [], uren: [] };
  if (!d.uren) d.uren = [];
  const entry = { id: crypto.randomBytes(8).toString('hex'), ...req.body, aangemaakt: new Date().toISOString() };
  d.uren.push(entry);
  slaJSON('personeel.json', d);
  res.json(entry);
});

app.put('/api/personeel/uren/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const d = laadJSON('personeel.json') || { medewerkers: [], uren: [] };
  const idx = (d.uren || []).findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  d.uren[idx] = { ...d.uren[idx], ...req.body };
  slaJSON('personeel.json', d);
  res.json(d.uren[idx]);
});

app.delete('/api/personeel/uren/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const d = laadJSON('personeel.json') || { medewerkers: [], uren: [] };
  d.uren = (d.uren || []).filter(u => u.id !== req.params.id);
  slaJSON('personeel.json', d);
  res.json({ ok: true });
});

// ─── API: Dashboard KPIs ───
app.get('/api/dashboard', (req, res) => {
  if (!requireAuth(req, res)) return;
  const franchisees = laadJSON('franchisees.json');
  const students = laadJSON('students.json');
  const orders = laadJSON('orders.json');
  const tasks = laadJSON('tasks.json');
  const cohorts = laadJSON('cohorts.json');
  const bookings = laadJSON('bookings.json');

  const nu = new Date();
  const maand = nu.getMonth();
  const jaar = nu.getFullYear();

  const clients = laadJSON('clients.json');

  const activeFranchisees = franchisees.filter(f => f.status === 'live').length;
  const activeStudents = students.filter(s => ['ingeschreven', 'in-opleiding'].includes(s.status)).length;
  const certifiedStudents = students.filter(s => s.status === 'gecertificeerd' || s.status === 'geplaatst').length;
  const openOrders = orders.filter(o => o.status !== 'afgeleverd').length;

  // Pipeline counts
  const pipeline = {};
  ['lead', 'contact', 'termsheet', 'getekend', 'onboarding', 'live'].forEach(s => {
    pipeline[s] = franchisees.filter(f => f.status === s).length;
  });

  // Alerts
  const alerts = [];
  const leadsNoActivity = franchisees.filter(f => f.status === 'lead' && (!f.gewijzigd || (nu - new Date(f.gewijzigd)) > 7 * 86400000));
  if (leadsNoActivity.length) alerts.push({ type: 'warning', tekst: `${leadsNoActivity.length} lead(s) wachten op follow-up`, link: 'franchisees' });

  const upcomingCohorts = cohorts.filter(c => c.status === 'gepland' && c.startdatum && (new Date(c.startdatum) - nu) < 14 * 86400000 && (new Date(c.startdatum) - nu) > 0);
  upcomingCohorts.forEach(c => alerts.push({ type: 'info', tekst: `Cohort "${c.naam}" start binnenkort`, link: 'cohorten' }));

  const overdueTasks = tasks.filter(t => t.status !== 'klaar' && t.deadline && new Date(t.deadline) < nu);
  if (overdueTasks.length) alerts.push({ type: 'danger', tekst: `${overdueTasks.length} verlopen taak/taken`, link: 'taken' });

  const openOrderCount = orders.filter(o => o.status === 'nieuw').length;
  if (openOrderCount) alerts.push({ type: 'info', tekst: `${openOrderCount} nieuwe bestelling(en) te verwerken`, link: 'bestellingen' });

  // Booking alerts
  const vandaagStr = nu.toISOString().slice(0,10);
  const vandaagBookings = bookings.filter(b => b.datum && b.datum.startsWith(vandaagStr) && b.status !== 'geannuleerd');
  if (vandaagBookings.length) alerts.push({ type: 'info', tekst: `${vandaagBookings.length} afspraak/afspraken vandaag`, link: 'agenda' });

  res.json({
    kpis: { activeFranchisees, activeStudents, certifiedStudents, openOrders, totalFranchisees: franchisees.length, totalStudents: students.length, todayBookings: vandaagBookings.length, totalClients: clients.length },
    pipeline,
    alerts
  });
});

// ─── Start ───
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  Wax Affairs CRM draait op http://localhost:${PORT}\n`);
});
