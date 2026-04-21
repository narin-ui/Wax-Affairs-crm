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

// ┐ Quiz-seed migratie (eenmalig per deploy als quizVragen ontbreken) ┐
function migrateQuizzes() {
  try {
    const academy = laadJSON('academy.json');
    if (!academy || !Array.isArray(academy.programmas)) return;
    const QUIZ_SEED = {"ws1-5": {"vragen": [{"vraag": "Wat is een absolute contra-indicatie voor Brazilian waxing?", "opties": ["Menstruatie", "Isotretinoïne-gebruik in de laatste 6 maanden", "Droge huid", "Vermoeidheid"], "juisteAntwoord": 1}, {"vraag": "Welke waxtype is de enige juiste keuze voor Brazilian waxing?", "opties": ["Warm wax", "Roll-on", "Hot wax", "Cold wax"], "juisteAntwoord": 2}, {"vraag": "Wat is het 'critical window' voor post-wax oil aanbrengen?", "opties": ["5-30 seconden", "1-2 minuten", "5-10 minuten", "Maakt niet uit"], "juisteAntwoord": 0}, {"vraag": "Waarom werk je in kleine deelzones van circa 3x5 cm?", "opties": ["Sneller werken", "Minder productverbruik", "Betere controle en minder pijn voor klant", "Gezondheidsdienst-eis"], "juisteAntwoord": 2}, {"vraag": "Wat is de correcte verwijderingsrichting van wax?", "opties": ["In de groeirichting", "Tegen de groeirichting in, parallel aan huid", "Omhoog", "Diagonaal"], "juisteAntwoord": 1}], "drempel": 75}, "ws2-5": {"vragen": [{"vraag": "Waarom is gezichtshuid PIH-gevoeliger dan been-huid?", "opties": ["Meer doorbloeding en hogere melanocyten-dichtheid", "Minder collageen", "Meer haren", "Dikker"], "juisteAntwoord": 0}, {"vraag": "Welke waxtype is standaard voor gezichtswaxing?", "opties": ["Warm wax", "Hot wax", "Roll-on", "Cold wax"], "juisteAntwoord": 1}, {"vraag": "Hoe vaak modelleer je wenkbrauwen naar eindresultaat in de eerste sessie?", "opties": ["Eén sessie is genoeg", "Gefaseerd over 2-3 sessies", "Elke 6 maanden", "Per klant verschillend"], "juisteAntwoord": 1}, {"vraag": "Wat doe je bij klant met actieve koortslip op of nabij bovenlip?", "opties": ["Door waxen, voorzichtig", "Niet behandelen, absolute contra-indicatie", "Alleen kin waxen", "Speciale wax gebruiken"], "juisteAntwoord": 1}, {"vraag": "Wat is de correcte verwijderingsrichting bij bovenlip-waxen?", "opties": ["Naar neus", "Naar beneden", "Richting mondhoek", "Diagonaal naar oor"], "juisteAntwoord": 2}], "drempel": 75}, "ws3-5": {"vragen": [{"vraag": "Hoeveel dikker is gemiddeld mannelijke huid dan vrouwelijke?", "opties": ["Gelijk", "5-10%", "20-25%", "40-50%"], "juisteAntwoord": 2}, {"vraag": "Wat is de enige juiste waxsoort voor mannelijke intimzone?", "opties": ["Warm wax", "Roll-on", "Hot wax", "Alle drie kunnen"], "juisteAntwoord": 2}, {"vraag": "Waarom is extra grondige reiniging kritischer bij mannelijke klanten?", "opties": ["Traditie", "Dubbel zoveel talgproductie verhindert waxhechting", "Gezondheidsdienst-eis", "Geen verschil"], "juisteAntwoord": 1}, {"vraag": "Wat is de juiste werkvolgorde bij borsthaar?", "opties": ["Van buiten naar centrum", "Vanuit borstbeen radiaal naar buiten", "Willekeurig", "Van onder naar boven"], "juisteAntwoord": 1}, {"vraag": "Welke aanpak past bij eerste-keer mannelijke klant?", "opties": ["Overdreven vriendelijk", "Directe, zakelijke communicatie met heldere aankondigingen", "Stilte", "Humor om spanning te breken"], "juisteAntwoord": 1}], "drempel": 75}, "ws4-5": {"vragen": [{"vraag": "Uit welk land komt de pijnhars die de basis vormt van Nao Depilatory Wax?", "opties": ["Duitsland", "Polen", "Portugal", "Italië"], "juisteAntwoord": 2}, {"vraag": "Wat is het belangrijkste verschil tussen Nao Premium en Economic wax?", "opties": ["Prijs", "Premium bevat bijenwas (niet-vegan), Economic is 100% vegan", "Geur", "Kleur"], "juisteAntwoord": 1}, {"vraag": "Wat is het critical window voor Nao Post-Depilatory Oil?", "opties": ["1 minuut", "5-30 seconden na laatste trek", "5 minuten", "Direct na douchen"], "juisteAntwoord": 1}, {"vraag": "Waarom bevat Nao Pre-Depilatory Powder geen talk?", "opties": ["Smaak", "Kostenbesparing", "Gebruikt mineraal dolomiet als natuurlijk alternatief", "Verboden in Nederland"], "juisteAntwoord": 2}, {"vraag": "Wanneer adviseer je Nao Body Scrub voor thuisgebruik?", "opties": ["Direct na de wax", "5-7 dagen na de waxsessie, 1-2x per week", "Dagelijks", "Nooit"], "juisteAntwoord": 1}, {"vraag": "Wat is de retail-conversie-richtlijn voor een goede waxbehandelaar?", "opties": ["5-10%", "15-20%", "35-45%", "70%+"], "juisteAntwoord": 2}], "drempel": 75}, "on1-5": {"vragen": [{"vraag": "Wat is het belangrijkste voordeel van waxing boven scheren?", "opties": ["Goedkoper", "Haar uit de wortel, langduriger resultaat", "Sneller", "Minder pijn"], "juisteAntwoord": 1}, {"vraag": "Welke klant behandel je NIET?", "opties": ["Klant met diabetes", "Klant die Roaccutane gebruikte 3 maanden geleden", "Klant met dunne huid", "Klant tijdens menstruatie"], "juisteAntwoord": 1}, {"vraag": "Wat betekent OCOC?", "opties": ["Organic Cotton Only Certified", "One Cup One Client", "Ontharing Centrum Overleg Commissie", "Oil Cup Oil Client"], "juisteAntwoord": 1}, {"vraag": "Bij welk Fitzpatrick-type is PIH-risico het hoogst?", "opties": ["Type I", "Type II", "Type III", "Type IV-VI"], "juisteAntwoord": 3}, {"vraag": "Wat is de standaard werktemperatuur voor hot wax?", "opties": ["30-35°C", "40-45°C", "55-60°C", "70-75°C"], "juisteAntwoord": 2}], "drempel": 75}, "on2-6": {"vragen": [{"vraag": "Hoeveel ingrediënten bevat Nao Pre-Depilatory Powder?", "opties": ["2", "4", "7", "13"], "juisteAntwoord": 1}, {"vraag": "Welke stof vervangt talk in Nao Pre-Powder?", "opties": ["Maïszetmeel", "Dolomiet", "Silica", "Zeolite"], "juisteAntwoord": 1}, {"vraag": "Wat is het hoofdingrediënt van Nao Depilatory Wax?", "opties": ["Bijenwas", "Carnauba", "Glyceryl Hydrogenated Rosinate", "Colophonium"], "juisteAntwoord": 2}, {"vraag": "Uit welk land komt de basis-pijnhars?", "opties": ["Polen", "Duitsland", "Portugal", "Spanje"], "juisteAntwoord": 2}, {"vraag": "Hoeveel procent lavendelwater bevat de Lavender Hydrosol Spray?", "opties": ["50%", "75%", "85%", "98,5%"], "juisteAntwoord": 3}, {"vraag": "Wat is de retailprijs van Nao Post-Depilatory Oil?", "opties": ["€5", "€12", "€16", "€25"], "juisteAntwoord": 2}, {"vraag": "Wanneer mag klant starten met Body Scrub na een sessie?", "opties": ["Direct", "Na 24 uur", "Na 5-7 dagen", "Na 4 weken"], "juisteAntwoord": 2}, {"vraag": "Wat is het critical window voor Post-Oil aanbrengen?", "opties": ["0-5 seconden", "5-30 seconden", "1-2 minuten", "5 minuten"], "juisteAntwoord": 1}, {"vraag": "Welke waxvariant is 100% vegan?", "opties": ["Premium", "Economic", "Beide", "Geen"], "juisteAntwoord": 1}, {"vraag": "Wat is de verpakking van Nao Body Scrub?", "opties": ["Plastic pot", "Wheat straw jar", "Glass jar", "Aluminium blik"], "juisteAntwoord": 1}], "drempel": 70}, "on3-5": {"vragen": [{"vraag": "Wat is een absolute contra-indicatie voor waxbehandeling?", "opties": ["Menstruatie", "Diabetes", "Isotretinoïne-gebruik in de laatste 6 maanden", "Droge huid"], "juisteAntwoord": 2}, {"vraag": "Welk Fitzpatrick-type heeft het hoogste PIH-risico?", "opties": ["Type I", "Type II", "Type III", "Type IV-VI"], "juisteAntwoord": 3}, {"vraag": "Wat betekent OCOC?", "opties": ["Organic Cotton Only Certified", "One Cup One Client", "Oil Cup Oil Client", "Over-the-Counter Only Cosmetics"], "juisteAntwoord": 1}, {"vraag": "Wat is het critical window voor Post-Oil aanbrengen?", "opties": ["5-30 seconden na laatste trek", "1-2 minuten", "5-10 minuten", "Maakt niet uit"], "juisteAntwoord": 0}, {"vraag": "Welke waxtype is standaard voor intieme zones?", "opties": ["Warm wax", "Hot wax", "Roll-on", "Cold wax"], "juisteAntwoord": 1}, {"vraag": "Hoeveel ingrediënten bevat Nao Pre-Powder?", "opties": ["2", "4", "7", "13"], "juisteAntwoord": 1}, {"vraag": "Welk land levert de basis-pijnhars?", "opties": ["Polen", "Portugal", "Italië", "Duitsland"], "juisteAntwoord": 1}, {"vraag": "Welke Nao-waxvariant is 100% vegan?", "opties": ["Premium", "Economic", "Beide", "Geen"], "juisteAntwoord": 1}, {"vraag": "Wat is de retailprijs van Nao Body Scrub?", "opties": ["€7", "€12", "€14", "€25"], "juisteAntwoord": 2}, {"vraag": "Wanneer start klant met thuis-scrub na sessie?", "opties": ["Direct", "Na 24 uur", "Na 5-7 dagen", "Na 4 weken"], "juisteAntwoord": 2}, {"vraag": "Wat is de eerste stap in klachtafhandeling?", "opties": ["Oplossing voorstellen", "Luisteren zonder onderbreken", "Klant verwijzen naar manager", "Excuses aanbieden"], "juisteAntwoord": 1}, {"vraag": "Wat is de minimale doelstelling voor Google-reviews?", "opties": ["3,5 sterren", "4,0 sterren", "4,7 sterren", "5,0 sterren"], "juisteAntwoord": 2}, {"vraag": "Welk platform is primair voor beauty-marketing?", "opties": ["Facebook", "LinkedIn", "Instagram", "Twitter"], "juisteAntwoord": 2}, {"vraag": "Wat is het streven voor retail-conversie?", "opties": ["5-10%", "15-20%", "35-45%", "70%+"], "juisteAntwoord": 2}, {"vraag": "Wat is het BTW-tarief op waxbehandeling in Duitsland?", "opties": ["7%", "9%", "19%", "21%"], "juisteAntwoord": 2}], "drempel": 75}, "ac1-5": {"vragen": [{"vraag": "Welk waxing-model kiest Wax Affairs expliciet?", "opties": ["Verkoopmodel", "Ambachtsmodel", "Beide", "Geen voorkeur"], "juisteAntwoord": 1}, {"vraag": "Hoeveel maanden wacht je na Isotretinoïne-kuur voor behandeling?", "opties": ["1 maand", "3 maanden", "6 maanden", "12 maanden"], "juisteAntwoord": 2}, {"vraag": "Bij welke Fitzpatrick-types is PIH-risico het hoogst?", "opties": ["I-II", "III", "IV-VI", "Geen verschil"], "juisteAntwoord": 2}, {"vraag": "Wat betekent OCOC?", "opties": ["One Cup One Client", "Oil Cup Oil Client", "Organic Cotton Only Certified", "Optimale Continue Ontsmetting Cosmetisch"], "juisteAntwoord": 0}, {"vraag": "Wat is het hoofdingrediënt van Nao Depilatory Wax?", "opties": ["Bijenwas", "Carnauba", "Glyceryl Hydrogenated Rosinate", "Jojoba-olie"], "juisteAntwoord": 2}, {"vraag": "Welk land levert de basispijnhars?", "opties": ["Polen", "Portugal", "Italië", "Duitsland"], "juisteAntwoord": 1}, {"vraag": "Welke Nao-waxvariant is 100% vegan?", "opties": ["Premium", "Economic", "Beide", "Geen"], "juisteAntwoord": 1}, {"vraag": "Wat is de standaard werktemperatuur voor hot wax?", "opties": ["30-35°C", "40-45°C", "55-60°C", "70-75°C"], "juisteAntwoord": 2}, {"vraag": "Welke ontharingsmethode geeft het langst resultaat?", "opties": ["Scheren", "Ontharingscrème", "Waxing", "Epilator"], "juisteAntwoord": 2}, {"vraag": "Hoeveel procent talk bevat Nao Pre-Powder?", "opties": ["50%", "25%", "10%", "0%"], "juisteAntwoord": 3}, {"vraag": "Wat doe je bij ontdekte open wond in de zone?", "opties": ["Rond de wond werken", "Niet behandelen", "Wond afplakken en behandelen", "Desinfecteren en behandelen"], "juisteAntwoord": 1}, {"vraag": "Welke PBM is verplicht bij intieme waxing?", "opties": ["Alleen handschoenen", "Handschoenen en masker", "Handschoenen en schort", "Oogbescherming"], "juisteAntwoord": 2}, {"vraag": "Hoelang blijft een waxsessie effectief?", "opties": ["3-7 dagen", "1-2 weken", "3-4 weken", "8+ weken"], "juisteAntwoord": 2}, {"vraag": "Wat gebeurt er na 3-5 waxsessies met het haar?", "opties": ["Haar wordt dikker", "Haar wordt fijner en synchroniseert", "Geen verschil", "Haar valt uit"], "juisteAntwoord": 1}, {"vraag": "Welke spatel-regel is belangrijk voor OCOC?", "opties": ["Spatel opnieuw gebruiken in hoofdpan", "Nooit dubbel dippen in hoofdpan, alleen in individuele cup", "Elke spatel wassen", "Spatels mogen overal in"], "juisteAntwoord": 1}], "drempel": 75}};
    let updated = 0;
    for (const p of academy.programmas) {
      for (const m of (p.modules || [])) {
        for (const l of (m.lessen || [])) {
          if (QUIZ_SEED[l.id] && (!l.quizVragen || l.quizVragen.length === 0)) {
            l.quizVragen = QUIZ_SEED[l.id].vragen;
            l.slagingsDrempel = QUIZ_SEED[l.id].drempel;
            updated++;
          }
        }
      }
    }
    if (updated > 0) {
      slaJSON('academy.json', academy);
      console.log('[migratie] ' + updated + ' quiz(zes) geseed in academy.json');
    } else {
      console.log('[migratie] quiz-seed: niets te doen');
    }
  } catch(e) { console.error('[migratie] quiz-seed fout:', e.message); }
}
migrateQuizzes();


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

// Update content of a single lesson (inhoud, videoUrl)
app.post('/api/academy/les/:lesId', (req, res) => {
  if (!requireAuth(req, res)) return;
  const { lesId } = req.params;
  const { inhoud, videoUrl } = req.body;
  const academy = laadJSON('academy.json');
  let updated = false;
  const updateLesIn = (lessen) => {
    if (!Array.isArray(lessen)) return;
    for (const les of lessen) {
      if (les.id === lesId) {
        if (typeof inhoud === 'string') les.inhoud = inhoud;
        if (typeof videoUrl === 'string') les.videoUrl = videoUrl;
        les.laatstBewerkt = new Date().toISOString();
        updated = true;
        return;
      }
    }
  };
  if (Array.isArray(academy.programmas)) {
    for (const prog of academy.programmas) {
      if (Array.isArray(prog.modules)) {
        for (const mod of prog.modules) updateLesIn(mod.lessen);
      }
    }
  }
  if (Array.isArray(academy.modules)) {
    for (const mod of academy.modules) updateLesIn(mod.lessen);
  }
  if (!updated) return res.status(404).json({ error: 'Les niet gevonden: ' + lesId });
  slaJSON('academy.json', academy);
  res.json({ ok: true, lesId });
});


// Update quiz-vragen (structured data) voor een les
app.post('/api/academy/quiz/:lesId', (req, res) => {
  if (!requireAuth(req, res)) return;
  const { lesId } = req.params;
  const { vragen, slagingsDrempel } = req.body;
  if (!Array.isArray(vragen)) return res.status(400).json({ error: 'vragen moet een array zijn' });
  const academy = laadJSON('academy.json');
  let updated = false;
  const updateLesIn = (lessen) => {
    if (!Array.isArray(lessen)) return;
    for (const les of lessen) {
      if (les.id === lesId) {
        les.quizVragen = vragen;
        if (typeof slagingsDrempel === 'number') les.slagingsDrempel = slagingsDrempel;
        les.laatstBewerkt = new Date().toISOString();
        updated = true;
        return;
      }
    }
  };
  if (Array.isArray(academy.programmas)) {
    for (const prog of academy.programmas) {
      if (Array.isArray(prog.modules)) for (const mod of prog.modules) updateLesIn(mod.lessen);
    }
  }
  if (Array.isArray(academy.modules)) for (const mod of academy.modules) updateLesIn(mod.lessen);
  if (!updated) return res.status(404).json({ error: 'Les niet gevonden: ' + lesId });
  slaJSON('academy.json', academy);
  res.json({ ok: true, lesId });
});

// Quiz-poging indienen, score berekenen, voortgang bijwerken
app.post('/api/academy/quiz-poging/:lesId', (req, res) => {
  if (!requireAuth(req, res)) return;
  const { lesId } = req.params;
  const { antwoorden } = req.body;
  const user = getSessionUser(req);
  const studentId = (user && user.id) || req.body.studentId;
  if (!studentId) return res.status(400).json({ error: 'Geen studentId' });
  if (!Array.isArray(antwoorden)) return res.status(400).json({ error: 'antwoorden moet array zijn' });

  const academy = laadJSON('academy.json');
  let les = null;
  const zoekLes = (lessen) => {
    if (!Array.isArray(lessen)) return;
    for (const l of lessen) if (l.id === lesId) les = l;
  };
  if (Array.isArray(academy.programmas)) {
    for (const prog of academy.programmas) {
      if (Array.isArray(prog.modules)) for (const mod of prog.modules) zoekLes(mod.lessen);
    }
  }
  if (Array.isArray(academy.modules)) for (const mod of academy.modules) zoekLes(mod.lessen);
  if (!les) return res.status(404).json({ error: 'Les niet gevonden' });
  if (!Array.isArray(les.quizVragen) || les.quizVragen.length === 0) return res.status(400).json({ error: 'Geen quiz op deze les' });

  let goed = 0;
  const details = les.quizVragen.map((v, i) => {
    const gegeven = antwoorden[i];
    const correct = gegeven === v.juisteAntwoord;
    if (correct) goed++;
    return { vraag: v.vraag, gegeven, juist: v.juisteAntwoord, correct };
  });
  const score = Math.round((goed / les.quizVragen.length) * 100);
  const drempel = typeof les.slagingsDrempel === 'number' ? les.slagingsDrempel : 75;
  const geslaagd = score >= drempel;

  if (!academy.voortgang) academy.voortgang = {};
  if (!academy.voortgang[studentId]) academy.voortgang[studentId] = {};
  const bestaand = academy.voortgang[studentId][lesId] || { pogingen: [] };
  if (!Array.isArray(bestaand.pogingen)) bestaand.pogingen = [];
  bestaand.pogingen.push({ datum: new Date().toISOString(), score, geslaagd });
  bestaand.quizScore = Math.max(bestaand.quizScore || 0, score);
  bestaand.quizGeslaagd = bestaand.quizGeslaagd || geslaagd;
  if (geslaagd) bestaand.status = 'afgerond';
  bestaand.datum = new Date().toISOString();
  academy.voortgang[studentId][lesId] = bestaand;
  slaJSON('academy.json', academy);

  res.json({ ok: true, score, geslaagd, drempel, goed, totaal: les.quizVragen.length, details });
});

// Voortgang ophalen voor huidige user
app.get('/api/academy/voortgang', (req, res) => {
  if (!requireAuth(req, res)) return;
  const user = getSessionUser(req);
  const studentId = (user && user.id) || req.query.studentId;
  if (!studentId) return res.status(400).json({ error: 'Geen studentId' });
  const academy = laadJSON('academy.json');
  const vgang = (academy.voortgang && academy.voortgang[studentId]) || {};
  res.json({ studentId, voortgang: vgang });
});

// Certificaat als HTML (printbaar naar PDF via Ctrl/Cmd+P)
app.get('/api/academy/certificaat/:programmaId', (req, res) => {
  if (!requireAuth(req, res)) return;
  const { programmaId } = req.params;
  const user = getSessionUser(req);
  const studentId = (user && user.id) || req.query.studentId;
  const studentNaam = (user && (user.naam || user.email)) || req.query.naam || 'Cursist';
  if (!studentId) return res.status(400).json({ error: 'Geen studentId' });

  const academy = laadJSON('academy.json');
  const prog = (academy.programmas || []).find(p => p.id === programmaId);
  if (!prog) return res.status(404).send('Programma niet gevonden');

  const alleLessen = [];
  for (const mod of (prog.modules || [])) for (const les of (mod.lessen || [])) alleLessen.push(les);
  const vgang = (academy.voortgang && academy.voortgang[studentId]) || {};
  const afgerond = alleLessen.filter(l => vgang[l.id] && vgang[l.id].status === 'afgerond');
  const percentage = Math.round((afgerond.length / alleLessen.length) * 100);
  const alleKlaar = afgerond.length === alleLessen.length && alleLessen.length > 0;

  if (!alleKlaar) {
    return res.status(200).send(`<!DOCTYPE html><html><head><title>Certificaat nog niet beschikbaar</title>
    <style>body{font-family:Georgia,serif;max-width:600px;margin:60px auto;padding:40px;text-align:center;color:#333}
    h1{color:#b8860b}</style></head><body>
    <h1>Nog niet beschikbaar</h1>
    <p>Om het certificaat te ontvangen moet je alle lessen van dit programma afronden.</p>
    <p><strong>Voortgang: ${afgerond.length} van ${alleLessen.length} lessen (${percentage}%)</strong></p>
    <p><a href="/">Terug naar Academy</a></p>
    </body></html>`);
  }

  const datum = new Date().toLocaleDateString('nl-NL', { day: 'numeric', month: 'long', year: 'numeric' });
  const code = (studentId + '-' + programmaId + '-' + Date.now().toString(36)).toUpperCase().replace(/[^A-Z0-9-]/g,'').slice(0,24);
  const niveaus = { workshops: 'Certified Wax Affairs Workshop Graduate', online: 'Certified Wax Affairs Online Specialist', academy: 'Certified Wax Affairs Master' };
  const titel = niveaus[programmaId] || 'Certified Wax Affairs Professional';

  res.send(`<!DOCTYPE html><html lang="nl"><head><meta charset="utf-8"><title>Certificaat - ${studentNaam}</title>
  <style>
    @page { size: A4 landscape; margin: 0; }
    * { box-sizing: border-box; }
    body { margin: 0; padding: 0; font-family: Georgia, 'Times New Roman', serif; background: #f5f0e8; }
    .cert { width: 297mm; height: 210mm; padding: 20mm; margin: 0 auto; background: linear-gradient(135deg, #faf7f2 0%, #f5ede0 100%); position: relative; border: 2px solid #b8860b; }
    .cert::before { content: ''; position: absolute; top: 8mm; left: 8mm; right: 8mm; bottom: 8mm; border: 1px solid #d4a545; pointer-events: none; }
    .inner { text-align: center; padding-top: 10mm; position: relative; z-index: 1; }
    .brand { font-size: 16pt; letter-spacing: 8px; color: #8b6914; text-transform: uppercase; margin-bottom: 8mm; }
    .titel-groot { font-size: 48pt; color: #4a3520; margin: 0; font-weight: normal; font-style: italic; letter-spacing: 2px; }
    .uitgereikt { font-size: 14pt; color: #6b5738; margin: 15mm 0 5mm 0; letter-spacing: 2px; }
    .naam { font-size: 42pt; color: #2c1810; font-weight: bold; margin: 3mm 0 8mm 0; border-bottom: 1px solid #b8860b; display: inline-block; padding: 0 30mm 3mm 30mm; min-width: 60%; }
    .programma { font-size: 18pt; color: #4a3520; margin: 8mm 20mm; font-style: italic; line-height: 1.5; }
    .titel-prof { font-size: 22pt; color: #8b6914; margin: 8mm 0; font-weight: bold; letter-spacing: 1px; }
    .footer { position: absolute; bottom: 20mm; left: 20mm; right: 20mm; display: flex; justify-content: space-between; align-items: flex-end; }
    .sig { text-align: center; font-size: 11pt; color: #4a3520; min-width: 200px; }
    .sig-line { border-top: 1px solid #4a3520; padding-top: 3mm; font-family: Georgia; }
    .sig-naam { font-family: 'Brush Script MT', cursive; font-size: 18pt; margin-bottom: 2mm; color: #2c1810; }
    .datum { font-size: 12pt; color: #4a3520; text-align: center; }
    .code { font-size: 9pt; color: #8b6914; font-family: Courier, monospace; letter-spacing: 1px; margin-top: 8mm; }
    .noprint { text-align: center; padding: 20px; background: #fff; }
    .btn { display: inline-block; padding: 10px 20px; background: #b8860b; color: white; text-decoration: none; border-radius: 4px; margin: 5px; }
    @media print { .noprint { display: none; } body { background: white; } }
  </style></head><body>
  <div class="noprint">
    <p>Klik op "Print / Opslaan als PDF" om dit certificaat op te slaan.</p>
    <a href="#" onclick="window.print();return false;" class="btn">Print / Opslaan als PDF</a>
    <a href="/" class="btn" style="background:#6b5738">Terug</a>
  </div>
  <div class="cert">
    <div class="inner">
      <div class="brand">Wax Affairs Academy</div>
      <h1 class="titel-groot">Certificaat van Voltooiing</h1>
      <div class="uitgereikt">UITGEREIKT AAN</div>
      <div class="naam">${studentNaam}</div>
      <div class="programma">voor het met succes afronden van alle ${alleLessen.length} lessen uit het programma</div>
      <div class="programma" style="font-weight:bold;font-style:normal;color:#2c1810">${prog.naam}</div>
      <div class="titel-prof">${titel}</div>
      <div class="footer">
        <div class="sig">
          <div class="sig-naam">Narin</div>
          <div class="sig-line">Narin &mdash; Franchise HQ</div>
        </div>
        <div class="datum">
          Uitgereikt op<br><strong>${datum}</strong>
          <div class="code">Code: ${code}</div>
        </div>
        <div class="sig">
          <div class="sig-naam">Leon</div>
          <div class="sig-line">Leon &mdash; Franchise HQ</div>
        </div>
      </div>
    </div>
  </div>
  </body></html>`);
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

// ─── API: Clients Bulk Import ───
app.post('/api/clients/import', (req, res) => {
  if (!requireAuth(req, res)) return;
  const { clients: newClients, source } = req.body;
  if (!Array.isArray(newClients)) return res.status(400).json({ error: 'clients array required' });
  const list = laadJSON('clients.json');
  let imported = 0, skipped = 0;
  newClients.forEach(c => {
    // Skip duplicates by email or phone
    const exists = list.some(e => (c.email && e.email === c.email) || (c.telefoon && e.telefoon === c.telefoon));
    if (exists) { skipped++; return; }
    list.push({
      id: 'client-' + crypto.randomBytes(8).toString('hex'),
      naam: c.naam || '',
      email: c.email || '',
      telefoon: c.telefoon || '',
      omzet: parseFloat(c.omzet) || 0,
      laatsteBezoek: c.laatsteBezoek || '',
      aantalAfspraken: parseInt(c.aantalAfspraken) || 0,
      notities: c.notities || '',
      bron: source || 'import',
      aangemaakt: c.aangemaakt || new Date().toISOString()
    });
    imported++;
  });
  slaJSON('clients.json', list);
  res.json({ imported, skipped, total: list.length });
});

// ─── API: Marketing Reports ───
app.get('/api/marketing-reports', (req, res) => {
  if (!requireAuth(req, res)) return;
  try {
    const marketingDir = path.join(__dirname, 'marketing');
    if (!fs.existsSync(marketingDir)) return res.json([]);
    const categories = ['blog', 'social', 'seo', 'ads', 'email', 'strategie'];
    const reports = [];
    categories.forEach(cat => {
      try {
        const catDir = path.join(marketingDir, cat);
        if (fs.existsSync(catDir)) {
          const files = fs.readdirSync(catDir).filter(f => f.endsWith('.md')).sort().reverse();
          files.forEach(file => {
            try {
              const filePath = path.join(catDir, file);
              const content = fs.readFileSync(filePath, 'utf8');
              const stat = fs.statSync(filePath);
              reports.push({ categorie: cat, bestand: file, inhoud: content, datum: stat.mtime.toISOString(), grootte: content.length });
            } catch(e) { /* skip file */ }
          });
        }
      } catch(e) { /* skip category */ }
    });
    res.json(reports);
  } catch(e) {
    console.error('Marketing API error:', e);
    res.json([]);
  }
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
  const tasks = laadJSON('tasks.json');
  const bookings = laadJSON('bookings.json');
  const clients = laadJSON('clients.json');
  const studios = laadJSON('studios.json');
  const services = laadJSON('services.json');
  const personeel = laadJSON('personeel.json');

  const nu = new Date();
  const maand = nu.getMonth();
  const jaar = nu.getFullYear();
  const vandaagStr = nu.toISOString().slice(0,10);

  // Current month string prefix (e.g. "2026-04")
  const maandPrefix = `${jaar}-${String(maand+1).padStart(2,'0')}`;

  // Revenue this month
  const boekingDezeMaand = bookings.filter(b =>
    ['bevestigd','voltooid'].includes(b.status) &&
    b.datum && b.datum.startsWith(maandPrefix)
  );
  const omzetDezeMaand = boekingDezeMaand.reduce((s, b) => {
    if (b.prijs) return s + (parseFloat(b.prijs) || 0);
    const svc = services.find(sv => sv.id === b.serviceId);
    return s + (svc ? (parseFloat(svc.prijs) || 0) : 0);
  }, 0);

  // Today's bookings
  const vandaagBookings = bookings.filter(b => b.datum && b.datum.startsWith(vandaagStr) && b.status !== 'geannuleerd');

  // Team members
  const medewerkers = (personeel && personeel.medewerkers) ? personeel.medewerkers : [];
  const teamLeden = medewerkers.filter(m => m.status === 'actief').length;

  // Active studios
  const activeStudios = studios.filter(s => s.actief !== false).length;

  // Alerts
  const alerts = [];
  const overdueTasks = tasks.filter(t => t.status !== 'klaar' && t.deadline && new Date(t.deadline) < nu);
  if (overdueTasks.length) alerts.push({ type: 'danger', tekst: `${overdueTasks.length} verlopen taak/taken`, link: 'taken' });

  if (vandaagBookings.length) alerts.push({ type: 'info', tekst: `${vandaagBookings.length} afspraak/afspraken vandaag`, link: 'agenda' });

  // Bookings without confirmation
  const nieuwBookings = bookings.filter(b => b.status === 'nieuw' && b.datum >= vandaagStr);
  if (nieuwBookings.length) alerts.push({ type: 'warning', tekst: `${nieuwBookings.length} onbevestigde boeking(en)`, link: 'agenda' });

  // No-shows this week
  const weekAgo = new Date(nu); weekAgo.setDate(weekAgo.getDate() - 7);
  const weekAgoStr = weekAgo.toISOString().slice(0,10);
  const noShows = bookings.filter(b => b.status === 'no-show' && b.datum >= weekAgoStr && b.datum <= vandaagStr);
  if (noShows.length) alerts.push({ type: 'warning', tekst: `${noShows.length} no-show(s) deze week`, link: 'agenda' });

  res.json({
    kpis: {
      omzetDezeMaand,
      boekingDezeMaand: boekingDezeMaand.length,
      todayBookings: vandaagBookings.length,
      totalClients: clients.length,
      teamLeden,
      activeStudios
    },
    alerts
  });
});

// ─── API: Vaste Lasten ───
app.get('/api/vastelasten', (req, res) => {
  if (!requireAuth(req, res)) return;
  res.json(laadJSON('vastelasten.json'));
});

app.post('/api/vastelasten', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('vastelasten.json');
  const item = { id: 'vl-' + crypto.randomBytes(8).toString('hex'), actief: true, ...req.body, aangemaakt: new Date().toISOString() };
  list.push(item);
  slaJSON('vastelasten.json', list);
  res.json(item);
});

app.put('/api/vastelasten/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  const list = laadJSON('vastelasten.json');
  const idx = list.findIndex(v => v.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Niet gevonden' });
  list[idx] = { ...list[idx], ...req.body, gewijzigd: new Date().toISOString() };
  slaJSON('vastelasten.json', list);
  res.json(list[idx]);
});

app.delete('/api/vastelasten/:id', (req, res) => {
  if (!requireAuth(req, res)) return;
  let list = laadJSON('vastelasten.json');
  list = list.filter(v => v.id !== req.params.id);
  slaJSON('vastelasten.json', list);
  res.json({ ok: true });
});

// ─── Start ───
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  Wax Affairs CRM draait op http://localhost:${PORT}\n`);
});
