require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite');
const nodemailer = require('nodemailer');

const app = express();
const db = new DatabaseSync(path.join(__dirname, 'buzenova.db'));
db.exec(`CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT,
  password_hash TEXT NOT NULL, interested INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_login TEXT)`);

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 465),
  secure: Number(process.env.SMTP_PORT || 465) === 465,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const wrap = (title, body) => `
<div style="background:#12062e;padding:32px 12px;font-family:Arial,sans-serif">
 <div style="max-width:520px;margin:auto;background:#1d0b4a;border-radius:16px;padding:32px;color:#fff;border-top:4px solid #ff2e93">
  <div style="font-size:20px;font-weight:800;letter-spacing:1px;color:#22e5ff">BUZENOVA TECHNOLOGIES</div>
  <h2 style="margin:20px 0 10px">${title}</h2>
  <div style="line-height:1.6;color:#d9d2f5">${body}</div>
 </div></div>`;

async function sendMail(to, subject, html) {
  try { await transporter.sendMail({ from: process.env.MAIL_FROM, to, subject, html }); }
  catch (e) { console.error('Mail failed:', e.message); }   // never block the user if SMTP fails
}

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 8 }
}));
app.use(express.static(path.join(__dirname, 'public')));

const needAuth = (req, res, next) =>
  req.session.uid ? next() : (req.path.startsWith('/api') ? res.status(401).json({ error: 'Please log in.' }) : res.redirect('/'));

app.post('/api/register', async (req, res) => {
  const { name, email, phone, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required.' });
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const mail = email.trim().toLowerCase();
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(mail))
    return res.status(409).json({ error: 'This email is already registered. Log in instead.' });
  const hash = await bcrypt.hash(password, 12);
  const info = db.prepare('INSERT INTO users(name,email,phone,password_hash) VALUES(?,?,?,?)')
    .run(name.trim(), mail, (phone || '').trim(), hash);
   req.session.uid = Number(info.lastInsertRowid);
  sendMail(mail, 'Welcome to Buzenova Technologies', wrap(`Welcome, ${esc(name)}!`,
    `Your account is ready. Explore our upcoming <b>AI Automation Cohort</b> inside your portal.`));
  res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(String(email || '').trim().toLowerCase());
  if (!user || !bcrypt.compareSync(String(password || ''), user.password_hash))
    return res.status(401).json({ error: 'Incorrect email or password.' });
  db.prepare('UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?').run(user.id);
  req.session.uid = user.id;
  sendMail(user.email, 'New login to your Buzenova account', wrap('You just logged in',
    `Hi ${esc(user.name)}, we noticed a login on ${new Date().toUTCString()}.<br>If this wasn't you, reply to this email right away.`));
  res.json({ ok: true });
});

app.get('/api/me', needAuth, (req, res) => {
  const u = db.prepare('SELECT name,email,interested FROM users WHERE id=?').get(req.session.uid);
  res.json(u);
});

app.post('/api/cohort/interest', needAuth, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.uid);
  db.prepare('UPDATE users SET interested=1 WHERE id=?').run(u.id);
  sendMail(u.email, 'Your seat request: AI Automation Cohort', wrap('Seat request received',
    `Hi ${esc(u.name)}, you're on the list for the <b>AI Automation Cohort</b>. Our team will contact you with next steps.`));
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/cohort', needAuth, (req, res) => res.sendFile(path.join(__dirname, 'private', 'cohort.html')));

app.listen(process.env.PORT || 3000, () => console.log('Buzenova portal running on port ' + (process.env.PORT || 3000)));