/**
 * SafeNetID v2 - combined portal with user & admin roles
 * - Register/login for users
 * - Admin login
 * - User can create reports after login and see their reports
 * - Admin can manage all reports (list, change status, delete)
 *
 * Usage:
 * 1) npm install
 * 2) node server.js
 * 3) Open http://localhost:3000
 */
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ensure data dir
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true }
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/admin', express.static(path.join(__dirname, 'admin')));

// sqlite db
const dbFile = path.join(dataDir, 'safenetid.db');
const db = new sqlite3.Database(dbFile, (err) => {
  if (err) return console.error('DB open error:', err.message);
  console.log('SQLite connected at', dbFile);
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    site TEXT,
    note TEXT,
    status TEXT DEFAULT 'Pending',
    created_at TEXT DEFAULT (datetime('now','localtime')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// create default admin if not exists
(async function ensureAdmin(){
  const adminUser = 'admin';
  const adminPass = 'admin123';
  db.get('SELECT * FROM admins WHERE username = ?', [adminUser], async (err, row) => {
    if (err) return console.error(err);
    if (!row){
      const hash = await bcrypt.hash(adminPass, 10);
      db.run('INSERT INTO admins(username, password) VALUES(?, ?)', [adminUser, hash]);
      console.log('Created default admin:', adminUser, '/', adminPass);
    }
  });
})();

// helpers
function requireUser(req, res, next){
  if (req.session.user && req.session.role === 'user') return next();
  res.redirect('/login.html');
}
function requireAdmin(req, res, next){
  if (req.session.user && req.session.role === 'admin') return next();
  res.redirect('/admin/login.html');
}

// routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// user auth
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Isi semua field' });
  try {
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users(name,email,password) VALUES(?,?,?)', [name, email, hash], function(err){
      if (err) return res.status(400).json({ error: err.message });
      res.json({ success: true, id: this.lastID });
    });
  } catch(e){
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.json({ success: false, message: 'User tidak ditemukan' });
    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.json({ success: false, message: 'Password salah' });
    req.session.user = { id: row.id, name: row.name, email: row.email };
    req.session.role = 'user';
    res.json({ success: true });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(()=> res.json({ success: true }));
});

// admin auth
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM admins WHERE username = ?', [username], async (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.json({ success: false, message: 'Admin tidak ditemukan' });
    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.json({ success: false, message: 'Password salah' });
    req.session.user = { id: row.id, username: row.username };
    req.session.role = 'admin';
    res.json({ success: true });
  });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(()=> res.json({ success: true }));
});

// user features
app.post('/api/report', requireUser, (req, res) => {
  const { site, note } = req.body;
  if (!site) return res.status(400).json({ error: 'site required' });
  db.run('INSERT INTO reports(user_id,site,note) VALUES(?,?,?)', [req.session.user.id, site, note], function(err){
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, id: this.lastID });
  });
});

app.get('/api/my-reports', requireUser, (req, res) => {
  db.all('SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC', [req.session.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// admin features
app.get('/api/admin/reports', requireAdmin, (req, res) => {
  db.all('SELECT reports.*, users.name as reporter FROM reports LEFT JOIN users ON reports.user_id = users.id ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/admin/reports/:id/status', requireAdmin, (req, res) => {
  const id = req.params.id;
  const status = req.body.status || 'Pending';
  db.run('UPDATE reports SET status = ? WHERE id = ?', [status, id], function(err){
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

app.delete('/api/admin/reports/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  db.run('DELETE FROM reports WHERE id = ?', [id], function(err){
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// serve dashboards (protected)
app.get('/dashboard.html', requireUser, (req, res) => res.sendFile(path.join(__dirname,'public','dashboard.html')));
app.get('/admin/dashboard.html', requireAdmin, (req, res) => res.sendFile(path.join(__dirname,'admin','dashboard.html')));

// fallback
app.use((req,res)=> res.status(404).send('Not found'));

app.listen(PORT, ()=> console.log('SafeNetID running at http://localhost:'+PORT));
