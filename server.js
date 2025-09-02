import express from 'express';
import cors from 'cors';
import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// Simple config
const ADMIN_KEY = process.env.ADMIN_KEY || '1738';

// Init DB
const dbFile = process.env.DB_FILE || path.join(__dirname, 'data.sqlite');
const db = new sqlite3.Database(dbFile);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    uid TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    name TEXT,
    created_at INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS user_auth (
    uid TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER,
    FOREIGN KEY(uid) REFERENCES users(uid)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS balances (
    uid TEXT PRIMARY KEY,
    balance_usd REAL NOT NULL DEFAULT 0,
    wallet_balance_usd REAL NOT NULL DEFAULT 0,
    updated_at INTEGER,
    FOREIGN KEY(uid) REFERENCES users(uid)
  )`);

  // Best-effort migration in case the column was missing in existing DBs
  db.run(`ALTER TABLE balances ADD COLUMN wallet_balance_usd REAL NOT NULL DEFAULT 0`, () => {});

  db.run(`CREATE TABLE IF NOT EXISTS deposits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT NOT NULL,
    amount_usd REAL NOT NULL,
    note TEXT,
    created_at INTEGER,
    FOREIGN KEY(uid) REFERENCES users(uid)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS stocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company TEXT UNIQUE NOT NULL,
    current_price REAL NOT NULL,
    percentage_change REAL NOT NULL,
    direction TEXT NOT NULL,
    updated_at INTEGER
  )`);
  
  // Percentage bubble per user
  db.run(`CREATE TABLE IF NOT EXISTS user_percentages (
    uid TEXT PRIMARY KEY,
    value REAL NOT NULL,
    direction TEXT NOT NULL,
    updated_at INTEGER,
    FOREIGN KEY(uid) REFERENCES users(uid)
  )`);
});

// Helpers
function getNow() { return Date.now(); }

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err){
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, function(err, row){
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, function(err, rows){
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
}

// Routes

// User signup with password
app.post('/api/signup', async (req, res) => {
  try {
    const { email, name, password } = req.body || {};
    if (!email || !password || password.length < 6) {
      return res.status(400).json({ error: 'email_and_password_required_min_6_chars' });
    }
    
    // Check if email already exists
    const existingUser = await get(`SELECT uid FROM user_auth WHERE email=?`, [email]);
    if (existingUser) {
      return res.status(400).json({ error: 'email_already_registered' });
    }
    
    // Generate unique UID
    const uid = 'uid_' + Math.random().toString(36).slice(2, 8) + Date.now().toString(36).slice(-6);
    const passwordHash = hashPassword(password);
    const now = getNow();
    
    // Create user profile
    await run(`INSERT INTO users(uid, email, name, created_at) VALUES(?,?,?,?)`,
      [uid, email, name || null, now]);
    
    // Create authentication record
    await run(`INSERT INTO user_auth(uid, email, password_hash, created_at) VALUES(?,?,?,?)`,
      [uid, email, passwordHash, now]);
    
    // Allocate default Home balance (set to 0)
    const DEFAULT_HOME_BALANCE = 0;
    await run(`INSERT INTO balances(uid, balance_usd, wallet_balance_usd, updated_at) VALUES(?,?,?,?)`,
      [uid, 0, DEFAULT_HOME_BALANCE, now]);
    
    // Create default deposit record (0 amount)
    await run(`INSERT INTO deposits(uid, amount_usd, note, created_at) VALUES(?,?,?,?)`,
      [uid, DEFAULT_HOME_BALANCE, 'default', now]);
    
    // Return user profile
    const profile = await get(`SELECT u.uid, u.email, u.name,
                                      IFNULL(b.balance_usd, 0) as balance_usd,
                                      IFNULL(b.wallet_balance_usd, 0) as wallet_balance_usd
                               FROM users u LEFT JOIN balances b ON b.uid=u.uid WHERE u.uid=?`, [uid]);
    
    res.json({ ok: true, profile });
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// User login with password
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'email_and_password_required' });
    }
    
    // Find user by email
    const auth = await get(`SELECT ua.uid, ua.password_hash, u.email, u.name
                           FROM user_auth ua 
                           JOIN users u ON u.uid = ua.uid 
                           WHERE ua.email=?`, [email]);
    
    if (!auth) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    
    // Verify password
    const passwordHash = hashPassword(password);
    if (auth.password_hash !== passwordHash) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    
    // Return user profile
    const profile = await get(`SELECT u.uid, u.email, u.name,
                                      IFNULL(b.balance_usd, 0) as balance_usd,
                                      IFNULL(b.wallet_balance_usd, 0) as wallet_balance_usd
                               FROM users u LEFT JOIN balances b ON b.uid=u.uid WHERE u.uid=?`, [auth.uid]);
    
    res.json({ ok: true, profile });
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// Get all users (admin only)
app.get('/api/users', async (req, res) => {
  try {
    const key = req.header('x-admin-key');
    if (key !== ADMIN_KEY) return res.status(401).json({ error: 'unauthorized' });
    
    const users = await all(`SELECT u.uid, u.email, u.name, u.created_at,
                                   IFNULL(b.balance_usd, 0) as balance_usd,
                                   IFNULL(b.wallet_balance_usd, 0) as wallet_balance_usd
                            FROM users u LEFT JOIN balances b ON b.uid=u.uid
                            ORDER BY u.created_at DESC`);
    
    res.json({ ok: true, users });
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// Upsert user registration (legacy endpoint for compatibility)
app.post('/api/register', async (req, res) => {
  try {
    const { uid, email, name } = req.body || {};
    if (!uid) return res.status(400).json({ error: 'uid is required' });
    await run(`INSERT INTO users(uid, email, name, created_at) VALUES(?,?,?,?)
              ON CONFLICT(uid) DO UPDATE SET email=excluded.email, name=excluded.name`,
      [uid, email || null, name || null, getNow()]);
    // Allocate default Home balance on first registration (set to 0)
    const DEFAULT_HOME_BALANCE = 0;
    await run(`INSERT INTO balances(uid, balance_usd, wallet_balance_usd, updated_at) VALUES(?,?,?,?)
              ON CONFLICT(uid) DO NOTHING`, [uid, 0, DEFAULT_HOME_BALANCE, getNow()]);
    // If the user already existed and has zero home balance, allocate it now
    await run(`UPDATE balances SET wallet_balance_usd=? , updated_at=?
               WHERE uid=? AND IFNULL(wallet_balance_usd,0)=0`, [DEFAULT_HOME_BALANCE, getNow(), uid]);

    // Ensure a matching deposit record exists for Personal feed
    const existsDefault = await get(`SELECT 1 AS ok FROM deposits WHERE uid=? AND note='default' LIMIT 1`, [uid]);
    if (!existsDefault?.ok) {
      await run(`INSERT INTO deposits(uid, amount_usd, note, created_at) VALUES(?,?,?,?)`, [uid, DEFAULT_HOME_BALANCE, 'default', getNow()]);
    }
    const profile = await get(`SELECT u.uid, u.email, u.name,
                                      IFNULL(b.balance_usd, 0) as balance_usd,
                                      IFNULL(b.wallet_balance_usd, 0) as wallet_balance_usd
                               FROM users u LEFT JOIN balances b ON b.uid=u.uid WHERE u.uid=?`, [uid]);
    res.json(profile);
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// Get profile by uid
app.get('/api/profile/:uid', async (req, res) => {
  try {
    const { uid } = req.params;
    const profile = await get(`SELECT u.uid, u.email, u.name,
                                      IFNULL(b.balance_usd, 0) as balance_usd,
                                      IFNULL(b.wallet_balance_usd, 0) as wallet_balance_usd
                               FROM users u LEFT JOIN balances b ON b.uid=u.uid WHERE u.uid=?`, [uid]);
    if (!profile) return res.status(404).json({ error: 'not_found' });
    res.json(profile);
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// Manual deposit (admin-only)
app.post('/api/deposits/manual', async (req, res) => {
  try {
    const key = req.header('x-admin-key');
    if (key !== ADMIN_KEY) return res.status(401).json({ error: 'unauthorized' });
    const { uid, amountUsd } = req.body || {};
    const amount = Number(amountUsd);
    if (!uid || !Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'invalid_params' });
    const user = await get(`SELECT uid FROM users WHERE uid=?`, [uid]);
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    // Always tag gas-balance deposits as gas_fee for correct personal feed labeling
    await run(`INSERT INTO deposits(uid, amount_usd, note, created_at) VALUES(?,?,?,?)`, [uid, amount, 'gas_fee', getNow()]);
    await run(`INSERT INTO balances(uid, balance_usd, updated_at) VALUES(?,?,?)
               ON CONFLICT(uid) DO UPDATE SET balance_usd = balance_usd + excluded.balance_usd, updated_at=excluded.updated_at`,
      [uid, amount, getNow()]);
    const profile = await get(`SELECT u.uid, u.email, u.name,
                                      IFNULL(b.balance_usd, 0) as balance_usd,
                                      IFNULL(b.wallet_balance_usd, 0) as wallet_balance_usd
                               FROM users u LEFT JOIN balances b ON b.uid=u.uid WHERE u.uid=?`, [uid]);
    res.json({ ok: true, profile });
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// Manual deposit to wallet (home) balance (admin-only)
app.post('/api/deposits/manual/home', async (req, res) => {
  try {
    const key = req.header('x-admin-key');
    if (key !== ADMIN_KEY) return res.status(401).json({ error: 'unauthorized' });
    const { uid, amountUsd, note } = req.body || {};
    const amount = Number(amountUsd);
    if (!uid || !Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'invalid_params' });
    const user = await get(`SELECT uid FROM users WHERE uid=?`, [uid]);
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    await run(`INSERT INTO deposits(uid, amount_usd, note, created_at) VALUES(?,?,?,?)`, [uid, amount, (note || 'wallet'), getNow()]);
    await run(`INSERT INTO balances(uid, wallet_balance_usd, updated_at) VALUES(?,?,?)
               ON CONFLICT(uid) DO UPDATE SET wallet_balance_usd = wallet_balance_usd + excluded.wallet_balance_usd, updated_at=excluded.updated_at`,
      [uid, amount, getNow()]);
    const profile = await get(`SELECT u.uid, u.email, u.name,
                                      IFNULL(b.balance_usd, 0) as balance_usd,
                                      IFNULL(b.wallet_balance_usd, 0) as wallet_balance_usd
                               FROM users u LEFT JOIN balances b ON b.uid=u.uid WHERE u.uid=?`, [uid]);
    res.json({ ok: true, profile });
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// List recent deposits for a user (admin and user-visible feed)
app.get('/api/deposits/:uid', async (req, res) => {
  try {
    const { uid } = req.params;
    if (!uid) return res.status(400).json({ error: 'uid_required' });
    const rows = await new Promise((resolve, reject) => {
      db.all(`SELECT id, uid, amount_usd, note, created_at FROM deposits WHERE uid=? ORDER BY id DESC LIMIT 20`, [uid], (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      });
    });
    res.json({ ok: true, deposits: rows });
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// Withdraw: deduct from home wallet balance and gas fee balance, record entries
app.post('/api/withdraw', async (req, res) => {
  try {
    const { uid, amountUsd, gasUsd } = req.body || {};
    const amount = Number(amountUsd);
    const gas = Number(gasUsd);
    if (!uid || !Number.isFinite(amount) || amount <= 0 || !Number.isFinite(gas) || gas < 0) {
      return res.status(400).json({ error: 'invalid_params' });
    }
    const row = await get(`SELECT IFNULL(balance_usd,0) as gas_bal, IFNULL(wallet_balance_usd,0) as home_bal FROM balances WHERE uid=?`, [uid]);
    if (!row) return res.status(404).json({ error: 'user_not_found' });
    if (row.home_bal < amount) return res.status(400).json({ error: 'insufficient_home_balance' });
    if (row.gas_bal < gas) return res.status(400).json({ error: 'insufficient_gas_balance' });
    const now = getNow();
    await run(`UPDATE balances SET wallet_balance_usd = wallet_balance_usd - ?, updated_at=? WHERE uid=?`, [amount, now, uid]);
    if (gas > 0) {
      await run(`UPDATE balances SET balance_usd = balance_usd - ?, updated_at=? WHERE uid=?`, [gas, now, uid]);
    }
    // Record negative amount as withdraw and gas fee entry
    await run(`INSERT INTO deposits(uid, amount_usd, note, created_at) VALUES(?,?,?,?)`, [uid, -amount, 'withdraw', now]);
    if (gas > 0) await run(`INSERT INTO deposits(uid, amount_usd, note, created_at) VALUES(?,?,?,?)`, [uid, -gas, 'gas_fee', now]);
    const profile = await get(`SELECT u.uid, u.email, u.name,
                                      IFNULL(b.balance_usd, 0) as balance_usd,
                                      IFNULL(b.wallet_balance_usd, 0) as wallet_balance_usd
                               FROM users u LEFT JOIN balances b ON b.uid=u.uid WHERE u.uid=?`, [uid]);
    res.json({ ok: true, profile });
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// Update stock percentage (admin-only)
app.post('/api/stocks/update-percentage', async (req, res) => {
  try {
    const key = req.header('x-admin-key');
    if (key !== ADMIN_KEY) return res.status(401).json({ error: 'unauthorized' });
    
    const { company, currentPrice, percentage, direction } = req.body || {};
    const price = Number(currentPrice);
    const pct = Number(percentage);
    
    if (!company || !Number.isFinite(price) || price <= 0 || !Number.isFinite(pct) || pct < 0 || !direction) {
      return res.status(400).json({ error: 'invalid_params' });
    }
    
    if (!['up', 'down'].includes(direction)) {
      return res.status(400).json({ error: 'invalid_direction' });
    }
    
    const now = getNow();
    
    // Calculate the new price based on percentage change
    const multiplier = direction === 'up' ? (1 + pct / 100) : (1 - pct / 100);
    const newPrice = price * multiplier;
    
    // Insert or update stock data with the calculated new price
    await run(`INSERT INTO stocks(company, current_price, percentage_change, direction, updated_at) 
               VALUES(?,?,?,?,?) 
               ON CONFLICT(company) DO UPDATE SET 
                 current_price=excluded.current_price,
                 percentage_change=excluded.percentage_change,
                 direction=excluded.direction,
                 updated_at=excluded.updated_at`,
      [company, newPrice, pct, direction, now]);
    
    res.json({ 
      ok: true, 
      message: 'Stock percentage updated successfully',
      newPrice: newPrice.toFixed(2)
    });
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// Get all stocks data
app.get('/api/stocks', async (req, res) => {
  try {
    const stocks = await all(`SELECT company, current_price, percentage_change, direction, updated_at 
                             FROM stocks ORDER BY company`);
    res.json({ ok: true, stocks });
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// Update percentage bubble (admin-only)
app.post('/api/percentage/update', async (req, res) => {
  try {
    const key = req.header('x-admin-key');
    if (key !== ADMIN_KEY) return res.status(401).json({ error: 'unauthorized' });
    
    const { uid, value, direction } = req.body || {};
    const hasUid = typeof uid === 'string' && uid.trim().length > 0;
    const percentageValue = Number(value);
    
    if (!Number.isFinite(percentageValue) || percentageValue < 0) {
      return res.status(400).json({ error: 'invalid_percentage_value' });
    }
    
    if (!['up', 'down', 'neutral'].includes(direction)) {
      return res.status(400).json({ error: 'invalid_direction' });
    }
    
    const now = getNow();
    
    if (hasUid) {
      const user = await get(`SELECT uid FROM users WHERE uid=?`, [uid]);
      if (!user) return res.status(404).json({ error: 'user_not_found' });
      await run(`INSERT INTO user_percentages(uid, value, direction, updated_at)
                 VALUES(?,?,?,?)
                 ON CONFLICT(uid) DO UPDATE SET value=excluded.value, direction=excluded.direction, updated_at=excluded.updated_at`,
        [uid, percentageValue, direction, now]);
      const row = await get(`SELECT uid, value, direction, updated_at FROM user_percentages WHERE uid=?`, [uid]);
      return res.json({ ok: true, scope: 'user', percentage: row });
    } else {
      // Global fallback
      const percentageData = { value: percentageValue, direction, updated_at: now };
      global.currentPercentage = percentageData;
      return res.json({ ok: true, scope: 'global', percentage: percentageData });
    }
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// Get current percentage bubble value
app.get('/api/percentage/current', async (req, res) => {
  try {
    const uid = (req.query?.uid || '').trim?.() || '';
    if (uid) {
      const row = await get(`SELECT uid, value, direction, updated_at FROM user_percentages WHERE uid=?`, [uid]);
      if (row) return res.json({ ok: true, scope: 'user', percentage: row });
    }
    const percentageData = global.currentPercentage || { value: 0, direction: 'neutral', updated_at: Date.now() };
    res.json({ ok: true, scope: 'global', percentage: percentageData });
  } catch (e) {
    res.status(500).json({ error: 'internal_error', detail: String(e?.message || e) });
  }
});

// Serve static site for convenience
app.use('/', express.static(__dirname));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Watchers Eye API running on http://localhost:${PORT}`);
});


