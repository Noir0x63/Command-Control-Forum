'use strict';
/**
 * COMMAND & CONTROL (C2) — Secure Express Backend Server
 * Security Level: Production-Grade / Security-by-Design 2026
 *
 * Defense layers:
 *  1. Helmet.js — HTTP security headers (CSP, HSTS, X-Frame, XCTO, Referrer)
 *  2. CORS — Strict origin allowlist from environment
 *  3. Rate limiting — Per-IP, SQLite-backed persistent store
 *  4. Input validation — Schema-based, pure-function validators, no external deps
 *  5. scrypt N=131072 — 2026-grade password hashing (8x stronger than OWASP 2017 min)
 *  6. Thread IDs — 16 bytes / 128-bit entropy (UUID-grade, eliminates birthday problem)
 *  7. Server-side logout — Token revocation on signout
 *  8. Error sanitization — No stack traces, no internal paths exposed to clients
 *  9. Static isolation — Only public/ served; server.js, DB, .env never reachable
 * 10. Commander role — Exclusively via CLI setup.js; UI registration always yields AGENT
 */

require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const sqlite3    = require('sqlite3').verbose();
const http       = require('http');
const { Server } = require('socket.io');
const crypto     = require('crypto');
const path       = require('path');
const fs         = require('fs');
const { Worker } = require('worker_threads');
const captcha    = require('./server/captcha');

// ─── Runtime Constants ────────────────────────────────────────────────────────

const PORT            = parseInt(process.env.PORT ?? '3000', 10);
const NODE_ENV        = process.env.NODE_ENV ?? 'development';
const IS_PROD         = NODE_ENV === 'production';
const CLOUDFLARE_DOMAIN = process.env.CLOUDFLARE_DOMAIN ?? '';
const ALLOWED_ORIGIN  = CLOUDFLARE_DOMAIN
  ? `https://${CLOUDFLARE_DOMAIN}`
  : `http://localhost:${PORT}`;

// scrypt 2026-grade (OWASP 2024 recommendation for interactive login)
const SCRYPT_PARAMS   = Object.freeze({ N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
const SCRYPT_KEY_LEN  = 64; // bytes
const HASH_VERSION    = 'v2';

const VALID_CATEGORIES = new Set([
  'announcements',
  'applied-crypto',
  'low-level',
  'web-security',
  'reverse-eng',
  'secure-coding',
  'pentesting',
  'red-team',
  'blue-team',
  'malware'
]);

// ─── Database ────────────────────────────────────────────────────────────────

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const dbPath = path.join(DATA_DIR, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('[FATAL] Cannot open database:', err.message);
    process.exit(1);
  }
  console.log('[OK] SQLite connected:', dbPath);
});

// WAL mode + FK enforcement
db.run('PRAGMA journal_mode=WAL');
db.run('PRAGMA foreign_keys=ON');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      codename             TEXT PRIMARY KEY,
      password_hash        TEXT NOT NULL,
      public_key_spki      TEXT NOT NULL,
      encrypted_private_key TEXT,
      role                 TEXT NOT NULL DEFAULT 'AGENT',
      bio                  TEXT NOT NULL DEFAULT 'INITIALIZED AGENT NODE.',
      joined_date          TEXT NOT NULL,
      last_seen            INTEGER DEFAULT 0
    )
  `);

  // Retroactive migration to add last_seen if user table already exists
  db.run("ALTER TABLE users ADD COLUMN last_seen INTEGER DEFAULT 0", (err) => {
    // Silent catch if column is already present
  });

  db.run(`
    CREATE TABLE IF NOT EXISTS threads (
      id        TEXT    PRIMARY KEY,
      title     TEXT    NOT NULL,
      content   TEXT    NOT NULL,
      author    TEXT    NOT NULL,
      category  TEXT    NOT NULL,
      timestamp TEXT    NOT NULL,
      upvotes   INTEGER NOT NULL DEFAULT 0,
      signature TEXT    NOT NULL,
      FOREIGN KEY (author) REFERENCES users(codename)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS replies (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      thread_id TEXT    NOT NULL,
      content   TEXT    NOT NULL,
      author    TEXT    NOT NULL,
      timestamp TEXT    NOT NULL,
      signature TEXT    NOT NULL,
      FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE,
      FOREIGN KEY (author)    REFERENCES users(codename)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      token      TEXT    PRIMARY KEY,
      codename   TEXT    NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (codename) REFERENCES users(codename) ON DELETE CASCADE
    )
  `);

  // Rate limiting persistence table
  db.run(`
    CREATE TABLE IF NOT EXISTS rate_limits (
      key      TEXT    PRIMARY KEY,
      hits     INTEGER NOT NULL DEFAULT 0,
      reset_at INTEGER NOT NULL
    )
  `);

  // Cryptographic Likes/Dislikes table
  db.run(`
    CREATE TABLE IF NOT EXISTS votes (
      thread_id  TEXT    NOT NULL,
      codename   TEXT    NOT NULL,
      value      INTEGER NOT NULL,
      signature  TEXT    NOT NULL,
      PRIMARY KEY (thread_id, codename),
      FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE,
      FOREIGN KEY (codename) REFERENCES users(codename) ON DELETE CASCADE
    )
  `);

  // Moderation status tracking (bans, shadowbans)
  db.run(`
    CREATE TABLE IF NOT EXISTS moderation (
      codename   TEXT PRIMARY KEY,
      status     TEXT NOT NULL,
      reason     TEXT,
      created_at INTEGER NOT NULL,
      FOREIGN KEY (codename) REFERENCES users(codename) ON DELETE CASCADE
    )
  `);

  // Moderation warning history logs
  db.run(`
    CREATE TABLE IF NOT EXISTS warnings (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      codename   TEXT NOT NULL,
      reason     TEXT NOT NULL,
      timestamp  INTEGER NOT NULL,
      FOREIGN KEY (codename) REFERENCES users(codename) ON DELETE CASCADE
    )
  `);

  // Phase 3 Schema Additions (Fail-safe for existing tables)
  db.run("ALTER TABLE threads ADD COLUMN client_nonce TEXT", () => {});
  db.run("ALTER TABLE threads ADD COLUMN client_timestamp TEXT", () => {});
  db.run("ALTER TABLE threads ADD COLUMN signature_op TEXT", () => {});

  db.run("ALTER TABLE replies ADD COLUMN client_nonce TEXT", () => {});
  db.run("ALTER TABLE replies ADD COLUMN client_timestamp TEXT", () => {});
  db.run("ALTER TABLE replies ADD COLUMN signature_op TEXT", () => {});

  db.run("ALTER TABLE votes ADD COLUMN client_nonce TEXT", () => {});
  db.run("ALTER TABLE votes ADD COLUMN client_timestamp TEXT", () => {});
  db.run("ALTER TABLE votes ADD COLUMN signature_op TEXT", () => {});
});

// ─── Background Tasks ────────────────────────────────────────────────────────

// Session garbage collector (every hour)
setInterval(() => {
  db.run('DELETE FROM sessions WHERE expires_at < ?', [Date.now()]);
}, 60 * 60 * 1000).unref();

// ─── Data Access Object (DAO) ──────────────────────────────────────────────────

const DB = {
  get: (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (err, row) => err ? reject(err) : resolve(row))),
  all: (sql, params = []) => new Promise((resolve, reject) => db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows))),
  run: (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, function (err) { err ? reject(err) : resolve(this) }))
};

// ─── SQLite Rate-Limit Store (express-rate-limit v7 interface) ────────────────

class SQLiteStore {
  constructor(windowMs) {
    this.windowMs = windowMs;
  }

  async increment(key) {
    const now     = Date.now();
    const resetAt = now + this.windowMs;

    return new Promise((resolve, reject) => {
      db.get(`
        INSERT INTO rate_limits (key, hits, reset_at)
        VALUES (?, 1, ?)
        ON CONFLICT(key) DO UPDATE SET
          hits = CASE WHEN reset_at < ? THEN 1 ELSE hits + 1 END,
          reset_at = CASE WHEN reset_at < ? THEN ? ELSE reset_at END
        RETURNING hits, reset_at;
      `, [key, resetAt, now, now, resetAt], (err, row) => {
        if (err) return reject(err);
        resolve({ totalHits: row.hits, resetTime: new Date(row.reset_at) });
      });
    });
  }

  async decrement(key) {
    return new Promise((resolve) => {
      db.run('UPDATE rate_limits SET hits = MAX(0, hits - 1) WHERE key = ?', [key], () => resolve());
    });
  }

  async resetKey(key) {
    return new Promise((resolve) => {
      db.run('DELETE FROM rate_limits WHERE key = ?', [key], () => resolve());
    });
  }
}

// ─── Rate Limiters ────────────────────────────────────────────────────────────

const AUTH_WINDOW_MS  = 15 * 60 * 1000; // 15 min
const WRITE_WINDOW_MS = 60 * 1000;      //  1 min

const authLimiter = rateLimit({
  windowMs:             AUTH_WINDOW_MS,
  max:                  10,
  standardHeaders:      true,
  legacyHeaders:        false,
  store:                new SQLiteStore(AUTH_WINDOW_MS),
  keyGenerator:         (req) => `auth:${ipKeyGenerator(req)}`,
  message:              { error: 'RATE_LIMIT_EXCEEDED: Too many authentication attempts. Try again in 15 minutes.' },
  skipSuccessfulRequests: false,
});

const writeLimiter = rateLimit({
  windowMs:        WRITE_WINDOW_MS,
  max:             20,
  standardHeaders: true,
  legacyHeaders:   false,
  store:           new SQLiteStore(WRITE_WINDOW_MS),
  keyGenerator:    (req) => `write:${ipKeyGenerator(req)}`,
  message:         { error: 'RATE_LIMIT_EXCEEDED: Write throttle engaged.' },
});

// ─── Input Validators (pure functions, zero external deps) ────────────────────

const Validators = Object.freeze({
  codename:    (v) => typeof v === 'string' && /^[a-zA-Z0-9_\-]{3,20}$/.test(v),
  authKey:     (v) => typeof v === 'string' && /^[0-9a-f]{64}$/i.test(v),
  spkiBase64:  (v) => typeof v === 'string' && v.length >= 50 && v.length <= 400 && /^[A-Za-z0-9+/=]+$/.test(v),
  encKey:      (v) => typeof v === 'string' && v.includes(':') && v.length > 30 && v.length <= 4096,
  signature:   (v) => typeof v === 'string' && v.length > 30 && v.length <= 512,
  text:        (max) => (v) => typeof v === 'string' && v.trim().length > 0 && v.length <= max,
  category:    (v) => VALID_CATEGORIES.has(v),
  bio:         (v) => typeof v === 'string' && v.length <= 500,
  voteValue:   (v) => v === 1 || v === -1,
  nonce:       (v) => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v),
  client_timestamp: (v) => typeof v === 'string' && !isNaN(new Date(v).getTime()),
  captchaInput: (v) => typeof v === 'string' && /^[a-zA-Z0-9]{5}$/.test(v),
  captchaToken: (v) => typeof v === 'string' && v.includes(':') && v.split(':').length === 3,
  powSalt:      (v) => typeof v === 'string' && /^[0-9a-f]+$/i.test(v),
  powChallenge: (v) => typeof v === 'string' && /^[0-9a-f]{32}$/i.test(v),
});

/**
 * Middleware factory: validates req.body fields against a schema map.
 * Returns 400 with the offending field name on the first failure.
 */
const validate = (schema) => (req, res, next) => {
  for (const [field, check] of Object.entries(schema)) {
    if (!check(req.body[field])) {
      return res.status(400).json({ error: `Invalid or missing field: ${field}` });
    }
  }
  next();
};

// ─── Cryptographic Routines ───────────────────────────────────────────────────

/**
 * Hash and verification routines using Worker Threads for scrypt offloading.
 */
const HASH_WORKERS_COUNT = 4;
const hashWorkers = [];
let hashWorkerIdx = 0;
const reqMap = new Map();
let reqIdCounter = 0;

for (let i = 0; i < HASH_WORKERS_COUNT; i++) {
  const worker = new Worker(path.join(__dirname, 'server', 'workers', 'hash-worker.js'));
  worker.on('message', (msg) => {
    const { id, error, result } = msg;
    const pending = reqMap.get(id);
    if (pending) {
      reqMap.delete(id);
      if (error) pending.reject(new Error(error));
      else pending.resolve(result);
    }
  });
  hashWorkers.push(worker);
}

function runInWorker(action, payload) {
  return new Promise((resolve, reject) => {
    const id = ++reqIdCounter;
    reqMap.set(id, { resolve, reject });
    const worker = hashWorkers[hashWorkerIdx];
    hashWorkerIdx = (hashWorkerIdx + 1) % HASH_WORKERS_COUNT;
    worker.postMessage({ id, action, payload });
  });
}

function hashPassword(password) {
  return runInWorker('hash', { password });
}

function verifyPassword(password, storedHash) {
  return runInWorker('verify', { password, storedHash });
}

/**
 * Verifies ECDSA P-256/SHA-256 signature in IEEE P1363 raw format.
 * WebCrypto SubtleCrypto produces this format natively.
 */
function verifyECDSASignature(payload, signatureBase64, publicKeySPKIBase64) {
  try {
    const clean  = publicKeySPKIBase64.replace(/[\s\r\n]+/g, '');
    const pem    = `-----BEGIN PUBLIC KEY-----\n${clean.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
    const verify = crypto.createVerify('SHA256');
    verify.update(payload, 'utf8');
    verify.end();
    return verify.verify(
      { key: pem, format: 'pem', type: 'spki', dsaEncoding: 'ieee-p1363' },
      Buffer.from(signatureBase64, 'base64')
    );
  } catch {
    return false;
  }
}

// ─── Freshness Protocol (Replay & Drift Defense) ──────────────────────────────
const usedNonces = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [nonce, ts] of usedNonces.entries()) {
    if (now - ts > 5 * 60 * 1000) usedNonces.delete(nonce); // 5 min memory
  }
}, 60000).unref();

function validateFreshness(nonce, timestamp) {
  if (usedNonces.has(nonce)) return false;
  const ts = new Date(timestamp).getTime();
  if (isNaN(ts) || Math.abs(Date.now() - ts) > 5 * 60 * 1000) return false;
  usedNonces.set(nonce, ts);
  return true;
}

// ─── Session Middleware ───────────────────────────────────────────────────────

function authenticateToken(req, res, next) {
  const cookies = req.headers.cookie ? Object.fromEntries(req.headers.cookie.split('; ').map(c => c.split('='))) : {};
  const header = req.headers['authorization'];
  const token  = cookies.token || (header?.startsWith('Bearer ') ? header.slice(7) : null);
  if (!token) return res.status(401).json({ error: 'Authentication required.' });

  db.get(
    'SELECT s.codename, s.expires_at, m.status FROM sessions s LEFT JOIN moderation m ON s.codename = m.codename WHERE s.token = ?',
    [token],
    (err, session) => {
      if (err || !session) return res.status(403).json({ error: 'Invalid session.' });
      if (Date.now() > session.expires_at) {
        db.run('DELETE FROM sessions WHERE token = ?', [token]);
        return res.status(403).json({ error: 'Session expired. Re-authenticate.' });
      }
      if (session.status === 'BANNED') {
        db.run('DELETE FROM sessions WHERE token = ?', [token]);
        return res.status(403).json({ error: 'Access denied. Account is banned.' });
      }
      req.userCodename = session.codename;
      // Async update last_seen activity timestamp
      db.run('UPDATE users SET last_seen = ? WHERE codename = ?', [Date.now(), session.codename]);
      next();
    }
  );
}

function requireCommander(req, res, next) {
  const cookies = req.headers.cookie ? Object.fromEntries(req.headers.cookie.split('; ').map(c => c.split('='))) : {};
  const header = req.headers['authorization'];
  const token  = cookies.token || (header?.startsWith('Bearer ') ? header.slice(7) : null);
  if (!token) return res.status(401).json({ error: 'Authentication required.' });

  db.get(
    'SELECT s.codename, s.expires_at, u.role FROM sessions s JOIN users u ON s.codename = u.codename WHERE s.token = ?',
    [token],
    (err, session) => {
      if (err || !session) return res.status(403).json({ error: 'Invalid session.' });
      if (Date.now() > session.expires_at) {
        db.run('DELETE FROM sessions WHERE token = ?', [token]);
        return res.status(403).json({ error: 'Session expired. Re-authenticate.' });
      }
      if (session.role !== 'COMMANDER') {
        return res.status(403).json({ error: 'Action restricted to Commanders.' });
      }
      req.userCodename = session.codename;
      next();
    }
  );
}

function optionalAuthenticateToken(req, res, next) {
  const cookies = req.headers.cookie ? Object.fromEntries(req.headers.cookie.split('; ').map(c => c.split('='))) : {};
  const header = req.headers['authorization'];
  const token  = cookies.token || (header?.startsWith('Bearer ') ? header.slice(7) : null);
  if (!token) {
    req.userCodename = null;
    return next();
  }
  db.get(
    'SELECT codename, expires_at FROM sessions WHERE token = ?',
    [token],
    (err, session) => {
      if (err || !session || Date.now() > session.expires_at) {
        req.userCodename = null;
      } else {
        req.userCodename = session.codename;
      }
      next();
    }
  );
}

// ─── Express Application ──────────────────────────────────────────────────────

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      if (process.env.NODE_ENV !== 'production') return callback(null, true);
      if (!origin || origin === ALLOWED_ORIGIN) return callback(null, true);
      return callback(new Error('CORS_POLICY_VIOLATION'));
    },
    methods: ["GET", "POST"]
  },
  maxHttpBufferSize: 5000 // 5KB max payload to prevent ZD-002 DoS
});

const activeSockets = new Map(); // codename -> Set of socket.ids

// Socket.io Handshake Authentication Middleware
io.use((socket, next) => {
  const cookieStr = socket.handshake.headers.cookie;
  const cookies = cookieStr ? Object.fromEntries(cookieStr.split('; ').map(c => c.split('='))) : {};
  const token = cookies.token || socket.handshake.auth.token;

  if (!token) return next(new Error('Authentication required.'));

  db.get(
    'SELECT codename, expires_at FROM sessions WHERE token = ?',
    [token],
    (err, session) => {
      if (err || !session) return next(new Error('Invalid session.'));
      if (Date.now() > session.expires_at) {
        db.run('DELETE FROM sessions WHERE token = ?', [token]);
        return next(new Error('Session expired.'));
      }
      socket.codename = session.codename;
      next();
    }
  );
});

// Active Socket Session Validator (Heartbeat)
setInterval(() => {
  if (activeSockets.size === 0) return;
  const codenames = Array.from(activeSockets.keys());
  const placeholders = codenames.map(() => '?').join(',');
  db.all(`SELECT codename FROM sessions WHERE codename IN (${placeholders}) AND expires_at > ?`, [...codenames, Date.now()], (err, rows) => {
    if (err) return;
    const validCodenames = new Set(rows.map(r => r.codename));
    for (const [codename, sockets] of activeSockets.entries()) {
      if (!validCodenames.has(codename)) {
        for (const sid of sockets) {
          const s = io.sockets.sockets.get(sid);
          if (s) s.disconnect(true);
        }
      }
    }
  });
}, 30000).unref();

io.on('connection', (socket) => {
  const codename = socket.codename;
  const isNewConnection = !activeSockets.has(codename);
  if (isNewConnection) {
    activeSockets.set(codename, new Set());
  }
  activeSockets.get(codename).add(socket.id);

  // Send full presence strictly to the connecting client
  db.all('SELECT codename, role, last_seen FROM users ORDER BY codename ASC', [], (err, rows) => {
    if (err) return;
    const presence = rows.map((u) => ({
      codename:  u.codename,
      role:      u.role,
      last_seen: u.last_seen,
      isOnline:  activeSockets.has(u.codename)
    }));
    socket.emit('presence-full', presence);
  });

  if (isNewConnection) {
    socket.broadcast.emit('presence:join', { codename });
  }

  db.run('UPDATE users SET last_seen = ? WHERE codename = ?', [Date.now(), codename]);

  // Telemetry Ping/Pong
  socket.on('ping', (timestamp, callback) => {
    if (typeof callback === 'function') callback(timestamp);
  });

  socket.on('disconnect', () => {
    const userSockets = activeSockets.get(codename);
    if (userSockets) {
      userSockets.delete(socket.id);
      if (userSockets.size === 0) {
        activeSockets.delete(codename);
        io.emit('presence:leave', { codename });
      }
    }
  });
});

// Path Traversal Mitigation — Global Gateway Filter
app.use((req, res, next) => {
  try {
    const decodedPath = decodeURIComponent(req.path);
    const decodedUrl  = decodeURIComponent(req.originalUrl);
    if (
      req.path.includes('..') ||
      req.originalUrl.includes('..') ||
      decodedPath.includes('..') ||
      decodedUrl.includes('..')
    ) {
      return res.status(400).json({ error: 'PATH_TRAVERSAL_DETECTED' });
    }
  } catch {
    return res.status(400).json({ error: 'INVALID_URI_ENCODING' });
  }
  next();
});

// 1. Security headers via Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:              ["'self'"],
      scriptSrc:               [
        "'self'",
        "https://static.cloudflareinsights.com",
        "https://cdn.jsdelivr.net",
        "'sha256-F6byk77cNxVzF4x4WJQiR7zH3D2ygGKe08AyULi3+mc='", // CF Web Analytics inline v1
        "'sha256-YoblW/D7Cyj5UvFJEEIU/p9tEmLkKTTJCNus6agifSI='", // CF Web Analytics inline v2
        "'sha256-BRHOS8D1IywhhZad5Q33iZTCKOy5HTNWiuGE7iMEtl0='", // CF Web Analytics inline v3
        "'sha256-hReOYIe3xZB7WQieCptTnLsGLtNdJXu59uAjmftfqSE='"  // CF Web Analytics inline v4
      ],
      styleSrc:                ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
      imgSrc:                  ["'self'", 'data:'],
      connectSrc:              ["'self'", "ws:", "wss:", "https://cloudflareinsights.com", "https://cdn.jsdelivr.net"],
      fontSrc:                 ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
      objectSrc:               ["'none'"],
      mediaSrc:                ["'none'"],
      frameSrc:                ["'none'"],
      baseUri:                 ["'self'"],
      formAction:              ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy:   { policy: 'strict-origin-when-cross-origin' },
  xContentTypeOptions: true,
  xFrameOptions:    { action: 'deny' },
  crossOriginEmbedderPolicy: false, // Avoid breaking Cloudflare Tunnel
}));

// 2. CORS — strict origin allowlist
app.use(cors({
  origin: (origin, callback) => {
    if (process.env.NODE_ENV !== 'production') return callback(null, true);
    // Allow requests with no origin (like direct browser navigation to index.html)
    if (!origin || origin === `https://${CLOUDFLARE_DOMAIN}`) return callback(null, true);
    return callback(new Error('CORS_POLICY_VIOLATION'));
  },
  methods:        ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials:    true,
  maxAge:         600,
}));

// 3. Body parsing with 50 KB hard cap
app.use(express.json({ limit: '50kb' }));

// 4. Static files — ONLY public/ directory (no-cache for instant development updates)
app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',
  index:    false,
  setHeaders: (res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  },
}));

// Root → index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Favicon fallback handler to prevent console clutter
app.get('/favicon.ico', (req, res) => {
  res.status(204).end();
});

// ─── API Routes ───────────────────────────────────────────────────────────────

// ── Auth: Captcha Challenge ──────────────────────────────────────────────────
app.get('/api/auth/captcha', (req, res) => {
  const text = captcha.generateCaptchaText();
  const svg = captcha.generateCaptchaSvg(text);
  const token = captcha.createCaptchaToken(text);
  const powChallenge = crypto.randomBytes(16).toString('hex');
  
  res.json({
    captchaSvg: Buffer.from(svg).toString('base64'),
    captchaToken: token,
    powChallenge,
    powDifficulty: captcha.POW_DIFFICULTY
  });
});

// ── Auth: Register ────────────────────────────────────────────────────────────
app.post('/api/auth/register',
  authLimiter,
  validate({
    codename:            Validators.codename,
    password:            Validators.authKey,
    publicKeySPKI:       Validators.spkiBase64,
    encryptedPrivateKey: Validators.encKey,
    captchaInput:        Validators.captchaInput,
    captchaToken:        Validators.captchaToken,
    powChallenge:        Validators.powChallenge,
    powSalt:             Validators.powSalt,
  }),
  async (req, res) => {
    const { 
      codename, 
      password, 
      publicKeySPKI, 
      encryptedPrivateKey, 
      email, 
      captchaInput, 
      captchaToken, 
      powChallenge, 
      powSalt 
    } = req.body;

    // Decoy honeypot check (only bots will fill it)
    if (email && email.trim() !== '') {
      return res.status(400).json({ error: 'Registration failed.' });
    }

    // Verify Captcha
    if (!captcha.verifyCaptcha(captchaToken, captchaInput)) {
      return res.status(400).json({ error: 'CAPTCHA verification failed.' });
    }

    // Verify Proof of Work
    if (!captcha.verifyPoW(powChallenge, powSalt)) {
      return res.status(400).json({ error: 'Proof of Work verification failed.' });
    }

    // Commander role is EXCLUSIVELY assigned by setup.js CLI — never via HTTP.
    if (codename.trim().toLowerCase() === 'noir') {
      return res.status(403).json({
        error: 'Commander registration via UI is not permitted. Use the server CLI (node setup.js --init-commander).',
      });
    }

    // Case-insensitive duplicate check
    db.get(
      'SELECT codename FROM users WHERE LOWER(codename) = ?',
      [codename.toLowerCase()],
      async (err, existing) => {
        if (err) return res.status(500).json({ error: 'Registration failed.' });
        if (existing) return res.status(409).json({ error: 'Codename already registered.' });

        try {
          const passwordHash = await hashPassword(password);
          const joinedDate   = new Date().toISOString().substring(0, 10);

          db.run(
            `INSERT INTO users (codename, password_hash, public_key_spki, encrypted_private_key, role, bio, joined_date)
             VALUES (?, ?, ?, ?, 'AGENT', 'INITIALIZED AGENT NODE.', ?)`,
            [codename, passwordHash, publicKeySPKI, encryptedPrivateKey, joinedDate],
            (insertErr) => {
              if (insertErr) return res.status(500).json({ error: 'Registration failed.' });
              res.status(201).json({ success: true });
            }
          );
        } catch {
          res.status(500).json({ error: 'Registration failed.' });
        }
      }
    );
  }
);

// ── Auth: Login ───────────────────────────────────────────────────────────────
app.post('/api/auth/login',
  authLimiter,
  validate({
    codename: Validators.codename,
    password: Validators.authKey,
  }),
  (req, res) => {
    const { codename, password } = req.body;

    db.get('SELECT u.*, m.status FROM users u LEFT JOIN moderation m ON u.codename = m.codename WHERE u.codename = ?', [codename], async (err, user) => {
      if (err || !user) {
        // Constant-time dummy scrypt to prevent user-enumeration via timing
        await verifyPassword(password, `v2:${'00'.repeat(32)}:${'00'.repeat(64)}`).catch(() => {});
        return res.status(401).json({ error: 'Authentication failed.' });
      }

      if (user.status === 'BANNED') {
        return res.status(403).json({ error: 'Authentication failed. This account has been banned.' });
      }

      try {
        const match = await verifyPassword(password, user.password_hash);
        if (!match) return res.status(401).json({ error: 'Authentication failed.' });

        const token    = crypto.randomBytes(32).toString('hex');
        const now      = Date.now();
        const expires  = now + 24 * 60 * 60 * 1000; // 24 h

        db.run(
          'INSERT INTO sessions (token, codename, created_at, expires_at) VALUES (?, ?, ?, ?)',
          [token, user.codename, now, expires],
          (sessErr) => {
            if (sessErr) return res.status(500).json({ error: 'Login failed.' });
            res.cookie('token', token, {
              httpOnly: true,
              secure: true,
              sameSite: 'Strict',
              maxAge: 24 * 60 * 60 * 1000 // 24 h
            });
            res.json({
              codename:            user.codename,
              role:                user.role,
              token,
              encryptedPrivateKey: user.encrypted_private_key,
            });
          }
        );
      } catch (err) {
        console.error('[LOGIN ERROR]', err);
        res.status(500).json({ error: 'Login failed.' });
      }
    });
  }
);

// ── Auth: Logout (server-side token revocation) ───────────────────────────────
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  const cookies = req.headers.cookie ? Object.fromEntries(req.headers.cookie.split('; ').map(c => c.split('='))) : {};
  const token = cookies.token || req.headers['authorization']?.slice(7);

  // ZD-004: Force engine.io socket disconnect
  const codename = req.userCodename;
  if (codename && activeSockets.has(codename)) {
    for (const socketId of activeSockets.get(codename)) {
      const targetSocket = io.sockets.sockets.get(socketId);
      if (targetSocket) targetSocket.disconnect(true);
    }
    activeSockets.delete(codename);
  }

  db.run('DELETE FROM sessions WHERE token = ?', [token], (err) => {
    res.clearCookie('token');
    if (err) return res.status(500).json({ error: 'Logout failed.' });
    res.json({ success: true });
  });
});

// ── Nodes (requires auth) ─────────────────────────────────────────────────────
app.get('/api/nodes', authenticateToken, (req, res) => {
  db.all('SELECT codename, joined_date, role FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to retrieve nodes.' });
    const nodes = rows.map((r) => ({
      codename: r.codename,
      role:     r.role,
      status:   activeSockets.has(r.codename) ? 'active' : 'offline',
    }));
    res.json(nodes);
  });
});

// ── User Profile (requires auth) ──────────────────────────────────────────────
app.get('/api/users/:codename', authenticateToken, (req, res) => {
  const { codename } = req.params;
  if (!Validators.codename(codename)) {
    return res.status(400).json({ error: 'Invalid codename format.' });
  }
  db.get(
    `SELECT codename, role, bio, joined_date, public_key_spki,
            (SELECT COALESCE(SUM(v.value), 0)
             FROM   votes v
             JOIN   threads t ON v.thread_id = t.id
             WHERE  t.author = users.codename) AS reputation
     FROM   users
     WHERE  codename = ?`,
    [codename],
    (err, row) => {
      // Homogeneous response — no differential between "not found" and "error"
      if (err || !row) return res.status(404).json({ error: 'Agent not found.' });
      res.json(row);
    }
  );
});

// ── Update Bio (requires auth) ────────────────────────────────────────────────
app.put('/api/profile',
  authenticateToken,
  validate({ bio: Validators.bio }),
  (req, res) => {
    db.run(
      'UPDATE users SET bio = ? WHERE codename = ?',
      [req.body.bio.trim(), req.userCodename],
      (err) => {
        if (err) return res.status(500).json({ error: 'Profile update failed.' });
        res.json({ success: true });
      }
    );
  }
);

app.get('/api/threads', optionalAuthenticateToken, (req, res) => {
  const { search, category, sort } = req.query;

  let query = `
    SELECT t.id, t.title, t.content, t.author, t.category, t.timestamp, t.signature,
           t.client_nonce, t.client_timestamp, t.signature_op,
           u.public_key_spki,
           (SELECT COUNT(*) FROM replies WHERE thread_id = t.id) AS reply_count,
           (SELECT COUNT(*) FROM votes WHERE thread_id = t.id AND value = 1) AS upvotes,
           (SELECT COUNT(*) FROM votes WHERE thread_id = t.id AND value = -1) AS downvotes,
           (SELECT COALESCE(SUM(value), 0) FROM votes WHERE thread_id = t.id) AS score
    FROM   threads t
    JOIN   users   u ON t.author = u.codename
  `;

  const conditions = [];
  const params = [];

  // Shadowban check: filter out threads from shadowbanned users unless requested by the author themselves
  if (req.userCodename) {
    conditions.push('(t.author = ? OR t.author NOT IN (SELECT codename FROM moderation WHERE status = "SHADOWBANNED"))');
    params.push(req.userCodename);
  } else {
    conditions.push('t.author NOT IN (SELECT codename FROM moderation WHERE status = "SHADOWBANNED")');
  }

  if (category) {
    conditions.push('t.category = ?');
    params.push(category);
  }

  if (search && typeof search === 'string') {
    conditions.push('(t.title LIKE ? OR t.content LIKE ?)');
    const searchTerm = `%${search}%`;
    params.push(searchTerm, searchTerm);
  }

  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }

  // Sorting logic
  if (sort === 'score') {
    query += ' ORDER BY score DESC, t.timestamp DESC';
  } else if (sort === 'replies') {
    query += ' ORDER BY reply_count DESC, t.timestamp DESC';
  } else {
    query += ' ORDER BY t.timestamp DESC';
  }

  db.all(query, params, (err, threads) => {
    if (err) return res.status(500).json({ error: 'Failed to retrieve threads.' });
    res.json(threads);
  });
});

// ── Threads: Create (requires auth + write rate limit) ────────────────────────
app.post('/api/threads',
  writeLimiter,
  authenticateToken,
  validate({
    title:     Validators.text(200),
    content:   Validators.text(10000),
    category:  Validators.category,
    signature: Validators.signature,
    nonce:     Validators.nonce,
    timestamp: Validators.client_timestamp,
  }),
  async (req, res) => {
    try {
      const { title, content, category, signature, nonce, timestamp } = req.body;

      if (!validateFreshness(nonce, timestamp)) {
        return res.status(400).json({ error: 'FRESHNESS_CHECK_FAILED: Payload expired or replayed.' });
      }

      const user = await DB.get('SELECT public_key_spki FROM users WHERE codename = ?', [req.userCodename]);
      if (!user) return res.status(404).json({ error: 'Author not found.' });

      const payloadObj = { op: 'create-thread', title, content, author: req.userCodename, nonce, timestamp };
      const payload = JSON.stringify(payloadObj, Object.keys(payloadObj).sort());
      
      if (!verifyECDSASignature(payload, signature, user.public_key_spki)) {
        return res.status(400).json({ error: 'CRYPTOGRAPHIC_SIGNATURE_MISMATCH: Signature verification failed.' });
      }

      const id = crypto.randomBytes(16).toString('hex');
      const serverTimestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

      await DB.run(
        'INSERT INTO threads (id, title, content, author, category, timestamp, upvotes, signature, client_nonce, client_timestamp, signature_op) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)',
        [id, title, content, req.userCodename, category, serverTimestamp, signature, nonce, timestamp, 'create-thread']
      );

      res.status(201).json({ success: true, id });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to create thread.' });
    }
  }
);

// ── Threads: Edit (requires auth + write rate limit) ──────────────────────────
app.put('/api/threads/:id',
  writeLimiter,
  authenticateToken,
  validate({
    title:     Validators.text(200),
    content:   Validators.text(10000),
    signature: Validators.signature,
    nonce:     Validators.nonce,
    timestamp: Validators.client_timestamp,
  }),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { title, content, signature, nonce, timestamp } = req.body;

      if (!validateFreshness(nonce, timestamp)) {
        return res.status(400).json({ error: 'FRESHNESS_CHECK_FAILED: Payload expired or replayed.' });
      }

      const thread = await DB.get('SELECT * FROM threads WHERE id = ?', [id]);
      if (!thread) return res.status(404).json({ error: 'Thread not found.' });

      const user = await DB.get('SELECT role, public_key_spki FROM users WHERE codename = ?', [req.userCodename]);
      if (!user) return res.status(403).json({ error: 'Access denied.' });

      const isOwner = thread.author.toLowerCase() === req.userCodename.toLowerCase();
      const isMod   = user.role === 'COMMANDER';
      if (!isOwner && !isMod) return res.status(403).json({ error: 'Access denied.' });

      const owner = await DB.get('SELECT public_key_spki FROM users WHERE codename = ?', [thread.author]);
      if (!owner) return res.status(404).json({ error: 'Thread author not found.' });

      const payloadObj = { op: 'edit-thread', threadId: id, title, content, author: thread.author, nonce, timestamp };
      const payload = JSON.stringify(payloadObj, Object.keys(payloadObj).sort());
      
      if (!verifyECDSASignature(payload, signature, owner.public_key_spki)) {
        return res.status(400).json({ error: 'CRYPTOGRAPHIC_SIGNATURE_MISMATCH.' });
      }

      await DB.run(
        'UPDATE threads SET title = ?, content = ?, signature = ?, client_nonce = ?, client_timestamp = ?, signature_op = ? WHERE id = ?',
        [title, content, signature, nonce, timestamp, 'edit-thread', id]
      );
      res.json({ success: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Update failed.' });
    }
  }
);

// ── Threads: Delete (requires auth) ──────────────────────────────────────────
app.delete('/api/threads/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const thread = await DB.get('SELECT * FROM threads WHERE id = ?', [id]);
    if (!thread) return res.status(404).json({ error: 'Thread not found.' });

    const user = await DB.get('SELECT role FROM users WHERE codename = ?', [req.userCodename]);
    if (!user) return res.status(403).json({ error: 'Access denied.' });

    const isOwner = thread.author.toLowerCase() === req.userCodename.toLowerCase();
    const isMod   = user.role === 'COMMANDER';
    if (!isOwner && !isMod) return res.status(403).json({ error: 'Access denied.' });

    await DB.run('DELETE FROM threads WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Delete failed.' });
  }
});

// ── Cryptographic Vote (Upvote/Downvote - requires auth) ──────────────────────
app.post('/api/threads/:id/vote',
  writeLimiter,
  authenticateToken,
  validate({
    value:     Validators.voteValue,
    signature: Validators.signature,
    nonce:     Validators.nonce,
    timestamp: Validators.client_timestamp,
  }),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { value, signature, nonce, timestamp } = req.body;

      if (!validateFreshness(nonce, timestamp)) {
        return res.status(400).json({ error: 'FRESHNESS_CHECK_FAILED: Payload expired or replayed.' });
      }

      const thread = await DB.get('SELECT id FROM threads WHERE id = ?', [id]);
      if (!thread) return res.status(404).json({ error: 'Thread not found.' });

      const user = await DB.get('SELECT public_key_spki FROM users WHERE codename = ?', [req.userCodename]);
      if (!user) return res.status(403).json({ error: 'Voter profile not found.' });

      const payloadObj = { op: 'vote', threadId: id, value, author: req.userCodename, nonce, timestamp };
      const payload = JSON.stringify(payloadObj, Object.keys(payloadObj).sort());

      const isValid = verifyECDSASignature(payload, signature, user.public_key_spki);
      if (!isValid) return res.status(400).json({ error: 'INVALID_SIGNATURE: Vote verification failed.' });

      await DB.run(
        `INSERT OR REPLACE INTO votes (thread_id, codename, value, signature, client_nonce, client_timestamp, signature_op)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [id, req.userCodename, value, signature, nonce, timestamp, 'vote']
      );
      res.json({ success: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Database error writing vote.' });
    }
  }
);

app.get('/api/threads/:id/replies', optionalAuthenticateToken, (req, res) => {
  const { id } = req.params;
  const user = req.userCodename || '';
  const query = `
    SELECT r.*, u.public_key_spki
    FROM   replies r
    JOIN   users   u ON r.author = u.codename
    WHERE  r.thread_id = ?
      AND  (r.author = ? OR r.author NOT IN (SELECT codename FROM moderation WHERE status = 'SHADOWBANNED'))
    ORDER BY r.timestamp ASC
  `;
  db.all(query, [id, user], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to retrieve replies.' });
    res.json(rows);
  });
});

// ── Replies: Create (requires auth + write rate limit) ───────────────────────
app.post('/api/threads/:id/replies',
  writeLimiter,
  authenticateToken,
  validate({
    content:   Validators.text(5000),
    signature: Validators.signature,
    nonce:     Validators.nonce,
    timestamp: Validators.client_timestamp,
  }),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { content, signature, nonce, timestamp } = req.body;

      if (!validateFreshness(nonce, timestamp)) {
        return res.status(400).json({ error: 'FRESHNESS_CHECK_FAILED: Payload expired or replayed.' });
      }

      const thread = await DB.get('SELECT id FROM threads WHERE id = ?', [id]);
      if (!thread) return res.status(404).json({ error: 'Thread not found.' });

      const user = await DB.get('SELECT public_key_spki FROM users WHERE codename = ?', [req.userCodename]);
      if (!user) return res.status(404).json({ error: 'Author not found.' });

      const payloadObj = { op: 'create-reply', threadId: id, content, author: req.userCodename, nonce, timestamp };
      const payload = JSON.stringify(payloadObj, Object.keys(payloadObj).sort());
      
      if (!verifyECDSASignature(payload, signature, user.public_key_spki)) {
        return res.status(400).json({ error: 'CRYPTOGRAPHIC_SIGNATURE_MISMATCH.' });
      }

      const serverTimestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
      await DB.run(
        'INSERT INTO replies (thread_id, content, author, timestamp, signature, client_nonce, client_timestamp, signature_op) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [id, content, req.userCodename, serverTimestamp, signature, nonce, timestamp, 'create-reply']
      );
      res.status(201).json({ success: true });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Failed to post reply.' });
    }
  }
);

// ── Replies: Delete (requires auth) ──────────────────────────────────────────
app.delete('/api/threads/:threadId/replies/:replyId', authenticateToken, (req, res) => {
  const { replyId } = req.params;

  db.get('SELECT * FROM replies WHERE id = ?', [replyId], (err, reply) => {
    if (err || !reply) return res.status(404).json({ error: 'Reply not found.' });

    db.get('SELECT role FROM users WHERE codename = ?', [req.userCodename], (userErr, user) => {
      if (userErr || !user) return res.status(403).json({ error: 'Access denied.' });
      const isOwner = reply.author.toLowerCase() === req.userCodename.toLowerCase();
      const isMod   = user.role === 'COMMANDER';
      if (!isOwner && !isMod) return res.status(403).json({ error: 'Access denied.' });

      db.run('DELETE FROM replies WHERE id = ?', [replyId], (delErr) => {
        if (delErr) return res.status(500).json({ error: 'Delete failed.' });
        res.json({ success: true });
      });
    });
  });
});

// ── Moderation: Ban User (requires COMMANDER) ──────────────────────────────────
app.post('/api/moderation/ban', requireCommander, (req, res) => {
  const { codename, status, reason } = req.body;
  if (!codename || !status) return res.status(400).json({ error: 'Missing codename or status.' });
  if (status !== 'BANNED' && status !== 'SHADOWBANNED') {
    return res.status(400).json({ error: 'Invalid status. Must be BANNED or SHADOWBANNED.' });
  }

  if (codename.toLowerCase() === req.userCodename.toLowerCase()) {
    return res.status(400).json({ error: 'Commanders cannot ban their own account.' });
  }

  const timestamp = Date.now();
  db.run(
    `INSERT INTO moderation (codename, status, reason, created_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(codename) DO UPDATE SET status = excluded.status, reason = excluded.reason, created_at = excluded.created_at`,
    [codename, status, reason || '', timestamp],
    (err) => {
      if (err) return res.status(500).json({ error: 'Failed to apply moderation action.' });
      
      // Invalidate banned user sessions and connection sockets
      if (status === 'BANNED') {
        db.run('DELETE FROM sessions WHERE codename = ?', [codename]);
        const targetSockets = activeSockets.get(codename) || [];
        targetSockets.forEach((sId) => {
          const s = io.sockets.sockets.get(sId);
          if (s) s.disconnect(true);
        });
        activeSockets.delete(codename);
      }
      
      res.json({ success: true, message: `User "${codename}" status set to "${status}" successfully.` });
    }
  );
});

// ── Moderation: Unban User (requires COMMANDER) ────────────────────────────────
app.post('/api/moderation/unban', requireCommander, (req, res) => {
  const { codename } = req.body;
  if (!codename) return res.status(400).json({ error: 'Missing codename.' });

  db.run('DELETE FROM moderation WHERE codename = ?', [codename], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to lift moderation action.' });
    res.json({ success: true, message: `Moderation status lifted for "${codename}".` });
  });
});

// ── Moderation: Warn User (requires COMMANDER) ──────────────────────────────────
app.post('/api/moderation/warn', requireCommander, (req, res) => {
  const { codename, reason } = req.body;
  if (!codename || !reason) return res.status(400).json({ error: 'Missing codename or reason.' });

  const timestamp = Date.now();
  db.run(
    'INSERT INTO warnings (codename, reason, timestamp) VALUES (?, ?, ?)',
    [codename, reason, timestamp],
    (err) => {
      if (err) return res.status(500).json({ error: 'Failed to issue warning.' });
      
      db.get('SELECT COUNT(*) as count FROM warnings WHERE codename = ?', [codename], (countErr, row) => {
        const count = row ? row.count : 0;
        res.json({ success: true, message: `Warning issued to "${codename}". Total warnings: ${count}.` });
      });
    }
  );
});

// ── Moderation: Purge User (requires COMMANDER) ────────────────────────────────
app.delete('/api/moderation/users/:codename', requireCommander, (req, res) => {
  const { codename } = req.params;
  
  if (codename.toLowerCase() === req.userCodename.toLowerCase()) {
    return res.status(400).json({ error: 'Commanders cannot purge their own account.' });
  }

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');
    db.run('DELETE FROM sessions WHERE codename = ?', [codename]);
    db.run('DELETE FROM votes WHERE codename = ?', [codename]);
    db.run('DELETE FROM replies WHERE author = ?', [codename]);
    db.run('DELETE FROM threads WHERE author = ?', [codename]);
    db.run('DELETE FROM warnings WHERE codename = ?', [codename]);
    db.run('DELETE FROM moderation WHERE codename = ?', [codename]);
    db.run('DELETE FROM users WHERE codename = ?', [codename], (err) => {
      if (err) {
        db.run('ROLLBACK');
        return res.status(500).json({ error: 'Atomic user purge failed.' });
      }
      db.run('COMMIT', (commitErr) => {
        if (commitErr) {
          return res.status(500).json({ error: 'Failed to commit transaction.' });
        }
        
        // Invalidate active sockets
        const targetSockets = activeSockets.get(codename) || [];
        targetSockets.forEach((sId) => {
          const s = io.sockets.sockets.get(sId);
          if (s) s.disconnect(true);
        });
        activeSockets.delete(codename);
        
        res.json({ success: true, message: `User "${codename}" and all associated data purged successfully.` });
      });
    });
  });
});

// ─── Error Handlers ───────────────────────────────────────────────────────────

// Sanitize JSON body-parser errors (prevents Windows path disclosure)
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid request body format.' });
  }
  next(err);
});

// 404 catch-all for unknown routes
app.use((_req, res) => {
  res.status(404).json({ error: 'Not Found.' });
});

// Global error handler — never expose stack traces or internal paths
app.use((err, req, res, _next) => {
  const requestId = crypto.randomBytes(4).toString('hex');
  console.error(`[${new Date().toISOString()}] [ERR:${requestId}]`, err.stack ?? err.message);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Internal server error.', requestId });
});

// ─── Graceful Shutdown ─────────────────────────────────────────────────────────

function gracefulShutdown(signal) {
  console.log(`\n[C2] ${signal} received — shutting down gracefully...`);
  io.close(() => console.log('[C2] Socket.IO closed'));
  server.close(() => {
    db.close((err) => {
      if (err) console.error('[C2] DB close error:', err.message);
      else console.log('[C2] SQLite closed');
      process.exit(0);
    });
  });
  setTimeout(() => {
    console.error('[C2] Forced exit after timeout');
    process.exit(1);
  }, 5000).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

// ─── Bind ─────────────────────────────────────────────────────────────────────

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[C2] Secure server on port ${PORT} (${NODE_ENV}) → ${ALLOWED_ORIGIN}`);
});
