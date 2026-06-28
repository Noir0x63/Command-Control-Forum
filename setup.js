#!/usr/bin/env node
/**
 * C2 Commander Bootstrap CLI — One-time initialization.
 *
 * This script is the ONLY way to create a COMMANDER account.
 * It runs exclusively on the server machine, never via HTTP.
 * Replicates client-side WebCrypto key derivation using Node native crypto.
 *
 * Usage: node setup.js --init-commander
 */
'use strict';

const readline = require('readline');
const {
  pbkdf2,
  createCipheriv,
  generateKeyPairSync,
  randomBytes,
  scrypt,
} = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const path    = require('path');
const fs      = require('fs');
require('dotenv').config();

// ─── Constants — must mirror app.js exactly ───────────────────────────────────

const DOMAIN            = process.env.CLOUDFLARE_DOMAIN ?? 'c2.secure.forum';
const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_KEY_LEN    = 32; // bytes → 256-bit keys
const SCRYPT_PARAMS     = { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
const SCRYPT_KEY_LEN    = 64;
const HASH_VERSION      = 'v2';

// ─── Guard ────────────────────────────────────────────────────────────────────

const flag = process.argv[2];
if (flag !== '--init-commander') {
  console.error('Usage: node setup.js --init-commander');
  process.exit(1);
}

// ─── Database ─────────────────────────────────────────────────────────────────

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new sqlite3.Database(path.join(dataDir, 'database.sqlite'), (err) => {
  if (err) { console.error('[FATAL] DB:', err.message); process.exit(1); }
});
db.run('PRAGMA foreign_keys=ON');
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    codename              TEXT PRIMARY KEY,
    password_hash         TEXT NOT NULL,
    public_key_spki       TEXT NOT NULL,
    encrypted_private_key TEXT,
    role                  TEXT NOT NULL DEFAULT 'AGENT',
    bio                   TEXT NOT NULL DEFAULT 'INITIALIZED AGENT NODE.',
    joined_date           TEXT NOT NULL
  )
`);

// ─── Interactive CLI ──────────────────────────────────────────────────────────

const IS_TTY = process.stdin.isTTY === true;

/**
 * On non-TTY environments (piped input), readline's rl.question() races with
 * the piped data causing premature EOF ("readline was closed").
 * Solution: when piped, read ALL lines up front, then serve them sequentially.
 */
const inputQueue = [];

/**
 * Populate inputQueue by reading all piped lines before interaction begins.
 * Returns a promise that resolves when stdin is fully buffered.
 */
let rl;

const bufferPipedInput = () =>
  new Promise((resolve) => {
    if (IS_TTY) {
      rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      return resolve();
    }
    rl = readline.createInterface({ input: process.stdin });
    rl.on('line', (line) => inputQueue.push(line));
    rl.on('close', resolve);
  });

const ask = (prompt) => {
  process.stdout.write(prompt);
  if (!IS_TTY) {
    const line = inputQueue.shift() ?? '';
    process.stdout.write(`${line}\n`);
    return Promise.resolve(line);
  }
  return new Promise((res) => rl.question('', res));
};

/**
 * Reads a secret from stdin.
 * TTY: masks characters with '*'.
 * Non-TTY: reads the next pre-buffered line.
 */
const askSecret = (prompt) => {
  process.stdout.write(prompt);
  if (!IS_TTY) {
    const line = inputQueue.shift() ?? '';
    process.stdout.write('**hidden**\n');
    return Promise.resolve(line);
  }

  return new Promise((resolve) => {
    rl.pause();
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buffer = '';

    const handler = (char) => {
      if (char === '\n' || char === '\r' || char === '\u0004') {
        stdin.setRawMode(false);
        stdin.removeListener('data', handler);
        stdin.pause();
        process.stdout.write('\n');
        rl.resume();
        resolve(buffer);
      } else if (char === '\u0003') {
        process.exit(0);
      } else if (char === '\u007f') {
        if (buffer.length > 0) {
          buffer = buffer.slice(0, -1);
          process.stdout.write('\b \b');
        }
      } else {
        buffer += char;
        process.stdout.write('*');
      }
    };
    stdin.on('data', handler);
  });
};

// ─── Crypto — mirrors WebCrypto deriveKeys() exactly ─────────────────────────

const pbkdf2Async = (password, salt, iterations, keyLen) =>
  new Promise((resolve, reject) => {
    pbkdf2(password, salt, iterations, keyLen, 'sha256', (err, dk) => {
      if (err) reject(err); else resolve(dk);
    });
  });

const scryptAsync = (password, salt) =>
  new Promise((resolve, reject) => {
    const rawSalt = randomBytes(32).toString('hex');
    scrypt(password, rawSalt, SCRYPT_KEY_LEN, SCRYPT_PARAMS, (err, dk) => {
      if (err) return reject(err);
      resolve(`${HASH_VERSION}:${rawSalt}:${dk.toString('hex')}`);
    });
  });

/**
 * Derives authKey and aesKeyBuf using PBKDF2-SHA256.
 * Salt format MUST match public/app.js CryptoEngine.deriveKeys() exactly:
 *   "${DOMAIN}:${codename.toLowerCase()}:auth:v2"
 *   "${DOMAIN}:${codename.toLowerCase()}:enc:v2"
 */
async function deriveKeys(passphrase, codename) {
  const name    = codename.toLowerCase();
  const authSalt = `${DOMAIN}:${name}:auth:v2`;
  const encSalt  = `${DOMAIN}:${name}:enc:v2`;

  const [authBuf, aesBuf] = await Promise.all([
    pbkdf2Async(passphrase, authSalt, PBKDF2_ITERATIONS, PBKDF2_KEY_LEN),
    pbkdf2Async(passphrase, encSalt,  PBKDF2_ITERATIONS, PBKDF2_KEY_LEN),
  ]);

  return {
    authKey:   authBuf.toString('hex'),
    aesKeyBuf: aesBuf,
  };
}

/**
 * Generates an ECDSA P-256 keypair using Node's native crypto.
 */
function generateKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    publicKeySPKI:    publicKey.export({ type: 'spki',  format: 'der' }).toString('base64'),
    privateKeyPKCS8:  privateKey.export({ type: 'pkcs8', format: 'der' }),
  };
}

/**
 * Encrypts the PKCS8 private key DER buffer with AES-256-GCM.
 * Output format MUST match WebCrypto encryptPrivateKey() output:
 *   "<iv-base64>:<ciphertext+authTag-base64>"
 * WebCrypto appends the 16-byte GCM auth tag to the ciphertext automatically.
 */
function encryptPrivateKey(privateKeyPKCS8, aesKeyBuf) {
  const iv      = randomBytes(12); // 96-bit IV for AES-GCM
  const cipher  = createCipheriv('aes-256-gcm', aesKeyBuf, iv);
  const encrypted = Buffer.concat([cipher.update(privateKeyPKCS8), cipher.final()]);
  const authTag   = cipher.getAuthTag(); // 16 bytes, appended to match WebCrypto

  return `${iv.toString('base64')}:${Buffer.concat([encrypted, authTag]).toString('base64')}`;
}

// ─── Bootstrap Flow ───────────────────────────────────────────────────────────

async function initCommander() {
  await bufferPipedInput();
  console.log('\n╔══════════════════════════════════════════╗');
  console.log('║   C2 — COMMANDER BOOTSTRAP CLI (v2)      ║');
  console.log('╚══════════════════════════════════════════╝\n');

  // Idempotency guard — abort if commander already exists
  const existing = await new Promise((resolve) => {
    db.get("SELECT codename FROM users WHERE role = 'COMMANDER'", [], (err, row) => resolve(row ?? null));
  });

  if (existing) {
    console.error(`[ABORT] Commander "${existing.codename}" is already initialized.`);
    console.error('[ABORT] To reinitialize: manually DELETE the record from data/database.sqlite, then re-run.');
    if (IS_TTY) rl.close();
    db.close(); process.exit(1);
  }

  console.log('[!] This runs ONCE. No UI registration of COMMANDER is possible after this.\n');

  const rawCodename = (await ask('Commander codename [Noir]: ')).trim();
  const codename    = rawCodename || 'Noir';

  const passphrase = await askSecret('Passphrase (hidden input): ');
  if (passphrase.length < 8) {
    console.error('\n[ERROR] Passphrase must be at least 8 characters.');
    if (IS_TTY) rl.close();
    db.close(); process.exit(1);
  }

  const confirm = await askSecret('Confirm passphrase (hidden input): ');
  if (passphrase !== confirm) {
    console.error('\n[ERROR] Passphrases do not match.');
    if (IS_TTY) rl.close();
    db.close(); process.exit(1);
  }

  if (IS_TTY) rl.close();

  console.log('\n[INFO] Deriving cryptographic material — please wait (~5–10 s)...');

  const { authKey, aesKeyBuf }             = await deriveKeys(passphrase, codename);
  const { publicKeySPKI, privateKeyPKCS8 } = generateKeyPair();
  const encryptedPrivateKey                = encryptPrivateKey(privateKeyPKCS8, aesKeyBuf);
  const passwordHash                       = await scryptAsync(authKey);
  const joinedDate                         = new Date().toISOString().substring(0, 10);

  await new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO users
         (codename, password_hash, public_key_spki, encrypted_private_key, role, status, bio, joined_date)
       VALUES (?, ?, ?, ?, 'COMMANDER', 'ACTIVE', 'COMMANDER NODE INITIALIZED.', ?)`,
      [codename, passwordHash, publicKeySPKI, encryptedPrivateKey, joinedDate],
      (err) => { if (err) reject(err); else resolve(); }
    );
  });

  console.log(`\n[OK] Commander "${codename}" initialized successfully.`);
  console.log('[OK] Log in from the forum UI with your passphrase.');
  console.log('[OK] Private key stored encrypted (AES-256-GCM, PBKDF2-600k).\n');

  db.close();
}

initCommander().catch((err) => {
  console.error('[FATAL]', err.message);
  db.close();
  process.exit(1);
});
