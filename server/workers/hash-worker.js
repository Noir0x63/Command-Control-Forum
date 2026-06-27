'use strict';

const { parentPort } = require('worker_threads');
const crypto = require('crypto');

// Security-grade scrypt parameters
const SCRYPT_PARAMS = Object.freeze({ N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
const SCRYPT_KEY_LEN = 64;
const HASH_VERSION = 'v2';

parentPort.on('message', async (msg) => {
  const { id, action, payload } = msg;
  try {
    if (action === 'hash') {
      const { password } = payload;
      const salt = crypto.randomBytes(32).toString('hex');
      crypto.scrypt(password, salt, SCRYPT_KEY_LEN, SCRYPT_PARAMS, (err, dk) => {
        if (err) return parentPort.postMessage({ id, error: err.message });
        parentPort.postMessage({ id, result: `${HASH_VERSION}:${salt}:${dk.toString('hex')}` });
      });
    } else if (action === 'verify') {
      const { password, storedHash } = payload;
      const parts = storedHash.split(':');
      let version, salt, key;
      
      if (parts.length === 3) {
        [version, salt, key] = parts;
      } else if (parts.length === 2) {
        version = 'v1';
        [salt, key] = parts;
      } else {
        return parentPort.postMessage({ id, result: false });
      }

      const params = version === 'v2' ? SCRYPT_PARAMS : { N: 16384, r: 8, p: 1 };
      crypto.scrypt(password, salt, SCRYPT_KEY_LEN, params, (err, dk) => {
        if (err) return parentPort.postMessage({ id, error: err.message });
        const storedBuf = Buffer.from(key, 'hex');
        const derivedBuf = dk;
        // Constant-time comparison even when lengths differ:
        // compute hash of both buffers first to avoid leaking length information
        const storedHash  = crypto.createHash('sha256').update(storedBuf).digest();
        const derivedHash = crypto.createHash('sha256').update(derivedBuf).digest();
        parentPort.postMessage({ id, result: crypto.timingSafeEqual(storedHash, derivedHash) });
      });
    }
  } catch (err) {
    parentPort.postMessage({ id, error: err.message });
  }
});
