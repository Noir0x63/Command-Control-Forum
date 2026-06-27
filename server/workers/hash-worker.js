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
        const buf1 = Buffer.from(key, 'hex');
        const buf2 = dk;
        if (buf1.length !== buf2.length) return parentPort.postMessage({ id, result: false });
        parentPort.postMessage({ id, result: crypto.timingSafeEqual(buf1, buf2) });
      });
    }
  } catch (err) {
    parentPort.postMessage({ id, error: err.message });
  }
});
