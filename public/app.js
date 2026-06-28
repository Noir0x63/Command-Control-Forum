/**
 * COMMAND & CONTROL (C2) — Application Controller
 * Security-by-Design 2026 Edition
 *
 * Crypto changes vs previous version:
 *  - PBKDF2 iterations: 50,000 → 600,000 (OWASP 2023 minimum for SHA-256)
 *  - Salt includes domain separator to prevent cross-context key reuse
 *    Old: codename + '_auth_salt'
 *    New: 'c2.secure.forum:' + codename.toLowerCase() + ':auth:v2'
 *
 * XSS changes:
 *  - All user-supplied text (title, content, author, bio) rendered via
 *    textContent or DOM API — never interpolated into innerHTML
 *  - escapeHtml regex typo fixed as secondary defense layer
 *
 * Auth changes:
 *  - logout() calls server-side token revocation endpoint
 *  - getUser() and upvote() include Authorization header
 */

'use strict';

const API_BASE = '/api';

// ─── Cryptographic Engine ─────────────────────────────────────────────────────

class CryptoEngine {
  static async generateKeyPair() {
    return window.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
  }

  /** Export public key as SPKI base64 string */
  static async exportPublicKey(publicKey) {
    const exported = await window.crypto.subtle.exportKey('spki', publicKey);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
  }

  /** Import SPKI base64 public key for verification */
  static async importPublicKey(spkiBase64) {
    const binary = atob(spkiBase64);
    const buffer = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return window.crypto.subtle.importKey(
      'spki',
      buffer.buffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );
  }

  /** Import PKCS8 base64 private key for signing */
  static async importPrivateKey(pkcs8Base64) {
    const binary = atob(pkcs8Base64);
    const buffer = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return window.crypto.subtle.importKey(
      'pkcs8',
      buffer.buffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign']
    );
  }

  /** Sign a message string — returns base64 signature (IEEE P1363) */
  static async signMessage(message, privateKey) {
    const data = new TextEncoder().encode(message);
    const sig  = await window.crypto.subtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      privateKey,
      data
    );
    return btoa(String.fromCharCode(...new Uint8Array(sig)));
  }

  /** Verify a base64 signature — returns boolean */
  static async verifyMessage(message, signatureBase64, publicKey) {
    try {
      const data = new TextEncoder().encode(message);
      const sig  = Uint8Array.from(atob(signatureBase64), (c) => c.charCodeAt(0));
      return window.crypto.subtle.verify(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        publicKey,
        sig,
        data
      );
    } catch {
      return false;
    }
  }

  /**
   * Derives authKey (hex string) and aesKey (CryptoKey) from the user's passphrase.
   *
   * PBKDF2 parameters — 2026-grade (OWASP 2023 minimum):
   *   Hash:       SHA-256
   *   Iterations: 600,000
   *   Salt:       domain-qualified, versioned, context-separated
   *
   * Salt format must stay in sync with setup.js:
   *   auth: "<DOMAIN>:<codename_lower>:auth:v2"
   *   enc:  "<DOMAIN>:<codename_lower>:enc:v2"
   */
  static async deriveKeys(passphrase, codename) {
    const DOMAIN     = window.location.hostname || 'c2.secure.forum';
    const ITERATIONS = 600_000;
    const encoder    = new TextEncoder();
    const name       = codename.toLowerCase();

    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey', 'deriveBits']
    );

    const authSalt = encoder.encode(`${DOMAIN}:${name}:auth:v2`);
    const encSalt  = encoder.encode(`${DOMAIN}:${name}:enc:v2`);

    const [authBits, aesKey] = await Promise.all([
      window.crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: authSalt, iterations: ITERATIONS, hash: 'SHA-256' },
        baseKey,
        256
      ),
      window.crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: encSalt, iterations: ITERATIONS, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      ),
    ]);

    const authKey = Array.from(new Uint8Array(authBits))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    return { authKey, aesKey };
  }

  /**
   * Encrypts the private key using AES-256-GCM.
   * Output: "<iv-base64>:<ciphertext+authTag-base64>"
   * (WebCrypto appends the 16-byte auth tag automatically)
   */
  static async encryptPrivateKey(privateKey, aesKey) {
    const exported  = await window.crypto.subtle.exportKey('pkcs8', privateKey);
    const iv        = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, exported);

    return `${btoa(String.fromCharCode(...iv))}:${btoa(String.fromCharCode(...new Uint8Array(encrypted)))}`;
  }

  /**
   * Decrypts the stored encrypted private key and imports it as a CryptoKey.
   */
  static async decryptPrivateKey(encryptedString, aesKey) {
    const [ivB64, ctB64] = encryptedString.split(':');
    const iv         = Uint8Array.from(atob(ivB64), (c) => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(ctB64),  (c) => c.charCodeAt(0));

    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      ciphertext
    );

    return window.crypto.subtle.importKey(
      'pkcs8',
      decrypted,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, // non-extractable to prevent XSS exfiltration!
      ['sign']
    );
  }
}

// ─── IndexedDB Keystore ───────────────────────────────────────────────────────

class IDBKeystore {
  static inMemoryDB = new Map();

  static async openDB() {
    if (typeof indexedDB === 'undefined') {
      throw new Error('IndexedDB not supported');
    }
    return new Promise((resolve, reject) => {
      try {
        const request = indexedDB.open('C2Keystore', 1);
        request.onupgradeneeded = () => request.result.createObjectStore('keys');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error('IndexedDB open error'));
      } catch (e) {
        reject(e);
      }
    });
  }

  static async setKey(name, cryptoKey) {
    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction('keys', 'readwrite');
        tx.objectStore('keys').put(cryptoKey, name);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch (e) {
      console.warn('[C2 Keystore] IndexedDB write failed, falling back to memory:', e);
      this.inMemoryDB.set(name, cryptoKey);
    }
  }

  static async getKey(name) {
    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction('keys', 'readonly');
        const req = tx.objectStore('keys').get(name);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    } catch (e) {
      console.warn('[C2 Keystore] IndexedDB read failed, falling back to memory:', e);
      return this.inMemoryDB.get(name) || null;
    }
  }

  static async clearKey(name) {
    try {
      const db = await this.openDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction('keys', 'readwrite');
        tx.objectStore('keys').delete(name);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch (e) {
      console.warn('[C2 Keystore] IndexedDB delete failed, falling back to memory:', e);
      this.inMemoryDB.delete(name);
    }
  }
}

// ─── REST API Service ─────────────────────────────────────────────────────────

class ApiService {
  #getAuthHeaders() {
    const token = localStorage.getItem('c2_auth_token');
    return token ? { 'Authorization': `Bearer ${token}` } : {};
  }

  async #fetchJSON(url, options = {}) {
    const res  = await fetch(url, options);
    const data = await res.json();
    if (!res.ok) {
      const err = new Error(data.error ?? `HTTP ${res.status}`);
      err.status = data.status;
      err.attempts_left = data.attempts_left;
      throw err;
    }
    return data;
  }

  getThreads(filters = {}) {
    const params = new URLSearchParams();
    if (filters.search) params.append('search', filters.search);
    if (filters.category) params.append('category', filters.category);
    if (filters.sort) params.append('sort', filters.sort);
    const queryStr = params.toString();
    const url = `${API_BASE}/threads${queryStr ? '?' + queryStr : ''}`;
    return this.#fetchJSON(url, {
      headers: this.#getAuthHeaders(),
    });
  }

  getReplies(threadId) {
    return this.#fetchJSON(`${API_BASE}/threads/${threadId}/replies`, {
      headers: this.#getAuthHeaders(),
    });
  }

  /** Requires auth — server enforces authenticateToken */
  getUser(codename) {
    return this.#fetchJSON(`${API_BASE}/users/${codename}`, {
      headers: this.#getAuthHeaders(),
    });
  }

  getCaptchaChallenge() {
    return this.#fetchJSON(`${API_BASE}/auth/captcha`);
  }

  register(registrationBody) {
    return this.#fetchJSON(`${API_BASE}/auth/register`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(registrationBody),
    });
  }

  login(codename, password) {
    return this.#fetchJSON(`${API_BASE}/auth/login`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ codename, password }),
    });
  }

  acceptTerms() {
    return this.#fetchJSON(`${API_BASE}/auth/terms/accept`, {
      method: 'POST',
      headers: this.#getAuthHeaders(),
    });
  }

  getGatekeeperChallenge() {
    return this.#fetchJSON(`${API_BASE}/auth/admission/challenge`, {
      headers: this.#getAuthHeaders(),
    });
  }

  evaluateGatekeeperChallenge(answers) {
    return this.#fetchJSON(`${API_BASE}/auth/admission/evaluate`, {
      method: 'POST',
      headers: { ...this.#getAuthHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ answers })
    });
  }

  /** Server-side token revocation */
  logout() {
    return this.#fetchJSON(`${API_BASE}/auth/logout`, {
      method:  'POST',
      headers: this.#getAuthHeaders(),
    }).catch(() => {}); // Best-effort; local state cleared regardless
  }

  createThread(title, content, category, signature, nonce, timestamp) {
    return this.#fetchJSON(`${API_BASE}/threads`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', ...this.#getAuthHeaders() },
      body:    JSON.stringify({ title, content, category, signature, nonce, timestamp }),
    });
  }

  updateThread(id, title, content, signature, nonce, timestamp) {
    return this.#fetchJSON(`${API_BASE}/threads/${id}`, {
      method:  'PUT',
      headers: { 'Content-Type': 'application/json', ...this.#getAuthHeaders() },
      body:    JSON.stringify({ title, content, signature, nonce, timestamp }),
    });
  }

  deleteThread(id) {
    return this.#fetchJSON(`${API_BASE}/threads/${id}`, {
      method:  'DELETE',
      headers: this.#getAuthHeaders(),
    });
  }

  /** Requires auth — server now enforces authenticateToken on upvote */
  vote(threadId, value, signature, nonce, timestamp) {
    return this.#fetchJSON(`${API_BASE}/threads/${threadId}/vote`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', ...this.#getAuthHeaders() },
      body:    JSON.stringify({ value, signature, nonce, timestamp }),
    });
  }

  createReply(threadId, content, signature, nonce, timestamp) {
    return this.#fetchJSON(`${API_BASE}/threads/${threadId}/replies`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', ...this.#getAuthHeaders() },
      body:    JSON.stringify({ content, signature, nonce, timestamp }),
    });
  }

  deleteReply(threadId, replyId) {
    return this.#fetchJSON(`${API_BASE}/threads/${threadId}/replies/${replyId}`, {
      method:  'DELETE',
      headers: this.#getAuthHeaders(),
    });
  }

  updateBio(bio) {
    return this.#fetchJSON(`${API_BASE}/profile`, {
      method:  'PUT',
      headers: { 'Content-Type': 'application/json', ...this.#getAuthHeaders() },
      body:    JSON.stringify({ bio }),
    });
  }

  banUser(codename, status, reason) {
    return this.#fetchJSON(`${API_BASE}/moderation/ban`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', ...this.#getAuthHeaders() },
      body:    JSON.stringify({ codename, status, reason }),
    });
  }

  unbanUser(codename) {
    return this.#fetchJSON(`${API_BASE}/moderation/unban`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', ...this.#getAuthHeaders() },
      body:    JSON.stringify({ codename }),
    });
  }

  warnUser(codename, reason) {
    return this.#fetchJSON(`${API_BASE}/moderation/warn`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', ...this.#getAuthHeaders() },
      body:    JSON.stringify({ codename, reason }),
    });
  }

  purgeUser(codename) {
    return this.#fetchJSON(`${API_BASE}/moderation/users/${codename}`, {
      method:  'DELETE',
      headers: this.#getAuthHeaders(),
    });
  }
}

// ─── Application State ────────────────────────────────────────────────────────

class AppState {
  #listeners = [];

  constructor(apiService) {
    this.api            = apiService;
    this.currentChannel = 'all';
    this.activeView     = 'feed';
    this.selectedThreadId = null;
    this.selectedProfileCodename = null;
    this.currentAgent   = localStorage.getItem('c2_auth_agent') ?? null;
    this.activePrivateKey = null;
    this.searchQuery    = '';
    this.sortCriteria   = 'recent';
    this.socket         = null;
    this.presenceList   = [];

    // Restore private key from IndexedDB to survive page refreshes
    IDBKeystore.getKey('c2_active_private_key').then((key) => {
      if (key) {
        console.log('[C2 Keystore] Key restored successfully from IndexedDB.');
        this.activePrivateKey = key;
        this.notify();
      }
    }).catch((err) => {
      console.error('[C2 Keystore] Failed to restore key from IndexedDB:', err);
    });

    // Initialize real-time presence socket connection
    this.initSocket();

    // SPA Router Setup
    window.addEventListener('popstate', (e) => {
      const st = e.state;
      if (st && st.view) {
        this.setView(st.view, st.threadId, false, st.profileCodename);
      } else {
        this.setView('feed', null, false);
      }
    });

    // Initial load state
    const params = new URLSearchParams(window.location.search);
    const initialView = params.get('view') || 'feed';
    const initialId = params.get('id') || null;
    const initialCodename = params.get('codename') || null;
    this.setView(initialView, initialId, true, initialCodename); // replace current state
  }

  subscribe(listener) { this.#listeners.push(listener); }
  notify()             { this.#listeners.forEach((fn) => fn(this)); }

  initSocket() {
    const token = localStorage.getItem('c2_auth_token');
    if (!token) {
      if (this.socket) {
        console.log('[C2 Socket] Revoking socket session. Disconnecting...');
        this.socket.disconnect();
        this.socket = null;
      }
      this.presenceList = [];
      if (this.pingInterval) clearInterval(this.pingInterval);
      return;
    }

    if (this.socket) {
      return; // Connection already active or in progress
    }

    console.log('[C2 Socket] Initializing secure WebSocket channel...');
    this.socket = io({
      withCredentials: true // allows cookies to be sent
    });

    this.socket.on('presence-full', (presence) => {
      console.log('[C2 Socket] Full presence snapshot received.');
      this.presenceList = presence;
      this.notify();
    });

    this.socket.on('presence:join', ({ codename }) => {
      console.log(`[C2 Socket] Node joined: ${codename}`);
      const user = this.presenceList.find(u => u.codename === codename);
      if (user) user.isOnline = true;
      else this.presenceList.push({ codename, isOnline: true });
      this.notify();
    });

    this.socket.on('presence:leave', ({ codename }) => {
      console.log(`[C2 Socket] Node left: ${codename}`);
      const user = this.presenceList.find(u => u.codename === codename);
      if (user) user.isOnline = false;
      this.notify();
    });

    this.socket.on('connect_error', (err) => {
      console.warn('[C2 Socket] Connection handshake failed:', err.message);
    });

    if (this.pingInterval) clearInterval(this.pingInterval);
    this.pingInterval = setInterval(() => {
      if (this.socket && this.socket.connected) {
        const start = Date.now();
        this.socket.emit('ping', start, (echo) => {
          this.latencyMs = Date.now() - echo;
          this.notify();
        });
      }
    }, 10000);
  }

  setChannel(channel) {
    this.currentChannel = channel;
    this.activeView     = 'feed';
    this.notify();
  }

  setView(view, threadId = null, pushState = true, profileCodename = null) {
    this.activeView     = view;
    this.selectedThreadId = threadId;
    this.selectedProfileCodename = profileCodename || (view === 'profile' ? this.currentAgent : null);
    
    if (pushState) {
      const profileQuery = this.selectedProfileCodename ? `&codename=${this.selectedProfileCodename}` : '';
      const url = view === 'feed' ? '/' : `/?view=${view}${threadId ? '&id=' + threadId : ''}${profileQuery}`;
      if (!window.history.state) {
        window.history.replaceState({ view, threadId, profileCodename: this.selectedProfileCodename }, '', url);
      } else {
        window.history.pushState({ view, threadId, profileCodename: this.selectedProfileCodename }, '', url);
      }
    }
    
    this.notify();
  }

  setSearch(query) {
    this.searchQuery = query;
    this.notify();
  }

  setSort(sort) {
    this.sortCriteria = sort;
    this.notify();
  }

  async register(codename, passphrase, captchaInput, captchaToken, powChallenge, powSalt, registerBody, hpToken, captchaIssuedAt) {
    if (codename.length < 3) throw new Error('Codename too short.');

    const keyPair   = await CryptoEngine.generateKeyPair();
    const pubSPKI   = await CryptoEngine.exportPublicKey(keyPair.publicKey);
    const { authKey, aesKey } = await CryptoEngine.deriveKeys(passphrase, codename);
    const encPriv   = await CryptoEngine.encryptPrivateKey(keyPair.privateKey, aesKey);

    await this.api.register({
      codename,
      password: authKey,
      publicKeySPKI: pubSPKI,
      encryptedPrivateKey: encPriv,
      captchaInput,
      captchaToken,
      powChallenge,
      powSalt,
      hpToken,
      captchaIssuedAt,
      ...registerBody,
    });
    return await this.login(codename, passphrase);
  }

  async login(codename, passphrase) {
    console.log('[C2 Auth] Attempting login key derivation...');
    const { authKey, aesKey } = await CryptoEngine.deriveKeys(passphrase, codename);
    console.log('[C2 Auth] Keys derived. Authenticating with backend...');
    const data = await this.api.login(codename, authKey);
    console.log('[C2 Auth] Authentication successful. Session token received.');

    this.currentAgent = data.codename;
    localStorage.setItem('c2_auth_agent', data.codename);
    localStorage.setItem('c2_auth_token', data.token);

    if (data.encryptedPrivateKey) {
      console.log('[C2 Keystore] Encrypted key present. Attempting decryption...');
      try {
        this.activePrivateKey = await CryptoEngine.decryptPrivateKey(data.encryptedPrivateKey, aesKey);
        
        // Save non-extractable private key directly in IndexedDB via Structured Clone
        await IDBKeystore.setKey('c2_active_private_key', this.activePrivateKey);
        console.log('[C2 Keystore] Decryption successful. Keystore UNLOCKED.');
      } catch (decErr) {
        console.error('[C2 Keystore] Decryption failed. Incorrect passphrase or corrupted payload:', decErr);
        throw new Error('Key decryption failed. Check your passphrase.');
      }
    } else {
      console.warn('[C2 Keystore] No encrypted private key returned from server.');
    }

    if (data.status === 'PENDING_ADMISSION') {
      console.log('[C2 Auth] Agent pending admission. Launching Gatekeeper protocol.');
      this.notify();
      return 'PENDING_ADMISSION';
    }

    this.initSocket();
    this.notify();
    return 'ACTIVE';
  }

  async logout() {
    // Revoke token on server (best-effort), then clear local state
    try {
      await this.api.logout();
    } catch (e) {
      console.warn('[C2 Auth] Server-side logout failed:', e);
    }
    this.currentAgent     = null;
    this.activePrivateKey = null;
    localStorage.removeItem('c2_auth_agent');
    localStorage.removeItem('c2_auth_token');
    await IDBKeystore.clearKey('c2_active_private_key');
    this.initSocket();
    this.notify();
  }

  async publishThread(title, category, content) {
    if (!this.currentAgent || !this.activePrivateKey) {
      throw new Error('Access denied. Session is locked.');
    }
    const nonce = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    const payloadObj = { op: 'create-thread', title, content, author: this.currentAgent, nonce, timestamp };
    const payload = JSON.stringify(payloadObj, Object.keys(payloadObj).sort());
    
    const signature = await CryptoEngine.signMessage(payload, this.activePrivateKey);
    await this.api.createThread(title, content, category, signature, nonce, timestamp);
    this.setView('feed');
  }

  async updateThread(id, title, content) {
    const threads = await this.api.getThreads();
    const thread  = threads.find((t) => t.id === id);
    if (!thread) return;
    if (!this.activePrivateKey) throw new Error('Signature key required.');

    const nonce = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    const payloadObj = { op: 'edit-thread', threadId: id, title, content, author: thread.author, nonce, timestamp };
    const payload = JSON.stringify(payloadObj, Object.keys(payloadObj).sort());

    const signature = await CryptoEngine.signMessage(payload, this.activePrivateKey);
    await this.api.updateThread(id, title, content, signature, nonce, timestamp);
    this.notify();
  }

  async deleteThread(id) {
    await this.api.deleteThread(id);
    this.setView('feed');
  }

  async publishReply(content) {
    if (!this.selectedThreadId || !this.currentAgent || !this.activePrivateKey) {
      throw new Error('Signature key unavailable.');
    }
    const nonce = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    const payloadObj = { op: 'create-reply', threadId: this.selectedThreadId, content, author: this.currentAgent, nonce, timestamp };
    const payload = JSON.stringify(payloadObj, Object.keys(payloadObj).sort());

    const signature = await CryptoEngine.signMessage(payload, this.activePrivateKey);
    await this.api.createReply(this.selectedThreadId, content, signature, nonce, timestamp);
    this.notify();
  }

  async deleteReply(replyId) {
    if (!this.selectedThreadId) return;
    await this.api.deleteReply(this.selectedThreadId, replyId);
    this.notify();
  }

  async vote(threadId, value) {
    if (!this.currentAgent || !this.activePrivateKey) {
      throw new Error('Voting failed. Login required.');
    }
    const nonce = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    const payloadObj = { op: 'vote', threadId, value, author: this.currentAgent, nonce, timestamp };
    const payload = JSON.stringify(payloadObj, Object.keys(payloadObj).sort());

    const signature = await CryptoEngine.signMessage(payload, this.activePrivateKey);
    await this.api.vote(threadId, value, signature, nonce, timestamp);
    this.notify();
  }

  async updateProfileBio(bio) {
    await this.api.updateBio(bio);
    this.notify();
  }

  async banAgent(codename, status, reason) {
    const res = await this.api.banUser(codename, status, reason);
    this.notify();
    return res;
  }

  async unbanAgent(codename) {
    const res = await this.api.unbanUser(codename);
    this.notify();
    return res;
  }

  async warnAgent(codename, reason) {
    const res = await this.api.warnUser(codename, reason);
    this.notify();
    return res;
  }

  async purgeAgent(codename) {
    const res = await this.api.purgeUser(codename);
    this.notify();
    return res;
  }
}

// ─── DOM Utility Helpers ──────────────────────────────────────────────────────

/**
 * Creates a DOM element with optional text content and attributes.
 * Using textContent instead of innerHTML for user-supplied data is XSS-safe
 * by specification — the browser never parses text as markup.
 */
function el(tag, text, attrs = {}) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = text;
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  return node;
}

/**
 * Renders Markdown and LaTeX equations securely using Marked and KaTeX.
 * Prevents DOM-based XSS by running DOMPurify.sanitize after Markdown parsing,
 * and then renders math in the safe DOM fragment.
 */
function renderFormattedContent(text) {
  if (typeof text !== 'string') return document.createElement('div');

  // Configure marked options
  if (typeof marked !== 'undefined' && marked.use) {
    marked.use({ breaks: true, gfm: true });
  }

  // 1. Convert Markdown to HTML
  let rawHtml = '';
  if (typeof marked !== 'undefined' && marked.parse) {
    rawHtml = marked.parse(text);
  } else {
    // Fallback if marked library fails to load
    rawHtml = escapeHtml(text).replace(/\n/g, '<br>');
  }

  // 2. Sanitize HTML using DOMPurify
  let cleanHtml = '';
  if (typeof DOMPurify !== 'undefined' && DOMPurify.sanitize) {
    cleanHtml = DOMPurify.sanitize(rawHtml, {
      ALLOWED_TAGS: [
        'p', 'br', 'strong', 'em', 'del', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'code', 'pre', 'blockquote', 'hr', 'a'
      ],
      ALLOWED_ATTR: ['href', 'title', 'target', 'class']
    });
  } else {
    // Fallback if DOMPurify fails to load: escape everything
    cleanHtml = escapeHtml(text).replace(/\n/g, '<br>');
  }

  const container = document.createElement('div');
  container.innerHTML = cleanHtml;

  // 2.5. Render syntax highlighting using Highlight.js
  if (typeof hljs !== 'undefined') {
    try {
      container.querySelectorAll('pre code').forEach((block) => {
        hljs.highlightElement(block);
      });
    } catch (hljsErr) {
      console.error('[C2 HighlightJS] Highlighting error:', hljsErr);
    }
  }

  // 3. Render LaTeX formulas using KaTeX auto-render extension
  if (typeof renderMathInElement !== 'undefined') {
    try {
      renderMathInElement(container, {
        delimiters: [
          { left: '$$', right: '$$', display: true },
          { left: '$', right: '$', display: false },
          { left: '\\(', right: '\\)', display: false },
          { left: '\\[', right: '\\]', display: true }
        ],
        throwOnError: false
      });
    } catch (err) {
      console.error('[C2 KaTeX] Rendering error:', err);
    }
  }

  return container;
}

/**
 * Creates a verification badge element (content is controlled, not user data).
 */
function verificationBadge(isVerified) {
  const span = document.createElement('span');
  span.className = `integrity-badge ${isVerified ? 'verified' : 'compromised'}`;
  span.textContent = isVerified ? '[SIGNATURE: VERIFIED]' : '[SIGNATURE: COMPROMISED]';
  return span;
}

/**
 * Secondary XSS defense: HTML-escape for any remaining innerHTML usages.
 * Primary defense is textContent / DOM API above.
 * Bug fixed: /\<,g/ → /</g
 */
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')   // Fixed: was /<,g/ (invalid regex — escaped nothing)
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#039;');
}

// ─── UI Controller ────────────────────────────────────────────────────────────

class UIController {
  constructor(state, api) {
    this.state = state;
    this.api   = api;

    // Cached DOM references
    this.elThreadFeed      = document.getElementById('thread-feed');
    this.elThreadDetailOP  = document.getElementById('thread-detail-op');
    this.elDetailThreadId  = document.getElementById('detail-thread-id');
    this.elCommentsList    = document.getElementById('comments-list');

    this.secFeed    = document.getElementById('feed-view');
    this.secDetail  = document.getElementById('thread-view');
    this.secCreate  = document.getElementById('create-view');
    this.secProfile = document.getElementById('profile-view');

    this.btnNavFeed      = document.getElementById('nav-btn-feed');
    this.btnNavAdmission = document.getElementById('nav-btn-admission');
    this.btnNavProfile   = document.getElementById('nav-btn-profile');
    this.btnLogin        = document.getElementById('btn-login');
    this.btnNewThread    = document.getElementById('btn-new-thread');
    this.btnBackFeed     = document.getElementById('btn-back-feed');
    this.btnCancelCreate = document.getElementById('btn-cancel-create');
    this.btnBackProfile  = document.getElementById('btn-close-profile');
    this.btnRegisterToggle = document.getElementById('toggle-auth-register');
    this.btnLoginToggle    = document.getElementById('toggle-auth-login');
    this.btnCloseLogin     = document.getElementById('btn-close-login');
    this.modalLogin        = document.getElementById('login-modal');

    this.formCreateThread = document.getElementById('create-thread-form');
    this.formReply        = document.getElementById('reply-form');
    this.replyRestrictedMsg = document.getElementById('reply-restricted-info');
    this.formProfile      = document.getElementById('profile-settings-form');
    this.profileAdmissionBox = document.getElementById('profile-admission-box');
    this.btnProfileAdmission  = document.getElementById('btn-profile-admission');
    this.captchaContainer = document.getElementById('captcha-container');
    this.captchaImg       = document.getElementById('captcha-img');
    this.captchaInput     = document.getElementById('captcha-input');
    this.btnRefreshCaptcha = document.getElementById('btn-refresh-captcha');
    this.powStatus        = document.getElementById('pow-status');
    this.honeypotContainer = document.getElementById('honeypot-container');
    
    this.captchaToken     = null;
    this.powChallenge     = null;
    this.powDifficulty    = 4;
    this.powSolvedSalt    = null;
    this.hpToken          = null;
    this.captchaIssuedAt  = null;
    this.honeypotFieldNames = [];

    this.profCodename = document.getElementById('prof-codename');
    this.profRole     = document.getElementById('prof-role');
    this.profJoined   = document.getElementById('prof-joined');
    this.profReputation = document.getElementById('prof-reputation');
    this.profBio      = document.getElementById('prof-bio');
    this.profPubKey   = document.getElementById('prof-pubkey');

    this.elSearchBox  = document.getElementById('search-box');
    this.elSortSelect = document.getElementById('sort-select');

    this.#initEventListeners();
  }

  #initEventListeners() {
    // Sidebar channels event navigation
    const sidebarItems = document.querySelectorAll('.sidebar-item');
    sidebarItems.forEach((btn) => {
      btn.addEventListener('click', () => {
        const category = btn.getAttribute('data-category');
        this.state.setChannel(category);
      });
    });

    let searchTimeout = null;
    this.elSearchBox.addEventListener('input', (e) => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        this.state.setSearch(e.target.value.trim());
      }, 300);
    });

    this.elSortSelect.addEventListener('change', (e) => {
      this.state.setSort(e.target.value);
    });

    // ─── PURE EVENT DELEGATION ────────────────────────────────────────────────

    this.btnNavFeed.addEventListener('click',    () => this.state.setView('feed'));
    this.btnNavAdmission.addEventListener('click', async () => {
      console.log('[C2 UI] btnNavAdmission clicked.');
      const agent = this.state.currentAgent;
      console.log('[C2 UI] currentAgent:', agent);
      if (!agent) return;
      try {
        const user = await this.api.getUser(agent);
        console.log('[C2 UI] User profile retrieved:', user);
        console.log('[C2 UI] user.status:', user.status);
        console.log('[C2 UI] user.terms_accepted_at:', user.terms_accepted_at);
        if (user.status === 'PENDING_ADMISSION') {
          if (user.terms_accepted_at) {
            console.log('[C2 UI] Terms already accepted. Starting gatekeeper flow.');
            this.#startGatekeeperFlow();
          } else {
            console.log('[C2 UI] Terms not accepted. Displaying terms modal.');
            this.#showTermsModalDirect();
          }
        } else {
          console.log('[C2 UI] User is not pending admission.');
        }
      } catch (err) {
        console.error('[C2 UI] Admission button retrieval failed:', err);
        alert('Failed to retrieve admission status: ' + err.message);
      }
    });

    this.btnProfileAdmission.addEventListener('click', async () => {
      console.log('[C2 UI] btnProfileAdmission clicked.');
      const agent = this.state.currentAgent;
      console.log('[C2 UI] currentAgent:', agent);
      if (!agent) return;
      try {
        const user = await this.api.getUser(agent);
        console.log('[C2 UI] User profile retrieved:', user);
        console.log('[C2 UI] user.status:', user.status);
        console.log('[C2 UI] user.terms_accepted_at:', user.terms_accepted_at);
        if (user.status === 'PENDING_ADMISSION') {
          if (user.terms_accepted_at) {
            console.log('[C2 UI] Terms already accepted. Starting gatekeeper flow.');
            this.#startGatekeeperFlow();
          } else {
            console.log('[C2 UI] Terms not accepted. Displaying terms modal.');
            this.#showTermsModalDirect();
          }
        } else {
          console.log('[C2 UI] User is not pending admission.');
        }
      } catch (err) {
        console.error('[C2 UI] Admission button retrieval failed:', err);
        alert('Failed to retrieve admission status: ' + err.message);
      }
    });

    this.btnNavProfile.addEventListener('click', () => this.state.setView('profile'));
    this.btnBackProfile.addEventListener('click',() => this.state.setView('feed'));

    this.elThreadFeed.addEventListener('click', async (e) => {
      const authorSpan = e.target.closest('.thread-author');
      if (authorSpan) {
        e.stopPropagation();
        this.state.setView('profile', null, true, authorSpan.textContent.trim());
        return;
      }

      const btn = e.target.closest('.c2-btn');
      if (btn) {
        if (btn.classList.contains('upvote-btn')) {
          e.stopPropagation();
          try { await this.state.vote(btn.dataset.id, 1); } catch (err) { alert(err.message); }
          return;
        }
        if (btn.classList.contains('downvote-btn')) {
          e.stopPropagation();
          try { await this.state.vote(btn.dataset.id, -1); } catch (err) { alert(err.message); }
          return;
        }
      }

      if (e.target.closest('.c2-btn') || e.target.closest('.action-link') || e.target.closest('.thread-author')) return;
      const card = e.target.closest('.thread-card');
      if (card) this.state.setView('thread-detail', card.dataset.id);
    });

    this.elThreadDetailOP.addEventListener('click', async (e) => {
      const target = e.target;
      if (target.classList.contains('edit-op-btn')) {
        document.getElementById('op-edit-block').classList.remove('hide');
        document.getElementById('op-title-text').classList.add('hide');
        document.getElementById('op-body-text').classList.add('hide');
      } else if (target.classList.contains('cancel-edit-op-btn')) {
        document.getElementById('op-edit-block').classList.add('hide');
        document.getElementById('op-title-text').classList.remove('hide');
        document.getElementById('op-body-text').classList.remove('hide');
      } else if (target.classList.contains('save-edit-op-btn')) {
        const newTitle = document.getElementById('edit-op-title-input').value.trim();
        const newContent = document.getElementById('edit-op-content-input').value.trim();
        try {
          await this.state.updateThread(this.state.selectedThreadId, newTitle, newContent);
          await this.#renderThreadDetail(this.state);
        } catch (err) { alert(err.message); }
      } else if (target.classList.contains('delete-op-btn')) {
        if (confirm('WARNING: Deletion is permanent. Execute purge?')) {
          try { await this.state.deleteThread(this.state.selectedThreadId); } catch (err) { alert(err.message); }
        }
      }

      const opAuthor = e.target.closest('.thread-author');
      if (opAuthor) {
        this.state.setView('profile', null, true, opAuthor.textContent.trim());
      }
    });

    this.elCommentsList.addEventListener('click', async (e) => {
      const cAuthor = e.target.closest('.comment-author');
      if (cAuthor) {
        this.state.setView('profile', null, true, cAuthor.textContent.trim());
        return;
      }

      const delBtn = e.target.closest('.delete-rep-btn');
      if (delBtn) {
        if (confirm('Execute delete payload command?')) {
          try { await this.state.deleteReply(delBtn.dataset.id); } catch (err) { alert(err.message); }
        }
      }
    });

    this.btnNewThread.addEventListener('click',    () => this.state.setView('create-thread'));
    this.btnCancelCreate.addEventListener('click', () => this.state.setView('feed'));
    this.btnBackFeed.addEventListener('click',     () => this.state.setView('feed'));

    this.btnLogin.addEventListener('click', () => {
      if (this.state.currentAgent) {
        this.state.logout();
      } else {
        this.#setAuthMode('login');
        this.modalLogin.classList.add('active');
      }
    });

    this.btnRefreshCaptcha.addEventListener('click', () => {
      this.#loadCaptchaChallenge();
    });

    this.btnCloseLogin.addEventListener('click', () => this.modalLogin.classList.remove('active'));
    this.btnLoginToggle.addEventListener('click',    () => this.#setAuthMode('login'));
    this.btnRegisterToggle.addEventListener('click', () => this.#setAuthMode('register'));

    document.getElementById('auth-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const mode    = document.getElementById('auth-mode').value;
      const alias   = document.getElementById('agent-alias').value.trim();
      const secret  = document.getElementById('agent-key').value;
      const btn     = document.getElementById('auth-submit-btn');

      btn.disabled   = true;
      btn.textContent = 'PROCESSING...';

      try {
        let status;
        if (mode === 'register') {
          const captchaVal = this.captchaInput.value.trim();
          if (!this.powSolvedSalt) {
            throw new Error('Proof of Work challenge not solved yet.');
          }

          const honeypotValues = {};
          for (const name of this.honeypotFieldNames) {
            const el = document.querySelector(`[name="${name}"]`);
            honeypotValues[name] = el ? el.value : '';
          }

          status = await this.state.register(
            alias, secret,
            captchaVal, this.captchaToken, this.powChallenge, this.powSolvedSalt,
            honeypotValues, this.hpToken, this.captchaIssuedAt
          );
        } else {
          status = await this.state.login(alias, secret);
        }
        
        this.modalLogin.classList.remove('active');
        document.getElementById('auth-form').reset();
        
        if (status === 'PENDING_ADMISSION') {
            this.#showTermsModalDirect();
        }
      } catch (err) {
        console.error('[C2 Portal Exception]', err);
        alert(`Authentication Error: ${err.message}`);
        // Reload captcha on registration error
        if (mode === 'register') this.#loadCaptchaChallenge();
      } finally {
        btn.disabled    = false;
        btn.textContent = mode === 'register' ? 'EXECUTE_REGISTRATION' : 'EXECUTE_AUTHORIZE';
      }
    });

    this.formCreateThread.addEventListener('submit', async (e) => {
      e.preventDefault();
      const title    = document.getElementById('thread-title').value.trim();
      const category = document.getElementById('thread-category').value;
      const content  = document.getElementById('thread-content').value.trim();
      try {
        await this.state.publishThread(title, category, content);
        this.formCreateThread.reset();
      } catch (err) {
        alert(err.message);
      }
    });

    this.formReply.addEventListener('submit', async (e) => {
      e.preventDefault();
      const replyVal = document.getElementById('reply-content').value.trim();
      try {
        await this.state.publishReply(replyVal);
        document.getElementById('reply-content').value = '';
      } catch (err) {
        alert(err.message);
      }
    });

    this.formProfile.addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        await this.state.updateProfileBio(this.profBio.value.trim());
      } catch (err) {
        alert(err.message);
      }
    });
  }

  async #solvePoW(challenge, difficulty) {
    this.powStatus.textContent = 'PoW State: Solving...';
    this.powStatus.style.color = '#eab308';
    const target = '0'.repeat(difficulty);
    let nonce = 0;
    
    const encoder = new TextEncoder();
    const challengeBuffer = encoder.encode(challenge);
    
    while (true) {
      const nonceStr = String(nonce);
      const nonceBuffer = encoder.encode(nonceStr);
      const combined = new Uint8Array(challengeBuffer.length + nonceBuffer.length);
      combined.set(challengeBuffer);
      combined.set(nonceBuffer, challengeBuffer.length);
      
      const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      if (hashHex.startsWith(target)) {
        this.powStatus.textContent = `PoW State: Active (salt verified)`;
        this.powStatus.style.color = '#00ff66';
        this.powSolvedSalt = nonceStr;
        break;
      }
      nonce++;
    }
  }

  async #loadCaptchaChallenge() {
    try {
      this.captchaImg.src = '';
      this.captchaInput.value = '';
      this.powStatus.textContent = 'PoW State: Fetching...';
      this.powStatus.style.color = '#eab308';
      this.powSolvedSalt = null;
      
      const res = await this.api.getCaptchaChallenge();
      this.captchaToken = res.captchaToken;
      this.powChallenge = res.powChallenge;
      this.powDifficulty = res.powDifficulty;
      this.hpToken = res.hpToken;
      this.captchaIssuedAt = res.captchaIssuedAt;
      
      // C2-004: Dynamically render honeypot fields
      this.#renderHoneypotFields(res.honeypotFields || []);
      
      this.captchaImg.src = `data:image/svg+xml;base64,${res.captchaSvg}`;
      await this.#solvePoW(res.powChallenge, res.powDifficulty);
    } catch (err) {
      console.error('[C2 Captcha Engine] Fetch error:', err);
      this.powStatus.textContent = 'PoW State: Error';
      this.powStatus.style.color = '#ef4444';
    }
  }

  #renderHoneypotFields(fields) {
    if (!this.honeypotContainer) return;
    this.honeypotContainer.innerHTML = '';
    this.honeypotFieldNames = [];

    const techniqueStyles = [
      // Technique 0: Positioned off-screen (screen readers may still find)
      'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;',
      // Technique 1: Zero opacity, still in layout flow (bots parsing layout may miss)
      'opacity:0;height:0;overflow:hidden;padding:0;margin:0;border:none;',
      // Technique 2: type="hidden" wrapped in visibly hidden container
      '',
    ];

    for (const field of fields) {
      const style = techniqueStyles[field.technique] || techniqueStyles[0];
      const wrapper = document.createElement('div');
      wrapper.setAttribute('style', style);
      wrapper.setAttribute('aria-hidden', 'true');

      if (field.technique === 2) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = field.name;
        input.setAttribute('autocomplete', 'off');
        input.setAttribute('tabindex', '-1');
        input.value = '';
        wrapper.appendChild(input);
      } else {
        const label = document.createElement('label');
        label.textContent = field.label;
        label.setAttribute('style', 'font-size:9px;color:#333;margin-bottom:2px;display:none;');
        label.htmlFor = `hp-${field.name}`;

        const input = document.createElement('input');
        input.type = 'text';
        input.name = field.name;
        input.id = `hp-${field.name}`;
        input.setAttribute('autocomplete', 'off');
        input.setAttribute('tabindex', '-1');
        input.setAttribute('style', 'background:#000;color:#333;border:1px solid #111;font-size:8px;padding:2px;width:100%;');

        wrapper.appendChild(label);
        wrapper.appendChild(input);
      }

      this.honeypotContainer.appendChild(wrapper);
      this.honeypotFieldNames.push(field.name);
    }
  }

  #setAuthMode(mode) {
    const authModeInput  = document.getElementById('auth-mode');
    const authSubmitBtn  = document.getElementById('auth-submit-btn');
    authModeInput.value  = mode;
    authSubmitBtn.textContent = mode === 'register' ? 'Register' : 'Login';
    this.btnRegisterToggle.classList.toggle('active', mode === 'register');
    this.btnLoginToggle.classList.toggle('active',    mode === 'login');
    
    if (mode === 'register') {
      this.captchaContainer.classList.remove('hide');
      this.#loadCaptchaChallenge();
    } else {
      this.captchaContainer.classList.add('hide');
      // C2-004: Destroy honeypot fields when not in register mode
      if (this.honeypotContainer) this.honeypotContainer.innerHTML = '';
      this.honeypotFieldNames = [];
      this.hpToken = null;
      this.captchaIssuedAt = null;
    }
  }

  async render(state) {
    const agent = state.currentAgent;

    const keystoreStatus = document.getElementById('keystore-status');
    if (keystoreStatus) {
      if (state.activePrivateKey) {
        keystoreStatus.textContent = 'KEY: UNLOCKED';
        keystoreStatus.className = 'integrity-badge verified';
      } else {
        keystoreStatus.textContent = 'KEY: LOCKED';
        keystoreStatus.className = 'integrity-badge compromised';
      }
    }

    // Render Auth buttons and forms
    if (agent) {
      this.btnLogin.textContent = '◇ logout';
      this.btnNavProfile.classList.remove('hide');
      this.btnNewThread.removeAttribute('disabled');
      this.formReply.classList.remove('hide');
      this.replyRestrictedMsg.classList.add('hide');
    } else {
      this.btnLogin.textContent = '◇ login';
      this.btnNavProfile.classList.add('hide');
      this.btnNavAdmission.classList.add('hide');
      this.btnNewThread.setAttribute('disabled', 'true');
      this.formReply.classList.add('hide');
      this.replyRestrictedMsg.classList.remove('hide');
      if (state.activeView === 'profile' && !state.selectedProfileCodename) {
        state.activeView = 'feed';
      }
    }

    const targetProfile = state.selectedProfileCodename || agent;
    if (targetProfile) {
      try {
        const isViewingOwnProfile = agent && targetProfile.toLowerCase() === agent.toLowerCase();
        
        // Single getUser call for the target profile; if viewing own profile,
        // this also provides the data needed for admission/gatekeeper checks.
        const userObj = await this.api.getUser(targetProfile);
        
        let isCommander = false;
        let admissionUser = null;
        if (agent) {
          admissionUser = isViewingOwnProfile ? userObj : await this.api.getUser(agent);
          isCommander = admissionUser.role === 'COMMANDER';
          
          if (admissionUser.status === 'PENDING_ADMISSION') {
              console.log('[C2 UI] PENDING_ADMISSION detected — showing admission flow. terms_accepted_at:', admissionUser.terms_accepted_at);
              if (admissionUser.terms_accepted_at) {
                this.#startGatekeeperFlow();
              } else {
                this.#showTermsModalDirect();
              }
              // Block feed/profile rendering while pending admission
              this.secFeed.classList.remove('active');
              this.secDetail.classList.remove('active');
              this.secCreate.classList.remove('active');
              this.secProfile.classList.remove('active');
              return;
          }

          // Admission button visibility (only for own profile)
          if (isViewingOwnProfile) {
            if (admissionUser.status === 'PENDING_ADMISSION') {
              this.btnNavAdmission.classList.remove('hide');
            } else {
              this.btnNavAdmission.classList.add('hide');
            }
          }
        }
        
        const isOwnProfile = agent && targetProfile.toLowerCase() === agent.toLowerCase();

        this.profCodename.textContent = targetProfile;
        this.profRole.textContent     = userObj.role;
        this.profJoined.textContent   = userObj.joined_date;
        this.profReputation.textContent = userObj.reputation;
        // Only update bio field if user is not actively editing it
        if (document.activeElement !== this.profBio) {
          this.profBio.value = userObj.bio;
        }
        this.profPubKey.value         =
          `-----BEGIN PUBLIC KEY-----\n${userObj.public_key_spki.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;

        const saveBioBtn = this.formProfile.querySelector('button[type="submit"]');
        const securityDesc = document.querySelector('.profile-security-card .profile-info-text');

        if (isOwnProfile) {
          if (saveBioBtn) saveBioBtn.classList.remove('hide');
          this.profBio.removeAttribute('readonly');
          if (securityDesc) {
            securityDesc.textContent = 'Your private signing key is stored encrypted on the server (AES-256-GCM). It is decrypted locally in your browser when you login using your password.';
          }
          if (userObj.status === 'PENDING_ADMISSION') {
            this.profileAdmissionBox.classList.remove('hide');
          } else {
            this.profileAdmissionBox.classList.add('hide');
          }
        } else {
          if (saveBioBtn) saveBioBtn.classList.add('hide');
          this.profBio.setAttribute('readonly', 'true');
          if (securityDesc) {
            securityDesc.textContent = 'Public key used to verify signatures from this node.';
          }
          this.profileAdmissionBox.classList.add('hide');
        }

        // Render dynamic moderation console if logged-in user is a COMMANDER
        let modCard = document.getElementById('prof-mod-card');
        if (modCard) modCard.remove();

        if (isCommander && !isOwnProfile) {
          modCard = el('div', null, { id: 'prof-mod-card', class: 'profile-security-card' });
          const modTitle = el('div', 'Commander Moderation Console', { class: 'section-title', style: 'margin-top:0;' });
          
          const actionsDiv = el('div', null, { style: 'display:flex; flex-direction:column; gap:10px; margin-top:15px;' });
          
          const warnBtn = el('button', 'ISSUE_WARN', { class: 'c2-btn block-btn text-warning' });
          warnBtn.addEventListener('click', async () => {
            const reason = prompt(`Reason for warning user "${targetProfile}":`);
            if (reason) {
              try {
                const res = await state.warnAgent(targetProfile, reason);
                alert(res.message);
              } catch (err) { alert(err.message); }
            }
          });

          const banBtn = el('button', 'EXECUTE_BAN', { class: 'c2-btn block-btn delete' });
          banBtn.addEventListener('click', async () => {
            const reason = prompt(`Reason for BANNING user "${targetProfile}":`);
            if (reason) {
              try {
                const res = await state.banAgent(targetProfile, 'BANNED', reason);
                alert(res.message);
              } catch (err) { alert(err.message); }
            }
          });

          const sbanBtn = el('button', 'EXECUTE_SHADOWBAN', { class: 'c2-btn block-btn text-muted' });
          sbanBtn.addEventListener('click', async () => {
            const reason = prompt(`Reason for SHADOWBANNING user "${targetProfile}":`);
            if (reason) {
              try {
                const res = await state.banAgent(targetProfile, 'SHADOWBANNED', reason);
                alert(res.message);
              } catch (err) { alert(err.message); }
            }
          });

          const unbanBtn = el('button', 'LIFT_RESTRICTIONS', { class: 'c2-btn block-btn text-accent' });
          unbanBtn.addEventListener('click', async () => {
            try {
              const res = await state.unbanAgent(targetProfile);
              alert(res.message);
            } catch (err) { alert(err.message); }
          });

          const purgeBtn = el('button', 'PURGE_NODE_ACCOUNT', { class: 'c2-btn block-btn delete', style: 'font-weight:bold;' });
          purgeBtn.addEventListener('click', async () => {
            if (confirm(`CRITICAL WARNING:\nPurging "${targetProfile}" will permanently delete their account, all threads, replies, and votes.\nThis cannot be undone. Proceed?`)) {
              try {
                const res = await state.purgeAgent(targetProfile);
                alert(res.message);
                state.setView('feed');
              } catch (err) { alert(err.message); }
            }
          });

          actionsDiv.append(warnBtn, banBtn, sbanBtn, unbanBtn, purgeBtn);
          modCard.append(modTitle, actionsDiv);
          const grid = document.querySelector('.profile-grid');
          if (grid) grid.append(modCard);
        }
      } catch (err) {
        console.error('Profile fetch failed:', err);
      }
    }

    this.secFeed.classList.remove('active');
    this.secDetail.classList.remove('active');
    this.secCreate.classList.remove('active');
    this.secProfile.classList.remove('active');
    this.btnNavFeed.classList.remove('active');
    this.btnNavProfile.classList.remove('active');

    if (state.activeView === 'feed') {
      this.secFeed.classList.add('active');
      this.btnNavFeed.classList.add('active');
      await this.#renderFeed(state);
    } else if (state.activeView === 'thread-detail') {
      this.secDetail.classList.add('active');
      await this.#renderThreadDetail(state);
    } else if (state.activeView === 'create-thread') {
      this.secCreate.classList.add('active');
    } else if (state.activeView === 'profile') {
      this.secProfile.classList.add('active');
      this.btnNavProfile.classList.add('active');
    }

    // Toggle active class on sidebar items
    const sidebarItems = document.querySelectorAll('.sidebar-item');
    sidebarItems.forEach((btn) => {
      const category = btn.getAttribute('data-category');
      btn.classList.toggle('active', category === state.currentChannel);
    });

    // Render active nodes list
    const nodesList = document.getElementById('active-nodes-list');
    if (nodesList) {
      if (state.currentAgent) {
        nodesList.innerHTML = '';
        state.presenceList.forEach((u) => {
          const nodeDiv = document.createElement('div');
          nodeDiv.style = 'display:flex; justify-content:space-between; align-items:center; font-size:10px; font-family:var(--font-mono);';
          
          const leftSpan = document.createElement('span');
          leftSpan.style = 'display:flex; align-items:center; gap:6px;';
          
          const statusDot = document.createElement('span');
          statusDot.style = `width:5px; height:5px; border-radius:50%; display:inline-block; background-color:${u.isOnline ? '#00ff66' : '#555'}; box-shadow: ${u.isOnline ? '0 0 4px #00ff66' : 'none'};`;
          
          const nameSpan = document.createElement('span');
          nameSpan.textContent = u.codename;
          nameSpan.style = 'color: #00ff66; cursor: pointer; text-decoration: underline;';
          nameSpan.addEventListener('click', () => {
            state.setView('profile', null, true, u.codename);
          });
          
          leftSpan.append(statusDot, nameSpan);
          
          const rightSpan = document.createElement('span');
          rightSpan.style = 'font-size:8px; color:var(--text-muted);';
          
          // Display RTT Telemetry for current agent
          if (u.codename === state.currentAgent && state.latencyMs !== undefined) {
             rightSpan.textContent = u.isOnline ? `ONLINE (${state.latencyMs}ms)` : 'OFFLINE';
          } else {
             rightSpan.textContent = u.isOnline ? 'ONLINE' : 'OFFLINE';
          }
          
          nodeDiv.append(leftSpan, rightSpan);
          nodesList.appendChild(nodeDiv);
        });
      } else {
        nodesList.innerHTML = '<div style="font-size:9px;color:var(--text-muted);font-family:var(--font-mono);">[AUTH_REQUIRED]</div>';
      }
    }
  }

  async #renderFeed(state) {
    let threads = [];
    try {
      threads = await this.api.getThreads({
        search:   state.searchQuery,
        category: state.currentChannel === 'all' ? undefined : state.currentChannel,
        sort:     state.sortCriteria,
      });
    } catch (err) {
      console.error('[C2 Feed Engine] Fetch failed:', err);
      this.elThreadFeed.innerHTML = '<div class="restricted-info">Offline. Server unreachable or Admission pending.</div>';
      return;
    }

    this.elThreadFeed.innerHTML = '';

    if (threads.length === 0) {
      this.elThreadFeed.innerHTML = '<div class="restricted-info">Feed database empty. No data lines transmitted.</div>';
      return;
    }

    for (const thread of threads) {
      let isVerified = false;
      if (thread.public_key_spki && thread.signature) {
        try {
          const pubKey  = await CryptoEngine.importPublicKey(thread.public_key_spki);
          
          let payload;
          if (thread.client_nonce && thread.client_timestamp && thread.signature_op) {
            let payloadObj;
            if (thread.signature_op === 'create-thread') {
              payloadObj = { op: 'create-thread', title: thread.title, content: thread.content, author: thread.author, nonce: thread.client_nonce, timestamp: thread.client_timestamp };
            } else if (thread.signature_op === 'edit-thread') {
              payloadObj = { op: 'edit-thread', threadId: thread.id, title: thread.title, content: thread.content, author: thread.author, nonce: thread.client_nonce, timestamp: thread.client_timestamp };
            }
            payload = JSON.stringify(payloadObj, Object.keys(payloadObj).sort());
          } else {
            payload = `${thread.title}|${thread.content}|${thread.author}`; // Legacy fallback
          }

          isVerified = await CryptoEngine.verifyMessage(payload, thread.signature, pubKey);
        } catch {
          isVerified = false;
        }
      }

      // ── Build card via DOM API — no user data in innerHTML ─────────────────
      const card = el('div', null, { class: 'thread-card', 'data-id': thread.id });

      // Header row
      const header      = el('div', null, { class: 'thread-card-header' });
      const idWrapper   = el('span');
      idWrapper.append(document.createTextNode('VECTOR ID: '));
      const idSpan = el('span', thread.id, { class: 'text-accent' });
      idWrapper.append(idSpan);

      const rightHeader = el('div', null, { style: 'display:flex;gap:8px;align-items:center;' });
      rightHeader.append(verificationBadge(isVerified));
      const originSpan  = el('span');
      originSpan.append(document.createTextNode('ORIGIN: '));
      originSpan.append(el('span', thread.author, { class: 'thread-author' }));
      rightHeader.append(originSpan);

      header.append(idWrapper, rightHeader);

      // Title — textContent prevents XSS
      const title = el('h2', thread.title, { class: 'thread-card-title' });

      // Footer
      const footer     = el('div', null, { class: 'thread-card-footer' });
      const tagSpan    = el('span', `#${thread.category}`, { class: 'thread-tag' });
      const actionsDiv = el('div', null, { style: 'display:flex;align-items:center;gap:12px;' });
      
      const upvoteBtn  = el('button', `▲ ${thread.upvotes}`, {
        class: 'c2-btn upvote-btn',
        'data-id': thread.id,
      });
      const downvoteBtn = el('button', `▼ ${thread.downvotes}`, {
        class: 'c2-btn downvote-btn',
        'data-id': thread.id,
      });
      const scoreBadge = el('span', `[SCORE: ${thread.score}]`, {
        class: `score-badge ${thread.score >= 0 ? 'score-pos' : 'score-neg'}`
      });

      const statsDiv   = el('div', null, { class: 'thread-stats', style: 'margin-left:8px;' });
      statsDiv.append(el('span', `REPLIES: ${thread.reply_count}`));
      
      actionsDiv.append(upvoteBtn, downvoteBtn, scoreBadge, statsDiv);
      footer.append(tagSpan, actionsDiv);

      card.append(header, title, footer);
      this.elThreadFeed.appendChild(card);
    }
  }

  async #renderThreadDetail(state) {
    let thread  = null;
    let replies = [];
    try {
      const threads = await this.api.getThreads();
      thread        = threads.find((t) => t.id === state.selectedThreadId);
      if (!thread) { this.state.setView('feed'); return; }
      replies = await this.api.getReplies(thread.id);
    } catch {
      this.state.setView('feed');
      return;
    }

    // Update header ID tag
    if (this.elDetailThreadId) {
      this.elDetailThreadId.textContent = `ID: ${thread.id}`;
    }

    let opVerified = false;
    if (thread.public_key_spki && thread.signature) {
      try {
        const pubKey  = await CryptoEngine.importPublicKey(thread.public_key_spki);
        let payload;
        if (thread.client_nonce && thread.client_timestamp && thread.signature_op) {
          let payloadObj;
          if (thread.signature_op === 'create-thread') {
            payloadObj = { op: 'create-thread', title: thread.title, content: thread.content, author: thread.author, nonce: thread.client_nonce, timestamp: thread.client_timestamp };
          } else if (thread.signature_op === 'edit-thread') {
            payloadObj = { op: 'edit-thread', threadId: thread.id, title: thread.title, content: thread.content, author: thread.author, nonce: thread.client_nonce, timestamp: thread.client_timestamp };
          }
          payload = JSON.stringify(payloadObj, Object.keys(payloadObj).sort());
        } else {
          payload = `${thread.title}|${thread.content}|${thread.author}`;
        }
        opVerified = await CryptoEngine.verifyMessage(payload, thread.signature, pubKey);
      } catch { opVerified = false; }
    }

    // Determine CRUD permissions
    let isOwner = false;
    let isMod   = false;
    if (state.currentAgent) {
      try {
        const currentUser = await this.api.getUser(state.currentAgent);
        isOwner = thread.author.toLowerCase() === state.currentAgent.toLowerCase();
        isMod   = currentUser?.role === 'COMMANDER';
      } catch { /* silent */ }
    }

    // ── Build OP card via DOM API ─────────────────────────────────────────────
    this.elThreadDetailOP.innerHTML = '';

    const opCard   = el('div', null, { class: 'op-card' });
    const opHeader = el('div', null, { class: 'op-header' });

    const leftH = el('div', null, { style: 'display:flex;gap:8px;align-items:center;' });
    leftH.append(verificationBadge(opVerified));
    const originSpan = el('span');
    originSpan.append(document.createTextNode('ORIGIN: '));
    originSpan.append(el('span', thread.author, { class: 'thread-author' }));
    leftH.append(originSpan);

    if (isMod && thread.author.toLowerCase() !== state.currentAgent.toLowerCase()) {
      const modDiv = el('span', null, { class: 'mod-actions-span', style: 'margin-left: 10px; font-size: 8px;' });
      
      const warn = el('a', '[WARN]', { href: '#', class: 'action-link text-warning', style: 'margin-right: 5px;' });
      warn.addEventListener('click', async (e) => {
        e.preventDefault();
        const reason = prompt(`Reason for warning user "${thread.author}":`);
        if (reason) {
          try {
            const res = await state.warnAgent(thread.author, reason);
            alert(res.message);
          } catch (err) { alert(err.message); }
        }
      });

      const ban = el('a', '[BAN]', { href: '#', class: 'action-link delete', style: 'margin-right: 5px;' });
      ban.addEventListener('click', async (e) => {
        e.preventDefault();
        const reason = prompt(`Reason for BANNING user "${thread.author}":`);
        if (reason) {
          try {
            const res = await state.banAgent(thread.author, 'BANNED', reason);
            alert(res.message);
          } catch (err) { alert(err.message); }
        }
      });

      const sban = el('a', '[S-BAN]', { href: '#', class: 'action-link text-muted', style: 'margin-right: 5px;' });
      sban.addEventListener('click', async (e) => {
        e.preventDefault();
        const reason = prompt(`Reason for SHADOWBANNING user "${thread.author}":`);
        if (reason) {
          try {
            const res = await state.banAgent(thread.author, 'SHADOWBANNED', reason);
            alert(res.message);
          } catch (err) { alert(err.message); }
        }
      });

      const purge = el('a', '[PURGE]', { href: '#', class: 'action-link delete', style: 'margin-right: 5px; font-weight: bold;' });
      purge.addEventListener('click', async (e) => {
        e.preventDefault();
        if (confirm(`CRITICAL WARNING:\nPurging "${thread.author}" will permanently delete their account, all threads, replies, and votes.\nThis cannot be undone. Proceed?`)) {
          try {
            const res = await state.purgeAgent(thread.author);
            alert(res.message);
            state.setView('feed');
          } catch (err) { alert(err.message); }
        }
      });

      const unban = el('a', '[UNBAN]', { href: '#', class: 'action-link text-accent' });
      unban.addEventListener('click', async (e) => {
        e.preventDefault();
        try {
          const res = await state.unbanAgent(thread.author);
          alert(res.message);
        } catch (err) { alert(err.message); }
      });

      modDiv.append(warn, ban, sban, purge, unban);
      leftH.append(modDiv);
    }

    const rightH = el('div', null, { style: 'display:flex;gap:15px;align-items:center;' });
    rightH.append(el('span', `TIMESTAMP: ${thread.timestamp}`));

    if (isOwner || isMod) {
      const crudDiv  = el('div', null, { class: 'crud-actions' });
      const editBtn  = el('button', 'EDIT_VECTOR',   { class: 'action-link edit-op-btn' });
      const delBtn   = el('button', 'PURGE_VECTOR',  { class: 'action-link delete delete-op-btn' });
      crudDiv.append(editBtn, delBtn);
      rightH.append(crudDiv);
    }

    opHeader.append(leftH, rightH);

    const opTitle   = el('h1', thread.title,   { class: 'op-title',   id: 'op-title-text' });
    const opBody    = renderFormattedContent(thread.content);
    opBody.className = 'op-body';
    opBody.id        = 'op-body-text';

    // Inline edit block (hidden by default)
    const editBlock = el('div', null, { id: 'op-edit-block', class: 'hide', style: 'margin-top:15px;' });
    const editTitleInput = el('input', null, {
      type: 'text', id: 'edit-op-title-input', class: 'c2-form',
      style: 'width:100%;margin-bottom:10px;', value: thread.title,
    });
    const editContentArea = el('textarea', thread.content, {
      id: 'edit-op-content-input', class: 'c2-form', rows: '6',
      style: 'width:100%;margin-bottom:10px;',
    });
    const saveBtn   = el('button', 'COMMIT_PAYLOAD', { class: 'c2-btn save-edit-op-btn' });
    const cancelBtn = el('button', 'ABORT',          { class: 'c2-btn cancel-edit-op-btn', style: 'margin-left:8px;' });
    editBlock.append(editTitleInput, editContentArea, saveBtn, cancelBtn);

    opCard.append(opHeader, opTitle, opBody, editBlock);
    this.elThreadDetailOP.appendChild(opCard);

    // ── Render replies ────────────────────────────────────────────────────────
    this.elCommentsList.innerHTML = '';

    if (replies.length === 0) {
      this.elCommentsList.innerHTML = '<div class="restricted-info" style="padding:10px 0;">No comments logged under thread vector.</div>';
      return;
    }

    for (const reply of replies) {
      let replyVerified = false;
      if (reply.public_key_spki && reply.signature) {
        try {
          const pubKey  = await CryptoEngine.importPublicKey(reply.public_key_spki);
          let payload;
          if (reply.client_nonce && reply.client_timestamp && reply.signature_op) {
            const payloadObj = { op: 'create-reply', threadId: thread.id, content: reply.content, author: reply.author, nonce: reply.client_nonce, timestamp: reply.client_timestamp };
            payload = JSON.stringify(payloadObj, Object.keys(payloadObj).sort());
          } else {
            payload = `${reply.content}|${reply.author}`;
          }
          replyVerified = await CryptoEngine.verifyMessage(payload, reply.signature, pubKey);
        } catch { replyVerified = false; }
      }

      let canDelete = false;
      if (state.currentAgent) {
        const isRepOwner = reply.author.toLowerCase() === state.currentAgent.toLowerCase();
        canDelete = isRepOwner || isMod;
      }

      // ── Build comment card via DOM API ────────────────────────────────────
      const commentDiv = el('div', null, { class: 'comment-card' });
      const cHeader    = el('div', null, { class: 'comment-header' });

      const cLeft = el('div', null, { style: 'display:flex;gap:8px;align-items:center;' });
      cLeft.append(verificationBadge(replyVerified));
      cLeft.append(el('span', reply.author, { class: 'comment-author' }));

      if (isMod && reply.author.toLowerCase() !== state.currentAgent.toLowerCase()) {
        const modDiv = el('span', null, { class: 'mod-actions-span', style: 'margin-left: 10px; font-size: 8px;' });
        
        const warn = el('a', '[WARN]', { href: '#', class: 'action-link text-warning', style: 'margin-right: 5px;' });
        warn.addEventListener('click', async (e) => {
          e.preventDefault();
          const reason = prompt(`Reason for warning user "${reply.author}":`);
          if (reason) {
            try {
              const res = await state.warnAgent(reply.author, reason);
              alert(res.message);
            } catch (err) { alert(err.message); }
          }
        });

        const ban = el('a', '[BAN]', { href: '#', class: 'action-link delete', style: 'margin-right: 5px;' });
        ban.addEventListener('click', async (e) => {
          e.preventDefault();
          const reason = prompt(`Reason for BANNING user "${reply.author}":`);
          if (reason) {
            try {
              const res = await state.banAgent(reply.author, 'BANNED', reason);
              alert(res.message);
            } catch (err) { alert(err.message); }
          }
        });

        const sban = el('a', '[S-BAN]', { href: '#', class: 'action-link text-muted', style: 'margin-right: 5px;' });
        sban.addEventListener('click', async (e) => {
          e.preventDefault();
          const reason = prompt(`Reason for SHADOWBANNING user "${reply.author}":`);
          if (reason) {
            try {
              const res = await state.banAgent(reply.author, 'SHADOWBANNED', reason);
              alert(res.message);
            } catch (err) { alert(err.message); }
          }
        });

        const purge = el('a', '[PURGE]', { href: '#', class: 'action-link delete', style: 'margin-right: 5px; font-weight: bold;' });
        purge.addEventListener('click', async (e) => {
          e.preventDefault();
          if (confirm(`CRITICAL WARNING:\nPurging "${reply.author}" will permanently delete their account, all threads, replies, and votes.\nThis cannot be undone. Proceed?`)) {
            try {
              const res = await state.purgeAgent(reply.author);
              alert(res.message);
              state.setView('feed');
            } catch (err) { alert(err.message); }
          }
        });

        const unban = el('a', '[UNBAN]', { href: '#', class: 'action-link text-accent' });
        unban.addEventListener('click', async (e) => {
          e.preventDefault();
          try {
            const res = await state.unbanAgent(reply.author);
            alert(res.message);
          } catch (err) { alert(err.message); }
        });

        modDiv.append(warn, ban, sban, purge, unban);
        cLeft.append(modDiv);
      }

      const cRight = el('div', null, { style: 'display:flex;gap:15px;align-items:center;' });
      cRight.append(el('span', reply.timestamp));

      if (canDelete) {
        const repDelBtn = el('button', 'DELETE', {
          class: 'action-link delete delete-rep-btn',
          'data-id': String(reply.id),
        });
        cRight.append(repDelBtn);
      }

      cHeader.append(cLeft, cRight);
      // Reply content — rendered with Markdown/LaTeX securely
      const cBody = renderFormattedContent(reply.content);
          cBody.className = 'comment-body';
      commentDiv.append(cHeader, cBody);
      this.elCommentsList.appendChild(commentDiv);
    }
  }

  async #startGatekeeperFlow() {
    if (document.getElementById('diag-gatekeeper-modal')) return;
    console.log('[C2 UI] #startGatekeeperFlow initiated.');

    const baseStyle = (el, css) => { for (const [k, v] of Object.entries(css)) el.style[k] = v; };

    // Overlay
    const overlay = document.createElement('div');
    overlay.id = 'diag-gatekeeper-modal';
    baseStyle(overlay, {
      position:'fixed', top:'0', left:'0', width:'100vw', height:'100vh',
      background:'rgba(0,0,0,0.95)', display:'flex', alignItems:'center',
      justifyContent:'center', zIndex:'2147483647', fontFamily:'monospace'
    });

    // Card container
    const card = document.createElement('div');
    baseStyle(card, {
      background:'#000', border:'1px solid #fff', maxWidth:'800px',
      width:'90%', color:'#fff', display:'flex', flexDirection:'column'
    });

    // Header
    const header = document.createElement('div');
    baseStyle(header, { padding:'10px 14px', borderBottom:'1px solid #333' });
    const headerSpan = document.createElement('span');
    baseStyle(headerSpan, { fontSize:'10px', color:'#fff', fontWeight:'bold' });
    headerSpan.textContent = 'AI-GATEKEEPER ADMISSION TERMINAL';
    header.appendChild(headerSpan);

    // Content area
    const content = document.createElement('div');
    baseStyle(content, { padding:'20px', minHeight:'200px' });

    // Status line
    const statusLine = document.createElement('div');
    statusLine.id = 'diag-gk-status';
    baseStyle(statusLine, { color:'#58a6ff', marginBottom:'20px', fontSize:'11px' });
    statusLine.textContent = '[SYS] Initializing admission protocol... [SYS] Connection established.';

    // Question box
    const questionBox = document.createElement('div');
    questionBox.id = 'diag-gk-question';
    baseStyle(questionBox, {
      background:'#050505', border:'1px solid #333', padding:'15px',
      marginBottom:'20px', color:'#e6e6e6', whiteSpace:'pre-wrap', fontSize:'13px'
    });
    questionBox.textContent = 'Fetching challenge...';

    // Input wrapper (dynamic content goes here)
    const inputWrapper = document.createElement('div');
    inputWrapper.id = 'diag-gk-input-wrapper';
    baseStyle(inputWrapper, { marginBottom:'15px' });

    // Footer row
    const footer = document.createElement('div');
    baseStyle(footer, { display:'flex', justifyContent:'space-between', alignItems:'center' });

    const attemptsSpan = document.createElement('span');
    attemptsSpan.id = 'diag-gk-attempts';
    baseStyle(attemptsSpan, { fontSize:'12px', color:'#f85149' });
    attemptsSpan.textContent = 'Attempts remaining: 5';

    const submitBtn = document.createElement('button');
    submitBtn.id = 'diag-gk-submit';
    baseStyle(submitBtn, {
      padding:'10px 20px', background:'#000', color:'#fff',
      border:'1px solid #fff', cursor:'pointer', fontFamily:'monospace',
      fontSize:'11px', textTransform:'uppercase'
    });
    submitBtn.textContent = '[ SUBMIT ANSWERS ]';

    footer.appendChild(attemptsSpan);
    footer.appendChild(submitBtn);

    content.appendChild(statusLine);
    content.appendChild(questionBox);
    content.appendChild(inputWrapper);
    content.appendChild(footer);

    card.appendChild(header);
    card.appendChild(content);
    overlay.appendChild(card);
    document.body.appendChild(overlay);

    // Dynamic content references (keep names matching the logic below)
    const questionEl = questionBox;
    const attemptsEl = attemptsSpan;

    try {
      const challenge = await this.api.getGatekeeperChallenge();
      questionEl.textContent = 'Complete the following admission challenges:';
      inputWrapper.innerHTML = '';

      for (const q of challenge.questions) {
        const qCard = document.createElement('div');
        baseStyle(qCard, { border:'1px solid #333', padding:'12px', marginBottom:'12px' });

        const qText = document.createElement('div');
        baseStyle(qText, { fontSize:'12px', color:'#e6e6e6', marginBottom:'8px', lineHeight:'1.5' });
        qText.textContent = q.question;
        qCard.appendChild(qText);

        q.options.forEach((opt, idx) => {
          const label = document.createElement('label');
          baseStyle(label, { display:'block', marginBottom:'4px', fontSize:'11px', cursor:'pointer' });
          const input = document.createElement('input');
          input.type = 'radio';
          input.name = 'diag-gk-' + q.id;
          input.value = String.fromCharCode(65 + idx);
          input.style.marginRight = '6px';
          label.appendChild(input);
          label.appendChild(document.createTextNode(' ' + opt));
          qCard.appendChild(label);
        });
        inputWrapper.appendChild(qCard);
      }

      submitBtn.disabled = false;

      submitBtn.onclick = async () => {
        const answers = {};
        let allAnswered = true;
        for (const q of challenge.questions) {
          const checked = document.querySelector(`input[name="diag-gk-${q.id}"]:checked`);
          if (!checked) { allAnswered = false; break; }
          answers[q.id] = checked.value;
        }
        if (!allAnswered) {
          alert('You must answer both questions before submitting.');
          return;
        }
        try {
          const res = await this.api.evaluateGatekeeperChallenge(answers);
          if (res.status === 'ACTIVE') {
            overlay.remove();
            this.state.initSocket();
            this.state.notify();
            alert('ADMISSION APPROVED. Welcome.');
          }
        } catch (err) {
          attemptsEl.textContent = 'Attempts remaining: ' + (err.attempts_left !== undefined ? err.attempts_left : '-');
          alert('ADMISSION REJECTED: ' + err.message);
        }
      };
    } catch(err) {
      questionEl.textContent = 'Error connecting to Arbiter: ' + err.message;
    }
  }

  #showTermsModalDirect() {
    if (document.getElementById('diag-fallback-modal')) return;

    const baseStyle = (el, css) => { for (const [k, v] of Object.entries(css)) el.style[k] = v; };
    const appendAll = (parent, ...children) => { children.forEach(c => parent.appendChild(c)); };

    // Overlay
    const overlay = document.createElement('div');
    overlay.id = 'diag-fallback-modal';
    baseStyle(overlay, {
      position:'fixed', top:'0', left:'0', width:'100vw', height:'100vh',
      background:'rgba(0,0,0,0.95)', display:'flex', alignItems:'center',
      justifyContent:'center', zIndex:'2147483647', fontFamily:'monospace'
    });

    // Card container
    const card = document.createElement('div');
    baseStyle(card, {
      background:'#000', border:'1px solid #fff', maxWidth:'600px',
      width:'90%', color:'#fff', display:'flex', flexDirection:'column'
    });

    // Header
    const header = document.createElement('div');
    baseStyle(header, { padding:'10px 14px', borderBottom:'1px solid #1a1a1a' });
    const headerSpan = document.createElement('span');
    baseStyle(headerSpan, { fontSize:'10px', color:'#fff', fontWeight:'bold' });
    headerSpan.textContent = 'ACTION REQUIRED: LEGAL ACCEPTANCE';
    header.appendChild(headerSpan);

    // Content wrapper
    const content = document.createElement('div');
    baseStyle(content, { padding:'20px' });

    // Title
    const h3 = document.createElement('h3');
    baseStyle(h3, { color:'#ff3333', margin:'0 0 12px 0', fontSize:'12px', fontWeight:'bold' });
    h3.textContent = 'RESTRICTED ACCESS ZONE';

    // Paragraph 1 (with <strong>)
    const p1 = document.createElement('p');
    baseStyle(p1, { fontSize:'12px', lineHeight:'1.6', margin:'0 0 12px 0' });
    p1.appendChild(document.createTextNode('You are attempting to enter a restricted cybersecurity research forum. By proceeding, you agree to assume '));
    const strong1 = document.createElement('strong');
    strong1.textContent = 'full civil and criminal liability';
    p1.appendChild(strong1);
    p1.appendChild(document.createTextNode(' for any content, payloads, or signatures you post.'));

    // Paragraph 2
    const p2 = document.createElement('p');
    baseStyle(p2, { fontSize:'12px', lineHeight:'1.6', margin:'0 0 12px 0' });
    p2.textContent = 'This platform operates strictly on an "As Is" basis. The operators are legally exempt from any liability regarding User-Generated Content (UGC).';

    // Link to terms
    const linkDiv = document.createElement('div');
    baseStyle(linkDiv, { margin:'16px 0' });
    const linkA = document.createElement('a');
    baseStyle(linkA, { color:'#00ff66', fontSize:'11px', textDecoration:'underline' });
    linkA.href = '/terms.html';
    linkA.target = '_blank';
    linkA.textContent = '[ READ FULL TERMS AND CONDITIONS ]';
    linkDiv.appendChild(linkA);

    // Buttons container
    const btnDiv = document.createElement('div');
    baseStyle(btnDiv, { display:'flex', gap:'15px', marginTop:'20px' });

    const btnStyle = {
      flex:'1', padding:'8px', background:'#000', cursor:'pointer',
      fontFamily:'monospace', fontSize:'10px', textTransform:'uppercase',
      transition:'all 0.1s', border:'1px solid #333'
    };

    // Cancel button
    const cancelBtn = document.createElement('button');
    cancelBtn.id = 'diag-terms-cancel';
    baseStyle(cancelBtn, { ...btnStyle, color:'#ff3333' });
    cancelBtn.textContent = '[ CANCEL & LOGOUT ]';
    cancelBtn.addEventListener('mouseenter', () => {
      cancelBtn.style.borderColor = '#ff3333';
      cancelBtn.style.background = '#ff3333';
      cancelBtn.style.color = '#000';
    });
    cancelBtn.addEventListener('mouseleave', () => {
      cancelBtn.style.borderColor = '#333';
      cancelBtn.style.background = '#000';
      cancelBtn.style.color = '#ff3333';
    });
    cancelBtn.addEventListener('click', () => { overlay.remove(); this.state.logout(); });

    // Accept button
    const acceptBtn = document.createElement('button');
    acceptBtn.id = 'diag-terms-accept';
    baseStyle(acceptBtn, { ...btnStyle, color:'#fff' });
    acceptBtn.textContent = '[ I ACCEPT FULL RESPONSIBILITY ]';
    acceptBtn.addEventListener('mouseenter', () => {
      acceptBtn.style.borderColor = '#fff';
      acceptBtn.style.background = '#fff';
      acceptBtn.style.color = '#000';
    });
    acceptBtn.addEventListener('mouseleave', () => {
      acceptBtn.style.borderColor = '#333';
      acceptBtn.style.background = '#000';
      acceptBtn.style.color = '#fff';
    });
    acceptBtn.addEventListener('click', async () => {
      try { await this.api.acceptTerms(); overlay.remove(); this.#startGatekeeperFlow(); }
      catch(e) { alert('Error: ' + e.message); }
    });

    appendAll(btnDiv, cancelBtn, acceptBtn);
    appendAll(content, h3, p1, p2, linkDiv, btnDiv);
    appendAll(card, header, content);
    overlay.appendChild(card);
    document.body.appendChild(overlay);
  }
}

// ─── Bootstrap ────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  const api   = new ApiService();
  const state = new AppState(api);
  const ui    = new UIController(state, api);

  state.subscribe((s) => ui.render(s));
  state.notify();
});
