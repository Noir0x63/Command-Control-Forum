'use strict';

const crypto = require('crypto');

const CAPTCHA_SECRET = process.env.CAPTCHA_SECRET || crypto.randomBytes(32).toString('hex');
const POW_DIFFICULTY = 5;
const CAPTCHA_TTL_MS = 180000;
const POW_SALT_MAX_LENGTH = 20;

// ─── Seeded PRNG (xoshiro128**) for deterministic procedural generation ────────
// Using a hash-derived seed ensures each CAPTCHA session produces unique but
// reproducible visuals, while preventing attackers from predicting the seed.

function createRng(seedHex) {
  const buf = Buffer.from(seedHex, 'hex');
  let s0 = buf.readUInt32BE(0);
  let s1 = buf.readUInt32BE(4);
  let s2 = buf.readUInt32BE(8);
  let s3 = buf.readUInt32BE(12);

  const rotl = (x, k) => ((x << k) | (x >>> (32 - k))) >>> 0;

  function next() {
    const result = Math.imul(rotl(Math.imul(s1, 5), 7), 9) >>> 0;
    const t = (s1 << 9) >>> 0;
    s2 ^= s0;
    s3 ^= s1;
    s1 ^= s2;
    s0 ^= s3;
    s2 ^= t;
    s3 = rotl(s3, 11);
    return result;
  }

  return {
    next: () => next(),
    float: () => next() / 4294967296,
    int: (min, max) => min + Math.floor((next() / 4294967296) * (max - min + 1)),
    shuffle: (arr) => {
      const a = arr.slice();
      for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor((next() / 4294967296) * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
      }
      return a;
    },
  };
}

// ─── Procedural Character Definition (Anchor Points + Deformation) ─────────────
// Each character is defined as a set of strokes. Each stroke is an array of
// anchor points in a 0-10 normalized space. The renderer converts these to
// cubic Bezier curves with randomized control points and per-request deformation.

const CHAR_STROKES = {
  'A': [[[0,10],[5,0],[10,10]], [[2,6],[8,6]]],
  'B': [[[0,0],[7,0],[9,2],[9,4],[7,5],[0,5]], [[0,5],[8,5],[10,7],[10,9],[8,10],[0,10]]],
  'C': [[[10,2],[8,0],[2,0],[0,2],[0,8],[2,10],[8,10],[10,8]]],
  'D': [[[0,0],[6,0],[10,3],[10,7],[6,10],[0,10],[0,0]]],
  'E': [[[10,0],[0,0],[0,10],[10,10]], [[0,5],[8,5]]],
  'F': [[[10,0],[0,0],[0,10]], [[0,5],[8,5]]],
  'G': [[[10,2],[8,0],[2,0],[0,2],[0,8],[2,10],[8,10],[10,8],[10,5],[5,5]]],
  'H': [[[0,0],[0,10]], [[10,0],[10,10]], [[0,5],[10,5]]],
  'J': [[[8,0],[8,8],[6,10],[2,10],[0,8]]],
  'K': [[[0,0],[0,10]], [[0,5],[8,0]], [[0,5],[8,10]]],
  'L': [[[0,0],[0,10],[10,10]]],
  'M': [[[0,10],[0,0],[5,5],[10,0],[10,10]]],
  'N': [[[0,10],[0,0],[10,10],[10,0]]],
  'P': [[[0,10],[0,0],[8,0],[10,2.5],[8,5],[0,5]]],
  'Q': [[[3,0],[7,0],[10,3],[10,7],[7,10],[3,10],[0,7],[0,3],[3,0]], [[6,6],[10,10]]],
  'R': [[[0,10],[0,0],[8,0],[10,2.5],[8,5],[0,5]], [[5,5],[10,10]]],
  'S': [[[10,2],[8,0],[2,0],[0,2],[0,4],[10,6],[10,8],[8,10],[2,10],[0,8]]],
  'T': [[[0,0],[10,0]], [[5,0],[5,10]]],
  'U': [[[0,0],[0,8],[2,10],[8,10],[10,8],[10,0]]],
  'V': [[[0,0],[5,10],[10,0]]],
  'W': [[[0,0],[2,10],[5,5],[8,10],[10,0]]],
  'X': [[[0,0],[10,10]], [[10,0],[0,10]]],
  'Y': [[[0,0],[5,5],[10,0]], [[5,5],[5,10]]],
  'Z': [[[0,0],[10,0],[0,10],[10,10]]],
  '2': [[[0,2],[2,0],[8,0],[10,2],[10,5],[0,10],[10,10]]],
  '3': [[[0,0],[10,0],[5,5],[10,5],[10,8],[8,10],[0,10]]],
  '4': [[[0,0],[0,6],[10,6]], [[8,0],[8,10]]],
  '5': [[[10,0],[0,0],[0,4],[8,4],[10,6],[10,8],[8,10],[0,10]]],
  '6': [[[8,0],[2,0],[0,2],[0,8],[2,10],[8,10],[10,8],[10,6],[8,5],[0,5]]],
  '7': [[[0,0],[10,0],[4,10]]],
  '8': [[[3,0],[7,0],[10,2],[10,4],[7,5],[3,5],[0,4],[0,2],[3,0]], [[3,5],[7,5],[10,6],[10,8],[7,10],[3,10],[0,8],[0,6],[3,5]]],
  '9': [[[10,5],[3,5],[0,4],[0,2],[3,0],[7,0],[10,2],[10,8],[8,10],[2,10]]],
};

const CAPTCHA_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

// ─── Cubic Bezier Path Generator ───────────────────────────────────────────────
// Converts anchor points to smooth cubic Bezier curves with randomized control
// points. Uses the seeded RNG so the result is deterministic per token but unique.

function anchorPointsToBezierPath(anchors, rng) {
  if (anchors.length < 2) return '';

  const pts = anchors.map(([ax, ay]) => ({
    x: ax + (rng.float() * 1.6 - 0.8),
    y: ay + (rng.float() * 1.6 - 0.8),
  }));

  if (pts.length === 2) {
    const dx = Math.abs(pts[1].x - pts[0].x);
    const dy = Math.abs(pts[1].y - pts[0].y);
    const tension = 0.25 + rng.float() * 0.3;
    const cx1 = pts[0].x + dx * tension + (rng.float() * 0.6 - 0.3);
    const cy1 = pts[0].y + dy * tension + (rng.float() * 0.6 - 0.3);
    const cx2 = pts[1].x - dx * tension + (rng.float() * 0.6 - 0.3);
    const cy2 = pts[1].y - dy * tension + (rng.float() * 0.6 - 0.3);
    return `M${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)} C${cx1.toFixed(2)} ${cy1.toFixed(2)} ${cx2.toFixed(2)} ${cy2.toFixed(2)} ${pts[1].x.toFixed(2)} ${pts[1].y.toFixed(2)}`;
  }

  let path = `M${pts[0].x.toFixed(2)} ${pts[0].y.toFixed(2)}`;

  for (let i = 0; i < pts.length - 1; i++) {
    const a = pts[i];
    const b = pts[i + 1];
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    const tension = Math.min(dist * 0.35, 3.0) * (0.7 + rng.float() * 0.6);

    const angle = Math.atan2(dy, dx);
    const skew = (rng.float() * 0.8 - 0.4);

    const cp1x = a.x + Math.cos(angle) * tension + Math.cos(angle + Math.PI / 2) * skew * tension;
    const cp1y = a.y + Math.sin(angle) * tension + Math.sin(angle + Math.PI / 2) * skew * tension;
    const cp2x = b.x - Math.cos(angle) * tension + Math.cos(angle + Math.PI / 2) * skew * tension;
    const cp2y = b.y - Math.sin(angle) * tension + Math.sin(angle + Math.PI / 2) * skew * tension;

    path += ` C${cp1x.toFixed(2)} ${cp1y.toFixed(2)} ${cp2x.toFixed(2)} ${cp2y.toFixed(2)} ${b.x.toFixed(2)} ${b.y.toFixed(2)}`;
  }

  return path;
}

// ─── Declarative SVG generation helpers ───────────────────────────────────────

function generateCaptchaText(length = 5) {
  let text = '';
  for (let i = 0; i < length; i++) {
    text += CAPTCHA_CHARS.charAt(Math.floor(Math.random() * CAPTCHA_CHARS.length));
  }
  return text;
}

function generateCaptchaSvg(text) {
  const width = 180;
  const height = 55;

  const seedMaterial = `${text.toUpperCase()}:${CAPTCHA_SECRET}`;
  const seedHash = crypto.createHash('sha256').update(seedMaterial).digest('hex');
  const rng = createRng(seedHash);

  let svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">`;
  svg += `<rect width="100%" height="100%" fill="#050505"/>`;

  const colors = rng.shuffle(['#00ff66', '#007f3f', '#003f1f', '#39ff14', '#00cc44', '#006633']);

  // Phase 1: Interference grid (cross-hatching behind characters)
  for (let i = 0; i < 5; i++) {
    const x1 = rng.int(0, width);
    const y1 = rng.int(0, height);
    const x2 = rng.int(0, width);
    const y2 = rng.int(0, height);
    svg += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${colors[i % colors.length]}" stroke-width="${(rng.float() * 1.8 + 0.3).toFixed(2)}" opacity="${(rng.float() * 0.3 + 0.15).toFixed(2)}"/>`;
  }

  // Phase 2: Noise dot field
  for (let i = 0; i < 40; i++) {
    const cx = rng.int(0, width);
    const cy = rng.int(0, height);
    const r = (rng.float() * 1.8 + 0.3).toFixed(2);
    const opacity = (rng.float() * 0.35 + 0.1).toFixed(2);
    svg += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${colors[rng.int(0, colors.length - 1)]}" opacity="${opacity}"/>`;
  }

  const charSlotWidth = Math.floor(width / (text.length + 1));

  // Phase 3: Render characters with procedural Bezier deformation
  for (let i = 0; i < text.length; i++) {
    const ch = text[i].toUpperCase();
    const strokes = CHAR_STROKES[ch];
    if (!strokes) continue;

    const xOff = charSlotWidth * (i + 1) - 12 + (rng.float() * 8 - 4);
    const yOff = 15 + (rng.float() * 10 - 5);
    const sc = 1.8 + rng.float() * 0.6;
    const angle = rng.int(-25, 25);
    const color = colors[rng.int(0, colors.length - 1)];
    const strokeW = (rng.float() * 1.0 + 1.6).toFixed(2);

    svg += `<g transform="translate(${xOff.toFixed(2)}, ${yOff.toFixed(2)}) rotate(${angle}, 5, 5) scale(${sc.toFixed(2)})">`;

    for (const strokeAnchors of strokes) {
      const pathD = anchorPointsToBezierPath(strokeAnchors, rng);
      svg += `<path d="${pathD}" stroke="${color}" stroke-width="${strokeW}" fill="none" stroke-linecap="round" stroke-linejoin="round" opacity="${(rng.float() * 0.10 + 0.88).toFixed(2)}"/>`;
    }

    svg += `</g>`;
  }

  // Phase 4: Decoy path fragments (random short curves near characters)
  for (let i = 0; i < 3; i++) {
    const dx = rng.int(10, width - 10);
    const dy = rng.int(10, height - 10);
    const len = rng.int(6, 16);
    const ang = rng.float() * Math.PI * 2;
    const ex = dx + Math.cos(ang) * len;
    const ey = dy + Math.sin(ang) * len;
    const decoyColor = colors[rng.int(0, colors.length - 1)];
    const pathD = anchorPointsToBezierPath([[dx, dy], [ex, ey]], rng);
    svg += `<path d="${pathD}" stroke="${decoyColor}" stroke-width="${(rng.float() * 0.6 + 0.6).toFixed(2)}" fill="none" stroke-linecap="round" opacity="${(rng.float() * 0.3 + 0.25).toFixed(2)}"/>`;
  }

  // Phase 5: Foreground interference lines (intersect character strokes)
  for (let i = 0; i < 3; i++) {
    const charIdx = rng.int(0, text.length - 1);
    const charCenterX = charSlotWidth * (charIdx + 1);
    const charCenterY = 25;
    const spread = charSlotWidth * 0.8;

    const x1 = charCenterX - spread / 2 + rng.float() * spread;
    const y1 = charCenterY - 18 + rng.float() * 36;
    const x2 = charCenterX - spread / 2 + rng.float() * spread;
    const y2 = charCenterY - 18 + rng.float() * 36;

    svg += `<line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}" stroke="${colors[rng.int(0, colors.length - 1)]}" stroke-width="${(rng.float() * 1.4 + 0.4).toFixed(2)}" opacity="0.7"/>`;
  }

  svg += `</svg>`;
  return svg;
}

// ─── CAPTCHA Token (HMAC-based, server-side verified) ─────────────────────────

function createCaptchaToken(text) {
  const nonce = crypto.randomBytes(16);
  const nonceHex = nonce.toString('hex');
  const timestamp = Date.now();
  const signature = crypto.createHmac('sha256', CAPTCHA_SECRET)
    .update(`${text.toUpperCase()}:${timestamp}:${nonceHex}`)
    .digest('hex');
  return `${timestamp}:${nonceHex}:${signature}`;
}

function verifyCaptcha(token, text) {
  if (!token || !text) return false;
  const parts = token.split(':');
  if (parts.length !== 3) return false;

  const [timestampStr, nonce, signature] = parts;
  const timestamp = parseInt(timestampStr, 10);

  if (isNaN(timestamp) || Date.now() - timestamp > CAPTCHA_TTL_MS) return false;

  const expectedSignature = crypto.createHmac('sha256', CAPTCHA_SECRET)
    .update(`${text.toUpperCase()}:${timestampStr}:${nonce}`)
    .digest('hex');

  try {
    const sigBuf = Buffer.from(signature, 'hex');
    const expBuf = Buffer.from(expectedSignature, 'hex');
    if (sigBuf.length !== expBuf.length) return false;
    return crypto.timingSafeEqual(sigBuf, expBuf);
  } catch {
    return false;
  }
}

// ─── Proof of Work ─────────────────────────────────────────────────────────────

function verifyPoW(challenge, salt) {
  if (!challenge || typeof salt !== 'string') return false;
  if (!/^[0-9a-f]{32}$/i.test(challenge)) return false;
  if (salt.length > POW_SALT_MAX_LENGTH) return false;

  const hash = crypto.createHash('sha256')
    .update(challenge + salt)
    .digest('hex');

  const target = '0'.repeat(POW_DIFFICULTY);
  return hash.startsWith(target);
}

module.exports = {
  generateCaptchaText,
  generateCaptchaSvg,
  createCaptchaToken,
  verifyCaptcha,
  verifyPoW,
  POW_DIFFICULTY,
  CAPTCHA_SECRET_INTERNAL: CAPTCHA_SECRET,
};
