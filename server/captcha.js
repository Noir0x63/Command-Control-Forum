const crypto = require('crypto');

const CAPTCHA_SECRET = process.env.CAPTCHA_SECRET || crypto.randomBytes(32).toString('hex');
const POW_DIFFICULTY = 5; // Increased to 5 leading hex zeroes (20 bits of entropy)

// Normalized 10x10 coordinate instructions for character drawing (no text tags)
const CHAR_PATHS = {
  'A': [['M', 0, 10], ['L', 5, 0], ['L', 10, 10], ['M', 2, 6], ['L', 8, 6]],
  'B': [['M', 0, 0], ['L', 7, 0], ['L', 9, 2], ['L', 9, 4], ['L', 7, 5], ['L', 0, 5], ['L', 8, 5], ['L', 10, 7], ['L', 10, 9], ['L', 8, 10], ['L', 0, 10], ['L', 0, 0]],
  'C': [['M', 10, 2], ['L', 8, 0], ['L', 2, 0], ['L', 0, 2], ['L', 0, 8], ['L', 2, 10], ['L', 8, 10], ['L', 10, 8]],
  'D': [['M', 0, 0], ['L', 6, 0], ['L', 10, 3], ['L', 10, 7], ['L', 6, 10], ['L', 0, 10], ['L', 0, 0]],
  'E': [['M', 10, 0], ['L', 0, 0], ['L', 0, 10], ['L', 10, 10], ['M', 0, 5], ['L', 8, 5]],
  'F': [['M', 10, 0], ['L', 0, 0], ['L', 0, 10], ['M', 0, 5], ['L', 8, 5]],
  'G': [['M', 10, 2], ['L', 8, 0], ['L', 2, 0], ['L', 0, 2], ['L', 0, 8], ['L', 2, 10], ['L', 8, 10], ['L', 10, 8], ['L', 10, 5], ['L', 5, 5]],
  'H': [['M', 0, 0], ['L', 0, 10], ['M', 10, 0], ['L', 10, 10], ['M', 0, 5], ['L', 10, 5]],
  'J': [['M', 8, 0], ['L', 8, 8], ['L', 6, 10], ['L', 2, 10], ['L', 0, 8]],
  'K': [['M', 0, 0], ['L', 0, 10], ['M', 0, 5], ['L', 8, 0], ['M', 0, 5], ['L', 8, 10]],
  'L': [['M', 0, 0], ['L', 0, 10], ['L', 10, 10]],
  'M': [['M', 0, 10], ['L', 0, 0], ['L', 5, 5], ['L', 10, 0], ['L', 10, 10]],
  'N': [['M', 0, 10], ['L', 0, 0], ['L', 10, 10], ['L', 10, 0]],
  'P': [['M', 0, 10], ['L', 0, 0], ['L', 8, 0], ['L', 10, 2.5], ['L', 8, 5], ['L', 0, 5]],
  'Q': [['M', 3, 0], ['L', 7, 0], ['L', 10, 3], ['L', 10, 7], ['L', 7, 10], ['L', 3, 10], ['L', 0, 7], ['L', 0, 3], ['L', 3, 0], ['M', 6, 6], ['L', 10, 10]],
  'R': [['M', 0, 10], ['L', 0, 0], ['L', 8, 0], ['L', 10, 2.5], ['L', 8, 5], ['L', 0, 5], ['M', 5, 5], ['L', 10, 10]],
  'S': [['M', 10, 2], ['L', 8, 0], ['L', 2, 0], ['L', 0, 2], ['L', 0, 4], ['L', 10, 6], ['L', 10, 8], ['L', 8, 10], ['L', 2, 10], ['L', 0, 8]],
  'T': [['M', 0, 0], ['L', 10, 0], ['M', 5, 0], ['L', 5, 10]],
  'U': [['M', 0, 0], ['L', 0, 8], ['L', 2, 10], ['L', 8, 10], ['L', 10, 8], ['L', 10, 0]],
  'V': [['M', 0, 0], ['L', 5, 10], ['L', 10, 0]],
  'W': [['M', 0, 0], ['L', 2, 10], ['L', 5, 5], ['L', 8, 10], ['L', 10, 0]],
  'X': [['M', 0, 0], ['L', 10, 10], ['M', 10, 0], ['L', 0, 10]],
  'Y': [['M', 0, 0], ['L', 5, 5], ['L', 10, 0], ['M', 5, 5], ['L', 5, 10]],
  'Z': [['M', 0, 0], ['L', 10, 0], ['L', 0, 10], ['L', 10, 10]],
  '2': [['M', 0, 2], ['L', 2, 0], ['L', 8, 0], ['L', 10, 2], ['L', 10, 5], ['L', 0, 10], ['L', 10, 10]],
  '3': [['M', 0, 0], ['L', 10, 0], ['L', 5, 5], ['L', 10, 5], ['L', 10, 8], ['L', 8, 10], ['L', 0, 10]],
  '4': [['M', 0, 0], ['L', 0, 6], ['L', 10, 6], ['M', 8, 0], ['L', 8, 10]],
  '5': [['M', 10, 0], ['L', 0, 0], ['L', 0, 4], ['L', 8, 4], ['L', 10, 6], ['L', 10, 8], ['L', 8, 10], ['L', 0, 10]],
  '6': [['M', 8, 0], ['L', 2, 0], ['L', 0, 2], ['L', 0, 8], ['L', 2, 10], ['L', 8, 10], ['L', 10, 8], ['L', 10, 6], ['L', 8, 5], ['L', 0, 5]],
  '7': [['M', 0, 0], ['L', 10, 0], ['L', 4, 10]],
  '8': [['M', 3, 0], ['L', 7, 0], ['L', 10, 2], ['L', 10, 4], ['L', 7, 5], ['L', 3, 5], ['L', 0, 4], ['L', 0, 2], ['L', 3, 0], ['M', 3, 5], ['L', 7, 5], ['L', 10, 6], ['L', 10, 8], ['L', 7, 10], ['L', 3, 10], ['L', 0, 8], ['L', 0, 6], ['L', 3, 5]],
  '9': [['M', 10, 5], ['L', 3, 5], ['L', 0, 4], ['L', 0, 2], ['L', 3, 0], ['L', 7, 0], ['L', 10, 2], ['L', 10, 8], ['L', 8, 10], ['L', 2, 10]]
};

function generateCaptchaText(length = 5) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let text = '';
  for (let i = 0; i < length; i++) {
    text += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return text;
}

// Applies dynamic node-level jitter/deform to SVG paths to prevent static pattern mapping
function generateDynamicPath(char) {
  const commands = CHAR_PATHS[char];
  if (!commands) return '';
  
  return commands.map(([cmd, x, y]) => {
    if (x === undefined || y === undefined) return cmd;
    // Add ±0.4 random node coordinate distortion
    const dx = Math.random() * 0.8 - 0.4;
    const dy = Math.random() * 0.8 - 0.4;
    return `${cmd} ${(x + dx).toFixed(2)} ${(y + dy).toFixed(2)}`;
  }).join(' ');
}

function generateCaptchaSvg(text) {
  const width = 150;
  const height = 50;
  
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">`;
  svg += `<rect width="100%" height="100%" fill="#050505"/>`;
  
  // Noise lines
  for (let i = 0; i < 4; i++) {
    const x1 = Math.floor(Math.random() * width);
    const y1 = Math.floor(Math.random() * height);
    const x2 = Math.floor(Math.random() * width);
    const y2 = Math.floor(Math.random() * height);
    const colors = ['#00ff66', '#007f3f', '#003f1f', '#39ff14'];
    const color = colors[Math.floor(Math.random() * colors.length)];
    svg += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" stroke-width="${Math.random() * 1.5 + 0.5}" opacity="0.6"/>`;
  }
  
  // Noise dots
  for (let i = 0; i < 30; i++) {
    const cx = Math.floor(Math.random() * width);
    const cy = Math.floor(Math.random() * height);
    const r = Math.random() * 1.5 + 0.5;
    svg += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="#00ff66" opacity="0.4"/>`;
  }
  
  // Render each character as an isolated vector path group
  const charWidth = Math.floor(width / (text.length + 1));
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const pathD = generateDynamicPath(char);
    
    // Random placement, scale, and rotation matrix values
    const scale = 2.0 + Math.random() * 0.4; // Scale 10x10 up to ~22x22
    const angle = Math.floor(Math.random() * 40) - 20; // Rotate -20deg to 20deg
    const x = charWidth * (i + 1) - 10 + (Math.random() * 6 - 3);
    const y = 15 + (Math.random() * 8 - 4);
    const color = Math.random() > 0.5 ? '#00ff66' : '#a3e635';
    
    // Group-level transform with geometric path drawing (no raw text elements)
    svg += `<g transform="translate(${x}, ${y}) rotate(${angle}, 5, 5) scale(${scale})">`;
    svg += `<path d="${pathD}" stroke="${color}" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round" opacity="0.95"/>`;
    svg += `</g>`;
  }
  
  svg += `</svg>`;
  return svg;
}

function createCaptchaToken(text) {
  const nonce = crypto.randomUUID();
  const timestamp = Date.now();
  const signature = crypto.createHmac('sha256', CAPTCHA_SECRET)
    .update(`${text.toUpperCase()}:${timestamp}:${nonce}`)
    .digest('hex');
  return `${timestamp}:${nonce}:${signature}`;
}

function verifyCaptcha(token, text) {
  if (!token || !text) return false;
  const parts = token.split(':');
  if (parts.length !== 3) return false;
  
  const [timestampStr, nonce, signature] = parts;
  const timestamp = parseInt(timestampStr, 10);
  
  if (Date.now() - timestamp > 180000) return false;
  
  const expectedSignature = crypto.createHmac('sha256', CAPTCHA_SECRET)
    .update(`${text.toUpperCase()}:${timestampStr}:${nonce}`)
    .digest('hex');
    
  try {
    return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSignature, 'hex'));
  } catch {
    return false;
  }
}

function verifyPoW(challenge, salt) {
  if (!challenge || !salt) return false;
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
  POW_DIFFICULTY
};
