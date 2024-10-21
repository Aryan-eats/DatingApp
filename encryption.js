const crypto = require('crypto');

const algorithm = 'aes-256-cbc'; // Encryption algorithm
const encryptionKey = crypto.randomBytes(32); // 256-bit key
const ivLength = 16; // Initialization vector length

// Encrypt a message
function encryptMessage(text) {
  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
}

// Decrypt a message
function decryptMessage(encryptedMessage) {
  const [ivHex, encryptedText] = encryptedMessage.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv(algorithm, encryptionKey, iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = { encryptMessage, decryptMessage };
