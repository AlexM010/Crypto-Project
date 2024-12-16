const crypto = require('crypto');

// 3DES usage with Cipheriv
const key = Buffer.from('123456781234567812345678');  // 3DES requires 24-byte key
const iv = Buffer.from('12345678');   // 8-byte IV
const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
let encrypted = cipher.update('some data', 'utf8', 'hex');
encrypted += cipher.final('hex');
console.log(encrypted);

// 3DES decryption
const decipher = crypto.createDecipheriv('des-ede3', key, iv);
let decrypted = decipher.update(encrypted, 'hex', 'utf8');
decrypted += decipher.final('utf8');
console.log(decrypted);
