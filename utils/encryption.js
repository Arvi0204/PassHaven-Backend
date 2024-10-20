// encryption.js
const crypto = require('crypto');
const dotenv = require('dotenv');

dotenv.config();

const algorithm = 'aes-256-cbc';

// Use a fixed key (32 bytes for aes-256)
const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
const ivLength = 16; // For aes, this is always 16

// Encrypt the password
const encrypt = (text) => {
    let iv = crypto.randomBytes(ivLength); // Generate a new IV for each encryption
    let cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
        iv: iv.toString('hex'),
        encryptedData: encrypted
    };
};

// Decrypt the password
const decrypt = (encryption) => {
    let decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(encryption.iv, 'hex'));
    let decrypted = decipher.update(encryption.encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};

module.exports = { encrypt, decrypt };
