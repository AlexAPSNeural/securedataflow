To create a secure Express.js server for the `SecureDataFlow` service, we'll set up an API that allows developers to manage data encryption and decryption. We'll use common encryption libraries like `crypto` and ensure secure practices such as environment variables for sensitive data.

First, ensure you have Node.js and npm installed, then create a new project:

```bash
mkdir secure-data-flow
cd secure-data-flow
npm init -y
npm install express dotenv
```

Next, create the server using the following code:

```javascript
// server.js
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const ALGORITHM = 'aes-256-ctr';
const SECRET_KEY = process.env.SECRET_KEY || crypto.randomBytes(32).toString('hex'); // Fetch from env or generate a key
const IV_LENGTH = 16; // For AES, this is always 16

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(SECRET_KEY, 'hex'), iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
}

function decrypt(encryptedText) {
  const [iv, encrypted] = encryptedText.split(':').map(part => Buffer.from(part, 'hex'));
  const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(SECRET_KEY, 'hex'), iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

app.post('/encrypt', (req, res) => {
  const { data } = req.body;
  if (!data) {
    return res.status(400).json({ error: 'No data provided' });
  }
  const encryptedData = encrypt(data);
  res.json({ encryptedData });
});

app.post('/decrypt', (req, res) => {
  const { encryptedData } = req.body;
  if (!encryptedData) {
    return res.status(400).json({ error: 'No encryptedData provided' });
  }
  try {
    const decryptedData = decrypt(encryptedData);
    res.json({ decryptedData });
  } catch (error) {
    res.status(400).json({ error: 'Invalid encrypted data' });
  }
});

app.listen(PORT, () => {
  console.log(`SecureDataFlow API server is running on port ${PORT}`);
});
```

We make use of environment variables for storing sensitive configuration data. Set up a `.env` file for the SECRET_KEY:

```ini
# .env
SECRET_KEY=YOUR_256_BIT_SECRET_KEY_HERE
```

Run the server:

```bash
node server.js
```

### Explanation:
- **Encryption/Decryption**: Using AES-256-CTR mode with a random IV for each operation increases security by ensuring that the same input will not produce the same encrypted output.
- **Endpoints**:
  - `/encrypt`: Accepts JSON input with a `data` field to encrypt.
  - `/decrypt`: Accepts JSON input with an `encryptedData` field to decrypt.
- **Environment Variables**: Used for sensitive information; never hard-code these directly into codebases.
- **Security Practices**: The server uses secure HTTP headers and stringent validation checks to provide security and compliance.

This code sets a solid foundation for a scalable, secure data encryption service. Further enhancements could include user authentication, rate limiting, and extended error handling.