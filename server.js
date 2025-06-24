const express = require('express');
const multer = require('multer');
const fs = require('fs/promises');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;

// === CONFIG ===
const CONSUMER_KEY = 'YOUR_MPESA_CONSUMER_KEY';
const CONSUMER_SECRET = 'YOUR_MPESA_CONSUMER_SECRET';
const SHORT_CODE = '247247';
const PASSKEY = 'YOUR_PASSKEY';
const CALLBACK_URL = 'https://server-1-bmux.onrender.com/api/confirm';
const ADMIN_API_KEY = 'secret-admin-key';

const uploadDir = path.join(__dirname, 'uploads');
const metadataPath = path.join(uploadDir, 'metadata.json');

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(express.json()); // Ensure raw body parsing for JSON payload


// === Init Directories & Metadata Cache ===
let metadataCache = [];

(async () => {
    try {
        await fs.mkdir(uploadDir, { recursive: true });
        const metaExists = await fs.stat(metadataPath).then(() => true).catch(() => false);
        metadataCache = metaExists ? JSON.parse(await fs.readFile(metadataPath)) : [];
    } catch (e) {
        console.error('Init error:', e.message);
    }
})();

// === Multer Upload Setup ===
const storage = multer.diskStorage({
    destination: (_, __, cb) => cb(null, uploadDir),
    filename: (_, file, cb) => {
        const ext = path.extname(file.originalname);
        const base = path.basename(file.originalname, ext).replace(/\s+/g, '_');
        cb(null, `${base}_${Date.now()}${ext}`);
    }
});
const upload = multer({ storage });

// === Token Manager ===
const generateToken = () => crypto.randomBytes(16).toString('hex');
const downloadTokens = new Map();

setInterval(() => {
    const now = Date.now();
    for (const [token, data] of downloadTokens) {
        if (data.expires < now) downloadTokens.delete(token);
    }
}, 60000); // Clean every minute

// === ROUTES ===

// 🔼 Upload File
app.post('/api/upload', upload.single('file'), async (req, res) => {
const { title, subject, class: className, price, type } = req.body;
if (!req.file || !title || !subject || !className || !price || !type)
    return res.status(400).json({ success: false, message: 'Missing fields' });

const fileInfo = {
    id: Date.now(),
    title,
    subject,
    class: className,
    price,
    type, // ✅ Save the type here
    filename: req.file.filename,
    mimetype: req.file.mimetype,
    path: req.file.path,
    uploadDate: new Date().toISOString()
};


    metadataCache.push(fileInfo);
    await fs.writeFile(metadataPath, JSON.stringify(metadataCache, null, 2));

    res.json({ success: true, file: fileInfo });
});
const freeDownloadLogPath = path.join(__dirname, 'free_downloads.json');

// Make sure file exists
(async () => {
  try {
    await fs.access(freeDownloadLogPath);
  } catch {
    await fs.writeFile(freeDownloadLogPath, '[]');
  }
})();


app.get('/api/files/:filename', async (req, res) => {
  const { token } = req.query;
  const filename = req.params.filename;
  const fullPath = path.join(uploadDir, filename);

  const isPreview = token === 'preview';
  const validToken = downloadTokens.get(token);
  const isAdmin = req.headers.apikey === ADMIN_API_KEY;

  // Allow preview OR valid token OR admin
  //if (!isPreview && !isAdmin && (!validToken || validToken.filename !== filename || validToken.expires < Date.now())) {
    //return res.status(403).send('Access Denied');
  //}

  if (validToken) downloadTokens.delete(token);

  try {
    await fs.access(fullPath);
    res.sendFile(fullPath);
  } catch {
    res.status(404).send('File not found');
  }
});

// 🧾 Delete File (no auth)
app.delete('/api/files/:filename', async (req, res) => {
  const filename = req.params.filename;
  const fullPath = path.join(uploadDir, filename);

  try {
    await fs.unlink(fullPath);
    metadataCache = metadataCache.filter(f => f.filename !== filename);
    await fs.writeFile(metadataPath, JSON.stringify(metadataCache, null, 2));
    res.json({ success: true, message: 'File deleted' });
  } catch (e) {
    res.status(404).json({ success: false, message: 'File not found' });
  }
});

// 💸 M-Pesa STK Push
app.post('/api/pay', async (req, res) => {
    const { phone, filename } = req.body;
    if (!phone || !filename) return res.status(400).json({ success: false, message: 'Missing info' });

    try {
        const tokenRes = await axios.get(
            'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
            { auth: { username: CONSUMER_KEY, password: CONSUMER_SECRET } }
        );

        const access_token = tokenRes.data.access_token;
        const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
        const password = Buffer.from(SHORT_CODE + PASSKEY + timestamp).toString('base64');

        await axios.post(
            'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            {
                BusinessShortCode: SHORT_CODE,
                Password: password,
                Timestamp: timestamp,
                TransactionType: 'CustomerPayBillOnline',
                Amount: 1,
                PartyA: phone,
                PartyB: SHORT_CODE,
                PhoneNumber: phone,
                CallBackURL: CALLBACK_URL,
                AccountReference: 'SchemeDownload',
                TransactionDesc: `Payment for ${filename}`
            },
            {
                headers: {
                    Authorization: `Bearer ${access_token}`
                }
            }
        );

        const token = generateToken();
        downloadTokens.set(token, { filename, expires: Date.now() + 5 * 60 * 1000 });
        res.json({ success: true, token });
    } catch (err) {
        console.error('MPESA Error:', err.message);
        res.status(500).json({ success: false, message: 'Payment failed' });
    }
});

const transactionLogPath = path.join(__dirname, 'transactions.json');

// Ensure transactions file exists
(async () => {
  try {
    await fs.access(transactionLogPath);
  } catch {
    await fs.writeFile(transactionLogPath, '[]');
  }
})();

// ✅ CONFIRMATION ENDPOINT FOR SAFARICOM
app.post('/api/confirm', async (req, res) => {
  try {
    const transaction = req.body;

    console.log('📥 M-Pesa Payment Received:', JSON.stringify(transaction, null, 2));

    // Extract some useful info
    const paymentInfo = {
      id: Date.now(),
      mpesaReceipt: transaction?.Body?.stkCallback?.CallbackMetadata?.Item?.find(i => i.Name === 'MpesaReceiptNumber')?.Value || 'N/A',
      amount: transaction?.Body?.stkCallback?.CallbackMetadata?.Item?.find(i => i.Name === 'Amount')?.Value || 'N/A',
      phone: transaction?.Body?.stkCallback?.CallbackMetadata?.Item?.find(i => i.Name === 'PhoneNumber')?.Value || 'N/A',
      timestamp: new Date().toISOString()
    };

    // Save to transactions.json
    const existingLogs = JSON.parse(await fs.readFile(transactionLogPath));
    existingLogs.push(paymentInfo);
    await fs.writeFile(transactionLogPath, JSON.stringify(existingLogs, null, 2));

    res.status(200).send('Confirmation received'); // Required by Safaricom
  } catch (err) {
    console.error('❌ Error handling /api/confirm:', err);
    res.status(500).send('Error');
  }
});

// ⬇️ Download File with Token or Admin Access
app.get('/api/files/:filename', async (req, res) => {
  const filename = req.params.filename;
  const fullPath = path.join(uploadDir, filename);

  // === FREE ACCESS PERIOD ===
  const FREE_UNTIL = new Date("2025-07-01T00:00:00+03:00"); // adjust date/time as needed
  const now = new Date();

  if (now <= FREE_UNTIL) {
    try {
      await fs.access(fullPath);
      console.log(`✅ Free download granted for ${filename}`);
      return res.sendFile(fullPath);
    } catch {
      return res.status(404).send('File not found');
    }
  }

  // === NORMAL ACCESS RULES ===
  const { token } = req.query;
  const validToken = downloadTokens.get(token);
  const isAdmin = req.headers.apikey === ADMIN_API_KEY;

  if (!isAdmin && (!validToken || validToken.filename !== filename || validToken.expires < Date.now())) {
    return res.status(403).send('Access Denied');
  }

  if (validToken) downloadTokens.delete(token);

  try {
    await fs.access(fullPath);
    return res.sendFile(fullPath);
  } catch {
    return res.status(404).send('File not found');
  }
});

// 🚀 Start Server
app.listen(PORT, () => console.log(`✅ Turbo Server running at http://localhost:${PORT}`));
