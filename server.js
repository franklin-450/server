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
const CONSUMER_KEY = 'Glgbr8Pn6JJFqzG1w0nWfxHfdIpyPtlAZYUnzVYNAgrl2G7O';
const CONSUMER_SECRET = '2vbpVGO9t5qAOTMIbU7KmGbwcxZ2LHOhjlurhX02M79TK7W8g1qhNF1h9uO6ftLh';
const SHORT_CODE = '174379';
const PASSKEY = 'bfb279f9aa9bdbcf33b040938b0f8f5c';
const CALLBACK_URL = 'https://server-1-bmux.onrender.com/api/confirm';
const ADMIN_API_KEY = 'secret-admin-key';

const uploadDir = path.join(__dirname, 'uploads');
const metadataPath = path.join(uploadDir, 'metadata.json');

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(express.json());

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

const storage = multer.diskStorage({
    destination: (_, __, cb) => cb(null, uploadDir),
    filename: (_, file, cb) => {
        const ext = path.extname(file.originalname);
        const base = path.basename(file.originalname, ext).replace(/\s+/g, '_');
        cb(null, `${base}_${Date.now()}${ext}`);
    }
});
const upload = multer({ storage });

const generateToken = () => crypto.randomBytes(16).toString('hex');
const downloadTokens = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [token, data] of downloadTokens) {
        if (data.expires < now) downloadTokens.delete(token);
    }
}, 60000);

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
        type,
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
(async () => {
  try {
    await fs.access(freeDownloadLogPath);
  } catch {
    await fs.writeFile(freeDownloadLogPath, '[]');
  }
})();

app.get('/api/files', (_, res) => res.json(metadataCache));

app.get('/api/files/:filename', async (req, res) => {
  const filename = req.params.filename;
  const fullPath = path.join(uploadDir, filename);
  const now = new Date();
  const FREE_UNTIL = new Date("2025-07-01T00:00:00+03:00");

  if (now <= FREE_UNTIL) {
    try {
      await fs.access(fullPath);
      return res.sendFile(fullPath);
    } catch {
      return res.status(404).send('File not found');
    }
  }

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
        console.error('MPESA Error:', err.response?.data || err.message);
        res.status(500).json({ success: false, message: 'Payment failed' });
    }
});

const transactionLogPath = path.join(__dirname, 'transactions.json');
(async () => {
  try {
    await fs.access(transactionLogPath);
  } catch {
    await fs.writeFile(transactionLogPath, '[]');
  }
})();

app.post('/api/confirm', async (req, res) => {
  try {
    const transaction = req.body;
    console.log('📥 M-Pesa Payment Received:', JSON.stringify(transaction, null, 2));

    const paymentInfo = {
      id: Date.now(),
      mpesaReceipt: transaction?.Body?.stkCallback?.CallbackMetadata?.Item?.find(i => i.Name === 'MpesaReceiptNumber')?.Value || 'N/A',
      amount: transaction?.Body?.stkCallback?.CallbackMetadata?.Item?.find(i => i.Name === 'Amount')?.Value || 'N/A',
      phone: transaction?.Body?.stkCallback?.CallbackMetadata?.Item?.find(i => i.Name === 'PhoneNumber')?.Value || 'N/A',
      timestamp: new Date().toISOString()
    };

    const existingLogs = JSON.parse(await fs.readFile(transactionLogPath));
    existingLogs.push(paymentInfo);
    await fs.writeFile(transactionLogPath, JSON.stringify(existingLogs, null, 2));

    res.status(200).send('Confirmation received');
  } catch (err) {
    console.error('❌ Error handling /api/confirm:', err);
    res.status(500).send('Error');
  }
});

app.listen(PORT, () => console.log(`✅ Turbo Server running at http://localhost:${PORT}`));
