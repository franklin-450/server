const express = require('express');
const multer = require('multer');
const fs = require('fs/promises');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const bodyParser = require('body-parser');
const moment = require("moment");
const router = express.Router();

const app = express();
const PORT = 3000;

// === CONFIGURATION ===
const ADMIN_SECRET = ['adminsecret', 'wizard123', 'godmode', 'schemehub250', 'klinton']; // admin keys

const uploadDir = path.join(__dirname, 'uploads');
const metadataPath = path.join(uploadDir, 'metadata.json');
const transactionLogPath = path.join(__dirname, 'transactions.json');
const freeDownloadLogPath = path.join(__dirname, 'free_downloads.json');

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(express.json());
app.use('/files', express.static(path.join(__dirname, 'uploads')));

// ✅ Health check
app.get('/', (req, res) => res.send('🎉 Turbo Server with M-Pesa & File Manager is running.'));

// === STATE ===
let metadataCache = [];
const confirmations = new Map(); 
const downloadTokens = new Map();

// === INIT ===
(async () => {
  try {
    await fs.mkdir(uploadDir, { recursive: true });
    if (!(await fileExists(metadataPath))) await fs.writeFile(metadataPath, '[]');
    if (!(await fileExists(transactionLogPath))) await fs.writeFile(transactionLogPath, '[]');
    if (!(await fileExists(freeDownloadLogPath))) await fs.writeFile(freeDownloadLogPath, '[]');
    metadataCache = JSON.parse(await fs.readFile(metadataPath));
  } catch (e) {
    console.error('Init error:', e.message);
  }
})();

async function fileExists(filePath) {
  try { await fs.access(filePath); return true; } catch { return false; }
}

// === FILE UPLOAD ===
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname);
    const base = path.basename(file.originalname, ext).replace(/\s+/g, '_');
    cb(null, `${base}_${Date.now()}${ext}`);
  }
});
const upload = multer({ storage });

// === TOKEN CLEANUP ===
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of downloadTokens) {
    if (data.expires < now) downloadTokens.delete(token);
  }
}, 60000);

// === ROUTES ===

// Upload new file
app.post('/api/upload', upload.single('file'), async (req, res) => {
  const { title, subject, class: className, price, type, category } = req.body;
  if (!req.file || !title || !subject || !className || !price || !type || !category) {
    return res.status(400).json({ success: false, message: 'Missing fields' });
  }

  const fileInfo = {
    id: Date.now(),
    title,
    subject,
    class: className,
    category,
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

// List all files
app.get('/api/files', (_, res) => res.json(metadataCache));

// Download a file with token / admin / free access
app.get('/api/files/:filename', async (req, res) => {
  const { filename } = req.params;
  const { token } = req.query;
  const fullPath = path.join(uploadDir, filename);
  const FREE_UNTIL = new Date('2025-07-01T00:00:00+03:00');
  const now = new Date();

  const isAdmin = ADMIN_SECRET.includes(req.headers.apikey);
  const validToken = downloadTokens.get(token);

  if (now <= FREE_UNTIL || isAdmin || (validToken && validToken.filename === filename && validToken.expires >= Date.now())) {
    try {
      await fs.access(fullPath);
      if (validToken) downloadTokens.delete(token);
      return res.sendFile(fullPath);
    } catch {
      return res.status(404).send('File not found');
    }
  }

  return res.status(403).send('Access Denied');
});

// Delete file (admin only)
app.delete('/api/files/:filename', async (req, res) => {
  const { filename } = req.params;
  const key = req.headers.apikey;

  if (ADMIN_SECRET.includes(key)) {
    return res.status(403).json({ success: false, message: "Unauthorized" });
  }

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

// === M-PESA CONFIG ===
const consumerkey = "NkxcAadvkohxGErrIm84VAccHA3nfSSRd5DH0mIe9sv9DDCn";
const consumerSecret = "x636VF0x52vZBorz0Xjunw1dKZjHq7bdCbZnQeYkjemV6eA30qgtk6vylr9DSe8v";
const shortCode = "174379";
const passKey = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919";

async function getAccessToken() {
  const auth = Buffer.from(`${consumerkey}:${consumerSecret}`).toString("base64");
  const res = await axios.get(
    "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
    { headers: { Authorization: `Basic ${auth}` } }
  );
  return res.data.access_token;
}

// === STK PUSH ===
app.post("/api/pay", async (req, res) => {
  const phone = req.body.phone; // already formatted
  const { phoneNumber, fileName, filePrice } = req.body;

  try {
    const token = await getAccessToken();
    const timestamp = moment().format("YYYYMMDDHHmmss");
    const password = Buffer.from(shortCode + passKey + timestamp).toString("base64");

    const stkRes = await axios.post(
      "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
      {
        BusinessShortCode: shortCode,
        Password: password,
        Timestamp: timestamp,
        TransactionType: "CustomerPayBillOnline",
        Amount: filePrice,
        PartyA: phoneNumber,
        PartyB: shortCode,
        PhoneNumber: phoneNumber,
        CallBackURL: "https://server-1-bmux.onrender.com/api/confirm", // ✅ Replace with your domain
        AccountReference: fileName,
        TransactionDesc: `Payment for ${fileName}`,
      },
      { headers: { Authorization: `Bearer ${token}` } }
    );

    console.log("✅ STK Push Response:", stkRes.data);
    res.json({ success: true, data: stkRes.data });
  } catch (error) {
    console.error("❌ Error in STK Push:", error.response?.data || error.message);
    res.status(500).json({ success: false, error: error.response?.data || error.message });
  }
});

// === CONFIRMATION CALLBACK ===
app.post('/api/confirm', async (req, res) => {
  try {
    const transaction = req.body;
    console.log('📥 M-Pesa Payment Received:', JSON.stringify(transaction, null, 2));

    const callback = transaction?.Body?.stkCallback;
    const checkoutId = callback?.CheckoutRequestID;
    const status = callback?.ResultCode;

    confirmations.set(checkoutId, status === 0);

    const item = name => callback?.CallbackMetadata?.Item?.find(i => i.Name === name)?.Value || 'N/A';

    const paymentInfo = {
      id: Date.now(),
      checkoutId,
      mpesaReceipt: item('MpesaReceiptNumber'),
      amount: item('Amount'),
      phone: item('PhoneNumber'),
      timestamp: new Date().toISOString(),
      status: status === 0 ? 'SUCCESS' : 'FAILED'
    };

    const logs = JSON.parse(await fs.readFile(transactionLogPath));
    logs.push(paymentInfo);
    await fs.writeFile(transactionLogPath, JSON.stringify(logs, null, 2));

    if (status === 0) {
      const fileName = item('AccountReference');
      const token = crypto.randomBytes(16).toString('hex');
      downloadTokens.set(token, { filename: fileName, expires: Date.now() + 60 * 60 * 1000 });

      console.log(`✅ Payment success. Token generated for ${fileName}: ${token}`);

      return res.status(200).json({
        success: true,
        message: 'Payment confirmed',
        token,
        downloadURL: `/api/files/${fileName}?token=${token}`
      });
    }

    res.status(200).json({ success: false, message: 'Payment failed' });
  } catch (err) {
    console.error('❌ Error handling /api/confirm:', err);
    res.status(500).send('Error');
  }
});

// === ADMIN LOGIN ===
app.post('/api/admin-login', (req, res) => {
  const { key } = req.body;
  if (ADMIN_SECRET.includes(key)) return res.json({ success: true });
  res.status(401).json({ success: false, message: "Invalid key" });
});

// === PAYMENT STATUS ===
app.get('/api/status/:id', (req, res) => {
  const status = confirmations.get(req.params.id);
  res.json({ paid: status || false });
});

const transactionsFile = path.join(__dirname, 'transactions.json');

// Utility to read transactions
async function readTransactions() {
  try {
    const raw = await fs.readFile(transactionsFile, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    return [];
  }
}

// Utility to write transactions
async function writeTransactions(transactions) {
  await fs.writeFile(transactionsFile, JSON.stringify(transactions, null, 2));
}

// POST: log a transaction
router.post('/api/transactions', async (req, res) => {
  const { filename, token, phoneNumber, filePrice, mpesaTransactionID } = req.body;
  if (!filename || !token || !phoneNumber || !filePrice || !mpesaTransactionID) {
    return res.status(400).json({ success: false, message: 'Missing fields' });
  }

  try {
    const transactions = await readTransactions();
    transactions.push({
      filename,
      token,
      phoneNumber,
      filePrice,
      mpesaTransactionID,
      date: new Date().toISOString()
    });
    await writeTransactions(transactions);
    res.json({ success: true, message: 'Transaction logged' });
  } catch (err) {
    console.error('Transaction API error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// GET: fetch all transactions
router.get('/api/transactions', async (req, res) => {
  try {
    const transactions = await readTransactions();
    res.json(transactions);
  } catch (err) {
    console.error('Transaction API fetch error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;
// Mount the router so /api/transactions works
app.use('/', router);


// === SERVER START ===
app.listen(PORT, () => console.log(`✅ Turbo Server running at http://localhost:${PORT}`));





