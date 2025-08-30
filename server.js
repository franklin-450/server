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
const transactionLogPath = "./transactions.json";
const transactionsPath = path.join(__dirname, "transactions.json");
const tokensPath = "./tokens.json";
const freeDownloadLogPath = path.join(__dirname, 'free_downloads.json');

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// ✅ Health check
app.get('/', (req, res) => res.send('🎉 Turbo Server with M-Pesa & File Manager is running.'));

// === STATE ===
let metadataCache = [];
const confirmations = new Map(); 
const downloadTokens = new Map();
const checkoutFileMap = new Map();

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
  const fileUrl = `/uploads/${req.file.filename}`;
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
    path: fileUrl,
    uploadDate: new Date().toISOString()
  };

  metadataCache.push(fileInfo);
  await fs.writeFile(metadataPath, JSON.stringify(metadataCache, null, 2));
  res.json({ success: true, file: fileInfo });
});

// List all files
app.get('/api/files', (_, res) => res.json(metadataCache));

app.get('/api/files/:filename', async (req, res) => {
  try {
    const { filename } = req.params;
    const { token } = req.query;

    // Check token
    const entry = downloadTokens.get(token);
    if (!entry || entry.expires < Date.now() || entry.filename !== filename) {
      return res.status(403).send('❌ Invalid or expired token');
    }

    // File path (adjust as needed)
    const filePath = path.join(__dirname, 'files', filename);

    // Send file
    res.download(filePath, filename, (err) => {
      if (err) console.error('❌ Error sending file:', err);
    });
  } catch (err) {
    console.error('❌ Error in /api/files:', err);
    res.status(500).send('Server error');
  }
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
  const { phoneNumber, fileName, filePrice } = req.body;

  // Sanitize filename
  const sanitizedFileName = fileName
    ? fileName.replace(/[^\w.-]/g, "_").trim()
    : "UNKNOWN";

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
        CallBackURL: "https://server-1-bmux.onrender.com/api/confirm",
        AccountReference: sanitizedFileName,
        TransactionDesc: `Purchase ${sanitizedFileName}`
      },
      { headers: { Authorization: `Bearer ${token}` } }
    );
    checkoutFileMap.set(stkRes.data.CheckoutRequestID, sanitizedFileName);
    
    console.log("✅ STK Push Response:", stkRes.data);
    res.json({ success: true, data: stkRes.data });
  } catch (error) {
    console.error("❌ Error in STK Push:", error.response?.data || error.message);
    res.status(500).json({ success: false, error: error.response?.data || error.message });
  }
});

// === LOAD TOKENS ON SERVER START ===
(async () => {
  try {
    const saved = JSON.parse(await fs.readFile(tokensPath));
    for (const [k, v] of Object.entries(saved)) downloadTokens.set(k, v);
    console.log(`✅ Loaded ${downloadTokens.size} tokens from disk`);
  } catch (e) {
    console.log("⚠️ No saved tokens found, starting fresh");
  }
})();

// === SAVE TOKENS ===
async function saveTokens() {
  const obj = Object.fromEntries(downloadTokens);
  await fs.writeFile(tokensPath, JSON.stringify(obj, null, 2));
}

// === CONFIRMATION CALLBACK ===
app.post("/api/confirm", async (req, res) => {
  try {
    const body = req.body;
    console.log("📥 M-Pesa Callback Received:", JSON.stringify(body, null, 2));

    const callback = body?.Body?.stkCallback;
    if (!callback) {
      console.error("❌ Invalid callback payload");
      return res.status(200).json({ ResultCode: 0, ResultDesc: "Invalid payload" });
    }

    const checkoutId = callback.CheckoutRequestID;
    const status = callback.ResultCode;

    const getItem = (name) =>
      callback?.CallbackMetadata?.Item?.find((i) => i.Name === name)?.Value || null;
// Use the mapped filename if AccountReference is missing
const filename = getItem('AccountReference') || checkoutFileMap.get(checkoutId) || "UNKNOWN";

const paymentInfo = {
  id: Date.now(),
  checkoutId,
  mpesaReceipt: getItem('MpesaReceiptNumber'),
  amount: getItem('Amount'),
  phone: getItem('PhoneNumber'),
  filename, // now guaranteed to have the correct file
  timestamp: new Date().toISOString(),
  status: status === 0 ? 'SUCCESS' : 'FAILED'
};

    // Save transaction log
    let logs = [];
    try {
      logs = JSON.parse(await fs.readFile(transactionLogPath));
    } catch (e) {
      console.warn("⚠️ No transaction log found, creating new one");
    }
    logs.push(paymentInfo);
    await fs.writeFile(transactionLogPath, JSON.stringify(logs, null, 2));

    // Generate token if successful
    if (status === 0) {
      const token = crypto.randomBytes(16).toString("hex");
      downloadTokens.set(token, {
        filename: paymentInfo.filename,
        expires: Date.now() + 60 * 60 * 1000
      });
      await saveTokens();
      console.log(`✅ Payment success. File: ${paymentInfo.filename}, Token: ${token}`);
    } else {
      console.log(`❌ Payment failed: ${callback.ResultDesc}`);
    }

    return res.status(200).json({ ResultCode: 0, ResultDesc: "Accepted" });
  } catch (err) {
    console.error("❌ Error handling /api/confirm:", err);
    return res.status(200).json({ ResultCode: 0, ResultDesc: "Accepted with error" });
  }
});

// === POLLING FOR FRONTEND ===
// === GET /api/confirm - Frontend Polling + Token for Download ===
app.get('/api/confirm', async (req, res) => {
  try {
    const { filename } = req.query;
    if (!filename) return res.status(400).json({ confirmed: false, message: "Filename required" });

    // Load transaction logs
    const logs = JSON.parse(await fs.readFile(transactionLogPath));
    const tx = logs.find(l => l.status === "SUCCESS" && l.filename === filename);

    if (tx) {
      const now = Date.now();

      // Cleanup expired tokens
      for (const [k, v] of downloadTokens) {
        if (v.expires <= now) downloadTokens.delete(k);
      }

      // Find or create active token for this file
      let entry = [...downloadTokens.entries()].find(([_, obj]) => obj.filename === filename && obj.expires > now);
      if (!entry) {
        const token = crypto.randomBytes(16).toString('hex');
        downloadTokens.set(token, {
          filename,
          expires: now + 60 * 60 * 1000 // 1 hour
        });
        await saveTokens();
        entry = [token, downloadTokens.get(token)];
      }

      return res.json({
        confirmed: true,
        token: entry[0],
        mpesaReceipt: tx.mpesaReceipt,
        amount: tx.amount,
        phone: tx.phone
      });
    }

    res.json({ confirmed: false });
  } catch (err) {
    console.error("❌ Error in /api/confirm (GET):", err);
    res.status(500).json({ confirmed: false, error: "Server error" });
  }
});

// === DOWNLOAD BY TOKEN ===
app.get("/download", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).send("Token required");

    const entry = downloadTokens.get(token);
    if (!entry || entry.expires < Date.now()) {
      return res.status(403).send("Invalid or expired token");
    }

    const filePath = path.join(__dirname, "uploads", file.fileName);


    return res.download(filePath, entry.filename, (err) => {
      if (err) {
        console.error("❌ Error serving file:", err);
        res.status(500).send("Error downloading file");
      } else {
        console.log(`✅ File downloaded: ${entry.filename}`);
        // Optionally invalidate token after first download
        downloadTokens.delete(token);
        saveTokens().catch(console.error);
      }
    });
  } catch (err) {
    console.error("❌ Error in /download:", err);
    res.status(500).send("Server error");
  }
});


// === CLEANUP TOKENS PERIODICALLY ===
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const [k, v] of downloadTokens) {
    if (v.expires <= now) {
      downloadTokens.delete(k);
      changed = true;
    }
  }
  if (changed) saveTokens().catch(console.error);
}, 10 * 60 * 1000);

module.exports = app;

// === ADMIN LOGIN ===
app.post('/api/admin-login', (req, res) => {
  const { key } = req.body;
  if (ADMIN_SECRET.includes(key)) return res.json({ success: true });
  res.status(401).json({ success: false, message: "Invalid key" });
});const TRANSACTION_FILE = path.join(__dirname, "transactions.json");
const METADATA_FILE = path.join(__dirname, "metadata.json");

// ✅ Currency formatter for KES
const formatKES = (amount) => {
  return new Intl.NumberFormat("en-KE", {
    style: "currency",
    currency: "KES",
    minimumFractionDigits: 2,
  }).format(amount || 0);
};

// ✅ Utility: read transactions
async function readTransactions() {
  try {
    const data = await fs.readFile(TRANSACTION_FILE, "utf8"); // no .promises
    return JSON.parse(data);
  } catch (err) {
    if (err.code === "ENOENT") return [];
    throw err;
  }
}

// ✅ Utility: write transactions
async function writeTransactions(transactions) {
  await fs.writeFile(
    TRANSACTION_FILE,
    JSON.stringify(transactions, null, 2)
  );
}


// === ADMIN STATS ===
app.get("/api/admin/transactions", async (req, res) => {
  try {
    const transactions = await readTransactions();
    const metadata = fs.existsSync(METADATA_FILE)
      ? JSON.parse(fs.readFileSync(METADATA_FILE, "utf-8"))
      : [];

    let revenue = { today: 0, week: 0, month: 0, year: 0, total: 0 };
    let downloadsMap = {};

    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const startOfWeek = new Date(now);
    startOfWeek.setDate(now.getDate() - now.getDay());
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const startOfYear = new Date(now.getFullYear(), 0, 1);

    transactions.forEach((t) => {
      const amount = parseFloat(t.amount) || 0;
      const createdAt = new Date(t.date || t.timestamp || now);

      if (createdAt >= startOfToday) revenue.today += amount;
      if (createdAt >= startOfWeek) revenue.week += amount;
      if (createdAt >= startOfMonth) revenue.month += amount;
      if (createdAt >= startOfYear) revenue.year += amount;
      revenue.total += amount;

      if (t.fileId) {
        downloadsMap[t.fileId] = (downloadsMap[t.fileId] || 0) + 1;
      }
    });

    let highestDownloads = Object.entries(downloadsMap)
      .map(([fileId, count]) => {
        const fileMeta = metadata.find((m) => m.id == fileId) || {};
        return {
          fileId,
          filename: fileMeta.filename || "Unknown File",
          count,
        };
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    res.json({
      revenue: {
        today: formatKES(revenue.today),
        week: formatKES(revenue.week),
        month: formatKES(revenue.month),
        year: formatKES(revenue.year),
        total: formatKES(revenue.total),
      },
      highestDownloads,
      totalTransactions: transactions.length,
      transactions: transactions.map((t) => ({
        ...t,
        amount: formatKES(t.amount),
        date: new Date(t.date || t.timestamp).toLocaleString("en-KE", {
          timeZone: "Africa/Nairobi",
        }),
      })),
    });
  } catch (err) {
    console.error("Error reading transactions:", err);
    res.status(500).json({ error: "Failed to load admin stats" });
  }
});

// === PAYMENT STATUS ===
app.get("/api/status/:id", (req, res) => {
  const status = confirmations.get(req.params.id);
  res.json({ paid: status || false });
});

// === LOG TRANSACTION ===
router.post("/api/transactions", async (req, res) => {
  try {
    const { mpesaReceipt, phone, amount, filename } = req.body;
    if (!mpesaReceipt || !phone || !amount || !filename) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const transactions = await readTransactions();

    const newTx = {
      id: mpesaReceipt,
      phone,
      amount: parseFloat(amount),
      filename,
      status: "Confirmed",
      date: new Date().toISOString(),
    };

    transactions.push(newTx);
    await writeTransactions(transactions);

    res.json({ success: true, transaction: newTx });
  } catch (err) {
    console.error("Error saving transaction:", err);
    res.status(500).json({ error: "Failed to save transaction" });
  }
});

// === GET ALL TRANSACTIONS ===
router.get("/api/transactions", async (req, res) => {
  try {
    const transactions = await readTransactions();
    res.json(transactions);
  } catch (err) {
    console.error("Error reading transactions:", err);
    res.status(500).json({ error: "Failed to read transactions" });
  }
});

// === GET ONE TRANSACTION ===
router.get("/api/transactions/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const transactions = await readTransactions();
    const tx = transactions.find((t) => t.id === id);

    if (!tx) {
      return res.status(404).json({ error: "Transaction not found" });
    }

    res.json({
      ...tx,
      amount: formatKES(tx.amount),
      date: new Date(tx.date).toLocaleString("en-KE", {
        timeZone: "Africa/Nairobi",
      }),
    });
  } catch (err) {
    console.error("Error fetching transaction:", err);
    res.status(500).json({ error: "Failed to fetch transaction" });
  }
});

module.exports = router;

// Mount the router so /api/transactions works
app.use('/', router);


// === SERVER START ===
app.listen(PORT, () => console.log(`✅ Turbo Server running at http://localhost:${PORT}`));


