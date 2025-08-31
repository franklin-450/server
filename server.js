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
// ===== ADMIN / TRANSACTIONS UTILITIES (fs/promises only) =====

// Files:
// - transactionLogPath -> where M-Pesa callback logs (your code already writes here)
// - metadataPath       -> your metadata.json (created on init above)

const NAIROBI_TZ = "Africa/Nairobi";

// KES currency formatter
const formatKES = (amount) =>
  new Intl.NumberFormat("en-KE", {
    style: "currency",
    currency: "KES",
    minimumFractionDigits: 2,
  }).format(Number.isFinite(+amount) ? +amount : 0);

// Safe JSON read (no existsSync, no sync IO)
async function readJsonSafe(filePath, fallback = []) {
  try {
    const txt = await fs.readFile(filePath, "utf8");
    return JSON.parse(txt);
  } catch (err) {
    if (err && err.code === "ENOENT") return fallback;
    throw err;
  }
}

// Format a date-like value to Nairobi local time
function formatDateNairobi(dateLike) {
  const d = dateLike ? new Date(dateLike) : null;
  if (!d || isNaN(d.getTime())) return "N/A";
  return d.toLocaleString("en-KE", { timeZone: NAIROBI_TZ });
}

// Normalize a transaction (guard against null/undefined)
function normalizeTx(raw) {
  const tx = raw || {};

  // prefer explicit mpesaReceipt, fall back to id
  const mpesaReceipt = tx.mpesaReceipt || tx.id || "N/A";

  // prefer `timestamp` (from your callback), fallback to `date`
  const transactionDateRaw = tx.timestamp || tx.date || null;
  const dateFormatted = formatDateNairobi(transactionDateRaw);

  const amountNum = Number.isFinite(+tx.amount) ? +tx.amount : 0;

  return {
    id: String(mpesaReceipt),                 // expose ID as mpesaReceipt
    mpesaReceipt: String(mpesaReceipt),
    phone: tx.phone || "N/A",
    filename: tx.filename || "UNKNOWN",
    status: tx.status || "PENDING",           // SUCCESS/FAILED/PENDING
    amount: amountNum,                        // numeric (raw)
    amountKES: formatKES(amountNum),          // formatted
    transactionDate: transactionDateRaw || null,
    transactionDateFormatted: dateFormatted,  // human-friendly (Nairobi)
    // keep originals if you want to inspect later
    _original: tx,
  };
}

// Get period boundaries (using server time; display is in Nairobi)
function getPeriodStarts() {
  const now = new Date();
  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const startOfWeek = new Date(startOfToday);
  startOfWeek.setDate(startOfToday.getDate() - startOfToday.getDay()); // Sunday start
  const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
  const startOfYear  = new Date(now.getFullYear(), 0, 1);
  return { now, startOfToday, startOfWeek, startOfMonth, startOfYear };
}

// ===== ADMIN: AGGREGATED STATS =====
// GET /api/admin/transactions
// Optional query params:
//   ?status=SUCCESS|FAILED|PENDING
//   &from=2025-01-01
//   &to=2025-12-31
//   &page=1&limit=50
app.get("/api/admin/transactions", async (req, res) => {
  try {
    // Load data
    const logs = await readJsonSafe(transactionLogPath, []);
    const metadata = await readJsonSafe(metadataPath, []);

    // Normalize
    let txs = logs.map(normalizeTx);

    // --- Filtering (optional) ---
    const { status, from, to, page = "1", limit = "100" } = req.query;

    if (status) {
      const allowed = String(status).toUpperCase();
      txs = txs.filter(t => String(t.status).toUpperCase() === allowed);
    }

    if (from) {
      const fromDate = new Date(from);
      if (!isNaN(fromDate.getTime())) {
        txs = txs.filter(t => {
          const d = t.transactionDate ? new Date(t.transactionDate) : null;
          return d && !isNaN(d) && d >= fromDate;
        });
      }
    }

    if (to) {
      const toDate = new Date(to);
      if (!isNaN(toDate.getTime())) {
        txs = txs.filter(t => {
          const d = t.transactionDate ? new Date(t.transactionDate) : null;
          return d && !isNaN(d) && d <= toDate;
        });
      }
    }

    // --- Revenue buckets ---
    const { startOfToday, startOfWeek, startOfMonth, startOfYear } = getPeriodStarts();
    let rev = { today: 0, week: 0, month: 0, year: 0, total: 0 };

    for (const t of txs) {
      const amt = t.amount || 0;
      const d = t.transactionDate ? new Date(t.transactionDate) : null;

      // Only count successful transactions into revenue
      if (String(t.status).toUpperCase() !== "SUCCESS") {
        continue;
      }

      if (d && !isNaN(d)) {
        if (d >= startOfToday) rev.today += amt;
        if (d >= startOfWeek) rev.week += amt;
        if (d >= startOfMonth) rev.month += amt;
        if (d >= startOfYear) rev.year += amt;
      }
      rev.total += amt;
    }

    // --- Downloads per file (by filename) from successful transactions ---
    const downloadsMap = new Map(); // filename -> count
    for (const t of txs) {
      if (String(t.status).toUpperCase() === "SUCCESS" && t.filename && t.filename !== "UNKNOWN") {
        downloadsMap.set(t.filename, (downloadsMap.get(t.filename) || 0) + 1);
      }
    }

    const highestDownloads = [...downloadsMap.entries()]
      .map(([filename, count]) => {
        // try to find friendly title by filename in metadata.json
        const meta = metadata.find(m => m.filename === filename) || {};
        return {
          filename: filename || "Unknown File",
          title: meta.title || meta.filename || "Unknown",
          count
        };
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // --- Pagination (on the filtered set) ---
    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const limitNum = Math.max(1, Math.min(500, parseInt(limit, 10) || 100));
    const total = txs.length;
    const start = (pageNum - 1) * limitNum;
    const end = start + limitNum;

    const paged = txs
      .sort((a, b) => {
        // sort newest first by transactionDate; fallback to id
        const ad = a.transactionDate ? new Date(a.transactionDate).getTime() : 0;
        const bd = b.transactionDate ? new Date(b.transactionDate).getTime() : 0;
        return bd - ad || String(b.id).localeCompare(String(a.id));
      })
      .slice(start, end)
      .map(t => ({
        id: t.id,
        mpesaReceipt: t.mpesaReceipt,
        phone: t.phone,
        filename: t.filename,
        status: t.status,
        amount: t.amount,                     // numeric
        amountKES: t.amountKES,               // formatted
        transactionDate: t.transactionDate,   // raw ISO or null
        transactionDateFormatted: t.transactionDateFormatted,
      }));

    // Respond
    res.json({
      revenue: {
        today: formatKES(rev.today),
        week:  formatKES(rev.week),
        month: formatKES(rev.month),
        year:  formatKES(rev.year),
        total: formatKES(rev.total),
      },
      highestDownloads,
      totals: {
        all: total,
        success: txs.filter(t => String(t.status).toUpperCase() === "SUCCESS").length,
        failed:  txs.filter(t => String(t.status).toUpperCase() === "FAILED").length,
        pending: txs.filter(t => String(t.status).toUpperCase() === "PENDING").length,
      },
      page: pageNum,
      limit: limitNum,
      count: paged.length,
      transactions: paged,
    });
  } catch (err) {
    console.error("Error reading transactions (admin):", err);
    res.status(500).json({ error: "Failed to load admin stats" });
  }
});
app.get("/api/status/:id", (req, res) => {
            const status = confirmations.get(req.params.id);
            res.json({ paid: status || false });
          });

// ===== LOG A TRANSACTION (manual insert, NOT hardcoded) =====
// POST /api/transactions
// body: { mpesaReceipt, phone, amount, filename, status?, date? }
// - If date is omitted, server will set current time (ISO) as `date`
app.post("/api/transactions", async (req, res) => {
  try {
    const { mpesaReceipt, phone, amount, filename, status, date } = req.body;

    if (!mpesaReceipt || !phone || !amount || !filename) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const logs = await readJsonSafe(transactionLogPath, []);

    const newTx = {
      // keep your callback-compatible field names
      id: mpesaReceipt,
      mpesaReceipt,
      phone,
      amount: Number(amount),
      filename,
      status: status || "Confirmed", // You can pass SUCCESS/FAILED/Confirmed etc.
      date: date ? new Date(date).toISOString() : new Date().toISOString(),
    };

    logs.push(newTx);
    await fs.writeFile(transactionLogPath, JSON.stringify(logs, null, 2));

    res.json({ success: true, transaction: normalizeTx(newTx) });
  } catch (err) {
    console.error("Error saving transaction:", err);
    res.status(500).json({ error: "Failed to save transaction" });
  }
});

// ===== GET ALL TRANSACTIONS (raw, unpaginated) =====
// GET /api/transactions
app.get("/api/transactions", async (_req, res) => {
  try {
    const logs = await readJsonSafe(transactionLogPath, []);
    res.json(logs.map(normalizeTx));
  } catch (err) {
    console.error("Error reading transactions:", err);
    res.status(500).json({ error: "Failed to read transactions" });
  }
});

// ===== GET SINGLE TRANSACTION BY RECEIPT/ID =====
// GET /api/transactions/:id
app.get("/api/transactions/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const logs = await readJsonSafe(transactionLogPath, []);

    // match either mpesaReceipt or id
    const raw = logs.find(t => String(t.mpesaReceipt || t.id) === String(id));
    if (!raw) return res.status(404).json({ error: "Transaction not found" });

    const tx = normalizeTx(raw);
    res.json(tx);
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



