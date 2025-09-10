// server.js - consolidated, robust version (fs/promises only)
// Replace your existing file with this. Keeps your routes and behavior,
// but fixes token/download handling and normalizes transaction data.

const express = require('express');
const multer = require('multer');
const fs = require('fs/promises');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const bodyParser = require('body-parser');
const moment = require("moment");

const app = express();
const router = express.Router();
const PORT = process.env.PORT || 3000;

/* === CONFIG === */
const ADMIN_SECRET = ['adminsecret', 'wizard123', 'godmode', 'schemehub250', 'klinton'];
// Change just this one line at the top
const uploadDir = path.join(__dirname, 'files'); 
const metadataPath = path.join(uploadDir, 'metadata.json');
const transactionLogPath = path.join(__dirname, 'transactions.json');
const tokensPath = path.join(__dirname, 'tokens.json');
const freeDownloadLogPath = path.join(__dirname, 'free_downloads.json');

const NAIROBI_TZ = "Africa/Nairobi";

/* === MIDDLEWARE === */
app.use(cors());
app.use(bodyParser.json());
app.use(express.json());
// Keep static for public, but do NOT expose raw uploads without token check
app.use(express.static('public'));
// NOTE: we do NOT mount express.static on /api/uploads to avoid bypassing token check
// If you want public direct access for some files, you can add a separate public folder.

/* === STATE === */
let metadataCache = [];
const confirmations = new Map();
const downloadTokens = new Map(); // token -> { filename, expires, mpesaReceipt? }
const checkoutFileMap = new Map(); // CheckoutRequestID -> sanitized filename

/* === INIT FS (create uploads folder & metadata) === */
(async () => {
  try {
    await fs.mkdir(uploadDir, { recursive: true });
    if (!(await fileExists(metadataPath))) await fs.writeFile(metadataPath, '[]', 'utf8');
    if (!(await fileExists(transactionLogPath))) await fs.writeFile(transactionLogPath, '[]', 'utf8');
    if (!(await fileExists(freeDownloadLogPath))) await fs.writeFile(freeDownloadLogPath, '[]', 'utf8');
    if (!(await fileExists(tokensPath))) await fs.writeFile(tokensPath, '{}', 'utf8');

    // load metadata
    try {
      const md = JSON.parse(await fs.readFile(metadataPath, 'utf8'));
      metadataCache = Array.isArray(md) ? md : [];
    } catch (e) {
      metadataCache = [];
    }

    // load tokens
    try {
      const saved = JSON.parse(await fs.readFile(tokensPath, 'utf8'));
      for (const [k, v] of Object.entries(saved)) downloadTokens.set(k, v);
      console.log(`✅ Loaded ${downloadTokens.size} tokens from disk`);
    } catch (e) {
      console.log('⚠️ No tokens loaded (starting fresh)');
    }

    console.log('✅ Init complete');
  } catch (e) {
    console.error('Init error:', e);
  }
})();

async function fileExists(filePath) {
  try { await fs.access(filePath); return true; } catch { return false; }
}

/* === Multer storage === */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    // Replace spaces & special characters with underscores
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, safeName.split('.')[0] + '_' + Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

/* === UTIL: formaters & safe reads === */
const formatKES = (amount) => new Intl.NumberFormat("en-KE", {
  style: "currency",
  currency: "KES",
  minimumFractionDigits: 2
}).format(Number.isFinite(+amount) ? +amount : 0);

async function readJsonSafe(filePath, fallback = []) {
  try {
    const txt = await fs.readFile(filePath, 'utf8');
    return JSON.parse(txt);
  } catch (err) {
    if (err && err.code === 'ENOENT') return fallback;
    return fallback;
  }
}

function formatDateNairobi(dateLike) {
  const d = dateLike ? new Date(dateLike) : null;
  if (!d || isNaN(d.getTime())) return 'N/A';
  return d.toLocaleString('en-KE', { timeZone: NAIROBI_TZ });
}

function normalizeTx(raw) {
  const tx = raw || {};
  const mpesaReceipt = tx.mpesaReceipt || tx.id || 'N/A';
  const transactionDateRaw = tx.timestamp || tx.date || tx.timestampAt || null;
  const amountNum = Number.isFinite(+tx.amount) ? +tx.amount : 0;
  return {
    id: String(mpesaReceipt),
    mpesaReceipt: String(mpesaReceipt),
    phone: tx.phone || 'N/A',
    filename: tx.filename || tx.file || 'UNKNOWN',
    status: (tx.status || tx.result || 'PENDING').toString().toUpperCase(),
    amount: amountNum,
    amountKES: formatKES(amountNum),
    transactionDate: transactionDateRaw || null,
    transactionDateFormatted: formatDateNairobi(transactionDateRaw),
    _original: tx
  };
}

/* === TOKEN PERSISTENCE === */
async function saveTokens() {
  try {
    const obj = Object.fromEntries(downloadTokens);
    await fs.writeFile(tokensPath, JSON.stringify(obj, null, 2), 'utf8');
  } catch (e) {
    console.error('Error saving tokens:', e);
  }
}

/* === ROUTES START === */

// health
app.get('/', (req, res) => res.send('🎉 Turbo Server with M-Pesa & File Manager is running.'));


/* ---------- Upload ---------- */
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    console.log('📂 File saved at:', req.file.path);
    const metadata = {
      id: Date.now(),
      title: req.body.title,
      subject: req.body.subject,
      class: req.body.class,
      category: req.body.category,
      price: req.body.price,
      type: req.body.type,
      filename: req.file.filename,  // ✅ sanitized & actual saved name
      mimetype: req.file.mimetype,
      path: `/api/uploads/${req.file.filename}`, // ✅ matches saved
      uploadDate: new Date()
    };

    metadataCache.push(metadata);
    await fs.writeFile(metadataPath, JSON.stringify(metadataCache, null, 2));

    res.json({ success: true, metadata });
  } catch (err) {
    res.status(500).json({ error: 'Upload failed', details: err.message });
  }
});


/* ---------- List files (metadata) ---------- */
app.get('/api/files', (_req, res) => res.json(metadataCache));
app.get('/api/list-files', async (req, res) => {
  try {
    const files = await fs.readdir(uploadDir);
    res.json({ files });
  } catch (err) {
    res.status(500).json({ error: 'Unable to list files', details: err.message });
  }
});

/* ---------- Serve a file with token check ---------- */
/*
  GET /api/files/:filename?token=<token>
  This endpoint enforces token-based access to uploaded files.
*/
app.get('/api/files/:filename', async (req, res) => {
  try {
    const { filename } = req.params;
    const rawToken = (req.query.token || '').toString();

    // tolerant parsing for malformed token like "<filename>?token=<realtoken>"
    const tokenCandidate = rawToken.split('?token=')[0].split('&token=')[0];

    // If the tokenCandidate looks like a filename (contains '.'), then the client sent the filename as token.
    // Try to find a valid token for that filename.
    let token = tokenCandidate;
    let entry = downloadTokens.get(token);

    if ((!entry || entry.expires < Date.now()) && tokenCandidate.includes('.')) {
      // tokenCandidate might be the filename; find an active token for that filename
      const now = Date.now();
      entry = [...downloadTokens.entries()].find(([k, v]) => {
        return v.filename === tokenCandidate && v.expires > now;
      });
      if (entry) {
        token = entry[0];
        entry = entry[1];
      } else {
        entry = null;
      }
    }

    if (!entry || entry.expires < Date.now() || entry.filename !== filename) {
      return res.status(403).send('❌ Invalid or expired token');
    }

    const filePath = path.join(uploadDir, filename);
    // verify file exists
    if (!(await fileExists(filePath))) {
      return res.status(404).send('❌ File not found on server');
    }

    return res.download(filePath, filename, (err) => {
      if (err) {
        console.error('❌ Error sending file:', err);
        // If error, send 500 if file exists but cannot be read
        if (err.code === 'ENOENT') return res.status(404).send('❌ File not found');
        return res.status(500).send('❌ Error serving file');
      } else {
        // invalidate token after download (optional) — currently we keep but delete to prevent reuse
        downloadTokens.delete(token);
        saveTokens().catch(console.error);
        console.log(`✅ File served: ${filename} (token: ${token})`);
      }
    });

  } catch (err) {
    console.error('Error in /api/files/:filename:', err);
    res.status(500).send('Server error');
  }
});

/* ---------- Admin Metadata Management ---------- */

// View all metadata
app.get('/api/admin/files', async (req, res) => {
  const key = req.headers.apikey;
  if (!ADMIN_SECRET.includes(key)) {
    return res.status(403).json({ success: false, message: "Unauthorized" });
  }
  res.json(metadataCache);
});

// Edit metadata by filename
app.put('/api/admin/files/:filename', async (req, res) => {
  const key = req.headers.apikey;
  if (!ADMIN_SECRET.includes(key)) {
    return res.status(403).json({ success: false, message: "Unauthorized" });
  }

  const { filename } = req.params;
  const updates = req.body;

  let fileMeta = metadataCache.find(f => f.filename === filename);
  if (!fileMeta) {
    return res.status(404).json({ success: false, message: 'Metadata not found' });
  }

  fileMeta = Object.assign(fileMeta, updates);
  await fs.writeFile(metadataPath, JSON.stringify(metadataCache, null, 2), 'utf8');
  res.json({ success: true, metadata: fileMeta });
});

// Delete metadata only (not the file itself, unless you want both)
app.delete('/api/admin/files/:filename/metadata', async (req, res) => {
  const key = req.headers.apikey;
  if (!ADMIN_SECRET.includes(key)) {
    return res.status(403).json({ success: false, message: "Unauthorized" });
  }

  const { filename } = req.params;
  const before = metadataCache.length;
  metadataCache = metadataCache.filter(f => f.filename !== filename);
  await fs.writeFile(metadataPath, JSON.stringify(metadataCache, null, 2), 'utf8');

  if (metadataCache.length === before) {
    return res.status(404).json({ success: false, message: 'Metadata not found' });
  }

  res.json({ success: true, message: 'Metadata deleted' });
});


/* === M-PESA CONFIG & STK PUSH (unchanged logic) === */
const consumerkey = process.env.MPESA_CONSUMER_KEY || "NkxcAadvkohxGErrIm84VAccHA3nfSSRd5DH0mIe9sv9DDCn";
const consumerSecret = process.env.MPESA_CONSUMER_SECRET || "x636VF0x52vZBorz0Xjunw1dKZjHq7bdCbZnQeYkjemV6eA30qgtk6vylr9DSe8v";
const shortCode = process.env.MPESA_SHORTCODE || "174379";
const passKey = process.env.MPESA_PASSKEY || "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919";

async function getAccessToken() {
  const auth = Buffer.from(`${consumerkey}:${consumerSecret}`).toString("base64");
  const r = await axios.get("https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
    { headers: { Authorization: `Basic ${auth}` }});
  return r.data.access_token;
}

app.post("/api/pay", async (req, res) => {
  try {
    const { phoneNumber, fileName, filePrice } = req.body;
    const sanitizedFileName = fileName ? fileName.replace(/[^\w.-]/g, "_").trim() : "UNKNOWN";

    const token = await getAccessToken();
    const timestamp = moment().format("YYYYMMDDHHmmss");
    const password = Buffer.from(shortCode + passKey + timestamp).toString("base64");

    const stkRes = await axios.post("https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest", {
      BusinessShortCode: shortCode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: "CustomerPayBillOnline",
      Amount: filePrice,
      PartyA: phoneNumber,
      PartyB: shortCode,
      PhoneNumber: phoneNumber,
      CallBackURL: process.env.MPESA_CALLBACK_URL || "https://server-1-bmux.onrender.com/api/confirm",
      AccountReference: sanitizedFileName,
      TransactionDesc: `Purchase ${sanitizedFileName}`
    }, { headers: { Authorization: `Bearer ${token}` }});

    checkoutFileMap.set(stkRes.data.CheckoutRequestID, sanitizedFileName);
    console.log('✅ STK Push Response:', stkRes.data);
    res.json({ success: true, data: stkRes.data });
  } catch (error) {
    console.error('❌ Error in STK Push:', error.response?.data || error.message);
    res.status(500).json({ success: false, error: error.response?.data || error.message });
  }
});

/* ---------- Confirmation callback from Safaricom (STK callback) ---------- */
app.post("/api/confirm", async (req, res) => {
  try {
    const body = req.body;
    console.log("📥 M-Pesa Callback Received:", JSON.stringify(body, null, 2));
    const callback = body?.Body?.stkCallback;
    if (!callback) {
      console.error('Invalid callback payload');
      return res.status(200).json({ ResultCode: 0, ResultDesc: "Invalid payload" });
    }

    const checkoutId = callback.CheckoutRequestID;
    const status = callback.ResultCode;
    const getItem = (name) => callback?.CallbackMetadata?.Item?.find(i => i.Name === name)?.Value || null;

    // try account reference fallback using checkoutFileMap
    const filename = getItem('AccountReference') || checkoutFileMap.get(checkoutId) || "UNKNOWN";

    const paymentInfo = {
      id: Date.now(),
      checkoutId,
      mpesaReceipt: getItem('MpesaReceiptNumber') || `R${Date.now()}`,
      amount: getItem('Amount') || 0,
      phone: getItem('PhoneNumber') || 'N/A',
      filename,
      timestamp: new Date().toISOString(),
      status: status === 0 ? 'SUCCESS' : 'FAILED'
    };

    // append to transaction log
    let logs = [];
    try {
      logs = JSON.parse(await fs.readFile(transactionLogPath, 'utf8'));
      if (!Array.isArray(logs)) logs = [];
    } catch (e) {
      logs = [];
    }
    logs.push(paymentInfo);
    await fs.writeFile(transactionLogPath, JSON.stringify(logs, null, 2), 'utf8');

    // generate token on success
    if (status === 0) {
      const token = crypto.randomBytes(16).toString('hex');
      downloadTokens.set(token, {
        filename: paymentInfo.filename,
        expires: Date.now() + 60 * 60 * 1000, // 1 hour
        mpesaReceipt: paymentInfo.mpesaReceipt
      });
      await saveTokens();
      console.log(`✅ Payment success. Generated token: ${token} -> ${paymentInfo.filename}`);
    } else {
      console.log(`❌ Payment failed (${checkoutId}): ${callback.ResultDesc || 'No desc'}`);
    }

    return res.status(200).json({ ResultCode: 0, ResultDesc: "Accepted" });
  } catch (err) {
    console.error('Error handling /api/confirm:', err);
    return res.status(200).json({ ResultCode: 0, ResultDesc: "Accepted with error" });
  }
});

/* ---------- Polling endpoint used by frontend to get token once payment confirmed ---------- */
/*
  GET /api/confirm?filename=<filename>
  returns { confirmed: true, token, mpesaReceipt, amount, phone } when found
*/
app.get('/api/confirm', async (req, res) => {
  try {
    const { filename } = req.query;
    if (!filename) return res.status(400).json({ confirmed: false, message: "Filename required" });

    const logs = JSON.parse(await fs.readFile(transactionLogPath, 'utf8')).filter(Boolean);
    const tx = logs.reverse().find(l => String((l.status||'').toUpperCase()) === "SUCCESS" && l.filename === filename);

    if (tx) {
      const now = Date.now();
      // cleanup expired
      for (const [k, v] of downloadTokens) if (v.expires <= now) downloadTokens.delete(k);

      // find or create token for this filename
      let entry = [...downloadTokens.entries()].find(([k, v]) => v.filename === filename && v.expires > now);
      if (!entry) {
        const token = crypto.randomBytes(16).toString('hex');
        downloadTokens.set(token, { filename, expires: now + 60 * 60 * 1000, mpesaReceipt: tx.mpesaReceipt });
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

    return res.json({ confirmed: false });
  } catch (err) {
    console.error('Error in /api/confirm (GET):', err);
    return res.status(500).json({ confirmed: false, error: 'Server error' });
  }
});

/* ---------- DOWNLOAD endpoint (robust) ----------
   GET /download?token=<token>
   Accepts malformed tokens that contain '?token=' (will extract), or if token is a filename,
   it will try to locate an active token for that filename and serve.
*/
// Secure download route (one-time token + STK push re-validation)
app.get('/download', async (req, res) => {
  try {
    const token = (req.query.token || '').toString().trim();
    const entry = downloadTokens.get(token);

    // Token missing or already used
    if (!entry) {
      return res.status(403).json({
        success: false,
        message: '❌ Token expired. Please complete STK push payment to get a new one.'
      });
    }

    // Token expired by time
    if (entry.expires < Date.now()) {
      downloadTokens.delete(token);
      await saveTokens().catch(console.error);
      return res.status(403).json({
        success: false,
        message: '❌ Token expired by time. Please complete STK push payment again.'
      });
    }

    const filePath = path.join(uploadDir, entry.filename);
    if (!(await fileExists(filePath))) {
      return res.status(404).json({ success: false, message: '❌ File not found' });
    }

    // Find pretty name from metadata
    const meta = metadataCache.find(m => m.filename === entry.filename);
    const displayName = meta?.title
      ? meta.title.replace(/[^\w.\-]/g, "_") + path.extname(entry.filename)
      : entry.filename;

    return res.download(filePath, displayName, async (err) => {
      if (err) {
        console.error('❌ Error serving file:', err);
        return res.status(500).json({ success: false, message: 'Error downloading file' });
      } else {
        // Delete token after successful download (one-time use)
        downloadTokens.delete(token);
        await saveTokens().catch(console.error);
        console.log(`✅ File downloaded: ${entry.filename} (as ${displayName})`);
      }
    });
  } catch (err) {
    console.error('❌ Error in /download:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ---------- ADMIN / TRANSACTIONS API (aggregated stats) ---------- */
function getPeriodStarts() {
  const now = new Date();
  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const startOfWeek = new Date(startOfToday);
  startOfWeek.setDate(startOfToday.getDate() - startOfToday.getDay());
  const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
  const startOfYear = new Date(now.getFullYear(), 0, 1);
  return { now, startOfToday, startOfWeek, startOfMonth, startOfYear };
}

app.get("/api/admin/transactions", async (req, res) => {
  try {
    const logs = await readJsonSafe(transactionLogPath, []);
    const metadata = await readJsonSafe(metadataPath, []);

    let txs = logs.map(normalizeTx);
    const { status, from, to, page = "1", limit = "100" } = req.query;

    if (status) {
      const allowed = String(status).toUpperCase();
      txs = txs.filter(t => String(t.status).toUpperCase() === allowed);
    }
    if (from) {
      const fromDate = new Date(from);
      if (!isNaN(fromDate.getTime())) {
        txs = txs.filter(t => t.transactionDate && new Date(t.transactionDate) >= fromDate);
      }
    }
    if (to) {
      const toDate = new Date(to);
      if (!isNaN(toDate.getTime())) {
        txs = txs.filter(t => t.transactionDate && new Date(t.transactionDate) <= toDate);
      }
    }

    const { startOfToday, startOfWeek, startOfMonth, startOfYear } = getPeriodStarts();
    let rev = { today: 0, week: 0, month: 0, year: 0, total: 0 };
    for (const t of txs) {
      if (String(t.status).toUpperCase() !== 'SUCCESS') continue;
      const d = t.transactionDate ? new Date(t.transactionDate) : null;
      const amt = t.amount || 0;
      if (d && !isNaN(d)) {
        if (d >= startOfToday) rev.today += amt;
        if (d >= startOfWeek) rev.week += amt;
        if (d >= startOfMonth) rev.month += amt;
        if (d >= startOfYear) rev.year += amt;
      }
      rev.total += amt;
    }

    const downloadsMap = new Map();
    for (const t of txs) {
      if (String(t.status).toUpperCase() === 'SUCCESS' && t.filename && t.filename !== 'UNKNOWN') {
        downloadsMap.set(t.filename, (downloadsMap.get(t.filename) || 0) + 1);
      }
    }
    const highestDownloads = [...downloadsMap.entries()].map(([filename, count]) => {
      const meta = metadata.find(m => m.filename === filename) || {};
      return { filename, title: meta.title || meta.filename || filename, count };
    }).sort((a, b) => b.count - a.count).slice(0, 10);

    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const limitNum = Math.max(1, Math.min(500, parseInt(limit, 10) || 100));
    const total = txs.length;
    const paged = txs.sort((a, b) => {
      const ad = a.transactionDate ? new Date(a.transactionDate).getTime() : 0;
      const bd = b.transactionDate ? new Date(b.transactionDate).getTime() : 0;
      return bd - ad || String(b.id).localeCompare(String(a.id));
    }).slice((pageNum - 1) * limitNum, (pageNum - 1) * limitNum + limitNum)
      .map(t => ({
        id: t.id,
        mpesaReceipt: t.mpesaReceipt,
        phone: t.phone,
        filename: t.filename,
        status: t.status,
        amount: t.amount,
        amountKES: t.amountKES,
        transactionDate: t.transactionDate,
        transactionDateFormatted: t.transactionDateFormatted
      }));

    res.json({
      revenue: {
        today: formatKES(rev.today),
        week: formatKES(rev.week),
        month: formatKES(rev.month),
        year: formatKES(rev.year),
        total: formatKES(rev.total)
      },
      highestDownloads,
      totals: {
        all: total,
        success: txs.filter(t => String(t.status).toUpperCase() === 'SUCCESS').length,
        failed: txs.filter(t => String(t.status).toUpperCase() === 'FAILED').length,
        pending: txs.filter(t => String(t.status).toUpperCase() === 'PENDING').length
      },
      page: pageNum,
      limit: limitNum,
      count: paged.length,
      transactions: paged
    });

  } catch (err) {
    console.error('Error reading transactions (admin):', err);
    res.status(500).json({ error: 'Failed to load admin stats' });
  }
});

/* ---------- Simple status endpoint ---------- */
app.get("/api/status/:id", (req, res) => {
  const status = confirmations.get(req.params.id);
  res.json({ paid: status || false });
});

/* ---------- Manual transaction logging ---------- */
/*
  POST /api/transactions
  body: { mpesaReceipt, phone, amount, filename, status?, date? }
*/
app.post("/api/transactions", async (req, res) => {
  try {
    const { mpesaReceipt, phone, amount, filename, status, date } = req.body;
    if (!mpesaReceipt || !phone || !amount || !filename) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const logs = await readJsonSafe(transactionLogPath, []);
    const newTx = {
      id: mpesaReceipt,
      mpesaReceipt,
      phone,
      amount: Number(amount),
      filename,
      status: (status || 'PENDING').toString(),
      date: date ? new Date(date).toISOString() : new Date().toISOString()
    };
    logs.push(newTx);
    await fs.writeFile(transactionLogPath, JSON.stringify(logs, null, 2), 'utf8');
    res.json({ success: true, transaction: normalizeTx(newTx) });
  } catch (err) {
    console.error('Error saving transaction:', err);
    res.status(500).json({ error: 'Failed to save transaction' });
  }
});

/* ---------- Get all transactions (raw) ---------- */
app.get("/api/transactions", async (_req, res) => {
  try {
    const logs = await readJsonSafe(transactionLogPath, []);
    res.json(logs.map(normalizeTx));
  } catch (err) {
    console.error('Error reading transactions:', err);
    res.status(500).json({ error: 'Failed to read transactions' });
  }
});

/* ---------- Get single transaction ---------- */
app.get("/api/transactions/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const logs = await readJsonSafe(transactionLogPath, []);
    const raw = logs.find(t => String(t.mpesaReceipt || t.id) === String(id));
    if (!raw) return res.status(404).json({ error: 'Transaction not found' });
    res.json(normalizeTx(raw));
  } catch (err) {
    console.error('Error fetching transaction:', err);
    res.status(500).json({ error: 'Failed to fetch transaction' });
  }
});

/* ---------- Admin login (simple key check) ---------- */
app.post('/api/admin-login', (req, res) => {
  const { key } = req.body;
  if (ADMIN_SECRET.includes(key)) return res.json({ success: true });
  res.status(401).json({ success: false, message: "Invalid key" });
});

/* ---------- Periodic cleanup of expired tokens ---------- */
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

/* ---------- Start server ---------- */
app.listen(PORT, () => console.log(`✅ Turbo Server running at http://localhost:${PORT}`));








