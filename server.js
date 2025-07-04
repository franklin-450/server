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

// === CONFIGURATION ===
const CONSUMER_KEY = 'Glgbr8Pn6JJFqzG1w0nWfxHfdIpyPtlAZYUnzVYNAgrl2G7O';
const CONSUMER_SECRET = '2vbpVGO9t5qAOTMIbU7KmGbwcxZ2LHOhjlurhX02M79TK7W8g1qhNF1h9uO6ftLh';
const SHORT_CODE = '174379';
const PASSKEY = 'bfb279f9aa9bdbcf33b040938b0f8f5c';
const CALLBACK_URL = 'https://server-1-bmux.onrender.com/api/confirm';
const ADMIN_API_KEY = 'secret-admin-key';

const uploadDir = path.join(__dirname, 'uploads');
const metadataPath = path.join(uploadDir, 'metadata.json');
const transactionLogPath = path.join(__dirname, 'transactions.json');
const freeDownloadLogPath = path.join(__dirname, 'free_downloads.json');

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(express.json());

let metadataCache = [];
const confirmations = new Map(); // Track confirmations

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

const fileExists = async (filePath) => {
    try {
        await fs.access(filePath);
        return true;
    } catch {
        return false;
    }
};

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

app.get('/api/files', (_, res) => res.json(metadataCache));

app.get('/api/files/:filename', async (req, res) => {
    const { filename } = req.params;
    const { token } = req.query;
    const fullPath = path.join(uploadDir, filename);
    const FREE_UNTIL = new Date('2025-07-01T00:00:00+03:00');
    const now = new Date();

    const isAdmin = req.headers.apikey === ADMIN_API_KEY;
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

app.delete('/api/files/:filename', async (req, res) => {
    const { filename } = req.params;
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
        const tokenRes = await axios.get('https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
            auth: { username: CONSUMER_KEY, password: CONSUMER_SECRET }
        });

        const access_token = tokenRes.data.access_token;
        const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
        const password = Buffer.from(SHORT_CODE + PASSKEY + timestamp).toString('base64');

        const stkResponse = await axios.post('https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest', {
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
        }, {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        const checkoutId = stkResponse.data.CheckoutRequestID;
        confirmations.set(checkoutId, false);
        res.json({ success: true, checkoutId });
    } catch (err) {
        console.error('MPESA Error:', err.message);
        res.status(500).json({ success: false, message: 'Payment failed' });
    }
});

app.get('/api/status/:id', (req, res) => {
    const status = confirmations.get(req.params.id);
    res.json({ paid: status || false });
});

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
            timestamp: new Date().toISOString()
        };

        const logs = JSON.parse(await fs.readFile(transactionLogPath));
        logs.push(paymentInfo);
        await fs.writeFile(transactionLogPath, JSON.stringify(logs, null, 2));

        res.status(200).send('Confirmation received');
    } catch (err) {
        console.error('❌ Error handling /api/confirm:', err);
        res.status(500).send('Error');
    }
});

app.listen(PORT, () => console.log(`✅ Turbo Server running at http://localhost:${PORT}`));
