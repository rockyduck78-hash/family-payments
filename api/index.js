const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: '1mb' }));

const MONGODB_URI = process.env.MONGODB_URI || '';
const JWT_SECRET = process.env.JWT_SECRET || '';
const DOUBLONS_API = 'https://doublons-bank.vercel.app';

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests' }
});

let mongoReady = false;
let mongoPromise = null;

async function connectMongo() {
    if (mongoReady && mongoose.connection.readyState === 1) return;
    if (mongoPromise) return mongoPromise;
    mongoPromise = (async () => {
        try {
            if (!MONGODB_URI) throw new Error('MONGODB_URI not set');
            await mongoose.connect(MONGODB_URI, {
                serverSelectionTimeoutMS: 5000,
                maxPoolSize: 5
            });
            mongoReady = true;
        } catch (err) {
            mongoReady = false;
            mongoPromise = null;
            throw err;
        }
    })();
    return mongoPromise;
}

const accountSchema = new mongoose.Schema({
    userId: { type: String, required: true, index: true },
    name: { type: String, required: true },
    balance: { type: Number, default: 0 },
    currency: { type: String, default: 'USD' },
    doublonsToken: { type: String, default: null },
    doublonsEmail: { type: String, default: null },
    doublonsAccountId: { type: String, default: null },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
    from: { type: String, required: true },
    to: { type: String, required: true },
    amount: { type: Number, required: true },
    currency: { type: String, default: 'USD' },
    type: { type: String, enum: ['internal', 'doublons_out', 'doublons_in', 'request'], default: 'internal' },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
    note: { type: String, default: '' },
    doublonsTransferId: { type: String, default: null },
    createdAt: { type: Date, default: Date.now }
});

const requestSchema = new mongoose.Schema({
    from: { type: String, required: true },
    to: { type: String, required: true },
    amount: { type: Number, required: true },
    note: { type: String, default: '' },
    status: { type: String, enum: ['pending', 'approved', 'denied'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const Account = mongoose.models.Account || mongoose.model('Account', accountSchema);
const Transaction = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);
const MoneyRequest = mongoose.models.MoneyRequest || mongoose.model('MoneyRequest', requestSchema);

function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        req.authUser = decoded.username;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

app.get('/health', async (req, res) => {
    try {
        await connectMongo();
        res.json({ status: 'ok', mongodb: 'connected' });
    } catch (err) {
        res.status(503).json({ status: 'error', mongodb: err.message });
    }
});

app.get('/api/accounts', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const accounts = await Account.find({ userId: req.authUser, active: true }).sort({ createdAt: 1 });
        res.json(accounts);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/accounts', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const { name, currency } = req.body;
        if (!name) return res.status(400).json({ error: 'Account name required' });
        const account = new Account({
            userId: req.authUser,
            name: name.trim(),
            currency: currency || 'USD',
            balance: 0
        });
        await account.save();
        res.json(account);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/accounts/:accountId', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const account = await Account.findOne({ _id: req.params.accountId, userId: req.authUser });
        if (!account) return res.status(404).json({ error: 'Account not found' });
        account.active = false;
        await account.save();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/transfer', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const { from_id, to_id, amount, note } = req.body;
        if (!from_id || !to_id || !amount) return res.status(400).json({ error: 'from_id, to_id, and amount required' });
        if (from_id === to_id) return res.status(400).json({ error: 'Cannot transfer to the same account' });
        const amt = parseFloat(amount);
        if (isNaN(amt) || amt <= 0) return res.status(400).json({ error: 'Invalid amount' });

        const fromAccount = await Account.findOne({ _id: from_id, userId: req.authUser, active: true });
        if (!fromAccount) return res.status(404).json({ error: 'Source account not found' });
        if (fromAccount.balance < amt) return res.status(400).json({ error: 'Insufficient balance' });

        const toAccount = await Account.findOne({ _id: to_id, active: true });
        if (!toAccount) return res.status(404).json({ error: 'Destination account not found' });

        fromAccount.balance -= amt;
        toAccount.balance += amt;
        await fromAccount.save();
        await toAccount.save();

        const tx = new Transaction({
            from: from_id,
            to: to_id,
            amount: amt,
            currency: fromAccount.currency,
            type: 'internal',
            status: 'completed',
            note: note || ''
        });
        await tx.save();
        res.json({ success: true, transaction: tx });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/request', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const { to_account_id, amount, note } = req.body;
        if (!to_account_id || !amount) return res.status(400).json({ error: 'to_account_id and amount required' });
        const amt = parseFloat(amount);
        if (isNaN(amt) || amt <= 0) return res.status(400).json({ error: 'Invalid amount' });

        const toAccount = await Account.findOne({ _id: to_account_id, active: true });
        if (!toAccount) return res.status(404).json({ error: 'Target account not found' });

        const moneyRequest = new MoneyRequest({
            from: req.authUser,
            to: toAccount.userId,
            amount: amt,
            note: note || '',
            status: 'pending'
        });
        await moneyRequest.save();
        res.json({ success: true, request: moneyRequest });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/requests', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const requests = await MoneyRequest.find({
            $or: [{ from: req.authUser }, { to: req.authUser }],
            status: 'pending'
        }).sort({ createdAt: -1 });
        res.json(requests);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/requests/:requestId/approve', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const moneyRequest = await MoneyRequest.findOne({ _id: req.params.requestId, to: req.authUser, status: 'pending' });
        if (!moneyRequest) return res.status(404).json({ error: 'Request not found' });

        const senderAccounts = await Account.find({ userId: moneyRequest.from, active: true }).sort({ balance: -1 });
        const senderAccount = senderAccounts.find(a => a.balance >= moneyRequest.amount);
        if (!senderAccount) {
            moneyRequest.status = 'denied';
            await moneyRequest.save();
            return res.status(400).json({ error: 'Sender has insufficient balance' });
        }

        const receiverAccounts = await Account.find({ userId: moneyRequest.to, active: true });
        if (receiverAccounts.length === 0) return res.status(400).json({ error: 'Receiver has no active accounts' });
        const receiverAccount = receiverAccounts[0];

        senderAccount.balance -= moneyRequest.amount;
        receiverAccount.balance += moneyRequest.amount;
        await senderAccount.save();
        await receiverAccount.save();

        const tx = new Transaction({
            from: senderAccount._id.toString(),
            to: receiverAccount._id.toString(),
            amount: moneyRequest.amount,
            type: 'request',
            status: 'completed',
            note: moneyRequest.note
        });
        await tx.save();

        moneyRequest.status = 'approved';
        await moneyRequest.save();

        res.json({ success: true, transaction: tx });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/requests/:requestId/deny', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const moneyRequest = await MoneyRequest.findOne({ _id: req.params.requestId, to: req.authUser, status: 'pending' });
        if (!moneyRequest) return res.status(404).json({ error: 'Request not found' });
        moneyRequest.status = 'denied';
        await moneyRequest.save();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/transactions', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const userAccounts = await Account.find({ userId: req.authUser, active: true });
        const accountIds = userAccounts.map(a => a._id.toString());
        const transactions = await Transaction.find({
            $or: [{ from: { $in: accountIds } }, { to: { $in: accountIds } }]
        }).sort({ createdAt: -1 }).limit(100);
        res.json(transactions);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/doublons/register', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
        const r = await fetch(DOUBLONS_API + '/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await r.json();
        if (!r.ok) return res.status(r.status).json(data);
        res.json(data);
    } catch (err) {
        res.status(502).json({ error: 'Doublons Bank unavailable' });
    }
});

app.post('/api/doublons/login', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
        const r = await fetch(DOUBLONS_API + '/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await r.json();
        if (!r.ok) return res.status(r.status).json(data);
        res.json(data);
    } catch (err) {
        res.status(502).json({ error: 'Doublons Bank unavailable' });
    }
});

app.post('/api/accounts/:accountId/link-doublons', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const { token, email, doublons_account_id } = req.body;
        if (!token) return res.status(400).json({ error: 'Doublons token required' });
        const account = await Account.findOne({ _id: req.params.accountId, userId: req.authUser });
        if (!account) return res.status(404).json({ error: 'Account not found' });
        account.doublonsToken = token;
        account.doublonsEmail = email || null;
        account.doublonsAccountId = doublons_account_id || null;
        await account.save();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/accounts/:accountId/unlink-doublons', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const account = await Account.findOne({ _id: req.params.accountId, userId: req.authUser });
        if (!account) return res.status(404).json({ error: 'Account not found' });
        account.doublonsToken = null;
        account.doublonsEmail = null;
        account.doublonsAccountId = null;
        await account.save();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/accounts/:accountId/doublons-accounts', apiLimiter, authMiddleware, async (req, res) => {
    try {
        const account = await Account.findOne({ _id: req.params.accountId, userId: req.authUser });
        if (!account) return res.status(404).json({ error: 'Account not found' });
        if (!account.doublonsToken) return res.status(400).json({ error: 'Doublons Bank not linked' });
        const r = await fetch(DOUBLONS_API + '/accounts', {
            headers: { 'Authorization': 'Bearer ' + account.doublonsToken }
        });
        const data = await r.json();
        if (!r.ok) return res.status(r.status).json(data);
        res.json(data);
    } catch (err) {
        res.status(502).json({ error: 'Doublons Bank unavailable' });
    }
});

app.post('/api/accounts/:accountId/withdraw-doublons', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const { to_doublons_account, amount } = req.body;
        if (!to_doublons_account || !amount) return res.status(400).json({ error: 'to_doublons_account and amount required' });
        const amt = parseFloat(amount);
        if (isNaN(amt) || amt <= 0) return res.status(400).json({ error: 'Invalid amount' });

        const account = await Account.findOne({ _id: req.params.accountId, userId: req.authUser });
        if (!account) return res.status(404).json({ error: 'Account not found' });
        if (!account.doublonsToken) return res.status(400).json({ error: 'Doublons Bank not linked' });
        if (account.balance < amt) return res.status(400).json({ error: 'Insufficient balance' });

        const r = await fetch(DOUBLONS_API + '/transfers', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + account.doublonsToken },
            body: JSON.stringify({ from_id: account.doublonsAccountId, to_id: to_doublons_account, amount: amt.toString(), currency: 'USD' })
        });
        const data = await r.json();
        if (!r.ok) return res.status(r.status).json(data);

        account.balance -= amt;
        await account.save();

        const tx = new Transaction({
            from: account._id.toString(),
            to: 'doublons:' + to_doublons_account,
            amount: amt,
            type: 'doublons_out',
            status: 'completed',
            doublonsTransferId: data.id || null
        });
        await tx.save();
        res.json({ success: true, transaction: tx, doublons: data });
    } catch (err) {
        res.status(502).json({ error: 'Doublons Bank unavailable' });
    }
});

app.post('/api/accounts/:accountId/deposit-doublons', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const { from_doublons_account, amount } = req.body;
        if (!from_doublons_account || !amount) return res.status(400).json({ error: 'from_doublons_account and amount required' });
        const amt = parseFloat(amount);
        if (isNaN(amt) || amt <= 0) return res.status(400).json({ error: 'Invalid amount' });

        const account = await Account.findOne({ _id: req.params.accountId, userId: req.authUser });
        if (!account) return res.status(404).json({ error: 'Account not found' });
        if (!account.doublonsToken) return res.status(400).json({ error: 'Doublons Bank not linked' });

        const r = await fetch(DOUBLONS_API + '/transfers', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + account.doublonsToken },
            body: JSON.stringify({ from_id: from_doublons_account, to_id: account.doublonsAccountId, amount: amt.toString(), currency: 'USD' })
        });
        const data = await r.json();
        if (!r.ok) return res.status(r.status).json(data);

        account.balance += amt;
        await account.save();

        const tx = new Transaction({
            from: 'doublons:' + from_doublons_account,
            to: account._id.toString(),
            amount: amt,
            type: 'doublons_in',
            status: 'completed',
            doublonsTransferId: data.id || null
        });
        await tx.save();
        res.json({ success: true, transaction: tx, doublons: data });
    } catch (err) {
        res.status(502).json({ error: 'Doublons Bank unavailable' });
    }
});

module.exports = app;
