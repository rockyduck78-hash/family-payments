const express = require('express');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(cors());
app.use(express.json());
app.use(cors());

// --- Config ---
const MONGODB_URI = process.env.MONGODB_URI || '';
const JWT_SECRET = process.env.JWT_SECRET || '';
const DOUBLONS_API = 'https://doublons-bank.vercel.app';

if (!JWT_SECRET) {
    console.warn('WARNING: JWT_SECRET not set.');
}

// --- Rate Limiting ---
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests' }
});

// --- MongoDB ---
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
            console.log('Connected to MongoDB');
        } catch (err) {
            console.error('MongoDB connection error:', err.message);
            mongoReady = false;
            mongoPromise = null;
            throw err;
        }
    })();
    return mongoPromise;
}

// --- Schemas ---
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
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
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

const Account = mongoose.model('Account', accountSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Request = mongoose.model('Request', requestSchema);

// --- Auth Middleware ---
// Accepts the same JWT tokens as family-finance (shared JWT_SECRET)
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

// --- Health ---
app.get('/health', async (req, res) => {
    try {
        await connectMongo();
        res.json({ status: 'ok', mongodb: 'connected' });
    } catch (err) {
        res.status(503).json({ status: 'error', mongodb: err.message });
    }
});

// === ACCOUNT ENDPOINTS ===

// List user's accounts
app.get('/api/accounts', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const accounts = await Account.find({ userId: req.authUser, active: true }).sort({ createdAt: 1 });
        res.json(accounts);
    } catch (err) {
        console.error('List accounts error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create a new payment account
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
        console.error('Create account error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete (deactivate) an account
app.delete('/api/accounts/:accountId', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const account = await Account.findOne({ _id: req.params.accountId, userId: req.authUser });
        if (!account) return res.status(404).json({ error: 'Account not found' });
        account.active = false;
        await account.save();
        res.json({ success: true });
    } catch (err) {
        console.error('Delete account error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// === TRANSFER ENDPOINTS ===

// Internal transfer between accounts
app.post('/api/transfer', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const { from_id, to_id, amount, note } = req.body;
        if (!from_id || !to_id || !amount) {
            return res.status(400).json({ error: 'from_id, to_id, and amount required' });
        }
        if (from_id === to_id) {
            return res.status(400).json({ error: 'Cannot transfer to the same account' });
        }

        const amt = parseFloat(amount);
        if (isNaN(amt) || amt <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        const fromAccount = await Account.findOne({ _id: from_id, userId: req.authUser, active: true });
        if (!fromAccount) return res.status(404).json({ error: 'Source account not found' });
        if (fromAccount.balance < amt) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        // to_id can be another user's account ID
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
        console.error('Transfer error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Request money from another account
app.post('/api/request', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const { to_account_id, amount, note } = req.body;
        if (!to_account_id || !amount) {
            return res.status(400).json({ error: 'to_account_id and amount required' });
        }

        const amt = parseFloat(amount);
        if (isNaN(amt) || amt <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        const toAccount = await Account.findOne({ _id: to_account_id, active: true });
        if (!toAccount) return res.status(404).json({ error: 'Target account not found' });

        const request = new Request({
            from: req.authUser,
            to: toAccount.userId,
            amount: amt,
            note: note || '',
            status: 'pending'
        });
        await request.save();

        res.json({ success: true, request });
    } catch (err) {
        console.error('Request error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get pending requests for user
app.get('/api/requests', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const requests = await Request.find({
            $or: [{ from: req.authUser }, { to: req.authUser }],
            status: 'pending'
        }).sort({ createdAt: -1 });
        res.json(requests);
    } catch (err) {
        console.error('List requests error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Approve a money request
app.post('/api/requests/:requestId/approve', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const request = await Request.findOne({ _id: req.params.requestId, to: req.authUser, status: 'pending' });
        if (!request) return res.status(404).json({ error: 'Request not found' });

        // Find sender's account with enough balance
        const senderAccounts = await Account.find({ userId: request.from, active: true }).sort({ balance: -1 });
        const senderAccount = senderAccounts.find(a => a.balance >= request.amount);
        if (!senderAccount) {
            request.status = 'denied';
            await request.save();
            return res.status(400).json({ error: 'Sender has insufficient balance' });
        }

        const receiverAccounts = await Account.find({ userId: request.to, active: true });
        if (receiverAccounts.length === 0) {
            return res.status(400).json({ error: 'Receiver has no active accounts' });
        }
        const receiverAccount = receiverAccounts[0];

        senderAccount.balance -= request.amount;
        receiverAccount.balance += request.amount;
        await senderAccount.save();
        await receiverAccount.save();

        const tx = new Transaction({
            from: senderAccount._id.toString(),
            to: receiverAccount._id.toString(),
            amount: request.amount,
            type: 'request',
            status: 'completed',
            note: request.note
        });
        await tx.save();

        request.status = 'approved';
        await request.save();

        res.json({ success: true, transaction: tx });
    } catch (err) {
        console.error('Approve request error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Deny a money request
app.post('/api/requests/:requestId/deny', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const request = await Request.findOne({ _id: req.params.requestId, to: req.authUser, status: 'pending' });
        if (!request) return res.status(404).json({ error: 'Request not found' });
        request.status = 'denied';
        await request.save();
        res.json({ success: true });
    } catch (err) {
        console.error('Deny request error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get transaction history
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
        console.error('List transactions error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// === DOUBLONS BANK ENDPOINTS ===

// Register on Doublons Bank
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
        console.error('Doublons register error:', err.message);
        res.status(502).json({ error: 'Doublons Bank unavailable' });
    }
});

// Login to Doublons Bank
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
        console.error('Doublons login error:', err.message);
        res.status(502).json({ error: 'Doublons Bank unavailable' });
    }
});

// Link Doublons Bank account to a payment account
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
        console.error('Link doublons error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Unlink Doublons Bank account
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
        console.error('Unlink doublons error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Doublons Bank accounts for a linked payment account
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
        console.error('Doublons accounts error:', err.message);
        res.status(502).json({ error: 'Doublons Bank unavailable' });
    }
});

// Transfer OUT to Doublons Bank (withdraw from payment account -> Doublons)
app.post('/api/accounts/:accountId/withdraw-doublons', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const { to_doublons_account, amount } = req.body;
        if (!to_doublons_account || !amount) {
            return res.status(400).json({ error: 'to_doublons_account and amount required' });
        }

        const amt = parseFloat(amount);
        if (isNaN(amt) || amt <= 0) return res.status(400).json({ error: 'Invalid amount' });

        const account = await Account.findOne({ _id: req.params.accountId, userId: req.authUser });
        if (!account) return res.status(404).json({ error: 'Account not found' });
        if (!account.doublonsToken) return res.status(400).json({ error: 'Doublons Bank not linked' });
        if (account.balance < amt) return res.status(400).json({ error: 'Insufficient balance' });

        // Transfer to Doublons Bank
        const r = await fetch(DOUBLONS_API + '/transfers', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + account.doublonsToken },
            body: JSON.stringify({ from_id: account.doublonsAccountId, to_id: to_doublons_account, amount: amt.toString(), currency: 'USD' })
        });
        const data = await r.json();
        if (!r.ok) return res.status(r.status).json(data);

        // Deduct from internal balance
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
        console.error('Withdraw doublons error:', err.message);
        res.status(502).json({ error: 'Doublons Bank unavailable' });
    }
});

// Transfer IN from Doublons Bank (deposit from Doublons -> payment account)
app.post('/api/accounts/:accountId/deposit-doublons', apiLimiter, authMiddleware, async (req, res) => {
    try {
        await connectMongo();
        const { from_doublons_account, amount } = req.body;
        if (!from_doublons_account || !amount) {
            return res.status(400).json({ error: 'from_doublons_account and amount required' });
        }

        const amt = parseFloat(amount);
        if (isNaN(amt) || amt <= 0) return res.status(400).json({ error: 'Invalid amount' });

        const account = await Account.findOne({ _id: req.params.accountId, userId: req.authUser });
        if (!account) return res.status(404).json({ error: 'Account not found' });
        if (!account.doublonsToken) return res.status(400).json({ error: 'Doublons Bank not linked' });

        // Transfer from Doublons Bank to our account
        const r = await fetch(DOUBLONS_API + '/transfers', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + account.doublonsToken },
            body: JSON.stringify({ from_id: from_doublons_account, to_id: account.doublonsAccountId, amount: amt.toString(), currency: 'USD' })
        });
        const data = await r.json();
        if (!r.ok) return res.status(r.status).json(data);

        // Add to internal balance
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
        console.error('Deposit doublons error:', err.message);
        res.status(502).json({ error: 'Doublons Bank unavailable' });
    }
});

// === SERVERLESS HANDLER (Vercel) ===
module.exports = app;
