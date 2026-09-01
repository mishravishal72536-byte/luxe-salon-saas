const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../frontend')));

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/luxe_salon_saas';
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_change_in_production';

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('📦 Connected to MongoDB Successfully (Secure Storage)');
}).catch(err => {
  console.error('❌ MongoDB Connection Error:', err);
});

const adminSchema = new mongoose.Schema({
  masterPinHash: { type: String, required: true }
});
const Admin = mongoose.model('Admin', adminSchema);

const salonSchema = new mongoose.Schema({
  slug: { type: String, required: true, unique: true, index: true },
  shopName: { type: String, required: true },
  passcodeHash: { type: String, default: '' },
  isHalted: { type: Boolean, default: false },
  isOnline: { type: Boolean, default: true },
  haltReason: { type: String, default: 'Salon access suspended by super admin.' },
  onboardedAt: { type: Date, default: Date.now },
  todayServed: { type: Number, default: 0 },
  todayRevenue: { type: Number, default: 0 },
  chairs: [
    {
      chairNumber: Number,
      status: { type: String, default: 'FREE' },
      currentToken: { type: Number, default: null },
      customerName: { type: String, default: '' },
      services: [String],
      amount: { type: Number, default: 150 },
      remainingMinutes: { type: Number, default: 0 }
    }
  ],
  queue: [
    {
      tokenNumber: Number,
      customerName: String,
      services: [String],
      totalDurationMinutes: Number,
      totalPrice: Number,
      createdAt: { type: Date, default: Date.now }
    }
  ]
});
const Salon = mongoose.model('Salon', salonSchema);

async function initAdmin() {
  try {
    let adminExists = await Admin.findOne();
    if (!adminExists) {
      const salt = await bcrypt.genSalt(10);
      const pin = process.env.DEFAULT_ADMIN_PIN || '8899';
      const hash = await bcrypt.hash(pin, salt);
      await Admin.create({ masterPinHash: hash });
      console.log('🛡️ Default Super Admin initialized with secure hash.');
    }
  } catch (err) {
    console.error('Admin init error:', err);
  }
}
initAdmin();

function verifyAdminJWT(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'Access Denied. No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, error: 'Invalid or expired token.' });
    req.admin = user;
    next();
  });
}

function verifySalonJWT(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'Access Denied. No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ success: false, error: 'Invalid or expired token.' });
    if (decoded.slug !== req.params.salon && decoded.role !== 'superadmin') {
      return res.status(403).json({ success: false, error: 'Unauthorized salon access.' });
    }
    req.salonUser = decoded;
    next();
  });
}

// In-memory tracker for failed attempts per specific target/account instead of blinding entire Wi-Fi IP
const failedAttemptStore = {};
function checkAccountBruteGuard(key) {
  const record = failedAttemptStore[key];
  if (!record) return { locked: false };
  if (Date.now() > record.unlockAt) {
    delete failedAttemptStore[key];
    return { locked: false };
  }
  const remainingMins = Math.ceil((record.unlockAt - Date.now()) / 60000);
  return { locked: true, remainingMins };
}

function recordFailedAttempt(key) {
  if (!failedAttemptStore[key]) {
    failedAttemptStore[key] = { count: 1, unlockAt: Date.now() + 5 * 60 * 1000 };
  } else {
    failedAttemptStore[key].count += 1;
    if (failedAttemptStore[key].count >= 4) {
      failedAttemptStore[key].unlockAt = Date.now() + 5 * 60 * 1000;
    }
  }
}

function clearFailedAttempts(key) {
  delete failedAttemptStore[key];
}

const bookingLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  handler: (req, res) => {
    res.status(429).json({ success: false, error: 'Aapne is network se bohot saare tokens generate kar liye hain.' });
  }
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const guard = checkAccountBruteGuard('super_admin_master');
    if (guard.locked) {
      return res.status(429).json({ 
        success: false, 
        error: `Too many incorrect Master PIN attempts. Please wait ${guard.remainingMins} minute(s) before trying again.` 
      });
    }

    const { pin } = req.body;
    if (!pin) return res.status(400).json({ success: false, error: 'PIN is required.' });

    let adminDoc = await Admin.findOne();
    if (!adminDoc) {
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash('8899', salt);
      adminDoc = await Admin.create({ masterPinHash: hash });
    }

    const matched = await bcrypt.compare(pin, adminDoc.masterPinHash);
    if (!matched) {
      recordFailedAttempt('super_admin_master');
      return res.status(401).json({ success: false, error: 'Invalid Master PIN.' });
    }

    clearFailedAttempts('super_admin_master');
    const token = jwt.sign({ role: 'superadmin' }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/admin/change-pin', verifyAdminJWT, async (req, res) => {
  try {
    const { currentPin, newPin } = req.body;
    const adminDoc = await Admin.findOne();
    
    const matched = await bcrypt.compare(currentPin, adminDoc.masterPinHash);
    if (!matched) {
      return res.status(400).json({ success: false, error: 'Current Master PIN is incorrect.' });
    }
    if (!newPin || newPin.length < 4) {
      return res.status(400).json({ success: false, error: 'New PIN must be at least 4 digits.' });
    }

    const salt = await bcrypt.genSalt(10);
    adminDoc.masterPinHash = await bcrypt.hash(newPin, salt);
    await adminDoc.save();

    res.json({ success: true, message: 'Master PIN updated securely.' });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.get('/api/admin/salons', verifyAdminJWT, async (req, res) => {
  try {
    const allSalons = await Salon.find({});
    const salonList = allSalons.map(s => {
      const diffTime = Math.abs(new Date() - new Date(s.onboardedAt));
      const days = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      return {
        slug: s.slug,
        shopName: s.shopName,
        isHalted: s.isHalted,
        onboardedAt: s.onboardedAt,
        daysOnboarded: days
      };
    });
    res.json(salonList);
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/admin/toggle-halt', verifyAdminJWT, async (req, res) => {
  try {
    const { slug } = req.body;
    const targetSalon = await Salon.findOne({ slug });
    if (!targetSalon) return res.status(404).json({ error: 'Salon not found.' });

    targetSalon.isHalted = !targetSalon.isHalted;
    await targetSalon.save();
    res.json({ success: true, isHalted: targetSalon.isHalted });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/admin/reset-salon-pin', verifyAdminJWT, async (req, res) => {
  try {
    const { slug, newPasscode } = req.body;
    const targetSalon = await Salon.findOne({ slug });
    if (!targetSalon || !newPasscode || newPasscode.length < 4) {
      return res.status(400).json({ error: 'Invalid PIN or salon slug.' });
    }

    const salt = await bcrypt.genSalt(10);
    targetSalon.passcodeHash = await bcrypt.hash(newPasscode, salt);
    await targetSalon.save();
    clearFailedAttempts(`salon_${slug}`);
    res.json({ success: true, message: `PIN reset successfully for ${slug}` });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/admin/delete', verifyAdminJWT, async (req, res) => {
  try {
    const { slug } = req.body;
    const delResult = await Salon.findOneAndDelete({ slug });
    if (!delResult) return res.status(404).json({ success: false, error: 'Salon not found.' });
    clearFailedAttempts(`salon_${slug}`);
    res.json({ success: true, message: 'Salon deleted successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/:salon/auth/verify', async (req, res) => {
  try {
    const slug = req.params.salon;
    const guardKey = `salon_${slug}`;
    const guard = checkAccountBruteGuard(guardKey);
    if (guard.locked) {
      return res.status(429).json({ 
        success: false, 
        error: `Too many incorrect PIN attempts for this salon. Please wait ${guard.remainingMins} minute(s).` 
      });
    }

    let targetSalon = await Salon.findOne({ slug });

    if (!targetSalon) {
      return res.json({ status: 'FIRST_TIME' });
    }

    if (targetSalon.isHalted) {
      return res.status(403).json({ status: 'HALTED', message: targetSalon.haltReason });
    }
    if (!targetSalon.passcodeHash) {
      return res.json({ status: 'FIRST_TIME' });
    }

    const { passcode } = req.body;
    if (!passcode) {
      return res.json({ authenticated: false });
    }

    const matched = await bcrypt.compare(passcode, targetSalon.passcodeHash);
    if (matched) {
      clearFailedAttempts(guardKey);
      const token = jwt.sign({ slug: targetSalon.slug, role: 'owner' }, JWT_SECRET, { expiresIn: '24h' });
      return res.json({ authenticated: true, success: true, token });
    } else {
      recordFailedAttempt(guardKey);
      return res.status(401).json({ authenticated: false, success: false, error: 'Incorrect PIN.' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/:salon/auth/set-passcode', async (req, res) => {
  try {
    const slug = req.params.salon;
    const { newPasscode, shopName } = req.body;
    if (!newPasscode || newPasscode.length < 4) {
      return res.status(400).json({ success: false, error: 'Passcode must be at least 4 digits.' });
    }

    let targetSalon = await Salon.findOne({ slug });
    if (!targetSalon) {
      targetSalon = new Salon({ 
        slug, 
        shopName: shopName || slug.replace(/-/g, ' ').toUpperCase(),
        isOnline: true,
        chairs: [
          { chairNumber: 1, status: 'FREE', currentToken: null, customerName: '', services: [], amount: 150, remainingMinutes: 0 },
          { chairNumber: 2, status: 'FREE', currentToken: null, customerName: '', services: [], amount: 150, remainingMinutes: 0 },
          { chairNumber: 3, status: 'FREE', currentToken: null, customerName: '', services: [], amount: 150, remainingMinutes: 0 }
        ]
      });
    } else if (shopName) {
      targetSalon.shopName = shopName;
    }

    const salt = await bcrypt.genSalt(10);
    targetSalon.passcodeHash = await bcrypt.hash(newPasscode, salt);
    await targetSalon.save();
    clearFailedAttempts(`salon_${slug}`);

    const token = jwt.sign({ slug: targetSalon.slug, role: 'owner' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/:salon/auth/change-passcode', verifySalonJWT, async (req, res) => {
  try {
    const slug = req.params.salon;
    const { currentPasscode, newPasscode } = req.body;
    const targetSalon = await Salon.findOne({ slug });

    if (!targetSalon) return res.status(404).json({ success: false, error: 'Salon not found.' });

    const matched = await bcrypt.compare(currentPasscode, targetSalon.passcodeHash);
    if (!matched) {
      return res.status(400).json({ success: false, error: 'Current PIN is incorrect.' });
    }
    if (!newPasscode || newPasscode.length < 4) {
      return res.status(400).json({ success: false, error: 'New PIN must be at least 4 digits.' });
    }

    const salt = await bcrypt.genSalt(10);
    targetSalon.passcodeHash = await bcrypt.hash(newPasscode, salt);
    await targetSalon.save();
    clearFailedAttempts(`salon_${slug}`);

    const token = jwt.sign({ slug: targetSalon.slug, role: 'owner' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.get('/api/:salon/state', async (req, res) => {
  try {
    const slug = req.params.salon;
    const targetSalon = await Salon.findOne({ slug });
    if (!targetSalon) {
      return res.status(404).json({ status: 'DELETED', message: 'Server Disconnected: Salon has been deleted by Super Admin.' });
    }

    if (targetSalon.isHalted) {
      return res.status(403).json({ status: 'HALTED', message: targetSalon.haltReason });
    }

    res.json({
      shopName: targetSalon.shopName,
      isOnline: targetSalon.isOnline,
      todayServed: targetSalon.todayServed,
      todayRevenue: targetSalon.todayRevenue,
      chairs: targetSalon.chairs,
      queue: targetSalon.queue
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/:salon/toggle-online', verifySalonJWT, async (req, res) => {
  try {
    const slug = req.params.salon;
    let targetSalon = await Salon.findOne({ slug });
    if (!targetSalon) {
      return res.status(404).json({ success: false, error: 'Salon not found.' });
    }
    targetSalon.isOnline = !targetSalon.isOnline;
    await targetSalon.save();
    res.json({ success: true, isOnline: targetSalon.isOnline });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/:salon/rename', verifySalonJWT, async (req, res) => {
  try {
    const slug = req.params.salon;
    const { shopName } = req.body;
    const targetSalon = await Salon.findOne({ slug });
    if (!targetSalon) return res.status(404).json({ success: false, error: 'Salon deleted.' });
    if (shopName) {
      targetSalon.shopName = shopName.trim();
      await targetSalon.save();
    }
    res.json({ success: true, shopName: targetSalon.shopName });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/:salon/reset-day', verifySalonJWT, async (req, res) => {
  try {
    const slug = req.params.salon;
    const targetSalon = await Salon.findOne({ slug });
    if (!targetSalon) return res.status(404).json({ success: false, error: 'Salon deleted.' });
    
    targetSalon.todayServed = 0;
    targetSalon.todayRevenue = 0;
    targetSalon.queue = [];
    targetSalon.chairs.forEach(c => {
      c.status = 'FREE';
      c.currentToken = null;
      c.customerName = '';
      c.services = [];
      c.amount = 150;
      c.remainingMinutes = 0;
    });
    await targetSalon.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/:salon/book', bookingLimiter, async (req, res) => {
  try {
    const slug = req.params.salon;
    const { customerName, services, totalDurationMinutes, totalPrice } = req.body;

    if (!customerName || customerName.trim() === '') {
      return res.status(400).json({ success: false, error: 'Customer name is mandatory.' });
    }

    let targetSalon = await Salon.findOne({ slug });
    if (!targetSalon) {
      targetSalon = await Salon.create({
        slug: slug,
        shopName: slug.replace(/-/g, ' ').toUpperCase(),
        isOnline: true,
        chairs: [
          { chairNumber: 1, status: 'FREE', currentToken: null, customerName: '', services: [], amount: 150, remainingMinutes: 0 },
          { chairNumber: 2, status: 'FREE', currentToken: null, customerName: '', services: [], amount: 150, remainingMinutes: 0 },
          { chairNumber: 3, status: 'FREE', currentToken: null, customerName: '', services: [], amount: 150, remainingMinutes: 0 }
        ]
      });
    }

    if (targetSalon.isHalted) {
      return res.status(403).json({ success: false, error: 'Server Disconnected: Salon is unavailable.' });
    }

    const durationMins = Number(totalDurationMinutes) || 20;
    const maxQueueToken = targetSalon.queue.length > 0 ? Math.max(...targetSalon.queue.map(q => q.tokenNumber)) : 0;
    const maxChairToken = targetSalon.chairs.reduce((max, c) => c.currentToken ? Math.max(max, c.currentToken) : max, 0);
    const nextTokenNum = Math.max(maxQueueToken, maxChairToken, targetSalon.todayServed) + 1;

    const bookingItem = {
      tokenNumber: nextTokenNum,
      customerName: customerName.trim(),
      services: services || ['Haircut'],
      totalDurationMinutes: durationMins,
      totalPrice: totalPrice || 150,
      createdAt: new Date()
    };

    const freeChair = targetSalon.isOnline ? targetSalon.chairs.find(c => c.status === 'FREE') : null;
    if (freeChair) {
      freeChair.status = 'BUSY';
      freeChair.currentToken = bookingItem.tokenNumber;
      freeChair.customerName = bookingItem.customerName;
      freeChair.services = bookingItem.services;
      freeChair.amount = bookingItem.totalPrice;
      freeChair.remainingMinutes = durationMins;
      bookingItem.estimatedWaitMinutes = 0;
    } else {
      let workloads = targetSalon.chairs.map(c => (c.status === 'BUSY' ? (c.remainingMinutes || 20) : 0));
      targetSalon.queue.forEach(q => {
        let minIdx = workloads.indexOf(Math.min(...workloads));
        workloads[minIdx] += (q.totalDurationMinutes || 20);
      });
      let bestChairIdx = workloads.indexOf(Math.min(...workloads));
      bookingItem.estimatedWaitMinutes = workloads[bestChairIdx];
      targetSalon.queue.push(bookingItem);
    }

    await targetSalon.save();
    res.json({ success: true, booking: bookingItem, tokenNumber: nextTokenNum });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/:salon/chair/start', verifySalonJWT, async (req, res) => {
  try {
    const slug = req.params.salon;
    const { tokenNumber, chairNumber } = req.body;
    const targetSalon = await Salon.findOne({ slug });
    if (!targetSalon) return res.status(404).json({ success: false, error: 'Salon deleted.' });

    const targetChair = targetSalon.chairs.find(c => c.chairNumber === Number(chairNumber));
    const qIndex = targetSalon.queue.findIndex(q => q.tokenNumber === Number(tokenNumber));

    if (targetChair && qIndex !== -1) {
      const customer = targetSalon.queue.splice(qIndex, 1)[0];
      targetChair.status = 'BUSY';
      targetChair.currentToken = customer.tokenNumber;
      targetChair.customerName = customer.customerName;
      targetChair.services = customer.services;
      targetChair.amount = customer.totalPrice || 150;
      targetChair.remainingMinutes = customer.totalDurationMinutes || 20;
      await targetSalon.save();
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.post('/api/:salon/chair/complete', verifySalonJWT, async (req, res) => {
  try {
    const slug = req.params.salon;
    const { chairNumber } = req.body;
    const targetSalon = await Salon.findOne({ slug });
    if (!targetSalon) return res.status(404).json({ success: false, error: 'Salon deleted.' });

    const targetChair = targetSalon.chairs.find(c => c.chairNumber === Number(chairNumber));
    if (targetChair && targetChair.status === 'BUSY') {
      targetSalon.todayServed += 1;
      targetSalon.todayRevenue += (targetChair.amount || 150);

      if (targetSalon.isOnline && targetSalon.queue.length > 0) {
        const nextCustomer = targetSalon.queue.shift();
        targetChair.currentToken = nextCustomer.tokenNumber;
        targetChair.customerName = nextCustomer.customerName;
        targetChair.services = nextCustomer.services;
        targetChair.amount = nextCustomer.totalPrice || 150;
        targetChair.remainingMinutes = nextCustomer.totalDurationMinutes || 20;
      } else {
        targetChair.status = 'FREE';
        targetChair.currentToken = null;
        targetChair.customerName = '';
        targetChair.services = [];
        targetChair.amount = 150;
        targetChair.remainingMinutes = 0;
      }
      await targetSalon.save();
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Secured Production SaaS Backend running on port ${PORT}`);
});