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

// Serve Frontend Static Files
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
  slug: { type: String, required: true, unique: true },
  shopName: { type: String, required: true },
  passcodeHash: { type: String, default: '' },
  isHalted: { type: Boolean, default: false },
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
  const existingAdmin = await Admin.findOne();
  if (!existingAdmin) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash('8899', salt);
    await Admin.create({ masterPinHash: hash });
    console.log('🛡️ Default Super Admin initialized with secure hash.');
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

const bookingLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({ success: false, error: 'Aapne is network/IP se bohot saare tokens generate kar liye hain.' });
    }
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const { pin } = req.body;
    const admin = await Admin.findOne();
    if (!admin) return res.status(500).json({ success: false, error: 'Admin not initialized.' });

    const isMatch = await bcrypt.compare(pin, admin.masterPinHash);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid Master PIN.' });
    }

    const token = jwt.sign({ role: 'superadmin' }, JWT_SECRET, { expiresIn: '12h' });
    return res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/change-pin', verifyAdminJWT, async (req, res) => {
  try {
    const { currentPin, newPin } = req.body;
    const admin = await Admin.findOne();
    
    const isMatch = await bcrypt.compare(currentPin, admin.masterPinHash);
    if (!isMatch) {
      return res.status(400).json({ success: false, error: 'Current Master PIN is incorrect.' });
    }
    if (!newPin || newPin.length < 4) {
      return res.status(400).json({ success: false, error: 'New PIN must be at least 4 digits.' });
    }

    const salt = await bcrypt.genSalt(10);
    admin.masterPinHash = await bcrypt.hash(newPin, salt);
    await admin.save();

    res.json({ success: true, message: 'Master PIN updated securely.' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/admin/salons', verifyAdminJWT, async (req, res) => {
  try {
    const salons = await Salon.find({});
    const salonList = salons.map(s => {
      const diffTime = Math.abs(new Date() - new Date(s.onboardedAt));
      const daysOnboarded = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      return {
        slug: s.slug,
        shopName: s.shopName,
        isHalted: s.isHalted,
        onboardedAt: s.onboardedAt,
        daysOnboarded: daysOnboarded
      };
    });
    res.json(salonList);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/toggle-halt', verifyAdminJWT, async (req, res) => {
  try {
    const { slug } = req.body;
    const salon = await Salon.findOne({ slug });
    if (!salon) return res.status(404).json({ error: 'Salon not found.' });

    salon.isHalted = !salon.isHalted;
    await salon.save();
    res.json({ success: true, isHalted: salon.isHalted });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/reset-salon-pin', verifyAdminJWT, async (req, res) => {
  try {
    const { slug, newPasscode } = req.body;
    const salon = await Salon.findOne({ slug });
    if (!salon || !newPasscode || newPasscode.length < 4) {
      return res.status(400).json({ error: 'Invalid PIN or salon slug.' });
    }

    const salt = await bcrypt.genSalt(10);
    salon.passcodeHash = await bcrypt.hash(newPasscode, salt);
    await salon.save();
    res.json({ success: true, message: `PIN reset successfully for ${slug}` });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/admin/delete', verifyAdminJWT, async (req, res) => {
  try {
    const { slug } = req.body;
    const result = await Salon.findOneAndDelete({ slug });
    if (!result) return res.status(404).json({ success: false, error: 'Salon not found.' });
    res.json({ success: true, message: 'Salon deleted successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/:salon/auth/verify', async (req, res) => {
  try {
    const slug = req.params.salon;
    let salon = await Salon.findOne({ slug });

    // Agar salon pehle se nahi hai, toh naya create kar do (First Time Setup)
    if (!salon) {
      salon = await Salon.create({
        slug: slug,
        shopName: slug.replace(/-/g, ' ').toUpperCase(),
        chairs: [
          { chairNumber: 1, status: 'FREE', currentToken: null, customerName: '', services: [], amount: 150, remainingMinutes: 0 },
          { chairNumber: 2, status: 'FREE', currentToken: null, customerName: '', services: [], amount: 150, remainingMinutes: 0 },
          { chairNumber: 3, status: 'FREE', currentToken: null, customerName: '', services: [], amount: 150, remainingMinutes: 0 }
        ]
      });
      return res.json({ status: 'FIRST_TIME' });
    }

    if (salon.isHalted) {
      return res.json({ status: 'HALTED', message: salon.haltReason });
    }
    if (!salon.passcodeHash) {
      return res.json({ status: 'FIRST_TIME' });
    }

    const { passcode } = req.body;
    if (!passcode) {
      return res.json({ authenticated: false });
    }

    const isMatch = await bcrypt.compare(passcode, salon.passcodeHash);
    if (isMatch) {
      return res.json({ authenticated: true, token: 'jwt_token_' + slug });
    } else {
      return res.json({ authenticated: false, message: 'Incorrect PIN.' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/:salon/auth/set-passcode', async (req, res) => {
  try {
    const slug = req.params.salon;
    const { newPasscode } = req.body;
    if (!newPasscode || newPasscode.length < 4) {
      return res.status(400).json({ success: false, message: 'Passcode must be at least 4 digits.' });
    }

    let salon = await Salon.findOne({ slug });
    if (!salon) {
      salon = new Salon({ 
        slug, 
        shopName: slug.replace(/-/g, ' ').toUpperCase(),
        chairs: [
          { chairNumber: 1, status: 'FREE', currentToken: null, customerName: '', services: [], amount: 150, remainingMinutes: 0 },
          { chairNumber: 2, status: 'FREE', currentToken: null, customerName: '', services: [], amount: 150, remainingMinutes: 0 },
          { chairNumber: 3, status: 'FREE', currentToken: null, customerName: '', services: [], amount: 150, remainingMinutes: 0 }
        ]
      });
    }

    const salt = await bcrypt.genSalt(10);
    salon.passcodeHash = await bcrypt.hash(newPasscode, salt);
    await salon.save();

    res.json({ success: true, token: 'jwt_token_' + slug });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/:salon/auth/change-passcode', async (req, res) => {
  try {
    const slug = req.params.salon;
    const { currentPasscode, newPasscode } = req.body;
    const salon = await Salon.findOne({ slug });

    if (!salon) return res.status(404).json({ success: false, message: 'Salon not found.' });

    const isMatch = await bcrypt.compare(currentPasscode, salon.passcodeHash);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Current PIN is incorrect.' });
    }
    if (!newPasscode || newPasscode.length < 4) {
      return res.status(400).json({ success: false, message: 'New PIN must be at least 4 digits.' });
    }

    const salt = await bcrypt.genSalt(10);
    salon.passcodeHash = await bcrypt.hash(newPasscode, salt);
    await salon.save();

    res.json({ success: true, token: 'jwt_token_' + slug });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/:salon/state', async (req, res) => {
  try {
    const slug = req.params.salon;
    let salon = await Salon.findOne({ slug });
    if (!salon) {
      return res.status(404).json({ status: 'DELETED', message: 'Server Disconnected: Salon has been deleted by Super Admin.' });
    }

    if (salon.isHalted) {
      return res.status(403).json({ status: 'HALTED', message: salon.haltReason });
    }

    res.json({
      shopName: salon.shopName,
      todayServed: salon.todayServed,
      todayRevenue: salon.todayRevenue,
      chairs: salon.chairs,
      queue: salon.queue
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/:salon/rename', async (req, res) => {
  try {
    const slug = req.params.salon;
    const { shopName } = req.body;
    const salon = await Salon.findOne({ slug });
    if (!salon) return res.status(404).json({ success: false, error: 'Salon deleted.' });
    if (shopName) {
      salon.shopName = shopName;
      await salon.save();
    }
    res.json({ success: true, shopName: salon.shopName });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/:salon/reset-day', async (req, res) => {
  try {
    const slug = req.params.salon;
    const salon = await Salon.findOne({ slug });
    if (!salon) return res.status(404).json({ success: false, error: 'Salon deleted.' });
    
    salon.todayServed = 0;
    salon.todayRevenue = 0;
    salon.queue = [];
    salon.chairs.forEach(c => {
      c.status = 'FREE';
      c.currentToken = null;
      c.customerName = '';
      c.services = [];
      c.amount = 150;
      c.remainingMinutes = 0;
    });
    await salon.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/:salon/book', bookingLimiter, async (req, res) => {
  try {
    const slug = req.params.salon;
    const { customerName, services, totalDurationMinutes, totalPrice } = req.body;

    if (!customerName || customerName.trim() === '') {
      return res.status(400).json({ success: false, error: 'Customer name is mandatory.' });
    }

    let salon = await Salon.findOne({ slug });
    if (!salon || salon.isHalted) {
      return res.status(403).json({ success: false, error: 'Server Disconnected: Salon is unavailable.' });
    }

    const durationMins = Number(totalDurationMinutes) || 20;
    const maxQueueToken = salon.queue.length > 0 ? Math.max(...salon.queue.map(q => q.tokenNumber)) : 0;
    const maxChairToken = salon.chairs.reduce((max, c) => c.currentToken ? Math.max(max, c.currentToken) : max, 0);
    const nextTokenNum = Math.max(maxQueueToken, maxChairToken, salon.todayServed) + 1;

    const booking = {
      tokenNumber: nextTokenNum,
      customerName: customerName.trim(),
      services: services || ['Haircut'],
      totalDurationMinutes: durationMins,
      totalPrice: totalPrice || 150,
      createdAt: new Date()
    };

    const freeChair = salon.chairs.find(c => c.status === 'FREE');
    if (freeChair) {
      freeChair.status = 'BUSY';
      freeChair.currentToken = booking.tokenNumber;
      freeChair.customerName = booking.customerName;
      freeChair.services = booking.services;
      freeChair.amount = booking.totalPrice;
      freeChair.remainingMinutes = durationMins;
      booking.estimatedWaitMinutes = 0;
    } else {
      let workloads = salon.chairs.map(c => (c.status === 'BUSY' ? (c.remainingMinutes || 20) : 0));
      salon.queue.forEach(q => {
        let minIdx = workloads.indexOf(Math.min(...workloads));
        workloads[minIdx] += (q.totalDurationMinutes || 20);
      });
      let bestChairIdx = workloads.indexOf(Math.min(...workloads));
      booking.estimatedWaitMinutes = workloads[bestChairIdx];
      salon.queue.push(booking);
    }

    await salon.save();
    res.json({ success: true, booking, tokenNumber: nextTokenNum });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/:salon/chair/start', async (req, res) => {
  try {
    const slug = req.params.salon;
    const { tokenNumber, chairNumber } = req.body;
    const salon = await Salon.findOne({ slug });
    if (!salon) return res.status(404).json({ success: false, error: 'Salon deleted.' });

    const chair = salon.chairs.find(c => c.chairNumber === Number(chairNumber));
    const qIndex = salon.queue.findIndex(q => q.tokenNumber === Number(tokenNumber));

    if (chair && qIndex !== -1) {
      const customer = salon.queue.splice(qIndex, 1)[0];
      chair.status = 'BUSY';
      chair.currentToken = customer.tokenNumber;
      chair.customerName = customer.customerName;
      chair.services = customer.services;
      chair.amount = customer.totalPrice || 150;
      chair.remainingMinutes = customer.totalDurationMinutes || 20;
      await salon.save();
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/:salon/chair/complete', async (req, res) => {
  try {
    const slug = req.params.salon;
    const { chairNumber } = req.body;
    const salon = await Salon.findOne({ slug });
    if (!salon) return res.status(404).json({ success: false, error: 'Salon deleted.' });

    const chair = salon.chairs.find(c => c.chairNumber === Number(chairNumber));
    if (chair && chair.status === 'BUSY') {
      salon.todayServed += 1;
      salon.todayRevenue += (chair.amount || 150);

      if (salon.queue.length > 0) {
        const nextCustomer = salon.queue.shift();
        chair.currentToken = nextCustomer.tokenNumber;
        chair.customerName = nextCustomer.customerName;
        chair.services = nextCustomer.services;
        chair.amount = nextCustomer.totalPrice || 150;
        chair.remainingMinutes = nextCustomer.totalDurationMinutes || 20;
      } else {
        chair.status = 'FREE';
        chair.currentToken = null;
        chair.customerName = '';
        chair.services = [];
        chair.amount = 150;
        chair.remainingMinutes = 0;
      }
      await salon.save();
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Secured Production SaaS Backend running on port ${PORT}`);
});