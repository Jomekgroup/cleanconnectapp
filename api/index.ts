import express, { Request, Response, NextFunction, RequestHandler } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import { GoogleGenAI } from '@google/genai';
import { fileURLToPath } from 'url';
import serverless from 'serverless-http';

// Determine __dirname in ESM/TS environment
const isESM = typeof import.meta !== 'undefined' && typeof import.meta.url !== 'undefined';
let __dirname_local = '';
if (isESM) {
  const __filename = fileURLToPath(import.meta.url);
  __dirname_local = path.dirname(__filename);
} else {
  // Fallback for CommonJS
  // @ts-ignore
  __dirname_local = typeof __dirname !== 'undefined' ? __dirname : path.resolve();
}

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_123';

// Increase payload limit for large image uploads
app.use(express.json({ limit: '50mb' }) as RequestHandler);
app.use(express.urlencoded({ extended: true, limit: '50mb' }) as RequestHandler);
app.use(cors());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Gemini AI Client
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY || '' });

// MOCK DATA STORE
const MOCK_TICKETS: any[] = [];

// TYPES
interface AuthRequest extends Request {
  user?: {
    id: string;
    role: string;
    isAdmin: boolean;
    adminRole?: string;
  };
  body: any;
  params: any;
  query: any;
}

// UTILITIES
const generateToken = (id: string, role: string, isAdmin: boolean, adminRole?: string) => {
  return jwt.sign({ id, role, isAdmin, adminRole }, JWT_SECRET, { expiresIn: '30d' });
};

const sendEmail = async (to: string, subject: string, text: string) => {
  if (process.env.NODE_ENV !== 'test') {
    console.log(`\n--- [MOCK EMAIL] ---\nTo: ${to}\nSubject: ${subject}\nBody: ${text}\n--------------------\n`);
  }
};

const handleError = (res: Response, error: any, message: string = 'Server Error') => {
  console.error(message, error);
  const status = error && error.status ? error.status : 500;
  res.status(status).json({ message: error.message || message });
};

// MIDDLEWARE
const protect: RequestHandler = (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      (req as AuthRequest).user = decoded;
      next();
    } catch (error) {
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  } else {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

const admin: RequestHandler = (req, res, next) => {
  const authReq = req as AuthRequest;
  if (authReq.user && authReq.user.isAdmin) next();
  else res.status(403).json({ message: 'Admin access required' });
};

// ------------------ AUTH ROUTES ------------------
app.post('/api/auth/register', async (req, res) => {
  const { email, password, role, fullName, phoneNumber, state, city, otherCity, address, clientType, cleanerType, companyName, companyAddress, experience, services, bio, chargeHourly, chargeDaily, chargePerContract, chargePerContractNegotiable, bankName, accountNumber, profilePhoto, governmentId, businessRegDoc } = req.body;

  try {
    const userExists = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (userExists.rows.length > 0) return res.status(400).json({ message: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const servicesJson = services ? JSON.stringify(services) : null;

    const result = await pool.query(
      `INSERT INTO users (
        email, password_hash, role, full_name, phone_number, state, city, other_city, address,
        client_type, cleaner_type, company_name, company_address, experience, services, bio,
        charge_hourly, charge_daily, charge_per_contract, charge_per_contract_negotiable,
        bank_name, account_number, profile_photo, government_id, business_reg_doc, subscription_tier, created_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,'Free',NOW()) RETURNING *`,
      [email, hashedPassword, role, fullName, phoneNumber, state, city, otherCity, address, clientType, cleanerType, companyName, companyAddress, experience, servicesJson, bio, chargeHourly, chargeDaily, chargePerContract, chargePerContractNegotiable, bankName, accountNumber, profilePhoto, governmentId, businessRegDoc]
    );

    const user = result.rows[0];
    res.status(201).json({ ...user, token: generateToken(user.id, user.role, user.is_admin, user.admin_role) });
  } catch (error) {
    handleError(res, error, 'Registration failed');
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = result.rows[0];
    if (user && (await bcrypt.compare(password, user.password_hash))) {
      if (user.is_suspended) return res.status(403).json({ message: 'Account is suspended.' });
      const userData = { id: user.id, fullName: user.full_name, email: user.email, role: user.role, isAdmin: user.is_admin, adminRole: user.admin_role, profilePhoto: user.profile_photo, subscriptionTier: user.subscription_tier };
      res.json({ token: generateToken(user.id, user.role, user.is_admin, user.admin_role), user: userData });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    handleError(res, error, 'Login failed');
  }
});

// ------------------ USER ROUTES ------------------
app.get('/api/users/me', protect, async (req, res) => {
  const authReq = req as AuthRequest;
  try {
    const result = await pool.query('SELECT * FROM users WHERE id=$1', [authReq.user!.id]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (error) {
    handleError(res, error);
  }
});

// ------------------ CLEANERS ------------------
app.get('/api/cleaners', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE role=$1 AND is_suspended=false', ['cleaner']);
    res.json(result.rows);
  } catch (error) {
    handleError(res, error);
  }
});

app.get('/api/cleaners/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id=$1 AND role=$2', [req.params.id, 'cleaner']);
    if (!result.rows[0]) return res.status(404).json({ message: 'Cleaner not found' });
    res.json(result.rows[0]);
  } catch (error) {
    handleError(res, error);
  }
});

// ------------------ BOOKINGS ------------------
app.post('/api/bookings', protect, async (req, res) => {
  const authReq = req as AuthRequest;
  const { cleanerId, service, date, amount, totalAmount, paymentMethod } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO bookings (client_id, cleaner_id, service, date, amount, total_amount, payment_method, status, payment_status, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'Upcoming', $8, NOW()) RETURNING *`,
      [authReq.user!.id, cleanerId, service, date, amount, totalAmount, paymentMethod, paymentMethod === 'Direct' ? 'Not Applicable' : 'Pending Payment']
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    handleError(res, error, 'Booking failed');
  }
});

// Booking receipts
app.post('/api/bookings/:id/receipt', protect, async (req, res) => {
  const { name, dataUrl } = req.body;
  try {
    const receiptJson = JSON.stringify({ name, dataUrl });
    const result = await pool.query("UPDATE bookings SET payment_receipt=$1, payment_status='Pending Admin Confirmation' WHERE id=$2 RETURNING *", [receiptJson, req.params.id]);
    res.json(result.rows[0]);
  } catch (error) {
    handleError(res, error, 'Failed to upload receipt');
  }
});

// ------------------ ADMIN BOOKING MANAGEMENT ------------------
app.post('/api/admin/bookings/:id/confirm-payment', protect, admin, async (req, res) => {
  try {
    await pool.query("UPDATE bookings SET payment_status='Confirmed' WHERE id=$1", [req.params.id]);
    res.json({ message: 'Payment confirmed' });
  } catch (error) {
    handleError(res, error);
  }
});

app.post('/api/admin/bookings/:id/mark-paid', protect, admin, async (req, res) => {
  try {
    await pool.query("UPDATE bookings SET payment_status='Paid' WHERE id=$1", [req.params.id]);
    res.json({ message: 'Marked as paid' });
  } catch (error) {
    handleError(res, error);
  }
});

// ------------------ SUBSCRIPTIONS ------------------
app.post('/api/users/subscription/upgrade', protect, async (req, res) => {
  const authReq = req as AuthRequest;
  const { plan } = req.body;
  try {
    const result = await pool.query("UPDATE users SET pending_subscription=$1 WHERE id=$2 RETURNING *", [plan, authReq.user!.id]);
    res.json(result.rows[0]);
  } catch (error) {
    handleError(res, error);
  }
});

app.post('/api/users/subscription/receipt', protect, async (req, res) => {
  const authReq = req as AuthRequest;
  const { name, dataUrl } = req.body;
  try {
    const receiptJson = JSON.stringify({ name, dataUrl });
    const result = await pool.query("UPDATE users SET subscription_receipt=$1 WHERE id=$2 RETURNING *", [receiptJson, authReq.user!.id]);
    res.json({ ...result.rows[0], subscriptionReceipt: JSON.parse(result.rows[0].subscription_receipt) });
  } catch (error) {
    handleError(res, error, 'Failed to upload subscription receipt');
  }
});

// ------------------ SUPPORT TICKETS ------------------
app.post('/api/support', protect, async (req, res) => {
  const authReq = req as AuthRequest;
  const { category, subject, message } = req.body;
  try {
    const result = await pool.query("INSERT INTO support_tickets (user_id, category, subject, message, created_at) VALUES ($1,$2,$3,$4,NOW()) RETURNING *", [authReq.user!.id, category, subject, message]);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    handleError(res, error);
  }
});

app.get('/api/support/my', protect, async (req, res) => {
  const authReq = req as AuthRequest;
  try {
    const result = await pool.query("SELECT * FROM support_tickets WHERE user_id=$1 ORDER BY created_at DESC", [authReq.user!.id]);
    res.json(result.rows);
  } catch (error) {
    handleError(res, error);
  }
});

app.get('/api/admin/support', protect, admin, async (req, res) => {
  try {
    const result = await pool.query("SELECT st.*, u.full_name, u.role FROM support_tickets st JOIN users u ON st.user_id=u.id ORDER BY st.status ASC, st.created_at DESC");
    res.json(result.rows);
  } catch (error) {
    handleError(res, error);
  }
});

app.post('/api/admin/support/:id/resolve', protect, admin, async (req, res) => {
  const { adminResponse } = req.body;
  try {
    const result = await pool.query("UPDATE support_tickets SET admin_response=$1, status='Resolved', updated_at=NOW() WHERE id=$2 RETURNING *", [adminResponse, req.params.id]);
    res.json(result.rows[0]);
  } catch (error) {
    handleError(res, error);
  }
});

// ------------------ CHAT ------------------
app.post('/api/chats', protect, async (req, res) => {
  const authReq = req as AuthRequest;
  const { participantId } = req.body;
  try {
    const existing = await pool.query('SELECT * FROM chats WHERE (participant_one=$1 AND participant_two=$2) OR (participant_one=$2 AND participant_two=$1)', [authReq.user!.id, participantId]);
    if (existing.rows.length > 0) return res.json(existing.rows[0]);
    const result = await pool.query('INSERT INTO chats (participant_one, participant_two) VALUES ($1,$2) RETURNING *', [authReq.user!.id, participantId]);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    handleError(res, error, 'Failed to create chat');
  }
});

app.get('/api/chats', protect, async (req, res) => {
  const authReq = req as AuthRequest;
  try {
    const result = await pool.query('SELECT * FROM chats WHERE participant_one=$1 OR participant_two=$1', [authReq.user!.id]);
    res.json(result.rows);
  } catch (error) {
    handleError(res, error);
  }
});

app.post('/api/chats/:id/messages', protect, async (req, res) => {
  const authReq = req as AuthRequest;
  const { text } = req.body;
  try {
    const result = await pool.query('INSERT INTO messages (chat_id, sender_id, text, created_at) VALUES ($1,$2,$3,NOW()) RETURNING *', [req.params.id, authReq.user!.id, text]);
    const message = result.rows[0];
    await pool.query('UPDATE chats SET last_message_id=$1 WHERE id=$2', [message.id, req.params.id]);
    res.status(201).json(message);
  } catch (error) {
    handleError(res, error);
  }
});

// ------------------ FALLBACKS ------------------
app.use('/api/*', (req, res) => res.status(404).json({ message: 'API route not found' }));

app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

// Export serverless handler
export const handler = serverless(app);
export default handler;
