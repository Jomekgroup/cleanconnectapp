import express, { Request, Response, NextFunction, RequestHandler } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import serverless from 'serverless-http';

dotenv.config();

/* -------------------- APP SETUP -------------------- */

const app = express();

app.use(express.json({ limit: '50mb' }) as RequestHandler);
app.use(express.urlencoded({ extended: true, limit: '50mb' }) as RequestHandler);
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_123';

/* -------------------- DB SETUP -------------------- */

if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL is missing');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.on('connect', () => console.log('✅ PostgreSQL connected'));
pool.on('error', (err) => console.error('❌ PostgreSQL error', err));

/* -------------------- TYPES -------------------- */

interface AuthRequest extends Request {
  user?: {
    id: string;
    role: string;
    isAdmin: boolean;
    adminRole?: string;
  };
}

/* -------------------- UTILITIES -------------------- */

const generateToken = (
  id: string,
  role: string,
  isAdmin: boolean,
  adminRole?: string
) =>
  jwt.sign({ id, role, isAdmin, adminRole }, JWT_SECRET, {
    expiresIn: '30d',
  });

const handleError = (
  res: Response,
  error: any,
  message = 'Server Error'
) => {
  console.error(message, error);
  res.status(500).json({ message });
};

/* -------------------- AUTH MIDDLEWARE -------------------- */

const protect: RequestHandler = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Not authorized' });
  }

  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    (req as AuthRequest).user = decoded;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const admin: RequestHandler = (req, res, next) => {
  const user = (req as AuthRequest).user;
  if (user?.isAdmin) return next();
  res.status(403).json({ message: 'Admin access required' });
};

/* -------------------- HEALTH -------------------- */

app.get('/api/health', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

/* -------------------- AUTH ROUTES -------------------- */

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, role, fullName } = req.body;

    const exists = await pool.query(
      'SELECT 1 FROM users WHERE email=$1',
      [email]
    );

    if (exists.rows.length > 0) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashed = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (email, password_hash, role, full_name, subscription_tier, created_at)
       VALUES ($1,$2,$3,$4,'Free',NOW())
       RETURNING *`,
      [email, hashed, role, fullName]
    );

    const user = result.rows[0];

    res.status(201).json({
      token: generateToken(user.id, user.role, user.is_admin, user.admin_role),
      user,
    });
  } catch (err) {
    handleError(res, err, 'Registration failed');
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      'SELECT * FROM users WHERE email=$1',
      [email]
    );

    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (user.is_suspended) {
      return res.status(403).json({ message: 'Account suspended' });
    }

    res.json({
      token: generateToken(user.id, user.role, user.is_admin, user.admin_role),
      user,
    });
  } catch (err) {
    handleError(res, err, 'Login failed');
  }
});

/* -------------------- USERS -------------------- */

app.get('/api/users/me', protect, async (req, res) => {
  try {
    const { id } = (req as AuthRequest).user!;
    const result = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
    res.json(result.rows[0]);
  } catch (err) {
    handleError(res, err);
  }
});

/* -------------------- CLEANERS -------------------- */

app.get('/api/cleaners', async (_req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE role='cleaner' AND is_suspended=false"
    );
    res.json(result.rows);
  } catch (err) {
    handleError(res, err);
  }
});

/* -------------------- BOOKINGS -------------------- */

app.post('/api/bookings', protect, async (req, res) => {
  try {
    const { id } = (req as AuthRequest).user!;
    const { cleanerId, service, date } = req.body;

    const result = await pool.query(
      `INSERT INTO bookings (client_id, cleaner_id, service, date, status, created_at)
       VALUES ($1,$2,$3,$4,'Upcoming',NOW())
       RETURNING *`,
      [id, cleanerId, service, date]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    handleError(res, err, 'Booking failed');
  }
});

/* -------------------- SUPPORT -------------------- */

app.post('/api/support', protect, async (req, res) => {
  try {
    const { id } = (req as AuthRequest).user!;
    const { subject, message } = req.body;

    const result = await pool.query(
      `INSERT INTO support_tickets (user_id, subject, message, created_at)
       VALUES ($1,$2,$3,NOW())
       RETURNING *`,
      [id, subject, message]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    handleError(res, err);
  }
});

/* -------------------- FALLBACKS -------------------- */

app.use('/api/*', (_req, res) => {
  res.status(404).json({ message: 'API route not found' });
});

app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

/* -------------------- GLOBAL CRASH LOGGING -------------------- */

process.on('unhandledRejection', (r) =>
  console.error('UNHANDLED REJECTION', r)
);
process.on('uncaughtException', (e) =>
  console.error('UNCAUGHT EXCEPTION', e)
);

/* -------------------- EXPORT -------------------- */

export default serverless(app);
