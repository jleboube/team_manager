const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Database connection with retry logic
const createPool = () => {
  return new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
  });
};

let pool = createPool();

// Middleware
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));

// Fix for rate limiting warning - set trust proxy
app.set('trust proxy', 1);

app.use(rateLimit({ 
  windowMs: 15 * 60 * 1000, 
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Database connection check
const checkDatabaseConnection = async () => {
  let retries = 10;
  while (retries > 0) {
    try {
      await pool.query('SELECT 1');
      console.log('✅ Database connected successfully');
      return true;
    } catch (error) {
      console.log(`⏳ Waiting for database... (${retries} retries left)`);
      retries--;
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  }
  console.error('❌ Failed to connect to database after multiple retries');
  return false;
};

// Routes
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Auth routes
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 1 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    const userResult = await pool.query(
      'SELECT id, name, email, role, password_hash FROM users WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = userResult.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT id, name, email, role FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: userResult.rows[0] });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.post('/api/auth/register', [
  body('name').trim().isLength({ min: 2 }),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('code').trim().isLength({ min: 1 }),
  body('role').isIn(['player', 'parent'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password, code, role } = req.body;

    const teamResult = await pool.query('SELECT id FROM teams WHERE invite_code = $1', [code]);
    if (teamResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid registration code' });
    }

    const teamId = teamResult.rows[0].id;

    const userCheck = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const userResult = await pool.query(
      'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role',
      [name, email, passwordHash, role]
    );

    const user = userResult.rows[0];

    await pool.query(
      'INSERT INTO team_memberships (user_id, team_id, role) VALUES ($1, $2, $3)',
      [user.id, teamId, role]
    );

    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Team routes
app.get('/api/teams', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT t.* FROM teams t
      JOIN team_memberships tm ON t.id = tm.team_id
      WHERE tm.user_id = $1
    `, [req.user.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching teams:', error);
    res.status(500).json({ error: 'Failed to fetch teams' });
  }
});

// Players routes
app.get('/api/players', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.* FROM players p
      JOIN teams t ON p.team_id = t.id
      JOIN team_memberships tm ON t.id = tm.team_id
      WHERE tm.user_id = $1
    `, [req.user.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching players:', error);
    res.status(500).json({ error: 'Failed to fetch players' });
  }
});

// Games routes
app.get('/api/games', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT g.* FROM games g
      JOIN teams t ON g.team_id = t.id
      JOIN team_memberships tm ON t.id = tm.team_id
      WHERE tm.user_id = $1
      ORDER BY g.game_date DESC, g.game_time DESC
    `, [req.user.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching games:', error);
    res.status(500).json({ error: 'Failed to fetch games' });
  }
});

// Stats routes
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT ps.* FROM player_stats ps
      JOIN players p ON ps.player_id = p.id
      JOIN teams t ON p.team_id = t.id
      JOIN team_memberships tm ON t.id = tm.team_id
      WHERE tm.user_id = $1
    `, [req.user.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Media routes
app.get('/api/media', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT m.* FROM media m
      JOIN teams t ON m.team_id = t.id
      JOIN team_memberships tm ON t.id = tm.team_id
      WHERE tm.user_id = $1
      ORDER BY m.created_at DESC
    `, [req.user.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching media:', error);
    res.status(500).json({ error: 'Failed to fetch media' });
  }
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Setup demo data after database is ready
const setupDemoData = async () => {
  try {
    console.log('🎬 Setting up demo data...');
    
    const passwordHash = await bcrypt.hash('password', 10);
    
    // Insert demo users
    await pool.query(`
      INSERT INTO users (name, email, password_hash, role) VALUES 
      ('Coach Johnson', 'coach@team.com', $1, 'admin'),
      ('Mike Johnson', 'player@team.com', $1, 'player'),
      ('Parent Smith', 'parent@team.com', $1, 'parent')
      ON CONFLICT (email) DO NOTHING
    `, [passwordHash]);

    // Get admin user
    const adminResult = await pool.query('SELECT id FROM users WHERE email = $1', ['coach@team.com']);
    const adminId = adminResult.rows[0]?.id;

    if (adminId) {
      // Insert demo team
      await pool.query(`
        INSERT INTO teams (name, season, admin_id, invite_code) VALUES 
        ('Eagles Baseball', '2025 Spring', $1, 'TEAM123')
        ON CONFLICT (invite_code) DO NOTHING
      `, [adminId]);

      // Get team
      const teamResult = await pool.query('SELECT id FROM teams WHERE invite_code = $1', ['TEAM123']);
      const teamId = teamResult.rows[0]?.id;

      if (teamId) {
        // Add users to team
        const users = await pool.query('SELECT id, role FROM users WHERE email IN ($1, $2, $3)', 
          ['coach@team.com', 'player@team.com', 'parent@team.com']);

        for (const user of users.rows) {
          await pool.query(`
            INSERT INTO team_memberships (user_id, team_id, role) VALUES ($1, $2, $3)
            ON CONFLICT (user_id, team_id) DO NOTHING
          `, [user.id, teamId, user.role]);
        }

        // Add demo players
        await pool.query(`
          INSERT INTO players (team_id, name, jersey_number, position, role, email) VALUES 
          ($1, 'Mike Johnson', 12, 'Pitcher', 'Starter', 'mike.johnson@email.com'),
          ($1, 'Sarah Davis', 7, 'Shortstop', 'Starter', 'sarah.davis@email.com'),
          ($1, 'Tom Wilson', 23, 'Outfield', 'Bench', 'tom.wilson@email.com')
          ON CONFLICT (team_id, jersey_number) DO NOTHING
        `, [teamId]);

        // Add demo games
        await pool.query(`
          INSERT INTO games (team_id, opponent, game_date, game_time, location, home_away, status) VALUES 
          ($1, 'Tigers', '2025-07-10', '15:00', 'Central Park Field 1', 'home', 'upcoming'),
          ($1, 'Lions', '2025-07-05', '14:00', 'Lions Stadium', 'away', 'completed')
          ON CONFLICT DO NOTHING
        `, [teamId]);

        console.log('✅ Demo data setup complete!');
      }
    }
  } catch (error) {
    console.error('❌ Demo setup error:', error);
  }
};

// Start server with proper initialization
const startServer = async () => {
  try {
    // Wait for database connection
    const dbConnected = await checkDatabaseConnection();
    if (!dbConnected) {
      process.exit(1);
    }

    // Setup demo data
    await setupDemoData();

    // Start server
    app.listen(PORT, () => {
      console.log(`🚀 Baseball Manager API running on port ${PORT}`);
      console.log(`🔑 Demo credentials: coach@team.com / password`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();