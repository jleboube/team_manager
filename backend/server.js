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

// Enhanced Players routes
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

// Add player (admin only)
app.post('/api/players', [
  body('teamId').isInt(),
  body('name').trim().isLength({ min: 2 }),
  body('jerseyNumber').isInt({ min: 0, max: 999 }),
  body('position').isIn(['Pitcher', 'Catcher', 'First Base', 'Second Base', 'Third Base', 'Shortstop', 'Left Field', 'Center Field', 'Right Field']),
  body('role').isIn(['Starter', 'Bench', 'Pitcher']),
  body('email').optional().isEmail()
], authenticateToken, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { teamId, name, jerseyNumber, position, role, email } = req.body;

    // Check if user is admin of this team
    const teamCheck = await pool.query(
      'SELECT id FROM teams WHERE id = $1 AND admin_id = $2',
      [teamId, req.user.userId]
    );

    if (teamCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Not authorized to add players to this team' });
    }

    // Check if jersey number is already taken
    const jerseyCheck = await pool.query(
      'SELECT id FROM players WHERE team_id = $1 AND jersey_number = $2',
      [teamId, jerseyNumber]
    );

    if (jerseyCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Jersey number already taken' });
    }

    const result = await pool.query(
      'INSERT INTO players (team_id, name, jersey_number, position, role, email) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [teamId, name, jerseyNumber, position, role, email]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error adding player:', error);
    res.status(500).json({ error: 'Failed to add player' });
  }
});

// Update player (admin only)
app.put('/api/players/:id', [
  body('name').trim().isLength({ min: 2 }),
  body('jerseyNumber').isInt({ min: 0, max: 999 }),
  body('position').isIn(['Pitcher', 'Catcher', 'First Base', 'Second Base', 'Third Base', 'Shortstop', 'Left Field', 'Center Field', 'Right Field']),
  body('role').isIn(['Starter', 'Bench', 'Pitcher']),
  body('email').optional().isEmail()
], authenticateToken, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const playerId = req.params.id;
    const { name, jerseyNumber, position, role, email } = req.body;

    // Check if player exists and user is admin of the team
    const playerCheck = await pool.query(`
      SELECT p.*, t.admin_id FROM players p
      JOIN teams t ON p.team_id = t.id
      WHERE p.id = $1
    `, [playerId]);

    if (playerCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Player not found' });
    }

    if (playerCheck.rows[0].admin_id !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to edit this player' });
    }

    const teamId = playerCheck.rows[0].team_id;

    // Check if jersey number is already taken by another player
    const jerseyCheck = await pool.query(
      'SELECT id FROM players WHERE team_id = $1 AND jersey_number = $2 AND id != $3',
      [teamId, jerseyNumber, playerId]
    );

    if (jerseyCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Jersey number already taken' });
    }

    const result = await pool.query(
      'UPDATE players SET name = $1, jersey_number = $2, position = $3, role = $4, email = $5, updated_at = CURRENT_TIMESTAMP WHERE id = $6 RETURNING *',
      [name, jerseyNumber, position, role, email, playerId]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating player:', error);
    res.status(500).json({ error: 'Failed to update player' });
  }
});

// Delete player (admin only)
app.delete('/api/players/:id', authenticateToken, async (req, res) => {
  try {
    const playerId = req.params.id;

    // Check if player exists and user is admin of the team
    const playerCheck = await pool.query(`
      SELECT p.*, t.admin_id FROM players p
      JOIN teams t ON p.team_id = t.id
      WHERE p.id = $1
    `, [playerId]);

    if (playerCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Player not found' });
    }

    if (playerCheck.rows[0].admin_id !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to delete this player' });
    }

    // Delete player (this will cascade delete stats due to foreign key constraints)
    await pool.query('DELETE FROM players WHERE id = $1', [playerId]);

    res.json({ message: 'Player deleted successfully' });
  } catch (error) {
    console.error('Error deleting player:', error);
    res.status(500).json({ error: 'Failed to delete player' });
  }
});

// Scouting Reports routes
app.post('/api/scouting-reports', authenticateToken, async (req, res) => {
  try {
    const { playerId, ...scoutingData } = req.body;

    // Check if player exists and user has access to the team
    const playerCheck = await pool.query(`
      SELECT p.*, tm.user_id FROM players p
      JOIN teams t ON p.team_id = t.id
      JOIN team_memberships tm ON t.id = tm.team_id
      WHERE p.id = $1 AND tm.user_id = $2
    `, [playerId, req.user.userId]);

    if (playerCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Player not found or access denied' });
    }

    // Insert or update scouting report
    const result = await pool.query(`
      INSERT INTO scouting_reports (
        player_id, scout_id, height, weight, throws, bats, birth_date, school, 
        parent_guardian, emergency_contact, contact_ability, power, plate_discipline,
        swing_mechanics, bunting_ability, clutch_hitting, hitting_notes,
        range_rating, arm_strength, accuracy, hands_glove_work, footwork, 
        game_awareness, fielding_notes, speed, base_running_iq, steal_ability,
        running_notes, fastball_velocity, control, command, curveball, changeup,
        slider_cutter, pitching_notes, overall_grade, potential, strengths,
        areas_for_improvement, overall_summary
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
        $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32,
        $33, $34, $35, $36, $37, $38, $39, $40
      )
      ON CONFLICT (player_id) 
      DO UPDATE SET 
        scout_id = $2, height = $3, weight = $4, throws = $5, bats = $6,
        birth_date = $7, school = $8, parent_guardian = $9, emergency_contact = $10,
        contact_ability = $11, power = $12, plate_discipline = $13, swing_mechanics = $14,
        bunting_ability = $15, clutch_hitting = $16, hitting_notes = $17, range_rating = $18,
        arm_strength = $19, accuracy = $20, hands_glove_work = $21, footwork = $22,
        game_awareness = $23, fielding_notes = $24, speed = $25, base_running_iq = $26,
        steal_ability = $27, running_notes = $28, fastball_velocity = $29, control = $30,
        command = $31, curveball = $32, changeup = $33, slider_cutter = $34,
        pitching_notes = $35, overall_grade = $36, potential = $37, strengths = $38,
        areas_for_improvement = $39, overall_summary = $40, updated_at = CURRENT_TIMESTAMP
      RETURNING *
    `, [
      playerId, req.user.userId, scoutingData.height, scoutingData.weight, scoutingData.throws,
      scoutingData.bats, scoutingData.birthDate, scoutingData.school, scoutingData.parentGuardian,
      scoutingData.emergencyContact, scoutingData.contactAbility, scoutingData.power,
      scoutingData.plateDiscipline, scoutingData.swingMechanics, scoutingData.buntingAbility,
      scoutingData.clutchHitting, scoutingData.hittingNotes, scoutingData.range,
      scoutingData.armStrength, scoutingData.accuracy, scoutingData.handsGloveWork,
      scoutingData.footwork, scoutingData.gameAwareness, scoutingData.fieldingNotes,
      scoutingData.speed, scoutingData.baseRunningIQ, scoutingData.stealAbility,
      scoutingData.runningNotes, scoutingData.fastballVelocity, scoutingData.control,
      scoutingData.command, scoutingData.curveball, scoutingData.changeup,
      scoutingData.sliderCutter, scoutingData.pitchingNotes, scoutingData.overallGrade,
      scoutingData.potential, scoutingData.strengths, scoutingData.areasForImprovement,
      scoutingData.overallSummary
    ]);

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error saving scouting report:', error);
    res.status(500).json({ error: 'Failed to save scouting report' });
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
          ($1, 'Tom Wilson', 23, 'Right Field', 'Bench', 'tom.wilson@email.com')
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