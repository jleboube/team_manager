-- Create database schema for Baseball Manager

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'player', 'parent')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Teams table
CREATE TABLE IF NOT EXISTS teams (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    season VARCHAR(100) NOT NULL,
    logo_url VARCHAR(500),
    admin_id INTEGER REFERENCES users(id),
    invite_code VARCHAR(50) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Players table
CREATE TABLE IF NOT EXISTS players (
    id SERIAL PRIMARY KEY,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id),
    name VARCHAR(255) NOT NULL,
    jersey_number INTEGER NOT NULL,
    position VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('Starter', 'Bench', 'Pitcher')),
    email VARCHAR(255),
    profile_pic_url VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(team_id, jersey_number)
);

-- Games table
CREATE TABLE IF NOT EXISTS games (
    id SERIAL PRIMARY KEY,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    opponent VARCHAR(255) NOT NULL,
    game_date DATE NOT NULL,
    game_time TIME NOT NULL,
    location VARCHAR(500) NOT NULL,
    home_away VARCHAR(10) NOT NULL CHECK (home_away IN ('home', 'away')),
    status VARCHAR(20) DEFAULT 'upcoming' CHECK (status IN ('upcoming', 'completed', 'cancelled')),
    home_score INTEGER DEFAULT 0,
    away_score INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Player statistics table
CREATE TABLE IF NOT EXISTS player_stats (
    id SERIAL PRIMARY KEY,
    player_id INTEGER REFERENCES players(id) ON DELETE CASCADE,
    game_id INTEGER REFERENCES games(id) ON DELETE CASCADE,
    at_bats INTEGER DEFAULT 0,
    hits INTEGER DEFAULT 0,
    rbis INTEGER DEFAULT 0,
    runs INTEGER DEFAULT 0,
    strikeouts INTEGER DEFAULT 0,
    walks INTEGER DEFAULT 0,
    innings_pitched DECIMAL(4,1) DEFAULT 0,
    earned_runs INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(player_id, game_id)
);

-- Media table
CREATE TABLE IF NOT EXISTS media (
    id SERIAL PRIMARY KEY,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    game_id INTEGER REFERENCES games(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    file_type VARCHAR(20) NOT NULL CHECK (file_type IN ('image', 'video')),
    file_url VARCHAR(500) NOT NULL,
    file_size INTEGER,
    uploaded_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Team memberships (for linking users to teams)
CREATE TABLE IF NOT EXISTS team_memberships (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'player', 'parent')),
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, team_id)
);

-- Scouting reports table
CREATE TABLE IF NOT EXISTS scouting_reports (
    id SERIAL PRIMARY KEY,
    player_id INTEGER REFERENCES players(id) ON DELETE CASCADE UNIQUE,
    scout_id INTEGER REFERENCES users(id),
    
    -- Basic Information
    height VARCHAR(20),
    weight VARCHAR(20),
    throws VARCHAR(10),
    bats VARCHAR(10),
    birth_date DATE,
    school VARCHAR(255),
    parent_guardian VARCHAR(255),
    emergency_contact VARCHAR(50),
    
    -- Hitting Assessment
    contact_ability INTEGER CHECK (contact_ability >= 1 AND contact_ability <= 10),
    power INTEGER CHECK (power >= 1 AND power <= 10),
    plate_discipline INTEGER CHECK (plate_discipline >= 1 AND plate_discipline <= 10),
    swing_mechanics VARCHAR(20),
    bunting_ability VARCHAR(20),
    clutch_hitting VARCHAR(20),
    hitting_notes TEXT,
    
    -- Fielding Assessment
    range_rating INTEGER CHECK (range_rating >= 1 AND range_rating <= 10),
    arm_strength INTEGER CHECK (arm_strength >= 1 AND arm_strength <= 10),
    accuracy INTEGER CHECK (accuracy >= 1 AND accuracy <= 10),
    hands_glove_work VARCHAR(20),
    footwork VARCHAR(20),
    game_awareness VARCHAR(20),
    fielding_notes TEXT,
    
    -- Running Assessment
    speed INTEGER CHECK (speed >= 1 AND speed <= 10),
    base_running_iq VARCHAR(20),
    steal_ability VARCHAR(20),
    running_notes TEXT,
    
    -- Pitching Assessment (optional)
    fastball_velocity VARCHAR(50),
    control INTEGER CHECK (control >= 1 AND control <= 10),
    command INTEGER CHECK (command >= 1 AND command <= 10),
    curveball VARCHAR(20),
    changeup VARCHAR(20),
    slider_cutter VARCHAR(20),
    pitching_notes TEXT,
    
    -- Overall Assessment
    overall_grade INTEGER CHECK (overall_grade >= 1 AND overall_grade <= 10),
    potential VARCHAR(20),
    strengths TEXT,
    areas_for_improvement TEXT,
    overall_summary TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_players_team_id ON players(team_id);
CREATE INDEX IF NOT EXISTS idx_games_team_id ON games(team_id);
CREATE INDEX IF NOT EXISTS idx_stats_player_id ON player_stats(player_id);
CREATE INDEX IF NOT EXISTS idx_stats_game_id ON player_stats(game_id);
CREATE INDEX IF NOT EXISTS idx_media_team_id ON media(team_id);
CREATE INDEX IF NOT EXISTS idx_memberships_user_id ON team_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_team_id ON team_memberships(team_id);
CREATE INDEX IF NOT EXISTS idx_scouting_player_id ON scouting_reports(player_id);
CREATE INDEX IF NOT EXISTS idx_scouting_scout_id ON scouting_reports(scout_id);