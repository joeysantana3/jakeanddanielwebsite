const express = require("express");
const session = require("express-session");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

// Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password VARCHAR(100) NOT NULL,
      is_admin BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scores (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      clicker_score INTEGER DEFAULT 0,
      clicker_total_earned INTEGER DEFAULT 0,
      protector_best INTEGER DEFAULT 0,
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
  // Create default admin if none exists
  const admins = await pool.query("SELECT id FROM users WHERE is_admin = TRUE");
  if (admins.rows.length === 0) {
    await pool.query(
      "INSERT INTO users (username, password, is_admin) VALUES ($1, $2, TRUE) ON CONFLICT DO NOTHING",
      ["admin", "admin123"]
    );
    const adminUser = await pool.query("SELECT id FROM users WHERE username = 'admin'");
    if (adminUser.rows.length > 0) {
      await pool.query(
        "INSERT INTO scores (user_id) VALUES ($1) ON CONFLICT DO NOTHING",
        [adminUser.rows[0].id]
      );
    }
  }
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }, // 1 week
  })
);
app.use(express.static("public"));

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  if (!req.session.isAdmin) return res.status(403).json({ error: "Not authorized" });
  next();
}

// ============ AUTH ROUTES ============

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  if (username.length < 2 || username.length > 50) return res.status(400).json({ error: "Username must be 2-50 characters" });
  if (password.length < 4) return res.status(400).json({ error: "Password must be at least 4 characters" });

  try {
    const existing = await pool.query("SELECT id FROM users WHERE username = $1", [username]);
    if (existing.rows.length > 0) return res.status(409).json({ error: "Username already taken" });

    const result = await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id",
      [username, password]
    );
    const userId = result.rows[0].id;
    await pool.query("INSERT INTO scores (user_id) VALUES ($1)", [userId]);

    req.session.userId = userId;
    req.session.username = username;
    req.session.isAdmin = false;
    res.json({ ok: true, username });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });

  try {
    const result = await pool.query("SELECT id, password, is_admin FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: "Invalid username or password" });

    const user = result.rows[0];
    if (password !== user.password) return res.status(401).json({ error: "Invalid username or password" });

    req.session.userId = user.id;
    req.session.username = username;
    req.session.isAdmin = user.is_admin;
    res.json({ ok: true, username, isAdmin: user.is_admin });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, username: req.session.username, isAdmin: req.session.isAdmin });
});

// ============ SCORE ROUTES ============

app.get("/api/scores", requireAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT clicker_score, clicker_total_earned, protector_best FROM scores WHERE user_id = $1", [req.session.userId]);
    if (result.rows.length === 0) return res.json({ clicker_score: 0, clicker_total_earned: 0, protector_best: 0 });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/scores", requireAuth, async (req, res) => {
  const { clicker_score, clicker_total_earned, protector_best } = req.body;
  try {
    await pool.query(
      `UPDATE scores SET clicker_score = $1, clicker_total_earned = $2, protector_best = GREATEST(protector_best, $3), updated_at = NOW() WHERE user_id = $4`,
      [clicker_score || 0, clicker_total_earned || 0, protector_best || 0, req.session.userId]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// ============ ADMIN ROUTES ============

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.username, u.is_admin, u.created_at,
             s.clicker_score, s.clicker_total_earned, s.protector_best, s.updated_at
      FROM users u
      LEFT JOIN scores s ON u.id = s.user_id
      ORDER BY u.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.delete("/api/admin/users/:id", requireAdmin, async (req, res) => {
  const userId = parseInt(req.params.id);
  if (userId === req.session.userId) return res.status(400).json({ error: "Cannot delete yourself" });
  try {
    await pool.query("DELETE FROM users WHERE id = $1", [userId]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/admin/users/:id/toggle-admin", requireAdmin, async (req, res) => {
  const userId = parseInt(req.params.id);
  if (userId === req.session.userId) return res.status(400).json({ error: "Cannot change your own admin status" });
  try {
    await pool.query("UPDATE users SET is_admin = NOT is_admin WHERE id = $1", [userId]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/admin/users/:id/reset-password", requireAdmin, async (req, res) => {
  const userId = parseInt(req.params.id);
  const { password } = req.body;
  if (!password || password.length < 4) return res.status(400).json({ error: "Password must be at least 4 characters" });
  try {
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [password, userId]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Serve admin page
app.get("/admin", (req, res) => {
  res.sendFile(__dirname + "/public/admin.html");
});

// Start
initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Failed to initialize database:", err);
    process.exit(1);
  });
