require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

// Render sits behind a proxy — required for secure cookies + correct IPs
app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const isProd = process.env.NODE_ENV === 'production';

// Session with memorystore (prunes expired entries automatically)
app.use(session({
  store: new MemoryStore({ checkPeriod: 86400000 }),
  secret: process.env.SESSION_SECRET || 'dev_secret_change_me',
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: isProd,       // HTTPS only on Render
    sameSite: 'lax',
    maxAge: 3600000       // 1 hour
  }
}));

// Rate limiter
const limiter = rateLimit({
  windowMs: 60000,
  max: 80,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Slow down.' }
});
app.use('/api/', limiter);

// Serve frontend
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ─── LEVEL 1 ────────────────────────────────────────────────────────────────

const QUESTIONS = [
  { q: "What is (17 × 13) - (8² + 11)?",               a: 146 },
  { q: "Solve: (2⁸ / 4) + (3 × 7) - 15",               a: 70  },
  { q: "If x = 9, what is (x² + 3x - 7) × 2?",         a: 170 },
  { q: "What is the sum of primes between 20 and 40?",  a: 179 },
  { q: "Calculate: (144 / 12) × (5 + 3) - 2³",         a: 88  },
  { q: "What is 7! / (5! × 2!)?",                       a: 21  },
  { q: "Solve: (15² - 100) / (5 × 5)",                  a: 5   },
  { q: "What is the 10th Fibonacci number?",            a: 55  },
  { q: "Calculate: (3³ + 4³) - (2⁵ + 1)",              a: 28  },
  { q: "What is 256 in base 10 from binary 100000000?", a: 256 },
];

app.get('/api/question', (req, res) => {
  if (!req.session.score)  req.session.score  = 0;
  if (!req.session.qIndex) req.session.qIndex = 0;
  if (!req.session.level)  req.session.level  = 1;
  const idx = req.session.qIndex % QUESTIONS.length;
  res.json({ question: QUESTIONS[idx].q, score: req.session.score, index: idx });
});

app.post('/api/answer', (req, res) => {
  if (req.session.level !== 1) return res.status(403).json({ error: 'Not on level 1' });
  const { answer, hintUsed } = req.body;
  const idx = (req.session.qIndex || 0) % QUESTIONS.length;
  if (parseInt(answer) !== QUESTIONS[idx].a) {
    return res.json({ correct: false, message: 'WRONG. Try again.' });
  }
  const pts = hintUsed ? 3 : 5;
  req.session.score  = (req.session.score  || 0) + pts;
  req.session.qIndex = (req.session.qIndex || 0) + 1;
  const score = req.session.score;
  const unlocked = score >= 40;
  if (unlocked) req.session.level = 2;
  res.json({ correct: true, score, pts, unlocked, message: `CORRECT. +${pts} pts` });
});

app.post('/api/hint', (req, res) => {
  if (req.session.level !== 1) return res.status(403).json({ error: 'Not on level 1' });
  if ((req.session.score || 0) < 2) return res.json({ error: 'Not enough points.' });
  const hints = [
    "Think: 17×13=221, 8²=64", "2⁸=256, divide by 4 first", "x²=81, 3x=27",
    "Primes: 23,29,31,37,41... check the upper limit", "144/12=12, then ×8",
    "7! = 5040", "15²=225", "Fib: 1,1,2,3,5,8,13,21,34,55", "3³=27, 4³=64, 2⁵=32",
    "Binary 100000000 = 2⁸"
  ];
  req.session.score -= 2;
  const idx = (req.session.qIndex || 0) % QUESTIONS.length;
  res.json({ hint: hints[idx], score: req.session.score });
});

// ─── LEVEL 1 → 2 URL CHECK ──────────────────────────────────────────────────

app.post('/api/navigate', (req, res) => {
  if (req.session.level !== 2) return res.status(403).json({ error: 'Complete level 1 first.' });
  const val = ((req.body.path) || '').trim().toLowerCase();
  const fakes = ['/admin_rl','/secret_rl','/hidden_rl','/exec_rl',
                 '/perl_rl','/url_rl','/ctrl_rl','/null_rl','/root_rl','/curl_rl'];
  if (fakes.includes(val)) return res.json({ success: false, message: 'Access denied. Wrong path.' });
  if (val === '/cu_rl' || val === 'cu_rl') {
    req.session.navDone = true;
    const encodedIP = Buffer.from(process.env.HIDDEN_IP).toString('base64');
    // httpOnly:false so the player can read it in DevTools
    res.cookie('session_data', encodedIP, { httpOnly: false, sameSite: 'lax', secure: isProd });
    return res.json({ success: true });
  }
  res.json({ success: false, message: 'Path not found. 404.' });
});

// ─── LEVEL 2 NMAP SCAN ──────────────────────────────────────────────────────

app.post('/api/scan', (req, res) => {
  if (!req.session.navDone) return res.status(403).json({ error: 'Complete level 1 URL first.' });
  if (req.body.ip !== process.env.HIDDEN_IP) {
    return res.json({ success: false, message: 'Host unreachable. Check the IP.' });
  }
  req.session.scanDone = true;
  const encodedKey = Buffer.from(process.env.LEVEL2_KEY).toString('base64');
  res.json({ success: true, encodedKey });
});

app.post('/api/verify-key', (req, res) => {
  if (!req.session.scanDone) return res.status(403).json({ error: 'Run the scan first.' });
  const { key } = req.body;
  if (key === process.env.LEVEL2_KEY) {
    req.session.level = 3;
    return res.json({ success: true });
  }
  const partials = ['traceback_recon_complete','LEVEL2_KEY','recon_complete','traceback'];
  if (partials.some(p => key === p)) {
    return res.json({ success: false, message: 'Partial match. Decode the full value.' });
  }
  res.json({ success: false, message: 'Incorrect. Decode the base64 string fully.' });
});

// ─── LEVEL 3 FLAG ENDPOINT ──────────────────────────────────────────────────

app.get('/api/flag', (req, res) =>
  res.status(405).json({ error: 'method not allowed', hint: 'try another method' })
);

app.post('/api/flag', (req, res) => {
  if (req.session.level !== 3) {
    return res.status(403).json({ error: 'Access denied. Complete previous levels.' });
  }
  res.json({ flag: process.env.CTF_FLAG });
});

app.put('/api/flag',    (req, res) => res.status(403).json({ error: 'not allowed' }));
app.patch('/api/flag',  (req, res) => res.status(400).json({ error: 'invalid method' }));
app.delete('/api/flag', (req, res) => res.status(403).json({ error: 'dangerous method blocked' }));
app.options('/api/flag',(req, res) => res.set('Allow', 'POST').status(200).json({ allow: 'POST' }));

// ─── START ───────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`TracebackCTF running on port ${PORT}`));
