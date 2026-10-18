
const fs = require("fs");

const QUESTIONS_FILE = path.join(
  __dirname,
  "data",
  "questions.json"
);

const ANSWER_KEY_FILE = path.join(
  __dirname,
  "data",
  "answer-key.json"
);

function readJsonFile(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}
"use strict";

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;
const db = new sqlite3.Database(
  path.join(__dirname, "mcq.sqlite")
); 
db.run(`
  CREATE TABLE IF NOT EXISTS app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL
  )
`, (err) => {
  if (err) {
    console.error("Settings table error:", err.message);
    return;
  }

  db.run(
    `INSERT OR IGNORE INTO app_settings
     (setting_key, setting_value)
     VALUES ('results_published', 'false')`,
    (insertErr) => {
      if (insertErr) {
        console.error(insertErr.message);
      } else {
        console.log("Results publication setting ready.");
      }
    }
  );
});

db.run(`
  CREATE TABLE IF NOT EXISTS exam_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    participant_id INTEGER NOT NULL UNIQUE,
    total_questions INTEGER NOT NULL,
    correct_answers INTEGER NOT NULL,
    wrong_answers INTEGER NOT NULL,
    unanswered INTEGER NOT NULL,
    score INTEGER NOT NULL,
    submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`, (err) => {
  if (err) {
    console.error("Exam results table error:", err.message);
  } else {
    console.log("Exam results table ready.");
  }
});

db.run(`
  CREATE TABLE IF NOT EXISTS exam_answers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    participant_id INTEGER NOT NULL,
    question_id TEXT NOT NULL,
    selected_option INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (participant_id, question_id)
  )
`, (err) => {
  if (err) {
    console.error("Exam answers table error:", err.message);
  } else {
    console.log("Exam answers table ready.");
  }
});


app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  store: new SQLiteStore({
    db: "sessions.sqlite",
    dir: __dirname
  }),
  secret: process.env.SESSION_SECRET || "",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 4
  }
}));

app.use(express.static(path.join(__dirname, "public")));

const run = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });

const get = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });

function requireVerifiedMobile(req, res, next) {
  if (!req.session.verifiedMobile) {
    return res.status(401).json({
      success: false,
      message: "প্রথমে SMS OTP যাচাই করুন।"
    });
  }
  next();
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

function normalizeMobile(value) {
  return String(value || "").replace(/\s+/g, "");
}

function validMobile(value) {
  return /^01[3-9]\d{8}$/.test(value);
}

function bkashConfigReady() {
  return [
    "BKASH_BASE_URL",
    "BKASH_USERNAME",
    "BKASH_PASSWORD",
    "BKASH_APP_KEY",
    "BKASH_APP_SECRET"
  ].every(k => process.env[k]);
}

function smsConfigReady() {
  return Boolean(
    process.env.SMS_API_URL &&
    process.env.SMS_API_KEY
  );
}

async function initializeDatabase() {
  await run(`
    CREATE TABLE IF NOT EXISTS otp_challenges (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mobile TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      used INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      registration_id TEXT NOT NULL,
      payment_id TEXT UNIQUE,
      invoice_number TEXT UNIQUE NOT NULL,
      amount TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDING',
      trx_id TEXT,
      created_at TEXT NOT NULL
    )
  `);

  const columns = await new Promise((resolve, reject) => {
    db.all("PRAGMA table_info(participants)", [], (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });

  if (!columns.some(c => c.name === "password_hash")) {
    await run(
      "ALTER TABLE participants ADD COLUMN password_hash TEXT"
    );
  }

  if (!columns.some(c => c.name === "payment_status")) {
    await run(`
      ALTER TABLE participants
      ADD COLUMN payment_status TEXT NOT NULL DEFAULT 'PENDING'
    `);
  }
}

/*
  SMS ADAPTER:
  এখানে JSON {to, message} ও Bearer API key-এর
  একটি সাধারণ উদাহরণ দেওয়া হয়েছে।
  আপনার provider-এর API format ভিন্ন হলে এই অংশ
  তাদের official documentation অনুযায়ী পরিবর্তন করতে হবে।
*/
async function sendSmsOtp(mobile, otp) {
  if (!smsConfigReady()) {
    throw new Error("SMS API configuration missing");
  }

  const response = await axios.post(
    process.env.SMS_API_URL,
    {
      to: mobile,
      message: `MCQ COMPETITION 2026 OTP: ${otp}. মেয়াদ 5 মিনিট।`
    },
    {
      timeout: 15000,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.SMS_API_KEY}`,
        ...(process.env.SMS_SENDER_ID
          ? { "Sender-ID": process.env.SMS_SENDER_ID }
          : {})
      }
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw new Error("SMS provider rejected request");
  }
}

/* bKash: credentials শুধু server-side-এ থাকবে */
async function getBkashToken() {
  if (!bkashConfigReady()) {
    throw new Error("bKash credentials missing");
  }

  const base = process.env.BKASH_BASE_URL.replace(/\/+$/, "");

  const response = await axios.post(
    `${base}/token/grant`,
    {
      app_key: process.env.BKASH_APP_KEY,
      app_secret: process.env.BKASH_APP_SECRET
    },
    {
      timeout: 15000,
      headers: {
        "Content-Type": "application/json",
        username: process.env.BKASH_USERNAME,
        password: process.env.BKASH_PASSWORD,
        "x-app-key": process.env.BKASH_APP_KEY
      }
    }
  );

  if (!response.data || !response.data.id_token) {
    throw new Error("bKash token was not returned");
  }

  return response.data.id_token;
}

async function bkashRequest(method, endpoint, token, data) {
  const base = process.env.BKASH_BASE_URL.replace(/\/+$/, "");

  const response = await axios({
    method,
    url: `${base}${endpoint}`,
    data,
    timeout: 20000,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      Authorization: token,
      "x-app-key": process.env.BKASH_APP_KEY
    }
  });

  return response.data;
}

/* Health check */
app.get("/api/health", async (req, res) => {
  try {
    await get("SELECT 1 AS ok");
    res.json({
      success: true,
      database: "connected",
      smsConfigured: smsConfigReady(),
      bkashConfigured: bkashConfigReady()
    });
  } catch {
    res.status(500).json({ success: false });
  }
});

/* Send OTP only to a registered mobile number */
app.post(
  "/api/auth/otp/send",
  authLimiter,
  async (req, res) => {
    try {
      const mobile = normalizeMobile(req.body.mobile);

      if (!validMobile(mobile)) {
        return res.status(400).json({
          success: false,
          message: "সঠিক বাংলাদেশি মোবাইল নম্বর দিন।"
        });
      }

      const participant = await get(
        "SELECT id FROM participants WHERE mobile = ?",
        [mobile]
      );

      // Avoid disclosing whether a mobile is registered.
      if (!participant) {
        return res.json({
          success: true,
          message: "যদি নম্বরটি নিবন্ধিত থাকে, OTP পাঠানো হবে।"
        });
      }

      const recent = await get(
        `SELECT created_at FROM otp_challenges
         WHERE mobile = ? ORDER BY id DESC LIMIT 1`,
        [mobile]
      );

      if (recent && Date.now() - recent.created_at < 60000) {
        return res.status(429).json({
          success: false,
          message: "নতুন OTP-এর আগে ১ মিনিট অপেক্ষা করুন।"
        });
      }

      const otp = String(crypto.randomInt(100000, 1000000));
      const otpHash = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

      await run(
        `INSERT INTO otp_challenges
         (mobile, otp_hash, expires_at, attempts, used, created_at)
         VALUES (?, ?, ?, 0, 0, ?)`,
        [mobile, otpHash, Date.now() + 5 * 60 * 1000, Date.now()]
      );

      // If SMS fails, do not report success.
      await sendSmsOtp(mobile, otp);

      res.json({
        success: true,
        message: "OTP পাঠানোর অনুরোধ গ্রহণ করা হয়েছে।"
      });
    } catch (err) {
      console.error("OTP send failed:", err.message);
      res.status(502).json({
        success: false,
        message: "SMS পাঠানো যায়নি। Gateway settings যাচাই করুন।"
      });
    }
  }
);

/* Verify OTP */
app.post(
  "/api/auth/otp/verify",
  authLimiter,
  async (req, res) => {
    try {
      const mobile = normalizeMobile(req.body.mobile);
      const otp = String(req.body.otp || "");

      if (!validMobile(mobile) || !/^\d{6}$/.test(otp)) {
        return res.status(400).json({
          success: false,
          message: "মোবাইল নম্বর ও ৬ সংখ্যার OTP দিন।"
        });
      }

      const challenge = await get(
        `SELECT * FROM otp_challenges
         WHERE mobile = ? AND used = 0
         ORDER BY id DESC LIMIT 1`,
        [mobile]
      );

      if (
        !challenge ||
        Date.now() > challenge.expires_at ||
        challenge.attempts >= 5
      ) {
        return res.status(400).json({
          success: false,
          message: "OTP-এর মেয়াদ শেষ অথবা চেষ্টা সীমা অতিক্রম হয়েছে।"
        });
      }

      const suppliedHash = crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");

      if (suppliedHash !== challenge.otp_hash) {
        await run(
          "UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ?",
          [challenge.id]
        );

        return res.status(400).json({
          success: false,
          message: "OTP সঠিক নয়।"
        });
      }

      await run(
        "UPDATE otp_challenges SET used = 1 WHERE id = ?",
        [challenge.id]
      );

      req.session.verifiedMobile = mobile;

      res.json({
        success: true,
        message: "মোবাইল OTP যাচাই সফল হয়েছে।"
      });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ success: false });
    }
  }
);

/* Set or reset password only after mobile OTP verification */
app.post(
  "/api/auth/password/set",
  authLimiter,
  requireVerifiedMobile,
  async (req, res) => {
    try {
      const { registrationId, password } = req.body;

      if (
        typeof password !== "string" ||
        password.length < 12 ||
        password.length > 72
      ) {
        return res.status(400).json({
          success: false,
          message: "পাসওয়ার্ড ১২–৭২ অক্ষরের মধ্যে দিন।"
        });
      }

      const participant = await get(
        `SELECT id, mobile FROM participants
         WHERE registration_id = ?`,
        [String(registrationId || "")]
      );

      if (
        !participant ||
        participant.mobile !== req.session.verifiedMobile
      ) {
        return res.status(403).json({
          success: false,
          message: "OTP-যাচাইকৃত মোবাইল ও Registration ID মিলছে না।"
        });
      }

      const hash = await bcrypt.hash(password, 12);

      await run(
        "UPDATE participants SET password_hash = ? WHERE id = ?",
        [hash, participant.id]
      );

      res.json({
        success: true,
        message: "পাসওয়ার্ড নিরাপদভাবে সংরক্ষণ করা হয়েছে।"
      });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ success: false });
    }
  }
);

/* Login */
app.post(
  "/api/auth/login",
  authLimiter,
  async (req, res) => {
    try {
      const registrationId = String(req.body.registrationId || "");
      const password = String(req.body.password || "");

      const participant = await get(
        `SELECT id, registration_id, password_hash
         FROM participants WHERE registration_id = ?`,
        [registrationId]
      );

      if (
        !participant ||
        !participant.password_hash ||
        !(await bcrypt.compare(password, participant.password_hash))
      ) {
        return res.status(401).json({
          success: false,
          message: "Registration ID অথবা password সঠিক নয়।"
        });
      }

      req.session.regenerate(err => {
        if (err) {
          return res.status(500).json({ success: false });
        }

        req.session.participantId = participant.id;
        req.session.registrationId = participant.registration_id;

        res.json({
          success: true,
          message: "Login সফল হয়েছে।"
        });
      });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ success: false });
    }
  }
);

/* Current login status */
app.get("/api/auth/me", (req, res) => {
  res.json({
    loggedIn: Boolean(req.session.participantId),
    registrationId: req.session.registrationId || null
  });
});

```javascript
// PART 15: Registration + Password + Session
// Existing server.js-এ পুরোনো /api/register route সরিয়ে এটি বসান।

app.post("/api/register/complete", authLimiter, async (req, res) => {
  try {
    const mobile = normalizeMobile(req.body.mobile);
    const password = req.body.password;

    // OTP verification must have happened in this session.
    if (
      !req.session.verifiedMobile ||
      req.session.verifiedMobile !== mobile
    ) {
      return res.status(403).json({
        success: false,
        message: "প্রথমে এই মোবাইল নম্বরের OTP যাচাই করুন।"
      });
    }

    if (!/^01[3-9]\d{8}$/.test(mobile)) {
      return res.status(400).json({
        success: false,
        message: "সঠিক বাংলাদেশি মোবাইল নম্বর দিন।"
      });
    }

    if (
      typeof password !== "string" ||
      password.length < 12 ||
      password.length > 72
    ) {
      return res.status(400).json({
        success: false,
        message: "পাসওয়ার্ড ১২–৭২ অক্ষরের মধ্যে হতে হবে।"
      });
    }

    const {
      name, fatherName, age, email,
      division, district, upazila, address, group
    } = req.body;

    const validDivisions = [
      "ঢাকা", "রাজশাহী", "চট্টগ্রাম", "খুলনা",
      "সিলেট", "রংপুর", "ময়মনসিংহ", "বরিশাল"
    ];

    const validGroups = ["ক", "খ", "গ", "ঘ", "ঙ", "চ", "ছ", "জ"];

    if (
      !name || !fatherName || !age ||
      !division || !district || !upazila ||
      !address || !group
    ) {
      return res.status(400).json({
        success: false,
        message: "সব আবশ্যক তথ্য পূরণ করুন।"
      });
    }

    if (
      !Number.isInteger(Number(age)) ||
      Number(age) < 5 ||
      Number(age) > 100 ||
      !validDivisions.includes(division) ||
      !validGroups.includes(group)
    ) {
      return res.status(400).json({
        success: false,
        message: "বয়স, বিভাগ অথবা গ্রুপ সঠিক নয়।"
      });
    }

    const existing = await get(
      "SELECT id FROM participants WHERE mobile = ?",
      [mobile]
    );

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "এই মোবাইল নম্বর দিয়ে আগে নিবন্ধন করা হয়েছে।"
      });
    }

    const registrationId =
      "MCQ26-" + crypto.randomBytes(6).toString("hex").toUpperCase();

    const passwordHash = await bcrypt.hash(password, 12);

    await run(
      `INSERT INTO participants (
        registration_id, name, father_name, age, mobile, email,
        division, district, upazila, address, group_name,
        created_at, password_hash, payment_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')`,
      [
        registrationId,
        String(name).trim(),
        String(fatherName).trim(),
        Number(age),
        mobile,
        email ? String(email).trim() : "",
        division,
        String(district).trim(),
        String(upazila).trim(),
        String(address).trim(),
        group,
        new Date().toISOString(),
        passwordHash
      ]
    );

    // Consume the verified-mobile state before creating login session.
    req.session.verifiedMobile = null;

    req.session.regenerate(err => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "Session তৈরি করা যায়নি।"
        });
      }

      req.session.participantId = null;
      req.session.registrationId = registrationId;
      req.session.registrationPendingPayment = true;

      req.session.save(saveErr => {
        if (saveErr) {
          return res.status(500).json({
            success: false,
            message: "Session সংরক্ষণ করা যায়নি।"
          });
        }

        res.status(201).json({
          success: true,
          message: "নিবন্ধন তৈরি হয়েছে। পেমেন্ট সম্পন্ন করুন।",
          registrationId
        });
      });
    });
  } catch (err) {
    console.error("Registration failed:", err.message);

    if (err.code === "SQLITE_CONSTRAINT") {
      return res.status(409).json({
        success: false,
        message: "এই মোবাইল নম্বর বা Registration ID আগে ব্যবহৃত হয়েছে।"
      });
    }

    res.status(500).json({
      success: false,
      message: "নিবন্ধন সম্পন্ন হয়নি। সার্ভারের লগ পরীক্ষা করুন।"
    });
  }
});
```
const registrationId =
  req.session.registrationId;

if (
  !registrationId ||
  !req.session.registrationPendingPayment
) {
  return res.status(401).json({
    success: false,
    message: "নিবন্ধন সম্পন্ন করে পেমেন্ট শুরু করুন।"
  });
}

const participant = await get(
  "SELECT * FROM participants WHERE registration_id = ?",
  [registrationId]
);

if (!participant) {
  return res.status(404).json({
    success: false,
    message: "নিবন্ধন পাওয়া যায়নি।"
  });
}
/* Create bKash payment for the verified participant */
app.post(
  "/api/payment/bkash/create",
  authLimiter,
  async (req, res) => {
    try {
      if (!req.session.participantId) {
        return res.status(401).json({
          success: false,
          message: "প্রথমে Login করুন।"
        });
      }

      if (!bkashConfigReady()) {
        return res.status(503).json({
          success: false,
          message: "bKash API credentials সেট করা হয়নি।"
        });
      }

      const participant = await get(
        "SELECT * FROM participants WHERE id = ?",
        [req.session.participantId]
      );

      if (!participant) {
        return res.status(404).json({ success: false });
      }

      const amount = "99.00";
      const invoice = "MCQ26-" + crypto.randomUUID().replace(/-/g, "");

      const token = await getBkashToken();

      const result = await bkashRequest(
        "POST",
        "/create",
        token,
        {
          mode: "0011",
          payerReference: participant.mobile,
          callbackURL: `${req.protocol}://${req.get("host")}/payment/callback`,
          amount,
          currency: "BDT",
          intent: "sale",
          merchantInvoiceNumber: invoice
        }
      );

      if (!result.paymentID || !result.bkashURL) {
        console.error("Unexpected bKash create response");
        return res.status(502).json({
          success: false,
          message: "bKash payment তৈরি হয়নি।"
        });
      }

      await run(
        `INSERT INTO payments
         (registration_id, payment_id, invoice_number, amount, status, created_at)
         VALUES (?, ?, ?, ?, 'PENDING', ?)`,
        [
          participant.registration_id,
          result.paymentID,
          invoice,
          amount,
          new Date().toISOString()
        ]
      );

      res.json({
        success: true,
        paymentID: result.paymentID,
        paymentURL: result.bkashURL
      });
    } catch (err) {
      console.error(
        "bKash create failed:",
        err.response?.data || err.message
      );

      res.status(502).json({
        success: false,
        message: "bKash payment তৈরি করা যায়নি।"
      });
    }
  }
);

/* Execute only a payment belonging to the logged-in participant */
app.post(
  "/api/payment/bkash/execute",
  authLimiter,
  async (req, res) => {
    try {
      if (!req.session.participantId) {
        return res.status(401).json({ success: false });
      }

      const paymentID = String(req.body.paymentID || "");
      const participant = await get(
        "SELECT registration_id FROM participants WHERE id = ?",
        [req.session.participantId]
      );

      const payment = await get(
        `SELECT * FROM payments
         WHERE payment_id = ? AND registration_id = ?`,
        [paymentID, participant.registration_id]
      );

      if (!payment) {
        return res.status(404).json({
          success: false,
          message: "পেমেন্ট পাওয়া যায়নি।"
        });
      }

      const token = await getBkashToken();

      const executed = await bkashRequest(
        "POST",
        "/execute",
        token,
        { paymentID }
      );

      // Do not trust execute response alone.
      const status = await bkashRequest(
        "POST",
        "/payment/status",
        token,
        { paymentID }
      );

      const completed =
        status.transactionStatus === "Completed" &&
        Number(status.amount) === Number(payment.amount) &&
        status.currency === "BDT";

      if (completed) {
        await run(
          `UPDATE payments
           SET status = 'PAID', trx_id = ?
           WHERE payment_id = ?`,
          [status.trxID || executed.trxID || null, paymentID]
        );

        await run(
          `UPDATE participants SET payment_status = 'PAID'
           WHERE registration_id = ?`,
          [participant.registration_id]
        );
      }

      res.json({
        success: true,
        paid: completed,
        status: completed ? "PAID" : "PENDING"
      });
    } catch (err) {
      console.error(
        "bKash execute/status failed:",
        err.response?.data || err.message
      );

      res.status(502).json({
        success: false,
        message: "পেমেন্ট যাচাই করা যায়নি। পরে আবার চেষ্টা করুন।"
      });
    }
  }
);

/* Callback: browser redirect is not proof of payment */
app.get("/payment/callback", (req, res) => {
  res.redirect("/result.html?payment=pending");
});
```javascript
// ==========================================
// PART 18: COMPETITOR DASHBOARD API
// ==========================================

app.get("/api/dashboard", (req, res) => {
  // লগইন করা আছে কি না যাচাই
  if (!req.session || !req.session.participantId) {
    return res.status(401).json({
      success: false,
      loggedIn: false,
      message: "আগে লগইন করুন।"
    });
  }

  const participantId = req.session.participantId;

  // শুধু লগইন করা প্রতিযোগীর নিজের তথ্য
  db.get(
    "SELECT * FROM participants WHERE id = ?",
    [participantId],
    (error, participant) => {
      if (error) {
        console.error("Dashboard database error:", error);

        return res.status(500).json({
          success: false,
          message: "ডেটাবেস থেকে তথ্য আনা যায়নি।"
        });
      }

      if (!participant) {
        return res.status(404).json({
          success: false,
          message: "প্রতিযোগীর তথ্য পাওয়া যায়নি।"
        });
      }

      // পেমেন্ট যাচাই না হলে Paid দেখানো হবে না
      const paymentStatus =
        participant.payment_status || "pending";

      // পরীক্ষার অবস্থা সার্ভারের ডেটা থেকে নেওয়া হবে
      const examStatus =
        participant.exam_status || "not_started";

      return res.json({
        success: true,
        loggedIn: true,

        registrationId: participant.registration_id,

        profile: {
          name: participant.name,
          father_name: participant.father_name,
          age: participant.age,
          mobile: participant.mobile,
          email: participant.email,
          division: participant.division,
          district: participant.district,
          upazila: participant.upazila,
          address: participant.address,
          group_name: participant.group_name
        },

        paymentStatus: paymentStatus,
        examStatus: examStatus
      });
    }
  );
});

// ==========================================
// PART 18 END
// ==========================================
```

/* Start only after DB migration succeeds */
initializeDatabase()
  .then(() => {
    
app.get("/api/exam/questions", (req, res) => {
  const participantId = req.session?.participantId;

  if (!participantId) {
    return res.status(401).json({
      success: false,
      message: "প্রথমে লগইন করুন।"
    });
  }

  db.get(
    `SELECT group_name, payment_status, exam_status
     FROM participants
     WHERE id = ?`,
    [participantId],
    (err, participant) => {
      if (err) {
        console.error(err.message);
        return res.status(500).json({
          success: false,
          message: "পরীক্ষার্থীর তথ্য যাচাই করা যায়নি।"
        });
      }

      if (!participant) {
        return res.status(404).json({
          success: false,
          message: "পরীক্ষার্থী পাওয়া যায়নি।"
        });
      }

      if (
        participant.payment_status !== "paid" ||
        participant.exam_status !== "ongoing"
      ) {
        return res.status(403).json({
          success: false,
          message: "আপনার পরীক্ষা এখন শুরু করার অনুমতি নেই।"
        });
      }

      try {
        const questions = readJsonFile(QUESTIONS_FILE);
        const groupName = String(participant.group_name).trim();

        const groupQuestions = questions
          .filter((q) => String(q.group).trim() === groupName)
          .map((q) => ({
            id: q.id,
            question: q.question,
            options: q.options
          }));

        if (groupQuestions.length === 0) {
          return res.status(404).json({
            success: false,
            message: "এই গ্রুপের প্রশ্ন পাওয়া যায়নি।"
          });
        }

        return res.json({
          success: true,
          group: groupName,
          questions: groupQuestions
        });
      } catch (fileError) {
        console.error(fileError.message);
        return res.status(500).json({
          success: false,
          message: "প্রশ্নের ফাইল পড়া যায়নি।"
        });
      }
    }
  );
}); 
function calculateScore(submittedAnswers, questions, answerKey) {
  let correct = 0;
  let wrong = 0;
  let unanswered = 0;

  for (const question of questions) {
    const id = String(question.id);

    if (
      !Object.prototype.hasOwnProperty.call(
        submittedAnswers,
        id
      )
    ) {
      unanswered++;
      continue;
    }

    const selected = submittedAnswers[id];

    if (![0, 1, 2, 3].includes(selected)) {
      throw new Error("Invalid option for question " + id);
    }

    if (
      !Object.prototype.hasOwnProperty.call(answerKey, id)
    ) {
      throw new Error("Answer key missing for " + id);
    }

    if (selected === answerKey[id]) {
      correct++;
    } else {
      wrong++;
    }
  }

  return {
    total: questions.length,
    correct,
    wrong,
    unanswered,
    score: correct
  };
}

app.post("/api/exam/submit", (req, res) => {
  const participantId = req.session?.participantId;

  if (!participantId) {
    return res.status(401).json({
      success: false,
      message: "প্রথমে লগইন করুন।"
    });
  }

  db.get(
    `SELECT group_name, payment_status, exam_status
     FROM participants
     WHERE id = ?`,
    [participantId],
    (participantErr, participant) => {
      if (participantErr) {
        console.error(participantErr.message);
        return res.status(500).json({
          success: false,
          message: "পরীক্ষার্থীর তথ্য যাচাই করা যায়নি।"
        });
      }

      if (!participant) {
        return res.status(404).json({
          success: false,
          message: "পরীক্ষার্থী পাওয়া যায়নি।"
        });
      }

      if (
        participant.payment_status !== "paid" ||
        participant.exam_status !== "ongoing"
      ) {
        return res.status(403).json({
          success: false,
          message: "পরীক্ষা জমা দেওয়ার অনুমতি নেই।"
        });
      }

      db.get(
        `SELECT id FROM exam_results WHERE participant_id = ?`,
        [participantId],
        (resultErr, existingResult) => {
          if (resultErr) {
            console.error(resultErr.message);
            return res.status(500).json({
              success: false,
              message: "ফলাফল যাচাই করা যায়নি।"
            });
          }

          if (existingResult) {
            return res.status(409).json({
              success: false,
              message: "আপনার পরীক্ষা ইতিমধ্যে জমা হয়েছে।"
            });
          }

          try {
            const allQuestions = readJsonFile(QUESTIONS_FILE);
            const answerKey = readJsonFile(ANSWER_KEY_FILE);
            const groupName = String(participant.group_name).trim();

            const questions = allQuestions.filter(
              (q) => String(q.group).trim() === groupName
            );

            if (questions.length === 0) {
              return res.status(400).json({
                success: false,
                message: "এই গ্রুপের প্রশ্ন পাওয়া যায়নি।"
              });
            }

            db.all(
              `SELECT question_id, selected_option
               FROM exam_answers
               WHERE participant_id = ?`,
              [participantId],
              (answersErr, rows) => {
                if (answersErr) {
                  console.error(answersErr.message);
                  return res.status(500).json({
                    success: false,
                    message: "সংরক্ষিত উত্তর পড়া যায়নি।"
                  });
                }

                try {
                  const submittedAnswers = {};

                  for (const row of rows) {
                    submittedAnswers[row.question_id] =
                      row.selected_option;
                  }

                  // শুধু এই গ্রুপের প্রশ্নের উত্তর দিয়ে নম্বর গণনা
                  const scoreData = calculateScore(
                    submittedAnswers,
                    questions,
                    answerKey
                  );

                  db.run(
                    `INSERT INTO exam_results
                     (participant_id, total_questions,
                      correct_answers, wrong_answers,
                      unanswered, score)
                     VALUES (?, ?, ?, ?, ?, ?)`,
                    [
                      participantId,
                      scoreData.total,
                      scoreData.correct,
                      scoreData.wrong,
                      scoreData.unanswered,
                      scoreData.score
                    ],
                    function (saveErr) {
                      if (saveErr) {
                        console.error(saveErr.message);

                        if (
                          saveErr.code === "SQLITE_CONSTRAINT"
                        ) {
                          return res.status(409).json({
                            success: false,
                            message: "পরীক্ষা ইতিমধ্যে জমা হয়েছে।"
                          });
                        }

                        return res.status(500).json({
                          success: false,
                          message: "ফলাফল সংরক্ষণ করা যায়নি।"
                        });
                      }

                      db.run(
                        `UPDATE participants
                         SET exam_status = 'submitted'
                         WHERE id = ?`,
                        [participantId],
                        (updateErr) => {
                          if (updateErr) {
                            console.error(updateErr.message);
                            return res.status(500).json({
                              success: false,
                              message:
                                "ফলাফল সংরক্ষিত হয়েছে, কিন্তু পরীক্ষার অবস্থা আপডেট হয়নি।"
                            });
                          }

                          return res.json({
                            success: true,
                            message: "পরীক্ষা সফলভাবে জমা হয়েছে।",
                            result: {
                              total: scoreData.total,
                              correct: scoreData.correct,
                              wrong: scoreData.wrong,
                              unanswered: scoreData.unanswered,
                              score: scoreData.score
                            }
                          });
                        }
                      );
                    }
                  );
                } catch (scoreErr) {
                  console.error(scoreErr.message);
                  return res.status(500).json({
                    success: false,
                    message: "নম্বর গণনা করা যায়নি।"
                  });
                }
              }
            );
          } catch (fileErr) {
            console.error(fileErr.message);
            return res.status(500).json({
              success: false,
              message: "প্রশ্ন বা উত্তরসূচির ফাইল পড়া যায়নি।"
            });
          }
        }
      );
    }
  );
});

db.get(
  `SELECT setting_value
   FROM app_settings
   WHERE setting_key = 'results_published'`,
  [],
  (settingsErr, setting) => {
    if (settingsErr) {
      return res.status(500).json({
        success: false,
        message: "প্রকাশের অবস্থা যাচাই করা যায়নি।"
      });
    }

    if (!setting || setting.setting_value !== "true") {
      return res.json({
        success: true,
        published: false,
        message: "ফলাফল এখনো প্রকাশ করা হয়নি।"
      });
    }

    // এখানে PART 25-এর বিদ্যমান ফলাফল response রাখুন।
  }
);

app.get("/api/result", (req, res) => {
  const participantId = req.session?.participantId;

  if (!participantId) {
    return res.status(401).json({
      success: false,
      message: "ফলাফল দেখতে প্রথমে লগইন করুন।"
    });
  }

  db.get(
    `SELECT
       p.registration_id,
       p.name,
       p.group_name,
       r.total_questions,
       r.correct_answers,
       r.wrong_answers,
       r.unanswered,
       r.score,
       r.submitted_at
     FROM participants p
     LEFT JOIN exam_results r
       ON r.participant_id = p.id
     WHERE p.id = ?`,
    [participantId],
    (err, row) => {
      if (err) {
        console.error("Result query error:", err.message);
        return res.status(500).json({
          success: false,
          message: "ফলাফল লোড করা যায়নি।"
        });
      }

      if (!row) {
        return res.status(404).json({
          success: false,
          message: "পরীক্ষার্থীর তথ্য পাওয়া যায়নি।"
        });
      }

      if (row.submitted_at === null) {
        return res.json({
          success: true,
          published: false,
          message: "আপনার পরীক্ষার ফলাফল এখনো তৈরি হয়নি।"
        });
      }

      return res.json({
        success: true,
        published: true,
        result: {
          registrationId: row.registration_id,
          name: row.name,
          group: row.group_name,
          total: row.total_questions,
          correct: row.correct_answers,
          wrong: row.wrong_answers,
          unanswered: row.unanswered,
          score: row.score,
          submittedAt: row.submitted_at
        }
      });
    }
  );
});

app.get("/api/ranking/:group", (req, res) => {
  const participantId = req.session?.participantId;

  if (!participantId) {
    return res.status(401).json({
      success: false,
      message: "মেধাতালিকা দেখতে প্রথমে লগইন করুন।"
    });
  }

  const allowedGroups = ["ক", "খ", "গ", "ঘ", "ঙ", "চ", "ছ", "জ"];
  const group = String(req.params.group || "").trim();

  if (!allowedGroups.includes(group)) {
    return res.status(400).json({
      success: false,
      message: "সঠিক গ্রুপ নির্বাচন করুন।"
    });
  }

  db.all(
    `SELECT
       p.registration_id,
       p.name,
       p.group_name,
       r.score,
       r.submitted_at
     FROM participants p
     INNER JOIN exam_results r
       ON r.participant_id = p.id
     WHERE TRIM(p.group_name) = ?
     ORDER BY
       r.score DESC,
       r.submitted_at ASC,
       p.registration_id ASC`,
    [group],
    (err, rows) => {
      if (err) {
        console.error("Ranking error:", err.message);
        return res.status(500).json({
          success: false,
          message: "মেধাতালিকা তৈরি করা যায়নি।"
        });
      }

      const ranking = rows.map((row, index) => ({
        rank: index + 1,
        registrationId: row.registration_id,
        name: row.name,
        group: row.group_name,
        score: row.score,
        submittedAt: row.submitted_at
      }));

      return res.json({
        success: true,
        group,
        totalParticipants: ranking.length,
        ranking
      });
    }
  );
});

function requireAdmin(req, res, next) {
  if (!req.session || req.session.isAdmin !== true) {
    return res.status(403).json({
      success: false,
      message: "শুধু অনুমোদিত অ্যাডমিন এই কাজ করতে পারবেন।"
    });
  }

  next();
}

app.get("/api/admin/results-status", requireAdmin, (req, res) => {
  db.get(
    `SELECT setting_value
     FROM app_settings
     WHERE setting_key = 'results_published'`,
    [],
    (err, row) => {
      if (err) {
        console.error(err.message);
        return res.status(500).json({
          success: false,
          message: "সেটিং পড়া যায়নি।"
        });
      }

      return res.json({
        success: true,
        published: row?.setting_value === "true"
      });
    }
  );
});

app.post("/api/admin/results-status", requireAdmin, (req, res) => {
  const published = req.body?.published;

  if (typeof published !== "boolean") {
    return res.status(400).json({
      success: false,
      message: "published-এর মান true অথবা false হতে হবে।"
    });
  }

  db.run(
    `UPDATE app_settings
     SET setting_value = ?
     WHERE setting_key = 'results_published'`,
    [published ? "true" : "false"],
    function (err) {
      if (err) {
        console.error(err.message);
        return res.status(500).json({
          success: false,
          message: "প্রকাশের অবস্থা পরিবর্তন করা যায়নি।"
        });
      }

      if (this.changes === 0) {
        return res.status(500).json({
          success: false,
          message: "প্রকাশের সেটিং পাওয়া যায়নি।"
        });
      }

      return res.json({
        success: true,
        published,
        message: published
          ? "ফলাফল প্রকাশ করা হয়েছে।"
          : "ফলাফল গোপন করা হয়েছে।"
      });
    }
  );
});

/* PART 28: Admin Group Ranking API */

app.get("/api/admin/ranking/:group", requireAdmin, (req, res) => {
  const allowedGroups = ["ক", "খ", "গ", "ঘ", "ঙ", "চ", "ছ", "জ"];
  const groupName = req.params.group;

  if (!allowedGroups.includes(groupName)) {
    return res.status(400).json({
      success: false,
      message: "সঠিক গ্রুপ নির্বাচন করুন।"
    });
  }

  // ফলাফল প্রকাশিত হয়েছে কি না পরীক্ষা
  db.get(
    `SELECT setting_value
     FROM app_settings
     WHERE setting_key = 'results_published'`,
    [],
    (settingsErr, setting) => {
      if (settingsErr) {
        return res.status(500).json({
          success: false,
          message: "ফলাফল প্রকাশের অবস্থা যাচাই করা যায়নি।"
        });
      }

      if (!setting || setting.setting_value !== "true") {
        return res.status(403).json({
          success: false,
          published: false,
          message: "অ্যাডমিন এখনো ফলাফল প্রকাশ করেননি।"
        });
      }

      // প্রকাশিত হলে নির্বাচিত গ্রুপের র‍্যাঙ্কিং দেখাবে
      db.all(
        `SELECT
           p.registration_id,
           p.name,
           p.group_name,
           r.score,
           r.correct_answers,
           r.wrong_answers,
           r.unanswered,
           r.submitted_at
         FROM participants p
         INNER JOIN exam_results r
           ON r.participant_id = p.id
         WHERE TRIM(p.group_name) = ?
         ORDER BY
           r.score DESC,
           r.submitted_at ASC,
           p.registration_id ASC`,
        [groupName],
        (err, rows) => {
          if (err) {
            return res.status(500).json({
              success: false,
              message: "র‍্যাঙ্কিং লোড করা যায়নি।"
            });
          }

          const ranking = rows.map((row, index) => ({
            rank: index + 1,
            registrationId: row.registration_id,
            name: row.name,
            group: row.group_name,
            score: row.score,
            correct: row.correct_answers,
            wrong: row.wrong_answers,
            unanswered: row.unanswered,
            submittedAt: row.submitted_at
          }));

          return res.json({
            success: true,
            published: true,
            group: groupName,
            total: ranking.length,
            ranking
          });
        }
      );
    }
  );
});

/* PART 30: Admin Participant Search API */

app.get("/api/admin/participant-search", requireAdmin, (req, res) => {
  const search = String(req.query.q || "").trim();

  if (search.length < 3 || search.length > 100) {
    return res.status(400).json({
      success: false,
      message: "কমপক্ষে ৩টি অক্ষর বা সংখ্যা লিখুন।"
    });
  }

  db.get(
    `SELECT
       registration_id,
       name,
       father_name,
       age,
       mobile,
       email,
       division,
       district,
       upazila,
       address,
       group_name,
       created_at
     FROM participants
     WHERE registration_id = ?
        OR mobile = ?
     LIMIT 1`,
    [search, search],
    (err, participant) => {
      if (err) {
        return res.status(500).json({
          success: false,
          message: "ডেটাবেসে অনুসন্ধান করা যায়নি।"
        });
      }

      if (!participant) {
        return res.status(404).json({
          success: false,
          message: "এই রেজিস্ট্রেশন নম্বর বা মোবাইল নম্বরে কোনো প্রতিযোগী পাওয়া যায়নি।"
        });
      }

      return res.json({
        success: true,
        participant
      });
    }
  );
});

app.listen(PORT, () => {
      console.log(`MCQ server running at http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error("Database initialization failed:", err.message);
    process.exit(1);
  });