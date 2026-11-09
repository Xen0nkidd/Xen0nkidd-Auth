const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-render-env";
const APP_URL = process.env.APP_URL || "https://xen0nkidd.github.io";
const EMAIL_FROM = process.env.EMAIL_FROM || "xenonnetworkofficial@gmail.com";
const DATA = path.join(__dirname, "users.json");

app.use(cors({ origin: true }));
app.use(express.json());

function load() {
  try {
    return JSON.parse(fs.readFileSync(DATA, "utf8"));
  } catch {
    return { users: [] };
  }
}

function save(db) {
  fs.writeFileSync(DATA, JSON.stringify(db, null, 2));
}

function token20() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
  const bytes = crypto.randomBytes(20);
  let out = "";
  for (let i = 0; i < 20; i++) out += chars[bytes[i] % chars.length];
  return out;
}

function sign(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: "30d",
  });
}

function normalizeCode(code) {
  return (code || "").trim().toUpperCase().replace(/-/g, "");
}

async function sendEmail({ to, subject, html, text }) {
  const key = process.env.BREVO_API_KEY;
  if (!key) {
    console.error("BREVO_API_KEY missing");
    throw new Error("Email not configured");
  }

  const res = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      accept: "application/json",
      "api-key": key,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      sender: { email: EMAIL_FROM, name: "Xenon" },
      to: [{ email: to }],
      subject,
      htmlContent: html,
      textContent: text || undefined,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    console.error("Brevo error", res.status, body);
    throw new Error("Brevo send failed");
  }
}

app.get("/", (req, res) => {
  res.json({ ok: true, service: "xen0nkidd-auth" });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const username = (req.body?.username || "").trim();
    const password = req.body?.password || "";
    const email = (req.body?.email || "").trim().toLowerCase();

    if (!username || password.length < 6) {
      return res.status(400).json({ error: "Username and password (6+ chars) required" });
    }
    if (!email || !email.includes("@")) {
      return res.status(400).json({ error: "Valid email required" });
    }

    const db = load();
    if (db.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(400).json({ error: "Username taken" });
    }

    const user = {
      id: crypto.randomUUID(),
      username,
      email,
      passwordHash: await bcrypt.hash(password, 10),
      backupCodeHash: null,
      resetToken: null,
      resetTokenExpires: null,
    };
    db.users.push(user);
    save(db);

    res.json({
      ok: true,
      token: sign(user),
      user: { username: user.username, email: user.email },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const username = (req.body?.username || "").trim();
    const password = req.body?.password || "";
    const db = load();
    const user = db.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: "Invalid username or password" });
    }
    res.json({
      ok: true,
      token: sign(user),
      user: { username: user.username, email: user.email || null },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/auth/me", (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Bearer ")) return res.status(401).json({ error: "Not logged in" });
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    const db = load();
    const user = db.users.find((u) => u.id === payload.id);
    if (!user) return res.status(401).json({ error: "Not logged in" });
    res.json({ ok: true, user: { username: user.username, email: user.email || null } });
  } catch {
    res.status(401).json({ error: "Not logged in" });
  }
});

app.post("/api/auth/logout", (req, res) => res.json({ ok: true }));

app.post("/api/auth/forgot-password", async (req, res) => {
  const email = (req.body?.email || "").trim().toLowerCase();
  res.json({ ok: true });

  if (!email) return;

  try {
    const db = load();
    const user = db.users.find((u) => (u.email || "").toLowerCase() === email);
    if (!user) return;

    const token = token20();
    user.resetToken = token;
    user.resetTokenExpires = Date.now() + 60 * 60 * 1000;
    save(db);

    const link = `${APP_URL}/reset.html?token=${token}`;
    await sendEmail({
      to: email,
      subject: "Reset your Xenon password",
      html: `
        <p>You requested a password reset.</p>
        <p><a href="${link}">Reset your password</a></p>
        <p>Or open ${APP_URL}/reset.html and paste this token:</p>
        <p><strong style="font-size:18px;letter-spacing:2px">${token}</strong></p>
        <p>Expires in 1 hour.</p>
      `,
      text: `Reset link: ${link}\n\nToken: ${token}\n\nExpires in 1 hour.`,
    });
  } catch (e) {
    console.error("email error", e);
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const token = (req.body?.token || "").trim();
    const password = req.body?.password || "";
    if (!token || password.length < 6) {
      return res.status(400).json({ error: "Invalid token or password" });
    }
    const db = load();
    const user = db.users.find(
      (u) => u.resetToken === token && u.resetTokenExpires && u.resetTokenExpires > Date.now()
    );
    if (!user) return res.status(400).json({ error: "Invalid or expired token" });

    user.passwordHash = await bcrypt.hash(password, 10);
    user.resetToken = null;
    user.resetTokenExpires = null;
    save(db);

    res.json({
      ok: true,
      token: sign(user),
      user: { username: user.username, email: user.email || null },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/add-email", async (req, res) => {
  try {
    const username = (req.body?.username || "").trim();
    const email = (req.body?.email || "").trim().toLowerCase();
    if (!username || !email.includes("@")) {
      return res.status(400).json({ error: "Username and email required" });
    }
    const db = load();
    const user = db.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user.email) return res.status(400).json({ error: "Account already has an email" });
    user.email = email;
    save(db);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/claim-account", async (req, res) => {
  try {
    const username = (req.body?.username || "").trim();
    const email = (req.body?.email || "").trim().toLowerCase();
    if (!username || !email.includes("@")) {
      return res.status(400).json({ error: "Username and email required" });
    }
    const db = load();
    const user = db.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
    if (!user) return res.status(404).json({ error: "User not found" });
    if (user.email) return res.status(400).json({ error: "Account already has an email" });
    user.email = email;
    save(db);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/backup-code", async (req, res) => {
  try {
    const code = normalizeCode(req.body?.code);
    if (code.length < 16) return res.status(400).json({ error: "Invalid backup code" });

    const db = load();
    let user = null;

    const auth = req.headers.authorization || "";
    if (auth.startsWith("Bearer ")) {
      try {
        const payload = jwt.verify(auth.slice(7), JWT_SECRET);
        user = db.users.find((u) => u.id === payload.id);
      } catch (e) {}
    }

    const username = (req.body?.username || "").trim();
    if (!user && username) {
      user = db.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
    }

    if (!user) return res.status(401).json({ error: "Not authorized to set backup code" });

    user.backupCodeHash = await bcrypt.hash(code, 10);
    save(db);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login-backup", async (req, res) => {
  try {
    const raw = normalizeCode(req.body?.code);
    if (raw.length < 16) return res.status(400).json({ error: "Invalid backup code" });

    const db = load();
    for (const user of db.users) {
      if (!user.backupCodeHash) continue;
      if (await bcrypt.compare(raw, user.backupCodeHash)) {
        return res.json({
          ok: true,
          token: sign(user),
          user: { username: user.username, email: user.email || null },
        });
      }
    }
    res.status(401).json({ error: "Invalid backup code" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.listen(PORT, () => {
  console.log("xen0nkidd-auth listening on", PORT);
});
