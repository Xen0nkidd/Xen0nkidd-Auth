const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Resend } = require("resend");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me";
const APP_URL = process.env.APP_URL || "https://xen0nkidd.github.io";
const EMAIL_FROM = process.env.EMAIL_FROM || "onboarding@resend.dev";
const resend = new Resend(process.env.EMAIL_API_KEY);

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

app.get("/", (req, res) => res.json({ ok: true, service: "xen0nkidd-auth" }));

app.post("/api/auth/register", async (req, res) => {
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
  const token = sign(user);
  res.json({ ok: true, token, user: { username, email } });
});

app.post("/api/auth/login", async (req, res) => {
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
});

app.post("/api/auth/forgot-password", async (req, res) => {
  const email = (req.body?.email || "").trim().toLowerCase();
  res.json({ ok: true });
  if (!email) return;
  const db = load();
  const user = db.users.find((u) => (u.email || "").toLowerCase() === email);
  if (!user) return;
  const token = token20();
  user.resetToken = token;
  user.resetTokenExpires = Date.now() + 60 * 60 * 1000;
  save(db);
  const link = `${APP_URL}/reset.html?token=${token}`;
  try {
    await resend.emails.send({
      from: EMAIL_FROM,
      to: email,
      subject: "Reset your Xenon password",
      html: `<p>Reset link: <a href="${link}">${link}</a></p>
             <p>Or paste this token on the reset page:</p>
             <p><strong>${token}</strong></p>
             <p>Expires in 1 hour.</p>`,
      text: `Reset link: ${link}\n\nToken: ${token}\n\nExpires in 1 hour.`,
    });
  } catch (e) {
    console.error("email error", e);
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
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
});

app.post("/api/auth/add-email", async (req, res) => {
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
});

app.listen(PORT, () => console.log("auth on", PORT));
