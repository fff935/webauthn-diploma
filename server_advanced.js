const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

if (!globalThis.crypto.webcrypto) {
  globalThis.crypto.webcrypto = require("node:crypto").webcrypto;
}

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const app = express();
app.use(express.json());
app.use(express.static("public"));

const DB_FILE = "db.json";
const UPLOADS_ROOT = "uploads";
const AUDIT_FILE = "audit.log";
const MASTER_SECRET = "super-secret-master-key-for-diploma-2024"; 
const IV_LENGTH = 16;

if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: {} }));
if (!fs.existsSync(UPLOADS_ROOT)) fs.mkdirSync(UPLOADS_ROOT);

function getDB() { return JSON.parse(fs.readFileSync(DB_FILE)); }
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }

function logEvent(user, action, status) {
  const time = new Date().toLocaleString("uk-UA");
  const logLine = `[${time}] Користувач: ${user || 'Невідомий'} | Дія: ${action} | Статус: ${status}\n`;
  fs.appendFileSync(AUDIT_FILE, logLine);
}

function getUserKey(salt) {
  return crypto.scryptSync(MASTER_SECRET, salt, 32);
}

let challenges = {};
let authenticatedUsers = {}; 

const checkAuth = (req, res, next) => {
  const user = authenticatedUsers[req.ip];
  if (!user) return res.status(401).send("Спочатку увійдіть!");
  next();
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const user = authenticatedUsers[req.ip] || 'unknown';
    const userDir = path.join(UPLOADS_ROOT, user);
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype === "image/jpeg" || file.mimetype === "image/png") {
    cb(null, true);
  } else {
    cb(new Error("Дозволені лише .jpg та .png!"), false);
  }
};

const upload = multer({ storage, fileFilter, limits: { fileSize: 5 * 1024 * 1024 } });

// --- API ---

app.get("/generate-registration", async (req, res) => {
  const { username } = req.query;
  const db = getDB();
  if (db.users[username]) return res.status(400).send("Користувач вже існує!");

  const options = await generateRegistrationOptions({
    rpName: "Біометричний Сейф",
    rpID: req.hostname,
    userID: Buffer.from(username),
    userName: username,
    attestationType: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
  });
  challenges[username] = options.challenge;
  res.json(options);
});

app.post("/verify-registration", async (req, res) => {
  const { username } = req.query;
  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: challenges[username],
      expectedOrigin: req.hostname === "localhost" ? "http://localhost:3000" : `https://${req.hostname}`,
      expectedRPID: req.hostname,
    });
    if (verification.verified) {
      const db = getDB();
      const userSalt = crypto.randomBytes(16).toString('hex');
      db.users[username] = { 
        ...verification.registrationInfo.credential, 
        transports: req.body.response.transports || ["internal", "hybrid"],
        salt: userSalt 
      };
      saveDB(db);
      logEvent(username, "Реєстрація", "Успіх");
      res.json({ verified: true });
    }
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get("/generate-authentication", async (req, res) => {
  const { username } = req.query;
  const db = getDB();
  const user = db.users[username];
  if (!user) return res.status(400).send("Користувача не знайдено!");

  const options = await generateAuthenticationOptions({
    rpID: req.hostname,
    allowCredentials: [{ id: user.id, type: "public-key", transports: user.transports }],
    userVerification: "preferred",
  });
  challenges[username] = options.challenge;
  res.json(options);
});

app.post("/verify-authentication", async (req, res) => {
  const { username } = req.query;
  const db = getDB();
  const userData = db.users[username];
  try {
    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: challenges[username],
      expectedOrigin: req.hostname === "localhost" ? "http://localhost:3000" : `https://${req.hostname}`,
      expectedRPID: req.hostname,
      credential: {
        id: userData.id,
        publicKey: new Uint8Array(Object.values(userData.publicKey)),
        counter: userData.counter,
        transports: userData.transports,
      },
    });
    if (verification.verified) {
      authenticatedUsers[req.ip] = username;
      logEvent(username, "Вхід", "Успіх");
      res.json({ verified: true });
    }
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/upload", checkAuth, (req, res) => {
  upload.single("photo")(req, res, (err) => {
    if (err) return res.status(400).send(err.message);
    if (!req.file) return res.status(400).send("Файл не обрано");

    const user = authenticatedUsers[req.ip];
    const db = getDB();
    const userKey = getUserKey(db.users[user].salt);
    const buffer = fs.readFileSync(req.file.path);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', userKey, iv);
    const encrypted = Buffer.concat([iv, cipher.update(buffer), cipher.final()]);
    
    fs.writeFileSync(req.file.path, encrypted);
    logEvent(user, "Завантаження файлу", "Успіх");
    res.send("ОК");
  });
});

app.get("/photos", checkAuth, (req, res) => {
  const user = authenticatedUsers[req.ip];
  const userDir = path.join(UPLOADS_ROOT, user);
  res.json(fs.existsSync(userDir) ? fs.readdirSync(userDir) : []);
});

app.get("/view-photo/:name", checkAuth, (req, res) => {
  const user = authenticatedUsers[req.ip];
  const filePath = path.join(UPLOADS_ROOT, user, req.params.name);
  if (!fs.existsSync(filePath)) return res.status(404).send("Не знайдено");

  try {
    const data = fs.readFileSync(filePath);
    const db = getDB();
    const userKey = getUserKey(db.users[user].salt);
    const iv = data.slice(0, IV_LENGTH);
    const encryptedText = data.slice(IV_LENGTH);
    const decipher = crypto.createDecipheriv('aes-256-cbc', userKey, iv);
    const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    res.contentType("image/jpeg").send(decrypted);
  } catch (err) { res.sendFile(path.resolve(filePath)); }
});

app.get("/audit-log", checkAuth, (req, res) => {
  const user = authenticatedUsers[req.ip];
  if (user.toLowerCase() !== 'admin') {
    logEvent(user, "Доступ до логів", "Відхилено");
    return res.status(403).send("Тільки для Admin!");
  }
  res.type('text/plain').send(fs.existsSync(AUDIT_FILE) ? fs.readFileSync(AUDIT_FILE) : "Пусто");
});

app.post("/logout", (req, res) => {
  delete authenticatedUsers[req.ip];
  res.json({ success: true });
});

app.listen(3000, () => console.log("Сервер запущено на порту 3000"));