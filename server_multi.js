const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const crypto = require("crypto");
const ENCRYPTION_KEY = Buffer.from("foxtrot-uniform-charley-kilo-123"); // 32 символи
const IV_LENGTH = 16; // Для алгоритму AES

// Забезпечуємо роботу криптографії (потрібно для WebAuthn на Node.js)
if (!globalThis.crypto) {
  globalThis.crypto = require("node:crypto").webcrypto;
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

// --- 1. ІНІЦІАЛІЗАЦІЯ БАЗИ ТА ПАПОК ---
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: {} }));
if (!fs.existsSync(UPLOADS_ROOT)) fs.mkdirSync(UPLOADS_ROOT);

function getDB() { return JSON.parse(fs.readFileSync(DB_FILE)); }
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }

// --- 2. ТИМЧАСОВІ ДАНІ ТА СЕСІЇ ---
let challenges = {};
let authenticatedUsers = {}; // Зберігаємо як { "IP-адреса": "username" }

// --- 3. ОХОРОНЕЦЬ (Middleware) ---
// Ця функція ПОВИННА бути вище за маршрути, які її використовують
const checkAuth = (req, res, next) => {
  const user = authenticatedUsers[req.ip];
  if (!user) {
    console.log(`🚫 Спроба доступу без авторизації з IP: ${req.ip}`);
    return res.status(401).send("Доступ заборонено: спочатку пройдіть біометрію!");
  }
  // Якщо користувач є в списку — пропускаємо до наступної функції
  next();
};

// --- 4. НАЛАШТУВАННЯ ЗАВАНТАЖЕННЯ (Multer) ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Використовуємо x-user з заголовка для створення папки
    const user = req.headers['x-user'] || 'unknown';
    const userDir = path.join(UPLOADS_ROOT, user);
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// Допоміжна функція для безпеки
const getExpectedOrigin = (req) => {
  return req.hostname === "localhost" ? "http://localhost:3000" : `https://${req.hostname}`;
};

// --- 5. МАРШРУТИ РЕЄСТРАЦІЇ ---
app.get("/generate-registration", async (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).send("Вкажіть ім'я!");

  const options = await generateRegistrationOptions({
    rpName: "Біометричний Сейф",
    rpID: req.hostname,
    userID: Buffer.from(username),
    userName: username,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "preferred",
    },
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
      expectedOrigin: getExpectedOrigin(req),
      expectedRPID: req.hostname,
    });

    if (verification.verified) {
      const db = getDB();
      db.users[username] = {
        ...verification.registrationInfo.credential,
        // Дозволяємо "hybrid" для можливості входу з телефону на ПК
        transports: req.body.response.transports || ["internal", "hybrid"]
      };
      saveDB(db);
      console.log(`✅ Користувач ${username} успішно зареєстрований`);
      res.json({ verified: true });
    }
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- 6. МАРШРУТИ ВХОДУ ---
app.get("/generate-authentication", async (req, res) => {
  const { username } = req.query;
  const db = getDB();
  const user = db.users[username];

  if (!user) return res.status(400).send("Користувача не знайдено!");

  const options = await generateAuthenticationOptions({
    rpID: req.hostname,
    allowCredentials: [{
      id: user.id,
      type: "public-key",
      transports: user.transports,
    }],
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
      expectedOrigin: getExpectedOrigin(req),
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
      console.log(`🔓 Користувач ${username} увійшов через IP ${req.ip}`);
      res.json({ verified: true });
    }
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- 7. РОБОТА З ФАЙЛАМИ (ЗАХИЩЕНА ОХОРОНЦЕМ) ---

// Завантаження: спочатку перевіряємо checkAuth, потім multer
app.post("/upload", checkAuth, upload.single("photo"), (req, res) => {
  const filePath = req.file.path;
  const buffer = fs.readFileSync(filePath);
  
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  
  const encrypted = Buffer.concat([iv, cipher.update(buffer), cipher.final()]);
  
  fs.writeFileSync(filePath, encrypted); // Перезаписуємо файл зашифрованими даними
  res.send("ОК (Зашифровано)");
});

// Список фото: доступний тільки авторизованим
app.get("/photos", checkAuth, (req, res) => {
  const user = authenticatedUsers[req.ip];
  const userDir = path.join(UPLOADS_ROOT, user);
  res.json(fs.existsSync(userDir) ? fs.readdirSync(userDir) : []);
});

// Перегляд фото: додано захист від кешування
app.get("/view-photo/:name", checkAuth, (req, res) => {
  const user = authenticatedUsers[req.ip];
  const filePath = path.join(__dirname, UPLOADS_ROOT, user, req.params.name);

  if (fs.existsSync(filePath)) {
    const data = fs.readFileSync(filePath);
    
    // Витягуємо IV (перші 16 байт) та самі дані
    const iv = data.slice(0, IV_LENGTH);
    const encryptedText = data.slice(IV_LENGTH);
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);

    res.setHeader('Cache-Control', 'no-store');
    res.contentType("image/jpeg"); // Кажемо браузеру, що це картинка
    res.send(decrypted);
  } else {
    res.status(404).send("Файл не знайдено");
  }
});

// --- 8. ВИХІД ---
app.post("/logout", (req, res) => {
  delete authenticatedUsers[req.ip];
  res.json({ success: true });
});

// --- ЗАПУСК ---
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Біометричний сейф запущено: http://localhost:${PORT}`);
});