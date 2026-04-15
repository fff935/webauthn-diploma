const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

// Потрібно для криптографії в Node.js
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

// 📂 Створення папки для завантажень
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// ⚙️ Налаштування WebAuthn
const rpID = "localhost";
const origin = `http://${rpID}:3000`;

// 🧠 "База даних" в оперативній пам'яті
let userCredential = null;
let currentChallenge = null;
let isAuthenticated = false;

// =======================
// 🔐 РЕЄСТРАЦІЯ
// =======================
app.get("/generate-registration", async (req, res) => {
  try {
    const options = await generateRegistrationOptions({
      rpName: "Photo Vault",
      rpID,
      userID: Buffer.from("user123"),
      userName: "admin@vault.com",
      userDisplayName: "Admin",
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
    });

    currentChallenge = options.challenge;
    res.json(options);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/verify-registration", async (req, res) => {
  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.verified && verification.registrationInfo) {
      // Зберігаємо оригінальні дані ключа без зайвих конвертацій
      userCredential = verification.registrationInfo.credential;

      console.log("✅ Пристрій успішно зареєстровано");
      return res.json({ verified: true });
    }

    throw new Error("Не вдалося отримати дані ключа");
  } catch (e) {
    console.error("❌ Помилка реєстрації:", e.message);
    res.status(400).json({ error: e.message });
  }
});

// =======================
// 🔓 ВХІД
// =======================
app.get("/generate-authentication", async (req, res) => {
  if (!userCredential) {
    return res.status(400).json({ error: "Спочатку зареєструйтесь!" });
  }

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: [
      {
        id: userCredential.id, // Передаємо як рядок
        type: "public-key",
        transports: userCredential.transports,
      },
    ],
  });

  currentChallenge = options.challenge;
  res.json(options);
});

app.post("/verify-authentication", async (req, res) => {
  try {
    if (!req.body || Object.keys(req.body).length === 0) {
      throw new Error("Порожній запит від браузера");
    }

    if (!userCredential) {
      throw new Error("Користувач не зареєстрований");
    }

    const verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: userCredential.id,
        publicKey: userCredential.publicKey,
        counter: userCredential.counter,
        transports: userCredential.transports,
      },
    });

    if (verification.verified) {
      isAuthenticated = true;
      console.log("🔓 Вхід успішний!");
      return res.json({ verified: true });
    }

    res.status(400).json({ verified: false, error: "Верифікація не пройшла" });
  } catch (error) {
    console.error("🔥 ПОМИЛКА СЕРВЕРА:", error.message);
    res.status(400).json({ error: error.message });
  }
});

// =======================
// 📂 ГАЛЕРЕЯ
// =======================
app.post("/upload", upload.single("photo"), (req, res) => {
  if (!isAuthenticated) return res.status(401).send("Немає доступу");
  res.send("ОК");
});

app.get("/photos", (req, res) => {
  if (!isAuthenticated) return res.status(401).json([]);
  res.json(fs.readdirSync("uploads/"));
});

app.use("/view-photo", express.static("uploads"));

// =======================
app.listen(3000, () => console.log("🚀 Сейф працює на http://localhost:3000"));