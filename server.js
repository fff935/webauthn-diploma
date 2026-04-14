const express = require('express');
const { 
    generateRegistrationOptions, 
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const app = express();
app.use(express.static('./'));
app.use(express.json());

const users = {}; 
const rpID = 'localhost';
const origin = `http://${rpID}:3000`;

app.get('/generate-registration', async (req, res) => {
    const options = await generateRegistrationOptions({
        rpName: 'WebAuthn Project',
        rpID,
        userID: Uint8Array.from('user123', c => c.charCodeAt(0)),
        userName: 'student@univer.edu.ua',
        userDisplayName: 'Студент',
        attestationType: 'none',
        authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    });
    users['currentChallenge'] = options.challenge;
    res.json(options);
});

app.post('/verify-registration', async (req, res) => {
    try {
        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge: users['currentChallenge'],
            expectedOrigin: origin,
            expectedRPID: rpID,
        });

        if (verification.verified) {
            // Отримуємо дані згідно з твоїм логом: registrationInfo -> credential
            const { credential } = verification.registrationInfo;

            users['credential'] = {
                credentialID: credential.id,
                // Перетворюємо об'єкт публічного ключа з логів назад у Buffer
                credentialPublicKey: Buffer.from(Object.values(credential.publicKey)),
                counter: credential.counter,
            };

            console.log('✅ КЛЮЧ ЗБЕРЕЖЕНО УСПІШНО!');
            console.log('ID ключа:', users['credential'].credentialID);
            res.json({ verified: true });
        }
    } catch (error) {
        console.error('❌ Помилка реєстрації:', error.message);
        res.status(400).json({ error: error.message });
    }
});

app.get('/generate-authentication', async (req, res) => {
    if (!users['credential']) return res.status(400).json({ error: 'Спочатку реєстрація!' });

    const options = await generateAuthenticationOptions({
        rpID,
        allowCredentials: [], 
        userVerification: 'preferred',
    });
    users['currentChallenge'] = options.challenge;
    res.json(options);
});

app.post('/verify-authentication', async (req, res) => {
    const savedKey = users['credential'];
    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge: users['currentChallenge'],
            expectedOrigin: origin,
            expectedRPID: rpID,
            credential: {
                id: savedKey.credentialID,
                publicKey: savedKey.credentialPublicKey,
                counter: savedKey.counter,
            },
        });

        if (verification.verified) {
            console.log('🎉 УСПІШНИЙ ВХІД!');
            res.json({ verified: true });
        }
    } catch (error) {
        console.error('❌ Помилка входу:', error.message);
        res.status(400).json({ error: error.message });
    }
});

app.listen(3000, () => console.log('🚀 Сервер: http://localhost:3000'));