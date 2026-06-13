const express = require('express');
const crypto = require('crypto');
const app = express();
const port = 8080;
const fs = require("fs");

const serverPrivateKey = fs.readFileSync("server-private.pem", "utf8");
const clientPublicKey = fs.readFileSync("client-public.pem", "utf8");
const algorithm = 'aes-256-gcm'; // AES encryption algorithm
const encryptionKey = "secret-password-123"
const ASYMMETRIC_PASSWORD_SIZE = 32;

function logRequest(type, encryptedData, decryptedData) {
    console.log(`
============================================================
🔐 ${type}
============================================================
Encrypted Payload:
${encryptedData}

Decrypted Payload:
${decryptedData}
============================================================
`);
}

app.use(express.json());

app.post("/unencrypted", (req, res) => {
    console.log(`
============================================================
📨 Unencrypted Request
============================================================
${JSON.stringify(req.body, null, 2)}
============================================================
`);

    res.json({
        code: 200,
        message: "Data received successfully",
        receivedData: req.body,
        response: "Hello from the server!",
    });
});

app.use(express.raw({ type: "application/octet-stream" }));

app.post(["/encrypted", "/encryptedNative"], (req, res) => {
    const encryptedData = req.body.toString();
    var decryptedData = "";

    try {
        decryptedData = decrypt(encryptedData, encryptionKey);
    }
    catch (error) {
        decryptedData = `Decryption failed: ${error.message}`;
    }

    logRequest("Symmetric Encrypted Request", encryptedData, decryptedData);

    try {
        const jsonData = JSON.parse(decryptedData);

        const responseJson = {
            code: 200,
            message: "Data received successfully",
            receivedData: jsonData,
            response: "Hello from the server!",
        };

        res.send(
            encrypt(
                JSON.stringify(responseJson),
                encryptionKey
            )
        );
    } catch (error) {
        res.send(
            encrypt(
                JSON.stringify({
                    code: 400,
                    message: "Invalid data received",
                    error: error.message
                }),
                encryptionKey
            )
        );
    }
});

app.post("/encryptedAsymmetric", (req, res) => {
    const encryptedData = req.body.toString();
    const decryptedData = decryptAsymmetric(
        encryptedData,
        serverPrivateKey
    );

    logRequest("Asymmetric Encrypted Request", encryptedData, decryptedData);

    try {
        const jsonData = JSON.parse(decryptedData);

        const responseJson = {
            code: 200,
            message: "Data received successfully",
            receivedData: jsonData,
            response: "Hello from the server!",
        };

        res.send(
            encryptAsymmetric(
                JSON.stringify(responseJson),
                clientPublicKey
            )
        );
    } catch (error) {
        res.send(
            encryptAsymmetric(
                JSON.stringify({
                    code: 400,
                    message: "Invalid data received",
                    error: error.message
                }),
                clientPublicKey
            )
        );
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

function deriveKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

function encrypt(text, password) {
    const salt = crypto.randomBytes(16);
    const key = deriveKey(password, salt);

    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(algorithm, key, iv);

    const ciphertext = Buffer.concat([
        cipher.update(text, "utf8"),
        cipher.final()
    ]);

    const authTag = cipher.getAuthTag();

    // Layout: IV || ciphertext || authTag
    const combined = Buffer.concat([
        iv,
        ciphertext,
        authTag
    ]);

    return `${combined.toString("base64")}:${salt.toString("base64")}`;
}

function decrypt(encryptedData, password) {
    const parts = encryptedData.split(":");

    if (parts.length !== 2) {
        throw new Error("Invalid encrypted data format");
    }

    const combined = Buffer.from(parts[0], "base64");
    const salt = Buffer.from(parts[1], "base64");

    const key = deriveKey(password, salt);

    // Extract components
    const iv = combined.subarray(0, 12);
    const authTag = combined.subarray(combined.length - 16);
    const ciphertext = combined.subarray(12, combined.length - 16);

    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);

    return plaintext.toString("utf8");
}

function encryptAsymmetric(plaintext, publicKeyPem) {
    // Generate a random password
    const password = crypto.randomBytes(ASYMMETRIC_PASSWORD_SIZE);

    // Encrypt the payload using the existing symmetric function
    const encryptedData = encrypt(plaintext, password);

    // Encrypt the random password with RSA
    const encryptedPassword = crypto.publicEncrypt(
        {
            key: publicKeyPem,
            padding: crypto.constants.RSA_PKCS1_PADDING
            // If you switched the C++ code to OAEP, use:
            // padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            // oaepHash: "sha256"
        },
        password
    );

    return (
        encryptedPassword.toString("base64") +
        ":" +
        encryptedData
    );
}

function decryptAsymmetric(encrypted, privateKeyPem) {
    const pos = encrypted.indexOf(":");

    if (pos === -1) {
        throw new Error("Invalid encrypted payload");
    }

    const encryptedPasswordB64 = encrypted.substring(0, pos);
    const encryptedData = encrypted.substring(pos + 1);

    const encryptedPassword = Buffer.from(
        encryptedPasswordB64,
        "base64"
    );

    const password = crypto.privateDecrypt(
        {
            key: privateKeyPem,
            padding: crypto.constants.RSA_PKCS1_PADDING
            // If using OAEP:
            // padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            // oaepHash: "sha256"
        },
        encryptedPassword
    );

    return decrypt(encryptedData, password);
}