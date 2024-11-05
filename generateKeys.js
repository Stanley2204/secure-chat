const crypto = require("crypto");
const fs = require("fs");

function generateKeys(username) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: "spki",
            format: "pem"
        },
        privateKeyEncoding: {
            type: "pkcs8",
            format: "pem"
        }
    });

    // Save the keys to files
    fs.writeFileSync(`${username}_public.pem`, publicKey);
    fs.writeFileSync(`${username}_private.pem`, privateKey);
    console.log(`Generated keys for ${username}.`);
}

// Generate keys for Alice and Bob
generateKeys("alice");
generateKeys("bob");
