const crypto = require("crypto");
const fs = require("fs");

// Load Alice's private key and Bob's public key
const alicePrivateKey = fs.readFileSync("alice_private.pem", "utf8");
const bobPublicKey = fs.readFileSync("bob_public.pem", "utf8");

// The message Alice wants to send to Bob
const message = "I want some apples";

// Step 1: Sign the message using Alice's private key
const signature = crypto.sign("sha256", Buffer.from(message), {
    key: alicePrivateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
});

console.log("Signature:", signature.toString("hex"));

// Step 2: Encrypt the message using Bob's public key
const encryptedMessage = crypto.publicEncrypt(
    {
        key: bobPublicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
    },
    Buffer.from(message)
);
console.log("Message:", encryptedMessage.toString("hex"));

// Alice will share `encryptedMessage` and `signature` with Bob.
