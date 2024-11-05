const crypto = require("crypto");
const fs = require("fs");

// Load Bob's private key and Alice's public key
const bobPrivateKey = fs.readFileSync("bob_private.pem", "utf8");
const alicePublicKey = fs.readFileSync("alice_public.pem", "utf8");

// Replace with actual values outputted by alice.js
const receivedEncryptedMessageHex = "99beaec5f084f7873527ebf190a6d5ce399d3dd23eac16098bd17e683e0dddfd399664114132c091361909fa58844e12ea8077464bcd391b1c036b25b98368a6461c415424a56a12786fda8dbb7f642ed432afb33f4808f3f2b8dc7b18c4e619f43cbb5f64cee9757f9d9ba37d25869eac4fe694da0e1aa820f5e9748779e04becd4bb20cd83e77dd0772bb118a05f520a8fb4623e4d09e48dc604879f5a282d32aa5da57d12a7a7990dc878b404511c80de21531055d1db93ba6e68977a039dc796927319e43ccc7c692ff3c7cf7198ac9be17715e0ed0c9ab91248c08e87ed3d944aa485ae011d99d129df3d479f94c6770896ab43ecb01b028173861d17e0"; // Replace with actual encrypted message
const receivedSignatureHex = "3877ff93b98c3d0f5b077c9e75775058bd42c69af02709b74447814abddce5ed2c547d15cacb3efa16b50401f49c6a18a6b25dc7b2ca71eff42efdcb86e3b8fb4cfb78b1b05032d8d1a90245c4910757779a81026fe640e45ce9a1cc8632326ca2c4568c4132a3a760f58774375d5a148b8749cb87e18e823f82c180a602f7fa9e329ed49705364bedf00082c9f7fba4d7e50595f75982cb323e35c6ec3ed59e6940c1546338857dd0343b6d8358f8477ddf30862562923f35ef61cdfadb86ab14fdb878253119736f65817bc5fc544482e89903d8610c70f694df7bc17bcfde43506f5882a321de4d46e0449282c8993d5a3f3939fc2f75afb8f3cb04b241d0"; // Replace with actual signature

const encryptedMessage = Buffer.from(receivedEncryptedMessageHex, "hex");
const signature = Buffer.from(receivedSignatureHex, "hex");

// Step 1: Decrypt the message using Bob's private key
const decryptedMessage = crypto.privateDecrypt(
    {
        key: bobPrivateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
    },
    encryptedMessage
);
console.log("Message:", decryptedMessage.toString("utf8"));

// Step 2: Verify the signature using Alice's public key
const isVerified = crypto.verify(
    "sha256",
    Buffer.from(decryptedMessage.toString("utf8")),
    {
        key: alicePublicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    },
    signature
);

console.log("Signature Verification:", isVerified);
