const elliptic = require('elliptic');
const { SHA256 } = require('crypto-js');

// Create an elliptic curve object with the curve 'secp256k1'
const ec = new elliptic.ec('secp256k1');

// Function to generate a key pair
function generateKeyPair() {
    const keyPair = ec.genKeyPair();
    return {
        privateKey: keyPair.getPrivate('hex'),
        publicKey: keyPair.getPublic('hex'),
    };
}

// Generate key pair for Car1
const car1KeyPair = generateKeyPair();
console.log("Car1's Private Key:", car1KeyPair.privateKey);
console.log("Car1's Public Key:", car1KeyPair.publicKey);

// Generate key pair for Car2
const car2KeyPair = generateKeyPair();
console.log("Car2's Private Key:", car2KeyPair.privateKey);
console.log("Car2's Public Key:", car2KeyPair.publicKey);

// Example message to sign
const message = 'Hello, ECDSA!';

// Sign the message with Car1's private key
const car1Signature = ec.keyFromPrivate(car1KeyPair.privateKey).sign(SHA256(message).toString(), 'hex');

console.log("Car1's Signature:", car1Signature);

// Verify the signature using Car1's public key
const isCar1SignatureValid = ec.keyFromPublic(car1KeyPair.publicKey, 'hex').verify(SHA256(message).toString(), car1Signature);
console.log("Car1's Signature Verification Result:", isCar1SignatureValid);

// Verify the signature using Car2's public key (should be false)
const isCar2SignatureValid = ec.keyFromPublic(car2KeyPair.publicKey, 'hex').verify(SHA256(message).toString(), car1Signature);
console.log("Car2's Signature Verification Result (using Car1's signature):", isCar2SignatureValid);
