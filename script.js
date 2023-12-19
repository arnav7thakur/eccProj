let car1PrivateKey;
let car2KeyPair; // Global variable to store Car2's key pair

function isValidKeyFormat(key) {
    return typeof key === 'string' && key.trim().length > 0;
}

function signAndEncrypt(senderOrReceiver) {
    const ec = new elliptic.ec('secp256k1');

    const messageInput = document.getElementById('messageInput').value;
    const publicKeyReceiverInput = document.getElementById('publicKeyReceiverInput');
    const privateKeyInput = document.getElementById('privateKeyInput');
    const publicKeySender = document.getElementById('publicKeySender');
    const publicKeyReceiver = publicKeyReceiverInput.value;
    const privateKey = privateKeyInput.value;
    
    publicKeySender.textContent = car1KeyPair.publicKey;

    if (!messageInput || !publicKeyReceiver || !privateKey) {
        alert("Please enter message, Car2's public key, and Car1's private key.");
        return;
    }

    if (!isValidKeyFormat(publicKeyReceiver) || !isValidKeyFormat(privateKey)) {
        alert(`Invalid key format! Please check and try again.`);
        return;
    }

    if (senderOrReceiver === 'sender') {
        car1PrivateKey = privateKey; // Store Car1's private key

        const keyPair = ec.keyFromPrivate(car1PrivateKey);

        // Verify that the provided private key corresponds to the public key of Car1
        if (keyPair.getPublic('hex') !== car1KeyPair.publicKey) {
            alert("Car1's private key does not match the public key.");
            return;
        }

        // Sign the message
        const signature = keyPair.sign(messageInput).toDER('hex');
        console.log(signature)
        // Encrypt the message
        const encryptedMessage = performEncryption(messageInput, signature, publicKeyReceiver);

        const encryptedDisplay = document.getElementById('encryptedDisplay');
        encryptedDisplay.innerHTML = `<p>Ciphertext: ${encryptedmessageInput}</p>`;

        // Continue with the rest of the function...
    } else if (senderOrReceiver === 'receiver') {
        const receivedMessageInput = document.getElementById('receivedMessageInput');
        const privateKeyReceiverInput = document.getElementById('privateKeyReceiverInput');

        const ciphertext = receivedMessageInput.value;
        const privateKeyReceiver = privateKeyReceiverInput.value;

        if (!ciphertext || !privateKeyReceiver) {
            alert("Please enter ciphertext and Car2's private key.");
            return;
        }

        // Perform decryption and signature verification using Car2's key pair
        performDecryptionAndVerification(ciphertext, car1KeyPair.publicKey, privateKeyReceiver);
    }
}

function generateKeyPair() {
    const ec = new elliptic.ec('secp256k1');
    const keyPair = ec.genKeyPair();
    return {
        privateKey: keyPair.getPrivate('hex'),
        publicKey: keyPair.getPublic('hex')
    };
}

// Call this function to generate Car1's key pair
const car1KeyPair = generateKeyPair();
console.log("Car1's Private Key:", car1KeyPair.privateKey);
console.log("Car1's Public Key:", car1KeyPair.publicKey);

// Call this function to generate Car2's key pair
car2KeyPair = generateKeyPair();
console.log("Car2's Private Key:", car2KeyPair.privateKey);
console.log("Car2's Public Key:", car2KeyPair.publicKey);

function performEncryption(messageInput, signature, publicKeyReceiver) {
    const receiverPublicKey = Buffer.from(publicKeyReceiver, 'hex');

    // Encrypt the message using the recipient's public key
    const encryptedMessage = ECIES.encrypt(receiverPublicKey, Buffer.from(messageInput + signature));

    return encryptedMessage.toString('hex');
}

document.addEventListener('DOMContentLoaded', function() {
    const publicKeySender = document.getElementById('publicKeySender');
    if (publicKeySender) {
        publicKeySender.textContent = car1KeyPair.publicKey;
    } else {
        console.error("Element with ID 'publicKeySender' not found.");
    }

    // Display Car2's public key on Car2's frontend
    const publicKeyReceiver = document.getElementById('publicKeyReceiver');
    if (publicKeyReceiver) {
        publicKeyReceiver.textContent = car2KeyPair.publicKey;
    } else {
        console.error("Element with ID 'publicKeyReceiver' not found.");
    }
});

// function performDecryptionAndVerification(ciphertext, car1PublicKey, car2PrivateKey) {
//     if (!isValidKeyFormat(car1PublicKey) || !isValidKeyFormat(car2PrivateKey)) {
//         alert(`Invalid key format! Please check and try again.`);
//         return;
//       }

//     const ec = new elliptic.ec('secp256k1');

//     try {
//         // Use Car2's private key for decryption
//         const keyPair = ec.keyFromPrivate(car2PrivateKey);

//         // Decrypt the message
//         const decryptedMessage = performDecryption(ciphertext, keyPair.getPrivate());

//         // Extract the signature from the decrypted message
//         const signatureStart = decryptedMessage.indexOf('(') + 1;
//         const signatureEnd = decryptedMessage.indexOf(')');
//         const signature = decryptedMessage.substring(signatureStart, signatureEnd);
//         // Extract the original message
//         const originalMessage = decryptedMessage.substring(signatureEnd + 1);

//         // Verify the signature using Car1's public key
//         const car1Key = ec.keyFromPublic(car1PublicKey, 'hex');
//         const isSignatureValid = car1Key.verify(originalMessage, signature);

//         if (isSignatureValid) {
//             // Decryption and verification successful
//             const decryptedDisplay = document.getElementById('decryptedDisplay');
//             decryptedDisplay.innerHTML = `<p>Decrypted Message: ${originalMessage}</p>`;
//             alert("Signature verified. Decryption successful!");
//         } else {
//             throw new Error("Signature verification failed!");
//         }
//     } catch (error) {
//         alert(`Decryption error: ${error.message}`);
//     }
// }

// function performDecryption(ciphertext, privateKey) {
//     const ec = new elliptic.ec('secp256k1');

//     // Convert the ciphertext to an ArrayBuffer
//     const encryptedBuffer = hexStringToArrayBuffer(ciphertext);

//     // Use Car2's private key for decryption
//     const keyPair = ec.keyFromPrivate(privateKey, 'hex');

//     // Decrypt the message
//     const decryptedBuffer = keyPair.decrypt(encryptedBuffer);

//     // Convert the decrypted ArrayBuffer back to a string
//     const decryptedMessage = arrayBufferToUtf8(decryptedBuffer);

//     return decryptedMessage;
// }

// Helper function to convert hex string to ArrayBuffer
function hexStringToArrayBuffer(hexString) {
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    return new Uint8Array(bytes).buffer;
}

// Helper function to convert ArrayBuffer to UTF-8 string
function arrayBufferToUtf8(buffer) {
    const decoder = new TextDecoder('utf-8');
    return decoder.decode(buffer);
}


// function decryptAndVerify() {
//     const receivedMessageInput = document.getElementById('receivedMessageInput');
//     const publicKeyCar1Input = document.getElementById('publicKeyCar1Input');
//     const privateKeyReceiverInput = document.getElementById('privateKeyReceiverInput');

//     const ciphertext = receivedMessageInput.value;
//     const car1PublicKey = publicKeyCar1Input.value;
//     const car2PrivateKey = privateKeyReceiverInput.value;

//     if (!ciphertext || !car1PublicKey || !car2PrivateKey) {
//         alert("Please enter ciphertext, Car1's public key, and Car2's private key.");
//         return;
//     }
//     // Perform decryption and signature verification
//     performDecryptionAndVerification(ciphertext, car1PublicKey, car2PrivateKey);
// }

// document.addEventListener('DOMContentLoaded', function() {
//     const decryptButton = document.getElementById('decryptButton');
//     if (decryptButton) {
//         decryptButton.addEventListener('click', decryptAndVerify);
//     } else {
//         console.error("Element with ID 'decryptButton' not found.");
//     }
// });

function isValidKeyFormat(keyString) {
    const regex = /^[0-9a-fA-F]{64}$/; // Regular expression for hex string of 64 characters
    return regex.test(keyString);
  }
const ec = new elliptic.ec('secp256k1');

// // Added logging for encryption process
// console.log(`Encrypting message with Car1's private key and Car2's public key...`);
// const encryptedMessage = performEncryption(messageInput, signature, publicKeyReceiver);
// console.log(`Encrypted message: ${encryptedMessage}`);

// // Added logging for decryption process
// console.log(`Decrypting message with Car2's private key and Car1's public key...`);
// const decryptedMessage = performDecryption(ciphertext, car2PrivateKey);
// console.log(`Decrypted message: ${decryptedMessage}`);



// const originalMessage = decryptedMessage.substring(0, decryptedMessage.indexOf('('));
// const extractedSignature = decryptedMessage.substring(decryptedMessage.indexOf('(') + 1, decryptedMessage.indexOf(')'));

// const decryptedDisplay = document.getElementById('decryptedDisplay');
// decryptedDisplay.innerHTML = `
//   <p>Decrypted Message: ${originalMessage}</p>
//   <p>Signature: ${extractedSignature}</p>
// `;
