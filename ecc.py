from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode('utf-8'),
        ec.ECDSA(ec.SECP256R1())
    )
    return signature

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            ec.ECDSA(ec.SECP256R1())
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# Example Usage
sender_private_key, sender_public_key = generate_ecc_key_pair()
receiver_private_key, receiver_public_key = generate_ecc_key_pair()

message = "Hello, V2V communication!"

# Sender signs the message
signature = sign_message(sender_private_key, message)

# Receiver verifies the signature
verification_result = verify_signature(sender_public_key, message, signature)

if verification_result:
    print("Signature verified. Message is authentic.")
else:
    print("Signature verification failed. Message may be tampered.")
