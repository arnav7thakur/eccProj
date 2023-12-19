from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

def generate_key_pair():
    private_key = ec.generate_private_key(
        ec.SECP256R1(),  # You can choose a different curve if needed
        default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    signature = private_key.exchange(
        ec.ECDH(),
        default_backend()
    )
    return signature

def verify_signature(public_key, message, signature):
    try:
        public_key.exchange(
            signature,
            ec.ECDH(),
            default_backend()
        )
        print("Signature is valid.")
    except Exception as e:
        print("Signature is invalid:", str(e))

# Example usage:
if __name__ == "__main__":
    # Sender side
    sender_private_key, sender_public_key = generate_key_pair()
    message_to_sign = b"Hello, this is a message to sign."

    signature = sign_message(sender_private_key, message_to_sign)

    # Transmit message and signature to the recipient

    # Recipient side
    recipient_private_key, recipient_public_key = generate_key_pair()

    # Assuming the recipient knows the sender's public key
    verify_signature(sender_public_key, message_to_sign, signature)
