from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Function to generate ECC key pair
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

@app.route('/')
def index():
    # Generate ECC key pair
    private_key, public_key = generate_ecc_key_pair()

    # Serialize keys to PEM format for display
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return render_template('index.html', private_key=private_key_pem, public_key=public_key_pem)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        # Get input data from the form
        public_key_pem = request.form['public_key']
        private_key_pem = request.form['private_key']
        message = request.form['message'].encode('utf-8')

        # Deserialize public and private keys
        public_key = serialization.load_pem_public_key(public_key_pem.encode(), default_backend())
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())

        # Encrypt the message with the public key
        encrypted_message = public_key.encrypt(
            message,
            ec.ECIES()
        )

        return render_template('index.html', encrypted_message=encrypted_message.hex(), success=True)

    except Exception as e:
        return render_template('index.html', error=str(e))

if __name__ == '__main__':
    app.run(debug=True)
