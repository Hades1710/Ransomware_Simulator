from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import os

def encrypt_file(file_path, public_key_path):
    # Read the public key
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Generate a random key for ChaCha20
    key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)

    # Read the file data
    with open(file_path, "rb") as f:
        data = f.read()

    # Encrypt the file data
    encrypted_data = cipher.encrypt(nonce, data, None)

    # Encrypt the symmetric key with the RSA public key
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the encrypted file and key
    with open(file_path + ".locked", "wb") as f:
        f.write(nonce + encrypted_key + encrypted_data)

    # Optionally, delete the original file
    # os.remove(file_path)

if __name__ == "__main__":
    file_path = "/home/kishan/Desktop/hello.txt"
    public_key_path = "public_key.pem"
    encrypt_file(file_path, public_key_path)

