from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def decrypt_file(encrypted_file_path, private_key_path):
    # Read the private key
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # Read the encrypted file
    with open(encrypted_file_path, "rb") as f:
        nonce = f.read(12)
        encrypted_key = f.read(private_key.key_size // 8)
        encrypted_data = f.read()

    # Decrypt the symmetric key with the RSA private key
    key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the file data
    cipher = ChaCha20Poly1305(key)
    decrypted_data = cipher.decrypt(nonce, encrypted_data, None)

    # Save the decrypted file
    with open(encrypted_file_path.replace(".locked", ""), "wb") as f:
        f.write(decrypted_data)

if __name__ == "__main__":
    encrypted_file_path = "/home/kishan/Desktop/hello.txt.locked"
    private_key_path = "private_key.pem"
    decrypt_file(encrypted_file_path, private_key_path)

