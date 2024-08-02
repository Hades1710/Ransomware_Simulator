import os
from cryptography.fernet import Fernet

# Load the key
def load_key():
    return open("key.key", "rb").read()

# Decrypt a file
def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_path, "wb") as file:
        file.write(decrypted_data)

# Decrypt all files with a specific extension on the desktop
def decrypt_desktop_files(extension):
    desktop_path = os.path.join(os.path.join(os.environ["USERPROFILE"]), "Desktop")
    key = load_key()
    for root, dirs, files in os.walk(desktop_path):
        for file in files:
            if file.endswith(extension):
                file_path = os.path.join(root, file)
                decrypt_file(file_path, key)
                print(f"Decrypted: {file_path}")

if __name__ == "__main__":
    # Change the extension as needed
    file_extension = ".txt"

    # Decrypt files
    decrypt_desktop_files(file_extension)
