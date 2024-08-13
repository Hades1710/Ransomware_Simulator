import os
import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Directory to decrypt
directory = r"D:\Cyber\Malware\Ransomware_Simulator\Ransim"

# Exclusions: Do not decrypt these files
exclusions = [
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\public_key.pem",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\private_key.pem",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\script.py",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\descript.py",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\requirements.txt",
    r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\ransomware_config.json"
]
# Remove : We need to remove this and see to it that somehow this needs to be passed once ransom is received
private_key_path = r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\private_key.pem"

# Function to list all encrypted files in a directory
def list_encrypted_files(dir_path, exclusions, extension):
    file_list = []
    for root, _, files in os.walk(dir_path):
        for file in files:
            if file.endswith(extension) and os.path.join(root, file) not in exclusions:
                file_list.append(os.path.join(root, file))
    return file_list

# Decrypt AES key using RSA
def decrypt_aes_key_rsa(encrypted_aes_key, private_key_path):
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    
    return aes_key

# Decrypt file with AES
def decrypt_file_aes(file_path, aes_key, mode='full'):
    with open(file_path, 'rb') as f:
        data = f.read()

    if mode == 'full':
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]

        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    elif mode == 'partial':
        num_chunks = 2
        chunk_size = 64 * 1024  # 64 KB

        plaintext = bytearray()
        offset = 0

        for _ in range(num_chunks):
            nonce = data[offset:offset+16]
            tag = data[offset+16:offset+32]
            chunk = data[offset+32:offset+32+chunk_size]

            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            decrypted_chunk = cipher_aes.decrypt_and_verify(chunk, tag)
            plaintext.extend(decrypted_chunk)
            offset += 16 + 16 + chunk_size

        # Append unencrypted remainder
        plaintext.extend(data[offset:])
        plaintext = bytes(plaintext)
    
    return plaintext

# Decrypt file with ChaCha20
def decrypt_file_chacha(file_path, private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    with open(file_path, "rb") as f:
        nonce = f.read(12)
        encrypted_key = f.read(private_key.key_size // 8)
        encrypted_data = f.read()

    key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, encrypted_data, None)
    
    return plaintext

# Decrypt all files based on configuration
def decrypt_all_files(ransomware, enc_type, settings, private_key_path):
    files = list_encrypted_files(directory, exclusions, settings['extension'])

    for file_path in files:
        with open(file_path, 'rb') as f:
            encrypted_aes_key = f.read(256)
            encrypted_data = f.read()

        aes_key = decrypt_aes_key_rsa(encrypted_aes_key, private_key_path)

        if ransomware == 'Play':
            plaintext = decrypt_file_aes(file_path, aes_key, enc_type)
        elif ransomware == 'Wannacry':
            plaintext = decrypt_file_chacha(file_path, private_key_path)
        else:
            continue

        decrypted_file_path = file_path.replace(settings['extension'], '')
        with open(decrypted_file_path, 'wb') as f:
            f.write(plaintext)
        os.remove(file_path)  # Optionally delete the encrypted file

# Main function to load JSON and execute decryption
def main():
    try:
        with open("ransomware_config.json", "r") as config_file:
            config = json.load(config_file)
        
        print("Available Ransomware Configurations:")
        for i, ransomware in enumerate(config.keys(), 1):
            print(f"{i}. {ransomware}")

        choice = input("Select the ransomware to decrypt (enter the number): ")
        
        if not choice.isdigit() or not (1 <= int(choice) <= len(config)):
            print("Invalid input. Please enter a valid number corresponding to the ransomware.")
            return
        
        selected_ransomware = list(config.keys())[int(choice) - 1]
        selected_settings = config[selected_ransomware]

        # If multiple encryption types are available, ask the user to choose
        if len(selected_settings['encryption_type']) > 1:
            print(f"Available encryption types for {selected_ransomware}:")
            for i, enc_type in enumerate(selected_settings['encryption_type'], 1):
                print(f"{i}. {enc_type.capitalize()}")
            enc_choice = input("Select the encryption type (enter the number): ")
            
            if not enc_choice.isdigit() or not (1 <= int(enc_choice) <= len(selected_settings['encryption_type'])):
                print("Invalid input. Please enter a valid number corresponding to the encryption type.")
                return
            
            selected_enc_type = selected_settings['encryption_type'][int(enc_choice) - 1]
        else:
            selected_enc_type = selected_settings['encryption_type'][0]
            print(f"Using default encryption type: {selected_enc_type.capitalize()}")

        decrypt_all_files(selected_ransomware, selected_enc_type, selected_settings, private_key_path)
        print(f"Decryption completed using {selected_ransomware} with {selected_enc_type.capitalize()} encryption.")
    except ValueError as ve:
        print("ValueError:", ve)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
