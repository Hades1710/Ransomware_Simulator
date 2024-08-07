import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# Directory to decrypt
directory = r"D:\Cyber\Malware\Play"

private_key_path = r"D:\Cyber\Malware\Play\private_key.pem" # need to add these as an input somehow

# Exclusions: Do not decrypt these files
exclusions = [
    r"D:\Cyber\Malware\Play\public_key.pem",
    r"D:\Cyber\Malware\Play\private_key.pem",
    r"D:\Cyber\Malware\Play\enc.py",
    r"D:\Cyber\Malware\Play\dec.py"  # Assuming a decryption script exists
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

# Decrypt AES key using RSA
def decrypt_aes_key_rsa(encrypted_aes_key, private_key_path):
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    
    return aes_key

# Decrypt data using AES
def decrypt_file_aes(file_path, aes_key):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # AES key length for RSA encryption is typically 256 bytes
    rsa_key_size = 256  # RSA key size in bytes (2048 bits / 8)
    encrypted_aes_key = data[:rsa_key_size]
    encrypted_data = data[rsa_key_size:]
    
    aes_key = decrypt_aes_key_rsa(encrypted_aes_key, private_key_path)
    
    decrypted_data = bytearray()
    
    # Check if it is a full or partial encryption
    try:
        # Try full decryption
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_chunk = cipher_aes.decrypt_and_verify(ciphertext, tag)
        decrypted_data.extend(decrypted_chunk)
        return bytes(decrypted_data)
    except (ValueError, KeyError):
        # Handle partial decryption
        chunk_size = 64 * 1024  # 64 KB
        start = 0
        
        while start < len(encrypted_data):
            end = min(start + chunk_size, len(encrypted_data))
            chunk = encrypted_data[start:end]
            
            if len(chunk) < 16:  # If chunk is too small, skip
                break
            
            nonce = chunk[:16]
            tag = chunk[16:32]
            encrypted_chunk = chunk[32:]
            
            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            try:
                decrypted_chunk = cipher_aes.decrypt_and_verify(encrypted_chunk, tag)
                decrypted_data.extend(decrypted_chunk)
            except (ValueError, KeyError):
                print(f"Error decrypting chunk starting at byte {start}")
                break
            
            start = end
        
        return bytes(decrypted_data)

# Decrypt all files in the directory
def decrypt_all_files(dir_path, private_key_path):
    files = list_files(dir_path, exclusions)
    
    for file_path in files:
        if not file_path.endswith('.enc'):
            continue
        
        original_file_path = file_path[:-4]
        
        decrypted_data = decrypt_file_aes(file_path, private_key_path)
        
        with open(original_file_path, 'wb') as f:
            f.write(decrypted_data)
        
        # Optionally, delete the encrypted file
        os.remove(file_path)

# Input handling
def main():
    try:
        print("Selected Decryption")
        decrypt_all_files(directory, private_key_path)
        print("Decryption completed.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
