# moSeR

# Your Friendly Ransomware Simulator

## Overview

**moSeR** is a Python-based tool designed to simulate the behavior of various ransomware families. This simulator replicates the encryption mechanisms, key management, and exfiltration techniques of 20 different ransomware variants, providing a comprehensive environment for studying and understanding these types of cyber threats.

## Features

- **20 Ransomware Variants**: Accurately simulates the encryption and key exfiltration techniques of 20 different ransomware families.
- **Multiple Encryption Techniques**: Supports encryption algorithms such as AES, ChaCha20, and RSA, tailored to specific ransomware types.
- **Configurable Simulation**: Easily customize and choose between full or partial file encryption based on the ransomware variant.
- **Private Key Exfiltration**: Simulates exfiltration of the private key via email, including different exfiltration methods for different ransomware families.
- **Modular Design**: The simulator is structured to allow easy addition or modification of ransomware variants and their corresponding behaviors.

## Ransomware Variants Simulated

The simulator currently includes the following ransomware variants:

1. **Play**
   - Simulates the Play ransomware's full and partial encryption techniques.

2. **Black Basta**
   - Implements Black Basta's encryption methods and key exfiltration techniques.

3. **Bianlian**
   - Mimics Bianlian ransomware with its unique encryption and behavior patterns.

4. **Cerber**
   - Replicates Cerber ransomware's encryption process and file extension changes.

5. **Conti**
   - Simulates Conti ransomware's advanced encryption methods.

6. **PYSA**
   - Implements PYSA ransomware's data encryption and key management techniques.

7. **REvil**
   - Mimics REvil ransomware with its highly effective encryption process.

8. **MAZE**
   - Simulates MAZE ransomware’s dual encryption techniques.

9. **Lockbit**
   - Implements Lockbit ransomware’s fast and efficient encryption methods.

10. **WANNACRY**
    - Replicates WANNACRY ransomware’s encryption and propagation techniques.

11. **Karakurt**
    - Simulates Karakurt ransomware with its encryption and exfiltration methods.

12. **Royal**
    - Implements Royal ransomware’s advanced encryption and key handling.

13. **Avaddon**
    - Mimics Avaddon ransomware’s encryption strategies and behavior.

14. **Bad Rabbit**
    - Simulates Bad Rabbit ransomware’s unique encryption and distribution methods.

15. **CLOP**
    - Implements CLOP ransomware’s encryption techniques and file manipulation.

16. **HIVE**
    - Mimics HIVE ransomware with its sophisticated encryption processes.

17. **DOPPELPAYMER**
    - Simulates DOPPELPAYMER ransomware’s encryption and ransom note generation.

18. **EGREGOR**
    - Implements EGREGOR ransomware’s rapid encryption techniques.

19. **BLACKCAT**
    - Replicates BLACKCAT ransomware’s modern encryption and behavior.

20. **CRYPTOLOCKER**
    - Simulates CRYPTOLOCKER ransomware’s encryption and key management.

## Installation

### Prerequisites

- Python 3.8+
- Pip (Python package manager)
- Dependencies listed in `requirements.txt` in Ransim Folder



### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/Ransomware_Simulator.git
   cd Ransomware_Simulator/Ransim

   
2. Installing Dependencies
     ```bash
     pip install -r requirements.txt
     
3. Run The Simulator:
   ```bash
   python script.py

  
### Usage

#### Main Script
The main script (script.py) allows you to simulate different ransomware variants. You will be prompted to select a ransomware variant and the encryption type (if applicable). The script will then simulate the encryption process.

#### Description Module
The simulator includes a module (descript.py) that handles the Description of Encrypted files.

#### Key Exfiltration Module
This module can send the private key to a remote server or an email address based on your selection.

#### Configuration
The ransomware behaviors are configurable via a ransomware_config.json file, where you can specify details like the encryption type and file extensions used by each ransomware variant.

#### Important Notes
Educational Purposes Only: This simulator is intended solely for educational and research purposes. The use of this tool in any unauthorized or malicious manner is strictly prohibited.
No Real Encryption: While the simulator mimics the behavior of ransomware, it does not perform actual encryption on sensitive files.

#### Contribution
Contributions are welcome! If you have suggestions for new features or ransomware variants to include, feel free to fork the repository and submit a pull request.# Ransomware_Simulator
