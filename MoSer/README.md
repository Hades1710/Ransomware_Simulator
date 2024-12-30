# Moser
Ransomware Simulator
This script implements the following functionality:
# 1. Loads the ransomware configurations from ransom.json 
Presents a menu for the user to select which ransomware to simulate
# Based on the selection:
If zip_type is specified (not "None"), it will create a password-protected archive of the matching files
If zip_type is "None", it will encrypt the files using the specified encryption method
# To use this script, you'll need to install the required dependencies:
  pip install cryptography py7zr rarfile

# The script will:
1.Look for files in the specified target directory that match the extensions for the chosen ransomware
2.Either encrypt them or add them to a password-protected archive
3.For encryption, it will add the specified extension to the encrypted files
4.For zipping, it will create a single archive with all matching files
Note: For RAR support, you'll need to have the WinRAR command-line tools installed on your system.
