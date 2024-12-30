# Moser
Ransomware Simulator
This script implements the following functionality:
1. Loads the ransomware configurations from ransom.json
Presents a menu for the user to select which ransomware to simulate
Based on the selection:
If zip_type is specified (not "None"), it will create a password-protected archive of the matching files
If zip_type is "None", it will encrypt the files using the specified encryption method
