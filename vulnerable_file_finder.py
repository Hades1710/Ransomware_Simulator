import os

# Define file types that are commonly targeted by ransomware
vulnerable_file_types = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', 
                         '.pdf', '.txt', '.jpg', '.jpeg', '.png']

# Define keywords that may indicate vulnerable files
vulnerable_keywords = [
    'password', 'confidential', 'secret', 'private', 'login', 
    'credentials', 'key', 'backup', 'finance', 'account', 
    'social', 'security', 'tax', 'medical', 'insurance', 
    'identity', 'bank', 'credit', 'transaction', 'invoice', 
    'report', 'statement', 'balance', 'contract', 'agreement', 
    'legal', 'payment', 'license', 'budget', 'project', 
    'planning', 'strategy', 'roadmap', 'sensitive', 'restricted', 
    'audit', 'compliance', 'HR', 'employee', 'resume', 
    'CV', 'personal', 'data', 'profile', 'address', 
    'phone', 'contact', 'email', 'SSN', 'passport', 
    'driver', 'ID', 'DOB', 'birthdate', 'PIN', 
    'access', 'auth', 'encrypted', 'certification', 'note', 
    'memo', 'internal', 'meeting', 'discussion', 'minutes', 
    'presentation', 'slides', 'proposal', 'submission', 'feedback'
]

# Function to check if a file has weak permissions
def has_weak_permissions(file_path):
    # Simulate weak permissions by checking if the file is writable by others
    return os.access(file_path, os.W_OK)

# Function to check if a file contains vulnerable keywords in its name
def has_vulnerable_keywords(file_name):
    for keyword in vulnerable_keywords:
        if keyword.lower() in file_name.lower():
            return True
    return False

# Function to simulate ransomware scanning for vulnerable files
def scan_for_vulnerable_files(starting_directory):
    vulnerable_files = []

    # Walk through the directory structure
    for root, dirs, files in os.walk(starting_directory):
        for file in files:
            file_path = os.path.join(root, file)
            
            # Check if the file type is in the vulnerable list
            if any(file.endswith(ext) for ext in vulnerable_file_types):
                vulnerable_files.append(file_path)
                continue
            
            # Check if the file name contains vulnerable keywords
            if has_vulnerable_keywords(file):
                vulnerable_files.append(file_path)
                continue
            
            # Check if the file has weak permissions
            if has_weak_permissions(file_path):
                vulnerable_files.append(file_path)
                continue

    return vulnerable_files

# Example usage: Start scanning from the current directory
starting_directory = '.'  # Change this to any directory you want to start scanning from
found_vulnerable_files = scan_for_vulnerable_files(starting_directory)

# Output the list of found files
print("Vulnerable files found:")
for file in found_vulnerable_files:
    print(file)
