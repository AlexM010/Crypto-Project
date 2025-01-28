from pymongo import MongoClient
from datetime import datetime
import uuid
import os

# Mapping of weak ciphers to strong replacements
cipher_replacement = {
    "DES": "AES-256",
    "3DES_1KEY": "AES-256",
    "3DES_2KEY": "AES-256",
    "3DES_3KEY": "AES-256",
    "RC4": "AES-256",
    "MD5": "SHA-512",
    "SHA-1": "SHA-512",
    "ECB_Mode": "CBC_Mode",
    "CBC_Static_IV": "CBC_Mode", # MANUAL
    "AES-128": "AES-256",
    "AES-192": "AES-256",
    "Blowfish_Short_Key": "AES-256",
    "DH_KE_Weak_Parameters": "ECDH_P521", # JUST FIX MOD SIZE
    "DH_KE_Quantum_Threat": "ECDH_P521", # JUST DOUBLE THE SIZE OF MOD AGAIN
    "ECDH": "RSA-4096",
    "RSA_512_1024": "RSA_4096",
    "RSA_2048_3072": "RSA_4096",
    "SHA-256": "SHA-512"
}




# Function to display scans
def print_scans(scans_collection):
    print("\nFetching available scan IDs...")
    for scan in scans_collection.find({}, {"scan_id": 1, "_id": 0}):
        print(f"Scan ID: {scan['scan_id']}")
        
# Function to create a patched collection
def create_patched_collection(db):
    if "patched" not in db.list_collection_names():
        db.create_collection("patched")
        print("Created patched collection.")
    else:
        print("Patched collection already exists.")
        
# Function to process a scan    
def process_scan(scan):
    for vulnerability in scan["vulnerabilities"]:
        if vulnerability["vulnerability"] == "SHA-1" or vulnerability["vulnerability"] == "SHA-256" or vulnerability["vulnerability"] == "MD5":    
            weak_cipher = vulnerability["vulnerability"]
            lines = vulnerability["lines"]
            file_path = vulnerability["path"]
            language = vulnerability["language"]

            # Lookup the appropriate function from the dictionary
            fix_func = cipher_replacement_funcs.get(weak_cipher, lambda f, c: print(f"No fix available for {c} in {f}"))

            # Call the appropriate function
            fix_func(weak_cipher, file_path, lines, language)
            print("////////////////")
        
        
        

def replace_with_aes_256(weak_cipher, path, lines, language):
    print(weak_cipher)    
    print(path)
    print(f"Replacing with AES-256 in path {path}")
        
    if weak_cipher == "DES":
        if language == "C" :
            print("hello")
                   
        
def replace_with_sha512(weak_cipher, path, lines, language):
    print(f"Replacing with SHA-512 in {path}")
    content = ""
    if weak_cipher == "MD5":
        with open(path, 'r') as file:
            content = file.read()
            if language == "C":
                # Replace MD5 with SHA-512
                content = content.replace("MD5", "SHA512")
                content = content.replace("md5", "sha")
            elif language == "Python":
                # Replace MD5 with SHA-512
                content = content.replace("MD5", "SHA-512")
                content = content.replace("md5", "sha512")
            elif language == "Java":
                # Replace MD5 with SHA-512
                new_class_name = f"patched_{os.path.basename(path).replace('.java', '')}"
                content = content.replace(f"{os.path.basename(path).replace('.java', '')}", f"{new_class_name}")
                content = content.replace("\"MD5\"", "\"SHA-512\"")
                content = content.replace("md5", "sha512")
            else: 
                print("Invalid language")
                
    elif weak_cipher == "SHA-1":
        with open(path, 'r') as file:
            content = file.read()
            if language == "C":
                # Replace SHA-1 with SHA-512
                content = content.replace("SHA-1", "SHA512")  # Most specific first
                content = content.replace("SHA1", "SHA512")   # Then exact term replacements
                content = content.replace("SHA_", "SHA512_")   # Then exact term replacements
                content = content.replace("sha1", "sha512")   # Then exact term replacements      
                
            elif language == "Python":
                # Replace SHA-1 with SHA-512
                content = content.replace("SHA-1", "SHA-512")
                content = content.replace("sha1", "sha512")
            elif language == "Java":
                # Replace SHA-1 with SHA-512
                new_class_name = f"patched_{os.path.basename(path).replace('.java', '')}"
                content = content.replace(f"{os.path.basename(path).replace('.java', '')}", f"{new_class_name}")
                content = content.replace("\"SHA-1\"", "\"SHA-512\"")
                content = content.replace("sha1", "sha512")
            else: 
                print("Invalid language")

    elif weak_cipher == "SHA-256":
        with open(path, 'r') as file:
            content = file.read()
            if language == "C":
                # Replace SHA-256 with SHA-512
                content = content.replace("SHA-256", "SHA512")
                content = content.replace("sha256", "sha512")
            elif language == "Python":
                # Replace SHA-256 with SHA-512
                content = content.replace("SHA-256", "SHA-512")
                content = content.replace("sha256", "sha512")
            elif language == "Java":
                # Replace SHA-256 with SHA-512
                new_class_name = f"patched_{os.path.basename(path).replace('.java', '')}"
                content = content.replace(f"{os.path.basename(path).replace('.java', '')}", f"{new_class_name}")
                content = content.replace("\"SHA-256\"", "\"SHA-512\"")
                content = content.replace("sha256", "sha512")
            else:
                print("Invalid language")
            
    else:
        print("Invalid weak cipher")
    
    # Make folder for patched files
    if not os.path.exists('patched_scripts'):
        os.makedirs('patched_scripts')
    
    # Write the patched content to a new file with name patched_<original_file_name> in a subdirectory of patched files with name patched_<name_of_vulnerability>
    if not os.path.exists(f'patched_scripts/patched_{weak_cipher}'):
        os.makedirs(f'patched_scripts/patched_{weak_cipher}')
        
    with open(f'patched_scripts/patched_{weak_cipher}/patched_{os.path.basename(path)}', 'w') as file:
        file.write(content)
     
def replace_with_rsa4096(weak_cipher, path, lines, language):       
    print(f"Replacing with RSA-4096 in {path}")
    print(weak_cipher)
    for line in lines:
        # write lines
        print(line['line_number'])
        print(line['content'])

def manual_fix_required(weak_cipher, path, lines, language):
    print(f"Manual fix required for in {path}")
    print(weak_cipher)
    for line in lines:
        # write lines
        print(line['line_number'])
        print(line['content'])
    
# Dictionary of functions to replace weak ciphers with strong ciphers
cipher_replacement_funcs = {
    "DES": replace_with_aes_256,
    "3DES_1KEY": replace_with_aes_256,
    "3DES_2KEY": replace_with_aes_256,
    "3DES_3KEY": replace_with_aes_256,
    "RC4": replace_with_aes_256,
    "MD5": replace_with_sha512,
    "SHA-1": replace_with_sha512,
    "SHA-256": replace_with_sha512,
    "ECB_Mode": replace_with_aes_256,
    "AES-128": replace_with_aes_256,
    "AES-192": replace_with_aes_256,
    "Blowfish_Short_Key": replace_with_aes_256,
    "ECDH": replace_with_rsa4096,
    "RSA_512_1024": replace_with_rsa4096,
    "RSA_2048_3072": replace_with_rsa4096,
    # Manual fix required
    "CBC_Static_IV": manual_fix_required,
    "DH_KE_Weak_Parameters": manual_fix_required,
    "DH_KE_Quantum_Threat": manual_fix_required
}
    
# Main function to handle the scanning process
def main():
    # Connect to MongoDB
    client = MongoClient("mongodb://localhost:27017/")
    db = client["cryptographic_inventory"]
    scans_collection = db["scans"]

    create_patched_collection(db)

    # Prompt user to select a scan
    while True:
        print_scans(scans_collection)
        scan_id = input("Enter the scan id: ").strip()

        # Find the scan in the database
        scan = scans_collection.find_one({"scan_id": scan_id})

        if scan:
            break
        else:
            print("Invalid scan ID, please try again.")

    print(f"Processing scan ID: {scan_id}")

    # Create a directory to store patched files
    if not os.path.exists("patched_scripts"):
        os.makedirs("patched_scripts")
    else:
        print("Directory already exists. Overwriting files.")
        
    # Process the scan
    process_scan(scan)
    

    print(f"Scan {scan_id} processed. Patched files saved in 'patched_scripts' directory.")

    # Close the MongoDB connection
    client.close()

# Entry point
if __name__ == "__main__":
    main()
