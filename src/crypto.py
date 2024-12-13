import os
import re
import tkinter as tk
from tkinter import filedialog, scrolledtext
from pymongo import MongoClient
from datetime import datetime

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["cryptographic_inventory"]
scans_collection = db["scans"]

# Vulnerability patterns for AES, 3DES, RC4, DES, and RSA
vulnerability_patterns = {
    "DES": {
        "patterns": {
            "Python": [
                r"DES\.new",              # Matches PyCryptodome usage
                r"from\s+Crypto\.Cipher\s+import\s+DES"  # Importing DES
            ],
            "C": [
                r"DES_ecb_encrypt",       # Matches OpenSSL DES usage
                r"DES_set_key_checked"    # Matches OpenSSL key setup
            ],
            "Java": [
                r"Cipher\.getInstance\(\"DES",   # Matches Java DES cipher initialization
                r"SecretKeySpec\(.*,\s*\"DES\""  # Matches DES key setup
            ]
        },
        "severity": "Very High",
        "explanation": "DES is insecure due to its 56-bit key size, making it vulnerable to brute-force attacks."
    },
    "3DES_1KEY": {
        "patterns": {
            "Python": [
                r"DES3\.new\(.*,\s*\"DESede\"\)",  # Detects 3DES with 1 key
            ],
            "C": [
                r"DES_set_key_unchecked\(.*,\s*&key_schedule\)",  # Detects 3DES with 1 key
            ],
            "Java": [
                r"SecretKeySpec\(.*,\s*\"DESede\"\)",  # Detects 3DES with 1 key
            ]
        },
        "severity": "Very High",
        "explanation": "3DES with 1 key offers no additional security over DES and is insecure."
    },
    "3DES_2KEY": {
        "patterns": {
            "Python": [
                r"DES3\.new\(.*,\s*\"DESede\"\)",  # Detects 3DES with 2 keys
            ],
            "C": [
                r"DES_set_key_unchecked\(.*,\s*&key_schedule\)",  # Detects 3DES with 2 keys
            ],
            "Java": [
                r"SecretKeySpec\(.*16,\s*\"DESede\"\)",  # Detects 3DES with 2 keys (128-bit key)
            ]
        },
        "severity": "High",
        "explanation": "3DES with 2 keys provides ~80 bits of security, which is inadequate by modern standards."
    },
    "3DES_3KEY": {
        "patterns": {
            "Python": [
                r"DES3\.new\(.*,\s*\"DESede\"\)",  # Detects 3DES with 3 keys
            ],
            "C": [
                r"DES_set_key_unchecked\(.*,\s*&key_schedule\)",  # Detects 3DES with 3 keys
            ],
            "Java": [
                r"SecretKeySpec\(.*24,\s*\"DESede\"\)",  # Detects 3DES with 3 keys (192-bit key)
            ]
        },
        "severity": "High",
        "explanation": "3DES with 3 keys provides ~112 bits of security, which is insufficient against quantum attacks."
    },
    "AES-128": {
        "patterns": {
            "Python": [
                r"AES\.new\((.*?)\)",  # Matches AES initialization
                r"key\s*=\s*.{16}",   # Matches key length for AES-128 (16 bytes)
            ],
            "C": [
                r"EVP_aes_128_[a-zA-Z0-9_]+",  # Matches OpenSSL AES-128 functions
            ],
            "Java": [
                r"Cipher\.getInstance\(\"AES/.*128",  # Matches Java AES-128
            ]
        },
        "severity": "Low",
        "explanation": "AES-128 is secure against classical attacks but not quantum-safe (vulnerable to Grover's algorithm)."
    },
    "AES-192": {
        "patterns": {
            "Python": [
                r"AES\.new\((.*?)\)",  # Matches AES initialization
                r"key\s*=\s*.{24}",   # Matches key length for AES-192 (24 bytes)
            ],
            "C": [
                r"EVP_aes_192_[a-zA-Z0-9_]+",  # Matches OpenSSL AES-192 functions
            ],
            "Java": [
                r"Cipher\.getInstance\(\"AES/.*192",  # Matches Java AES-192
            ]
        },
        "severity": "Very Low",
        "explanation": "AES-192 offers slightly better security than AES-128 but is still vulnerable to quantum attacks."
    },
    "Blowfish_Short_Key": {
        "patterns": {
            "Python": [
                r"Blowfish\.new\(.*key\s*=\s*['\"].{1,15}['\"]",  # Detects Blowfish with keys < 128 bits
                r"from\s+Crypto\.Cipher\s+import\s+Blowfish"      # Detects Blowfish import
            ],
            "C": [
                r"BF_set_key\(.*,\s*\d{1,2},",  # Detects Blowfish key setup with key length < 128 bits
            ],
            "Java": [
                r"Cipher\.getInstance\(\"Blowfish",  # Matches Blowfish cipher initialization
                r"SecretKeySpec\(.*,\s*\"Blowfish\""  # Detects key setup for Blowfish
            ]
        },
        "severity": "High",
        "explanation": "Short key sizes are inadequate for modern security standards."
    },

    "RC4": {
        "patterns": {
            "Python": [
                r"RC4",  # Matches usage of RC4 cipher
                r"from\s+Crypto\.Cipher\s+import\s+RC4"  # Importing RC4
            ],
            "C": [
                r"RC4_encrypt",  # Matches RC4 encryption function
            ],
            "Java": [
                r"Cipher\.getInstance\(\"RC4",  # Matches Java RC4 cipher initialization
            ]
        },
        "severity": "Very High",
        "explanation": "RC4 is insecure due to biases in its keystream, vulnerabilities in its key scheduling algorithm, and susceptibility to attacks like plaintext recovery and state inference."
    },
    "RSA_512_1024": {
        "patterns": {
            "Python": [
                r"RSA\.new_key\(512\)",  # Matches RSA 512-bit key generation in Python
                r"RSA\.new_key\(1024\)"  # Matches RSA 1024-bit key generation in Python
            ],
            "C": [
                r"RSA_generate_key\(512\)",  # Matches RSA 512-bit key generation in C
                r"RSA_generate_key\(1024\)"  # Matches RSA 1024-bit key generation in C
            ],
            "Java": [
                r"KeyPairGenerator\.getInstance\(\"RSA\"",  # Matches RSA key pair generation in Java
                r"keysize\s*=\s*512",  # Detects key size of 512 bits
                r"keysize\s*=\s*1024"  # Detects key size of 1024 bits
            ]
        },
        "severity": "High",
        "explanation": "RSA with short keys (512, 1024 bits) is easily breakable with classical attacks and completely broken with quantum computing (Shor's algorithm)."
    },
    "RSA_2048_3072": {
        "patterns": {
            "Python": [
                r"RSA\.new_key\(2048\)",  # Matches RSA 2048-bit key generation in Python
                r"RSA\.new_key\(3072\)"   # Matches RSA 3072-bit key generation in Python
            ],
            "C": [
                r"RSA_generate_key\(2048\)",  # Matches RSA 2048-bit key generation in C
                r"RSA_generate_key\(3072\)"   # Matches RSA 3072-bit key generation in C
            ],
            "Java": [
                r"KeyPairGenerator\.getInstance\(\"RSA\"",  # Matches RSA key pair generation in Java
                r"keysize\s*=\s*2048",  # Detects key size of 2048 bits
                r"keysize\s*=\s*3072"   # Detects key size of 3072 bits
            ]
        },
        "severity": "Very Low",
        "explanation": "RSA with 2048, 3072+ bits is secure against classical attacks but vulnerable to quantum computing."
    },
    "RSA_no_padding": {
        "patterns": {
            "Python": [
                r"RSA\.encrypt\(.*,\s*None\)",  # Matches RSA encryption with no padding
                r"RSA\.decrypt\(.*,\s*None\)"   # Matches RSA decryption with no padding
            ],
            "C": [
                r"RSA_private_encrypt\(.*,\s*RSA_NO_PADDING\)",  # Matches RSA with no padding in C
                r"RSA_public_encrypt\(.*,\s*RSA_NO_PADDING\)"    # Matches RSA with no padding in C
            ],
            "Java": [
                r"Cipher\.getInstance\(\"RSA/None\"",  # Matches RSA with no padding in Java
                r"RSAEncryptionPadding\.NoPadding"    # Detects RSA with no padding in Java
            ]
        },
        "severity": "Moderate",
        "explanation": "RSA without proper padding is vulnerable to padding oracle attacks, irrespective of key length."
    },
    "ECDH": {
        "patterns": {
            "Python": [
                r"ECDH\(",  # Matches ECDH class initialization (example: PyCryptodome)
                r"from\s+Crypto\.Protocol\.KDF\s+import\s+ECDH",  # Importing ECDH
            ],
            "C": [
                r"EC_KEY_new_by_curve_name",  # Matches OpenSSL ECDH key generation
                r"EC_POINT_mul",  # Matches ECDH shared secret computation
            ],
            "Java": [
                r"KeyAgreement\.getInstance\(\"ECDH",  # Matches Java ECDH initialization
                r"ECNamedCurveParameterSpec"  # Matches ECDH curve specification
            ]
        },
        "severity": "Low",
        "explanation": "ECDH is not quantum-safe as quantum computers can break its security using Shor's algorithm."
    },
    "DH_KE_Weak_Parameters": {
        "patterns": {
            "Python": [
                r"dh\.parameters_generate\(.*key_size\s*=\s*[0-9]{1,3}\)",  # Matches weak key sizes (e.g., < 2048 bits)
            ],
            "C": [
                r"DH_generate_parameters_ex\(.*,\s*\d{1,4},",  # Matches DH generation with small modulus sizes
            ],
            "Java": [
                r"KeyPairGenerator\.getInstance\(\"DH\"",  # Matches Java Diffie-Hellman initialization
                r"keysize\s*=\s*\d{1,3}"  # Matches weak key sizes
            ]
        },
        "severity": "High",
        "explanation": "Small modulus sizes (e.g., < 2048 bits) or insecure generator values (e.g., 1, or p−1) make the system susceptible to attacks."
    },
    "DH_KE_Quantum_Threat": {
        "patterns": {
            "Python": [
                r"dh\.parameters_generate\(.*\)",  # General Diffie-Hellman parameter generation
            ],
            "C": [
                r"DH_generate_parameters_ex\(.*\)",  # General DH parameter generation
            ],
            "Java": [
                r"KeyPairGenerator\.getInstance\(\"DH\"",  # General Diffie-Hellman initialization
            ]
        },
        "severity": "Very High",
        "explanation": "Diffie-Hellman is completely insecure against quantum computers; a transition to post-quantum cryptographic alternatives is necessary."
    },

        "MD5": {
        "patterns": {
            "Python": [
                r"hashlib\.md5",  # Detects MD5 hash initialization
                r"from\s+Crypto\.Hash\s+import\s+MD5",  # Detects MD5 import
            ],
            "C": [
                r"MD5_Init",  # Matches OpenSSL MD5 initialization
                r"MD5_Update",  # Matches OpenSSL MD5 update
                r"MD5_Final",  # Matches OpenSSL MD5 finalization
            ],
            "Java": [
                r"MessageDigest\.getInstance\(\"MD5\"",  # Matches Java MD5 initialization
            ]
        },
        "severity": "Very High",
        "explanation": "MD5 is broken due to collision vulnerabilities and is insecure under both classical and quantum attacks."
    },
    "SHA-1": {
        "patterns": {
            "Python": [
                r"hashlib\.sha1",  # Detects SHA-1 hash initialization
                r"from\s+Crypto\.Hash\s+import\s+SHA1",  # Detects SHA-1 import
            ],
            "C": [
                r"SHA1_Init",  # Matches OpenSSL SHA-1 initialization
                r"SHA1_Update",  # Matches OpenSSL SHA-1 update
                r"SHA1_Final",  # Matches OpenSSL SHA-1 finalization
            ],
            "Java": [
                r"MessageDigest\.getInstance\(\"SHA-1\"",  # Matches Java SHA-1 initialization
            ]
        },
        "severity": "High",
        "explanation": "SHA-1 is obsolete and vulnerable to collision attacks under classical and quantum contexts."
    },
    "SHA-256": {
        "patterns": {
            "Python": [
                r"hashlib\.sha256",  # Detects SHA-256 hash initialization
                r"from\s+Crypto\.Hash\s+import\s+SHA256",  # Detects SHA-256 import
            ],
            "C": [
                r"SHA256_Init",  # Matches OpenSSL SHA-256 initialization
                r"SHA256_Update",  # Matches OpenSSL SHA-256 update
                r"SHA256_Final",  # Matches OpenSSL SHA-256 finalization
            ],
            "Java": [
                r"MessageDigest\.getInstance\(\"SHA-256\"",  # Matches Java SHA-256 initialization
            ]
        },
        "severity": "Very Low",
        "explanation": "SHA-256 is secure under classical conditions, but Grover’s algorithm reduces its effective security to ~128 bits."
    },
    "SHA-224": {
        "patterns": {
            "Python": [
                r"hashlib\.sha224",  # Matches SHA-224 in Python
            ],
            "C": [
                r"SHA224",  # Matches SHA-224 in C (using OpenSSL or similar)
            ],
            "Java": [
                r"MessageDigest\.getInstance\(\"SHA-224\"",  # Matches SHA-224 initialization in Java
            ]
        },
        "severity": "High",
        "explanation": "Too small for modern security; effective security is reduced significantly."
    },
    "Whirlpool": {
        "patterns": {
            "Python": [
                r"hashlib\.new\('whirlpool'\)",  # Matches Whirlpool hash in Python
            ],
            "C": [
                r"whirlpool",  # Matches Whirlpool usage in C
            ],
            "Java": [
                r"MessageDigest\.getInstance\(\"Whirlpool\"",  # Matches Whirlpool initialization in Java
            ]
        },
        "severity": "Moderate",
        "explanation": "Secure but uncommon; improper implementations can introduce vulnerabilities."
    },
    "ECB_Mode": {
        "patterns": {
            "Python": [
                r"Cipher\.new\(\s*.*,\s*AES\.MODE_ECB",  # Matches AES in ECB mode
                r"Cipher\.new\(\s*.*,\s*DES\.MODE_ECB",  # Matches DES in ECB mode
            ],
            "C": [
                r"EVP_EncryptInit_ex\(.*,\s*EVP_aes_\d+_ecb",  # Matches OpenSSL AES ECB mode
                r"EVP_EncryptInit_ex\(.*,\s*EVP_des_ecb",      # Matches OpenSSL DES ECB mode
            ],
            "Java": [
                r"Cipher\.getInstance\(\"AES/ECB",  # Matches Java AES in ECB mode
                r"Cipher\.getInstance\(\"DES/ECB",  # Matches Java DES in ECB mode
            ]
        },
        "severity": "High",
        "explanation": "Insecure mode; leaks patterns in plaintext due to lack of diffusion."
    },
    "CBC_Static_IV": {
        "patterns": {
            "Python": [
                r"Cipher\.new\(\s*.*,\s*AES\.MODE_CBC,\s*iv\s*=\s*['\"].{16}['\"]",  # Matches CBC mode with static IV (AES)
                r"Cipher\.new\(\s*.*,\s*DES\.MODE_CBC,\s*iv\s*=\s*['\"].{8}['\"]",   # Matches CBC mode with static IV (DES)
            ],
            "C": [
                r"EVP_EncryptInit_ex\(.*,\s*EVP_aes_\d+_cbc,\s*NULL,\s*\"[a-fA-F0-9]{32}\"",  # AES CBC with static IV in C (hex IV)
                r"EVP_EncryptInit_ex\(.*,\s*EVP_des_cbc,\s*NULL,\s*\"[a-fA-F0-9]{16}\"",      # DES CBC with static IV in C (hex IV)
            ],
            "Java": [
                r"Cipher\.getInstance\(\"AES/CBC",  # Matches AES CBC mode in Java
                r"Cipher\.getInstance\(\"DES/CBC",  # Matches DES CBC mode in Java
            ]
        },
        "severity": "High",
        "explanation": "Predictable IVs make ciphertext vulnerable to chosen-plaintext attacks."
    }


}

def scan_for_vulnerability(file_path, patterns):
    """Check a single file for vulnerabilities."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            for i, line in enumerate(lines, start=1):
                for lang, lang_patterns in patterns.items():
                    for pattern in lang_patterns:
                        if re.search(pattern, line):
                            findings.append({
                                "language": lang,
                                "line_number": i,
                                "content": line.strip()
                            })
    except Exception as e:
        log_panel.insert(tk.END, f"[ERROR] Could not read file {file_path}: {e}\n")
        log_panel.see(tk.END)
    return findings

def scan_vulnerabilities(folder):
    """Scan folder for vulnerabilities and save findings in MongoDB."""
    log_panel.insert(tk.END, f"Scanning folder: {folder}\n")
    log_panel.see(tk.END)

    # Metadata for the scan
    scan_id = scans_collection.estimated_document_count() + 1
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_counts = {"Python": 0, "C": 0, "Java": 0}
    vulnerable_counts = {"Python": 0, "C": 0, "Java": 0}
    total_files = 0
    total_vulnerable_files = 0
    vulnerabilities = []
    found_files = set()  # To avoid double-counting files with the same vulnerabilities

    for root, _, files in os.walk(folder):
        for file in files:
            ext = os.path.splitext(file)[1]
            lang = None
            if ext == ".py":
                lang = "Python"
            elif ext == ".c":
                lang = "C"
            elif ext == ".java":
                lang = "Java"

            if lang:
                file_counts[lang] += 1
                total_files += 1
                file_path = os.path.join(root, file)

                # Skip already found files
                if file_path in found_files:
                    continue

                # Scan for each vulnerability
                for vuln_name, vuln_details in vulnerability_patterns.items():
                    vuln_findings = scan_for_vulnerability(file_path, {lang: vuln_details["patterns"].get(lang, [])})
                    
                    # Ensure that the file is processed correctly
                    if vuln_findings:
                        vulnerable_counts[lang] += 1
                        total_vulnerable_files += 1
                        found_files.add(file_path)

                        # Merge occurrences of the same vulnerability in the same file
                        merged_vulnerability = {
                            "language": lang,
                            "filename": file,
                            "path": file_path,
                            "lines": [],
                            "severity": vuln_details["severity"],
                            "explanation": vuln_details["explanation"]
                        }
                        for finding in vuln_findings:
                            merged_vulnerability["lines"].append({
                                "line_number": finding["line_number"],
                                "content": finding["content"]
                            })

                        # Add the merged entry to vulnerabilities
                        vulnerabilities.append(merged_vulnerability)
                        log_panel.insert(tk.END, f"[INFO] {vuln_name} vulnerability found in {file_path}\n")
                        log_panel.see(tk.END)

    # Save scan metadata and vulnerabilities to MongoDB
    scan_document = {
        "scan_id": scan_id,
        "date": date,
        "directory": folder,
        "files_scanned": file_counts,
        "vulnerable_files": vulnerable_counts,
        "vulnerabilities": vulnerabilities
    }
    scans_collection.insert_one(scan_document)

    # Print stats
    log_panel.insert(tk.END, f"\nScan Statistics:\n")
    log_panel.insert(tk.END, f"Scan ID: {scan_id}\n")
    log_panel.insert(tk.END, f"Total files scanned: {total_files}\n")
    for lang, count in file_counts.items():
        log_panel.insert(tk.END, f"{lang} files: {count}\n")
    log_panel.insert(tk.END, f"Total vulnerable files: {total_vulnerable_files}\n")
    for lang, count in vulnerable_counts.items():
        log_panel.insert(tk.END, f"Vulnerable {lang} files: {count}\n")
    log_panel.see(tk.END)

# GUI functionality
def select_folder_and_scan():
    """Select folder and scan for vulnerabilities."""
    folder = filedialog.askdirectory()
    if folder:
        scan_vulnerabilities(folder)

# Tkinter GUI setup
root = tk.Tk()
root.title("Cryptographic Inventory Tool")
root.geometry("850x600")
root.resizable(False, False)

# Log panel for output
log_label = tk.Label(root, text="Log Panel:", font=("Arial", 12))
log_label.pack(anchor="nw", padx=10, pady=5)

log_panel = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10), height=25, width=100)
log_panel.pack(padx=10, pady=5)

# Buttons
scan_button = tk.Button(root, text="Scan for Vulnerabilities", font=("Arial", 12, "bold"),
                        bg="#007BFF", fg="white", command=select_folder_and_scan)
scan_button.pack(pady=10)

clear_button = tk.Button(root, text="Clear Logs", font=("Arial", 12, "bold"),
                         bg="#FF5733", fg="white", command=lambda: log_panel.delete(1.0, tk.END))
clear_button.pack(pady=10)

export_button = tk.Button(root, text="Export Logs", font=("Arial", 12, "bold"),
                          bg="#FFA500", fg="white", command=lambda: export_logs())
export_button.pack(pady=10)

root.mainloop()
