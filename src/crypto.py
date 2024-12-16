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
                r"\bfrom\s+Crypto\.Cipher\s+import\s+DES\b",
                r"\bDES\.new\s*\("
            ],
            "C": [
                r"\bEVP_EncryptInit_ex\s*\(.*,\s*EVP_des_ecb\b",
                r"\bEVP_DecryptInit_ex\s*\(.*,\s*EVP_des_ecb\b",
                r"\bDES_set_key_checked\b"
            ],
            "Java": [
                r"\bCipher\.getInstance\(\s*\"DES",
                r"\bSecretKeySpec\s*\(.*,\s*\"DES\""
            ]
        },
        "severity": "Very High",
        "explanation": "DES is insecure due to its 56-bit key size, making it vulnerable to brute-force attacks."
    },
    "3DES_1KEY": {
        "patterns": {
            "Python": [
                r"\bDES3\.new\s*\(.*,\s*\"DESede\"\)"
            ],
            "C": [
                r"\bEVP_EncryptInit_ex\s*\(.*,\s*EVP_des_ede3_ecb\b",
                r"\bEVP_DecryptInit_ex\s*\(.*,\s*EVP_des_ede3_ecb\b",
                r"\bDES_set_key_unchecked\s*\(.*,\s*&key_schedule\)",
                r"\bDES_ecb_encrypt\s*\(.*,\s*&ciphertext,\s*&key_schedule,\s*DES_ENCRYPT\)"
            ],
            "Java": [
                r"\bSecretKeySpec\s*\(.*,\s*\"DESede\"\)"
            ]
        },
        "severity": "Very High",
        "explanation": "3DES with 1 key offers no additional security over DES and is insecure."
    },
    "3DES_2KEY": {
        "patterns": {
            "Python": [
                r"\bDES3\.new\s*\(.*,\s*\"DESede\"\)"
            ],
            "C": [
                r"\bEVP_EncryptInit_ex\s*\(.*,\s*EVP_des_ede3_ecb\b",
                r"\bDES_ede3_ecb_encrypt\s*\(.*,\s*&ciphertext,\s*&key_schedule\[0\],\s*&key_schedule\[1\],\s*&key_schedule\[0\],\s*DES_ENCRYPT\)"
            ],
            "Java": [
                r"\bSecretKeySpec\s*\(.*,\s*\"DESede\"\).{0,40}16"
            ]
        },
        "severity": "High",
        "explanation": "3DES with 2 keys provides ~80 bits of security, which is inadequate by modern standards."
    },
    "3DES_3KEY": {
        "patterns": {
            "Python": [
                r"\bDES3\.new\s*\(.*,\s*\"DESede\"\)"
            ],
            "C": [
                r"\bEVP_EncryptInit_ex\s*\(.*,\s*EVP_des_ede3_ecb\b",
                r"\bDES_ede3_ecb_encrypt\s*\(.*,\s*&ciphertext,\s*&key_schedule\[0\],\s*&key_schedule\[1\],\s*&key_schedule\[2\],\s*DES_ENCRYPT\)"
            ],
            "Java": [
                r"\bSecretKeySpec\s*\(.*,\s*\"DESede\"\).{0,40}24"
            ]
        },
        "severity": "High",
        "explanation": "3DES with 3 keys provides ~112 bits of security, which is insufficient against quantum attacks."
    },
    "AES-128": {
        "patterns": {
            "Python": [
                r"\bAES\.new\s*\(.*?\)",
                r"\bkey\s*=\s*.{16}\b"
            ],
            "C": [
                r"\bEVP_aes_128_[a-zA-Z0-9_]+\b"
            ],
            "Java": [
                r"\bCipher\.getInstance\(\"AES/.*128"
            ]
        },
        "severity": "Low",
        "explanation": "AES-128 is secure against classical attacks but not quantum-safe."
    },
    "AES-192": {
        "patterns": {
            "Python": [
                r"\bAES\.new\s*\(.*?\)",
                r"\bkey\s*=\s*.{24}\b"
            ],
            "C": [
                r"\bEVP_aes_192_[a-zA-Z0-9_]+\b"
            ],
            "Java": [
                r"\bCipher\.getInstance\(\"AES/.*192"
            ]
        },
        "severity": "Very Low",
        "explanation": "AES-192 is slightly better than AES-128, but still vulnerable to quantum attacks."
    },
    "Blowfish_Short_Key": {
        "patterns": {
            "Python": [
                r"\bfrom\s+Crypto\.Cipher\s+import\s+Blowfish\b",
                r"\bBlowfish\.new\s*\(.*key\s*=\s*['\"].{1,15}['\"]"
            ],
            "C": [
                r"\bBF_set_key\s*\(.*,\s*\d{1,2},"
            ],
            "Java": [
                r"\bCipher\.getInstance\(\"Blowfish",
                r"\bSecretKeySpec\s*\(.*,\s*\"Blowfish\""
            ]
        },
        "severity": "High",
        "explanation": "Short key sizes are inadequate for modern security standards."
    },
    "RC4": {
        "patterns": {
            "Python": [
                r"\bfrom\s+Crypto\.Cipher\s+import\s+RC4\b",
                r"\bRC4\s*\("
            ],
            "C": [
                r"\bRC4_encrypt\b"
            ],
            "Java": [
                r"\bCipher\.getInstance\(\"RC4"
            ]
        },
        "severity": "Very High",
        "explanation": "RC4 is insecure due to biases in its keystream and vulnerable to multiple attacks."
    },
    "RSA_512_1024": {
        "patterns": {
            "Python": [
                r"\bRSA\.new_key\s*\(512\)",
                r"\bRSA\.new_key\s*\(1024\)"
            ],
            "C": [
                r"\bRSA_generate_key\s*\(512\)",
                r"\bRSA_generate_key\s*\(1024\)"
            ],
            "Java": [
                r"\bKeyPairGenerator\.getInstance\(\"RSA\"",
                r"\bkeysize\s*=\s*512\b",
                r"\bkeysize\s*=\s*1024\b"
            ]
        },
        "severity": "High",
        "explanation": "RSA with short keys (512, 1024 bits) is easily breakable."
    },
    "RSA_2048_3072": {
        "patterns": {
            "Python": [
                r"\bRSA\.new_key\s*\(2048\)",
                r"\bRSA\.new_key\s*\(3072\)"
            ],
            "C": [
                r"\bRSA_generate_key\s*\(2048\)",
                r"\bRSA_generate_key\s*\(3072\)"
            ],
            "Java": [
                r"\bKeyPairGenerator\.getInstance\(\"RSA\"",
                r"\bkeysize\s*=\s*2048\b",
                r"\bkeysize\s*=\s*3072\b"
            ]
        },
        "severity": "Very Low",
        "explanation": "RSA with 2048 or 3072 bits is secure against classical attacks but not quantum-resistant."
    },
    "RSA_no_padding": {
        "patterns": {
            "Python": [
                r"\bRSA\.encrypt\s*\(.*,\s*None\)",
                r"\bRSA\.decrypt\s*\(.*,\s*None\)"
            ],
            "C": [
                r"\bRSA_private_encrypt\s*\(.*,\s*RSA_NO_PADDING\)",
                r"\bRSA_public_encrypt\s*\(.*,\s*RSA_NO_PADDING\)"
            ],
            "Java": [
                r"\bCipher\.getInstance\(\"RSA/None\"",
                r"\bRSAEncryptionPadding\.NoPadding"
            ]
        },
        "severity": "Moderate",
        "explanation": "RSA without proper padding is vulnerable to padding oracle attacks."
    },
    "ECDH": {
        "patterns": {
            "Python": [
                r"\bfrom\s+Crypto\.Protocol\.KDF\s+import\s+ECDH\b",
                r"\bECDH\s*\("
            ],
            "C": [
                r"\bEC_KEY_new_by_curve_name\b",
                r"\bEC_POINT_mul\b"
            ],
            "Java": [
                r"\bKeyAgreement\.getInstance\(\"ECDH\"",
                r"\bECNamedCurveParameterSpec\b"
            ]
        },
        "severity": "Low",
        "explanation": "ECDH is not quantum-safe; quantum computers can break its security."
    },
    "DH_KE_Weak_Parameters": {
        "patterns": {
            "Python": [
                r"\bdh\.parameters_generate\s*\(.*key_size\s*=\s*[0-9]{1,3}\)"
            ],
            "C": [
                r"\bDH_generate_parameters_ex\s*\(.*,\s*\d{1,4},"
            ],
            "Java": [
                r"\bKeyPairGenerator\.getInstance\(\"DH\"",
                r"\bkeysize\s*=\s*\d{1,3}\b"
            ]
        },
        "severity": "High",
        "explanation": "Small modulus sizes (<2048 bits) in DH are easily attacked."
    },
    "DH_KE_Quantum_Threat": {
        "patterns": {
            "Python": [
                r"\bdh\.parameters_generate\s*\(.*\)"
            ],
            "C": [
                r"\bDH_generate_parameters_ex\s*\(.*\)"
            ],
            "Java": [
                r"\bKeyPairGenerator\.getInstance\(\"DH\""
            ]
        },
        "severity": "Very High",
        "explanation": "DH is not secure against quantum computers."
    },
    "MD5": {
        "patterns": {
            "Python": [
                r"\bhashlib\.md5\b",
                r"\bfrom\s+Crypto\.Hash\s+import\s+MD5\b"
            ],
            "C": [
                r"\bMD5_Init\b",
                r"\bMD5_Update\b",
                r"\bMD5_Final\b"
            ],
            "Java": [
                r"\bMessageDigest\.getInstance\(\"MD5\""
            ]
        },
        "severity": "Very High",
        "explanation": "MD5 is broken due to collision vulnerabilities."
    },
    "SHA-1": {
        "patterns": {
            "Python": [
                r"\bhashlib\.sha1\b",
                r"\bfrom\s+Crypto\.Hash\s+import\s+SHA1\b"
            ],
            "C": [
                r"\bSHA1_Init\b",
                r"\bSHA1_Update\b",
                r"\bSHA1_Final\b"
            ],
            "Java": [
                r"\bMessageDigest\.getInstance\(\"SHA-1\""
            ]
        },
        "severity": "High",
        "explanation": "SHA-1 is obsolete and vulnerable to collisions."
    },
    "SHA-256": {
        "patterns": {
            "Python": [
                r"\bhashlib\.sha256\b",
                r"\bfrom\s+Crypto\.Hash\s+import\s+SHA256\b"
            ],
            "C": [
                r"\bSHA256_Init\b",
                r"\bSHA256_Update\b",
                r"\bSHA256_Final\b"
            ],
            "Java": [
                r"\bMessageDigest\.getInstance\(\"SHA-256\""
            ]
        },
        "severity": "Very Low",
        "explanation": "SHA-256 is secure classically, but less so under quantum threats."
    },
    "SHA-224": {
        "patterns": {
            "Python": [
                r"\bhashlib\.sha224\b"
            ],
            "C": [
                r"\bSHA224\b"
            ],
            "Java": [
                r"\bMessageDigest\.getInstance\(\"SHA-224\""
            ]
        },
        "severity": "High",
        "explanation": "SHA-224 provides reduced security compared to larger variants."
    },
    "Whirlpool": {
        "patterns": {
            "Python": [
                r"\bhashlib\.new\s*\(\s*'whirlpool'\)"
            ],
            "C": [
                r"\bwhirlpool\b"
            ],
            "Java": [
                r"\bMessageDigest\.getInstance\(\"Whirlpool\""
            ]
        },
        "severity": "Moderate",
        "explanation": "Whirlpool is secure but less commonly used; implementation quality may vary."
    },
    "ECB_Mode": {
        "patterns": {
            "Python": [
                r"\bCipher\.new\s*\(.*,\s*AES\.MODE_ECB",
                r"\bCipher\.new\s*\(.*,\s*DES\.MODE_ECB"
            ],
            "C": [
                r"\bEVP_EncryptInit_ex\s*\(.*,\s*EVP_aes_\d+_ecb\b",
                r"\bEVP_EncryptInit_ex\s*\(.*,\s*EVP_des_ecb\b"
            ],
            "Java": [
                r"\bCipher\.getInstance\(\"AES/ECB",
                r"\bCipher\.getInstance\(\"DES/ECB"
            ]
        },
        "severity": "High",
        "explanation": "ECB mode leaks plaintext patterns."
    },
    "CBC_Static_IV": {
        "patterns": {
            "Python": [
                r"\bCipher\.new\s*\(.*,\s*AES\.MODE_CBC,\s*iv\s*=\s*['\"].{16}['\"]",
                r"\bCipher\.new\s*\(.*,\s*DES\.MODE_CBC,\s*iv\s*=\s*['\"].{8}['\"]"
            ],
            "C": [
                r"\bEVP_EncryptInit_ex\s*\(.*,\s*EVP_aes_\d+_cbc,\s*NULL,\s*\"[a-fA-F0-9]{32}\"",
                r"\bEVP_EncryptInit_ex\s*\(.*,\s*EVP_des_cbc,\s*NULL,\s*\"[a-fA-F0-9]{16}\""
            ],
            "Java": [
                r"\bCipher\.getInstance\(\"AES/CBC",
                r"\bCipher\.getInstance\(\"DES/CBC"
            ]
        },
        "severity": "High",
        "explanation": "Static IVs in CBC mode weaken security and allow chosen-plaintext attacks."
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
