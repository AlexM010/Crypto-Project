#!/usr/bin/env python3
import os
import re
from pymongo import MongoClient
import sys
from datetime import datetime

# -- Dictionary that maps your vulnerabilities to recommended replacements
cipher_replacement = {
    "DES": "AES-256",
    "3DES_1KEY": "AES-256",
    "3DES_2KEY": "AES-256",
    "3DES_3KEY": "AES-256",
    "RC4": "AES-256",
    "MD5": "SHA-512",
    "SHA-1": "SHA-512",
    "ECB_Mode": "CBC_Mode",
    "CBC_Static_IV": "CBC_Mode",  # requires manual or special fix
    "AES-128": "AES-256",
    "AES-192": "AES-256",
    "Blowfish_Short_Key": "AES-256",
    "DH_KE_Weak_Parameters": "ECDH_P521",   # just fix mod size
    "DH_KE_Quantum_Threat": "ECDH_P521",   # double the mod size
    "ECDH": "RSA-4096",
    "RSA_512_1024": "RSA_4096",
    "RSA_2048_3072": "RSA_4096",
    "RSA_no_padding": "RSA_4096",
    "SHA-256": "SHA-512"
}


# -- Helper: Ensure we have a directory for patched output
def ensure_output_dir(vulnerability):
    """
    Makes sure the directory 'patched_scripts/patched_<vulnerability>' exists.
    Returns the path to the patched file.
    """
    if not os.path.exists("patched_scripts"):
        os.makedirs("patched_scripts")
    patch_dir = f'patched_scripts/patched_{vulnerability}'
    if not os.path.exists(patch_dir):
        os.makedirs(patch_dir)
    return patch_dir

def set_patch_log(file_path, file_name, transition_info, change, patched_file):
    """
    Set the patch log for each file.
    """
    patch_log = {
        "file_path": file_path,
        "file_name": file_name,
        "transition_info": transition_info,
        "change": change,
        "patched_file": patched_file
    }
    return patch_log



# =============================================================================
#               INDIVIDUAL FIX FUNCTIONS FOR EACH VULNERABILITY
# =============================================================================

def replace_DES(weak_cipher, path, lines, language, patch_log):
    """
    Replace DES references with AES-256 references
    in a more thorough way for C, Python, and Java.
    """
    transition_str = f"{weak_cipher} » {cipher_replacement.get(weak_cipher)}"

    if not os.path.isfile(path):
        patch_log.append(set_patch_log(path, os.path.basename(path), transition_str, f"  [!] File not found: {path}", ""))
        return

    with open(path, 'r', encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # -------------- C --------------
    if language == "C":
       # 1) Replace includes
        content = re.sub(
            r'#include\s+<openssl/des\.h>',
            '#include <openssl/evp.h>  // Replaced DES with EVP for AES-256\n#include <openssl/rand.h>',
            content
        )

        # 2) If there is a DES_key_schedule or DES_set_key, comment them out or remove
        content = re.sub(r'DES_key_schedule\s+\w+;', 
                        '// Removed old DES key schedule here', 
                        content)
        content = re.sub(r'DES_set_key_unchecked\(.*?\);', 
                        '// Removed DES_set_key_unchecked; will use EVP for AES-256', 
                        content, flags=re.DOTALL)

        # 3) Replace DES_ecb_encrypt calls with a placeholder EVP usage comment
        content = re.sub(
            r'DES_ecb_encrypt\(.*?\);', 
            '/* Replaced DES_ecb_encrypt with a minimal AES-256 EVP example: */\n'
            '// EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();\n'
            '// EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes256_key, NULL);\n'
            '// EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);\n'
            '// EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen);\n'
            '// EVP_CIPHER_CTX_free(ctx);\n',
            content,
            flags=re.DOTALL
        )

        # 4) Insert a 32-byte random key if we see references to 8-byte (DES) keys
        content = re.sub(
            r'unsigned\s+char\s+key\s*\[\s*8\s*\]\s*=\s*\".*?\";',
            '// --- Replace DES key with random AES-256 key ---\n'
            'unsigned char aes256_key[32];\n'
            'RAND_bytes(aes256_key, sizeof(aes256_key)); // 256-bit random key\n',
            content
        )

    # -------------- Python --------------
    elif language == "Python":
        # Replace from Crypto.Cipher import DES -> AES
        content = content.replace("from Crypto.Cipher import DES", 
                                  "from Crypto.Cipher import AES  # Replaced DES with AES-256")

        # 8-byte key -> 32 bytes
        content = re.sub(r'get_random_bytes\(8\)', 
                         'get_random_bytes(32)  # 256-bit key', 
                         content)

        # Replace DES.new(...) with AES.new(...)
        content = re.sub(r'DES\.new\s*\(', 
                         'AES.new(', 
                         content)

        # If someone used DES.block_size references
        content = re.sub(r'DES\.block_size', 
                         'AES.block_size', 
                         content)

    # -------------- Java --------------
    elif language == "Java":
        # Replace "DES/ECB/PKCS5Padding" with "AES/ECB/PKCS5Padding"
        content = content.replace("\"DES/ECB/PKCS5Padding\"", 
                                  "\"AES/ECB/PKCS5Padding\"")

        # Replace 8-byte key references with 32 bytes
        # e.g. "12345678" => "0123456789ABCDEF0123456789ABCDEF"
        content = re.sub(r'("12345678")',
                         '"0123456789ABCDEF0123456789ABCDEF"', 
                         content)

        # Replace 'new SecretKeySpec(keyBytes, "DES")' with AES
        content = re.sub(r'new\s+SecretKeySpec\s*\(\s*(\w+),\s*"DES"\)',
                         r'new SecretKeySpec(\1, "AES")',
                         content)

    else:
        print(f"[!] Language {language} not recognized for DES→AES-256 transformation.")

    # Write out the patched file
    patch_dir = ensure_output_dir(weak_cipher)
    patched_file = os.path.join(patch_dir, f"patched_{os.path.basename(path)}")
    with open(patched_file, 'w', encoding="utf-8", errors="ignore") as f:
        f.write(content)

    patch_log.append(set_patch_log(path, os.path.basename(path), transition_str, f"[+] Patching {weak_cipher} » {cipher_replacement.get(weak_cipher)} in {language}", patched_file))


def replace_3DES(weak_cipher, path, lines, language, patch_log):
    """
    Replace 3DES references with AES-256 in a more thorough way.
    This function handles 3DES_1KEY, 3DES_2KEY, 3DES_3KEY.
    """
    transition_str = f"{weak_cipher} » {cipher_replacement.get(weak_cipher)}"


    if not os.path.isfile(path):
        set_patch_log(path, os.path.basename(path), transition_str, f"  [!] File not found: {path}", "")
        return

    with open(path, 'r', encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # -------------- C --------------
    if language == "C":
        # Replace EVP_des_ede3_ecb => EVP_aes_256_ecb
        content = re.sub(r'EVP_des_ede3_ecb\s*\(\)', 
                         'EVP_aes_256_ecb()', 
                         content)

        # Replace "ABCDEFGHABCDEFGHABCDEFGH" or "ABCDEFGHIJKLMNOP" or "ABCDEFGH1234..." (24 bytes) with 32 bytes
        # For demonstration, we do a broad match on 24 bytes:
        #   Then replace with "0123456789ABCDEF0123456789ABCDEF" (32 bytes)
        content = re.sub(
            r'\"[A-Za-z0-9!@#\$%^&\*\(\)\-_+=\{\}\[\]\?\.]{24}\"',
            '"0123456789ABCDEF0123456789ABCDEF"', 
            content
        )
        # For 16-byte two-key or repeated 8 bytes single-key:
        content = re.sub(
            r'\"[A-Za-z0-9!@#\$%^&\*\(\)\-_+=\{\}\[\]\?\.]{16}\"',
            '"0123456789ABCDEF0123456789ABCDEF"', 
            content
        )

    # -------------- Python --------------
    elif language == "Python":
        # from Crypto.Cipher import DES3 => from Crypto.Cipher import AES
        content = content.replace("from Crypto.Cipher import DES3",
                                  "from Crypto.Cipher import AES  # replaced 3DES with AES-256")

        # DES3.new(...) => AES.new(...)
        content = re.sub(r'DES3\.new\s*\(', 
                         'AES.new(', 
                         content)

        # Replace DES3.MODE_ECB with AES.MODE_ECB
        content = re.sub(r'DES3\.MODE_ECB', 
                         'AES.MODE_ECB', 
                         content)
        
        # Replace 16- or 24-byte keys with 32 bytes
        # e.g. "ABCDEFGHABCDEFGHABCDEFGH" => "0123456789ABCDEF0123456789ABCDEF"
        content = re.sub(
            rb'b"[A-Za-z0-9!@#\$%^&\*\(\)\-_+=\{\}\[\]\?\.]{16,24}"',
            b'b"0123456789ABCDEF0123456789ABCDEF"',
            content.encode(),
            flags=re.DOTALL
        ).decode()

    # -------------- Java --------------
    elif language == "Java":
        # "DESede/ECB/PKCS5Padding" => "AES/ECB/PKCS5Padding"
        content = content.replace("\"DESede/ECB/PKCS5Padding\"", 
                                  "\"AES/ECB/PKCS5Padding\"")

        # new SecretKeySpec("ABCDEFGHABCDEFGHABCDEFGH".getBytes("UTF-8"), "DESede")
        # => new SecretKeySpec("0123456789ABCDEF0123456789ABCDEF".getBytes("UTF-8"), "AES")
        content = re.sub(
            r'new\s+SecretKeySpec\s*\(\s*\"[A-Za-z0-9!@#\$%^&\*\(\)\-_+=\{\}\[\]\?\.]{16,24}\"\.getBytes\("UTF-8"\),\s*"DESede"\)',
            'new SecretKeySpec("0123456789ABCDEF0123456789ABCDEF".getBytes("UTF-8"), "AES")',
            content
        )
        
        new_class_name = f"patched_{os.path.basename(path).replace('.java', '')}"
        content = content.replace(f"{os.path.basename(path).replace('.java', '')}", f"{new_class_name}")

    else:
        print(f"[!] Language {language} not recognized for 3DES→AES-256 transformation.")

    patch_dir = ensure_output_dir(weak_cipher)
    patched_file = os.path.join(patch_dir, f"patched_{os.path.basename(path)}")
    with open(patched_file, 'w', encoding="utf-8", errors="ignore") as f:
        f.write(content)

    set_patch_log(path, os.path.basename(path), transition_str, f"[+] Patching {weak_cipher} » {cipher_replacement.get(weak_cipher)} in {language}", patched_file)

    

def replace_RC4(weak_cipher, path, lines, language, patch_log):
    """
    Replace RC4 references with AES-256 in C, Python, Java.
    """
    transition_str = f"{weak_cipher} » {cipher_replacement.get(weak_cipher)}"
    
    patch_log.append({
        "file_path": path,
        "file_name": os.path.basename(path),
        "transition_info": transition_str,
        "change": f"[+] Patching {transition_str} in {path} (lang={language})"
    })

    if not os.path.isfile(path):
        patch_log.append({
            "file_path": path,
            "file_name": os.path.basename(path),
            "transition_info": transition_str,
            "change": f"  [!] File not found: {path}"
        })
        return

    with open(path, 'r', encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if language == "C":
        # #include <openssl/rc4.h> => #include <openssl/evp.h>
        content = re.sub(r'#include\s+<openssl/rc4\.h>', 
                         '#include <openssl/evp.h>  // replaced RC4 with AES-256', 
                         content)

        # RC4_set_key => comment out and place an EVP example
        content = re.sub(r'RC4_set_key\(.*?\);',
            '// Removed RC4_set_key; use AES via EVP_EncryptInit_ex(...) in real code.',
            content, flags=re.DOTALL)

        # RC4(...) calls => replaced with a placeholder
        content = re.sub(r'RC4\(.*?\);',
            '// Replaced RC4 encryption with AES-256 code. E.g.:\n'
            '// EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, aes256_key, NULL);\n'
            '// EVP_EncryptUpdate(...) etc.\n',
            content, flags=re.DOTALL)

    elif language == "Python":
        # from Crypto.Cipher import ARC4 => from Crypto.Cipher import AES
        content = content.replace("from Crypto.Cipher import ARC4",
                                  "from Crypto.Cipher import AES  # replaced RC4 with AES-256")

        # ARC4.new(key) => AES.new(key, AES.MODE_ECB) [just an example]
        content = re.sub(r'ARC4\.new\s*\(.*?\)',
                         'AES.new(key, AES.MODE_ECB)  # replaced RC4 usage with AES-256 ECB as a placeholder',
                         content)

    elif language == "Java":
        # "RC4" => "AES"
        content = content.replace("\"RC4\"", "\"AES\"")

        # Possibly also fix key lengths as needed, but your code
        # might not have an obvious place for that. 
        # So, we might leave a placeholder comment:
        content += "\n// NOTE: For RC4 -> AES transition, ensure a 256-bit key."

    patch_dir = ensure_output_dir(weak_cipher)
    patched_file = os.path.join(patch_dir, f"patched_{os.path.basename(path)}")
    with open(patched_file, 'w', encoding="utf-8", errors="ignore") as f:
        f.write(content)

    patch_log.append({
        "file": os.path.basename(path),
        "language": language,
        "transition_info": transition_str,
        "change": f"[*] Patched file saved to: {patched_file}"
    })



def replace_MD5_SHA1_SHA256_with_SHA512(weak_cipher, path, lines, language, patch_log):
    """
    Handles MD5, SHA-1, and SHA-256 → SHA-512 replacements in a more thorough manner.
    """
    print(f"[+] Patching {weak_cipher} → SHA-512 in {path} (lang={language})")

    if not os.path.isfile(path):
        print(f"  [!] File not found: {path}")
        return

    with open(path, 'r', encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if weak_cipher == "MD5":
        # -------------- C --------------
        if language == "C":
            # #include <openssl/md5.h> => #include <openssl/sha.h>
            content = content.replace("#include <openssl/md5.h>", 
                                      "#include <openssl/sha.h>  // replaced MD5 with SHA-512")

            # MD5_Init / MD5_Update / MD5_Final => SHA512_Init / SHA512_Update / SHA512_Final
            content = re.sub(r'MD5_Init', 'SHA512_Init', content)
            content = re.sub(r'MD5_Update', 'SHA512_Update', content)
            content = re.sub(r'MD5_Final', 'SHA512_Final', content)

        # -------------- Python --------------
        elif language == "Python":
            content = content.replace("import hashlib", "import hashlib")
            # Replace hashlib.md5(...) => hashlib.sha512(...)
            content = re.sub(r'hashlib\.md5', 'hashlib.sha512', content)

        # -------------- Java --------------
        elif language == "Java":
            # "MessageDigest md5 = MessageDigest.getInstance("MD5");" => "MessageDigest sha512 = MessageDigest.getInstance("SHA-512");"
            content = re.sub(r'(\"MD5\")', '"SHA-512"', content)
            content = content.replace("md5", "sha512")

    elif weak_cipher == "SHA-1":
        # -------------- C --------------
        if language == "C":
            # #include <openssl/sha.h> might remain the same, but we replace usage
            content = content.replace("SHA1_Init", "SHA512_Init")
            content = content.replace("SHA1_Update", "SHA512_Update")
            content = content.replace("SHA1_Final", "SHA512_Final")

        # -------------- Python --------------
        elif language == "Python":
            # hashlib.sha1 => hashlib.sha512
            content = content.replace("hashlib.sha1", "hashlib.sha512")

        # -------------- Java --------------
        elif language == "Java":
            content = re.sub(r'(\"SHA-1\")', '"SHA-512"', content)
            content = content.replace("sha1", "sha512")

    elif weak_cipher == "SHA-256":
        # -------------- C --------------
        if language == "C":
            # replace "SHA256_Init/Update/Final" => "SHA512_Init/Update/Final"
            content = re.sub(r'SHA256_Init', 'SHA512_Init', content)
            content = re.sub(r'SHA256_Update', 'SHA512_Update', content)
            content = re.sub(r'SHA256_Final', 'SHA512_Final', content)

        # -------------- Python --------------
        elif language == "Python":
            # hashlib.sha256 => hashlib.sha512
            content = re.sub(r'hashlib\.sha256', 'hashlib.sha512', content)

        # -------------- Java --------------
        elif language == "Java":
            content = content.replace("\"SHA-256\"", "\"SHA-512\"")
            content = content.replace("sha256", "sha512")

    patch_dir = ensure_output_dir(weak_cipher)
    patched_file = os.path.join(patch_dir, f"patched_{os.path.basename(path)}")
    with open(patched_file, 'w', encoding="utf-8", errors="ignore") as f:
        f.write(content)

    print(f"  [*] Patched file saved to: {patched_file}")


def replace_ECB_Mode(weak_cipher, path, lines, language, patch_log):
    """
    Replaces 'ECB' references with 'CBC' usage. This is partly naive, but tries to add an IV for CBC.
    """
    print(f"[+] Patching ECB → CBC in {path} (lang={language})")

    if not os.path.isfile(path):
        print(f"  [!] File not found: {path}")
        return

    with open(path, 'r', encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # We'll do a broad stroke: "ECB" => "CBC"
    content = content.replace("ECB", "CBC")

    # If we find references to 'Cipher.getInstance("AES/ECB/PKCS5Padding")'
    # we want to ensure we set an IV:
    if language == "Java":
        # Insert a comment that we need an IV
        content += "\n// NOTE: Make sure to define an IV: e.g. byte[] iv = new byte[16];\n"

    elif language == "C":
        # In a more advanced approach, we might automatically inject a random IV array and pass it to EVP_EncryptInit_ex
        # But let's just place a comment:
        content += "\n// NOTE: For CBC mode, we must supply an IV: e.g. unsigned char iv[16] = {0};\n"

    elif language == "Python":
        # If we see AES.MODE_ECB => AES.MODE_CBC plus an IV
        content = re.sub(r'AES\.MODE_CBC\)', 
                         'AES.MODE_CBC, iv=b"\\0"*16)', 
                         content)  # naive approach
        content += "\n# NOTE: Ensure a proper random IV for CBC, e.g. get_random_bytes(16)\n"

    patch_dir = ensure_output_dir(weak_cipher)
    patched_file = os.path.join(patch_dir, f"patched_{os.path.basename(path)}")
    with open(patched_file, 'w', encoding="utf-8", errors="ignore") as f:
        f.write(content)

    print(f"  [*] Patched file saved to: {patched_file}")


def fix_CBC_Static_IV(weak_cipher, path, lines, language, patch_log):
    """
    We still switch to random or dynamic IV in CBC. 
    We'll put in a placeholder for a random IV in each language.
    """
    print(f"[+] Fixing static IV usage in {path} (lang={language}).")

    if not os.path.isfile(path):
        print(f"  [!] File not found: {path}")
        return

    with open(path, 'r', encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # We'll insert a pseudo-random IV snippet:
    # For C with OpenSSL:
    if language == "C":
        # Replace "EVP_EncryptInit_ex(ctx, ..., key, iv);" with a comment about generating random IV
        content = re.sub(
            r'EVP_EncryptInit_ex\s*\(\s*ctx\s*,\s*([^\)]*?),\s*NULL,\s*(.*?)\s*,\s*(.*?)\);',
            r'// Using a random IV instead of a static one\n'
            r'// e.g. RAND_bytes(iv, sizeof(iv));\n'
            r'EVP_EncryptInit_ex(ctx, \1, NULL, \2, iv);\n',
            content, flags=re.DOTALL)

    elif language == "Python":
        # If we see "iv=some_static_iv", replace with a random IV from get_random_bytes(16)
        content = re.sub(
            r'iv\s*=\s*b?".{1,16}"',
            'iv=get_random_bytes(16)  # replaced static IV with random IV',
            content
        )
        # Insert an import if missing
        if "get_random_bytes" not in content:
            content = "from Crypto.Random import get_random_bytes\n" + content

    elif language == "Java":
        # e.g. Cipher.getInstance("AES/CBC/PKCS5Padding") with a static IV => we insert:
        content += "\n// For CBC mode, generate a random IV: SecureRandom sr = new SecureRandom();\n" \
                   "// byte[] iv = new byte[cipher.getBlockSize()];\n" \
                   "// sr.nextBytes(iv);\n" \
                   "// IvParameterSpec ivSpec = new IvParameterSpec(iv);\n" \
                   "// cipher.init(..., ivSpec);\n"

    patch_dir = ensure_output_dir(weak_cipher)
    patched_file = os.path.join(patch_dir, f"patched_{os.path.basename(path)}")
    with open(patched_file, 'w', encoding="utf-8", errors="ignore") as f:
        f.write(content)

    print(f"  [*] Patched file saved to: {patched_file}")


def replace_AES_128_192_with_256(weak_cipher, path, lines, language, patch_log):
    """
    Replace AES-128 or AES-192 references with AES-256 usage, adjusting key sizes accordingly.
    """
    print(f"[+] Patching {weak_cipher} → AES-256 in {path} (lang={language})")

    if not os.path.isfile(path):
        print(f"  [!] File not found: {path}")
        return

    with open(path, 'r', encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # -------------- C --------------
    if language == "C":
        # EVP_aes_128_* => EVP_aes_256_*
        # EVP_aes_192_* => EVP_aes_256_*
        content = re.sub(r'EVP_aes_128_(\w+)', 'EVP_aes_256_\\1', content)
        content = re.sub(r'EVP_aes_192_(\w+)', 'EVP_aes_256_\\1', content)

        # If we see references to 16-byte key => 32 byte 
        # If we see references to 24-byte key => 32 byte 
        # static const unsigned char key192[24] = "0123456789ABCDEFG012345"; with regex change only the string part
        
        pattern = (
            r'static\s+const\s+unsigned\s+char\s+key128\[\s*16\s*\]\s*=\s*"([^"]{16})";'
        )
        replacement = (
            'static const unsigned char key128[32] = '
            '"0123456789ABCDEF0123456789ABCDEF";'
        )

        content = re.sub(pattern, replacement, content)
        
        
        

    # -------------- Python --------------
    elif language == "Python":
        # AES.new(..., AES.MODE_ECB) with 16 or 24 bytes => 32 bytes
        # We do a broad approach: if we see b"1234567890ABCDEF" => 32 bytes
        content = re.sub(
            rb'b\"[A-Za-z0-9]{16}\"', 
            b'b\"0123456789ABCDEF0123456789ABCDEF\"', 
            content.encode()
        ).decode()
        content = re.sub(
            rb'b\"[A-Za-z0-9]{24}\"', 
            b'b\"0123456789ABCDEF0123456789ABCDEF\"', 
            content.encode()
        ).decode()

    # -------------- Java --------------
    elif language == "Java":
        # "AES/ECB/PKCS5Padding" is fine, but we want a 32-byte key
        # e.g. "1234567890abcdef" => 32 bytes
        content = re.sub(
            r'\"1234567890abcdef\"', 
            '"0123456789ABCDEF0123456789ABCDEF"', 
            content
        )
        
        
        # For AES-192 => we see "123456789012345678901234", we can do:
        content = re.sub(
            r'\"123456789012345678901234\"',
            '"0123456789ABCDEF0123456789ABCDEF"',
            content
        )
        
        new_class_name = f"patched_{os.path.basename(path).replace('.java', '')}"
        content = content.replace(f"{os.path.basename(path).replace('.java', '')}", f"{new_class_name}")
        

    patch_dir = ensure_output_dir(weak_cipher)
    patched_file = os.path.join(patch_dir, f"patched_{os.path.basename(path)}")
    with open(patched_file, 'w', encoding="utf-8", errors="ignore") as f:
        f.write(content)

    print(f"  [*] Patched file saved to: {patched_file}")


def replace_Blowfish_Short_Key(weak_cipher, path, lines, language, patch_log):
    """
    Replace Blowfish short key usage with AES-256 usage.
    """
    print(f"[+] Patching Blowfish_Short_Key → AES-256 in {path} (lang={language})")

    if not os.path.isfile(path):
        print(f"  [!] File not found: {path}")
        return

    with open(path, 'r', encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if language == "C":
        # #include <openssl/blowfish.h> => #include <openssl/evp.h>
        content = content.replace("#include <openssl/blowfish.h>", 
                                  "#include <openssl/evp.h>  // replaced Blowfish with AES-256")

        # BF_set_key => remove and replace with EVP usage comment
        content = re.sub(r'BF_set_key\(.*?\);',
            '// Removed BF_set_key; now would use AES-256 via EVP_EncryptInit_ex(...) etc.',
            content, flags=re.DOTALL)

        # BF_ecb_encrypt => placeholder
        content = re.sub(r'BF_ecb_encrypt\(.*?\);',
            '// Replaced BF_ecb_encrypt with AES-256 code example using EVP.\n',
            content, flags=re.DOTALL)

    elif language == "Python":
        # from Crypto.Cipher import Blowfish => from Crypto.Cipher import AES
        content = content.replace("from Crypto.Cipher import Blowfish",
                                  "from Crypto.Cipher import AES  # replaced Blowfish with AES-256")
        # Blowfish.new(...) => AES.new(...)
        content = re.sub(r'Blowfish\.new\s*\(',
                         'AES.new(', 
                         content)

    elif language == "Java":
        # Blowfish => AES
        content = content.replace("\"Blowfish\"", "\"AES\"")
        # Replace key references
        content += "\n// Ensure 32-byte key for AES-256.\n"

    patch_dir = ensure_output_dir(weak_cipher)
    patched_file = os.path.join(patch_dir, f"patched_{os.path.basename(path)}")
    with open(patched_file, 'w', encoding="utf-8", errors="ignore") as f:
        f.write(content)

    print(f"  [*] Patched file saved to: {patched_file}")


def replace_ECDH_with_RSA4096(weak_cipher, path, lines, language, patch_log):
    """
    Replace ECDH references with RSA-4096 usage. (Very simplified approach)
    """
    print(f"[+] Patching {weak_cipher} → RSA-4096 in {path} (lang={language})")

    if not os.path.isfile(path):
        print(f"  [!] File not found: {path}")
        return

    with open(path, 'r', encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if language == "C":
        # #include <openssl/ec.h> => #include <openssl/rsa.h> etc
        content = re.sub(r'#include\s+<openssl/ec.h>',
                         '#include <openssl/rsa.h>\n#include <openssl/pem.h>  // replaced ECDH with RSA-4096',
                         content)

        # Replace ECDH calls with a placeholder RSA usage
        content = re.sub(r'EC_KEY\s*\*\s*\w+\s*=\s*EC_KEY_new_by_curve_name\(.*?\);',
            '// Replaced ECDH key with RSA *\nRSA *rsa_key = RSA_new();\nBIGNUM *e = BN_new();\nBN_set_word(e, RSA_F4);\nRSA_generate_key_ex(rsa_key, 4096, e, NULL);\n',
            content, flags=re.DOTALL)

        # ECDH_compute_key => replaced
        content = re.sub(r'ECDH_compute_key\(.*?\);',
            '// Replaced ECDH_compute_key with an RSA encryption example.\n'
            '// RSA_public_encrypt(...), RSA_private_decrypt(...)\n',
            content, flags=re.DOTALL)

    elif language == "Python":
        # from Crypto.Protocol.KDF import ECDH => from Crypto.PublicKey import RSA
        # or from Crypto.PublicKey import ECC => from Crypto.PublicKey import RSA
        content = content.replace("from Crypto.Protocol.KDF import ECDH",
                                  "from Crypto.PublicKey import RSA  # replaced ECDH with RSA-4096")
        content = content.replace("from Crypto.PublicKey import ECC",
                                  "from Crypto.PublicKey import RSA  # replaced ECDH with RSA-4096")

        # ecdh = ECDH() => placeholder for RSA
        content = re.sub(r'ECDH\s*\(.*?\)',
            'RSA.generate(4096)  # replaced ECDH with 4096-bit RSA',
            content)

    elif language == "Java":
        content += "\n// In Java, to replace ECDH with RSA-4096, you would typically use:\n" \
                   "// KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");\n" \
                   "// kpg.initialize(4096);\n" \
                   "// KeyPair kp = kpg.generateKeyPair();\n"

    patch_dir = ensure_output_dir(weak_cipher)
    patched_file = os.path.join(patch_dir, f"patched_{os.path.basename(path)}")
    with open(patched_file, 'w', encoding="utf-8", errors="ignore") as f:
        f.write(content)

    print(f"  [*] Patched file saved to: {patched_file}")


def replace_RSA_to_4096(weak_cipher, path, lines, language, patch_log):
    """
    For RSA_512_1024, RSA_2048_3072, or RSA_no_padding => upgrade to RSA-4096 with OAEP or PKCS#1 v1.5
    """
    print(f"[+] Patching {weak_cipher} → RSA-4096 in {path} (lang={language})")

    if not os.path.isfile(path):
        print(f"  [!] File not found: {path}")
        return

    with open(path, 'r', encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Common approach: search for RSA_generate_key( < 4096 ) => 4096
    # or RSA.generate(...) in Python => 4096
    # Also remove "RSA_NO_PADDING" => "RSA_PKCS1_OAEP_PADDING"
    if language == "C":
        # e.g. RSA_generate_key(512, RSA_F4, ...)
        content = re.sub(r'RSA_generate_key\s*\(\s*(512|1024|2048|3072)\s*,\s*RSA_F4\s*,\s*NULL\s*,\s*NULL\s*\)',
                         'RSA_generate_key(4096, RSA_F4, NULL, NULL)', 
                         content)

        # If we see RSA_public_encrypt(..., RSA_NO_PADDING), replace with RSA_PKCS1_OAEP_PADDING
        content = content.replace("RSA_NO_PADDING", "RSA_PKCS1_OAEP_PADDING")

    elif language == "Python":
        # RSA.generate(512 or 1024 or 2048 or 3072) => 4096
        content = re.sub(r'RSA\.generate\(\s*(512|1024|2048|3072)\s*\)', 
                         'RSA.generate(4096)', 
                         content)

    elif language == "Java":
        # "Cipher.getInstance("RSA/ECB/NoPadding") => "Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")"
        content = content.replace("RSA/ECB/NoPadding", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding")

        # If there's code for KeyPairGenerator("RSA"), let's ensure we set 4096
        # e.g. kpg.initialize(2048) => 4096
        content = re.sub(r'kpg\.initialize\(\s*(512|1024|2048|3072)\s*\)',
                         'kpg.initialize(4096)',
                         content)

    patch_dir = ensure_output_dir(weak_cipher)
    patched_file = os.path.join(patch_dir, f"patched_{os.path.basename(path)}")
    with open(patched_file, 'w', encoding="utf-8", errors="ignore") as f:
        f.write(content)

    print(f"  [*] Patched file saved to: {patched_file}")


def fix_DH_KE(weak_cipher, path, lines, language, patch_log):
    """
    Fix DH_KE_Weak_Parameters or DH_KE_Quantum_Threat by adjusting
    the modulus size to 4096, or doubling if user wants to.
    """
    print(f"[+] Fixing {weak_cipher} in {path} (lang={language}).")

    if not os.path.isfile(path):
        print(f"  [!] File not found: {path}")
        return

    with open(path, 'r', encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if weak_cipher == "DH_KE_Weak_Parameters":
        # E.g., find something like DH_generate_parameters_ex(dh, prime_length, ...)
        # and replace prime_length with 4096
        content = re.sub(r'DH_generate_parameters_ex\s*\(\s*(\w+)\s*,\s*\d+\s*,\s*DH_GENERATOR_2\s*,\s*NULL\s*\);',
                         r'DH_generate_parameters_ex(\1, 4096, DH_GENERATOR_2, NULL);',
                         content)

    elif weak_cipher == "DH_KE_Quantum_Threat":
        # Similar approach, but let's do 8192 or something bigger
        # Or we do a 2x approach from whatever is found. This is just an example that sets 8192.
        content = re.sub(r'DH_generate_parameters_ex\s*\(\s*(\w+)\s*,\s*\d+\s*,\s*DH_GENERATOR_2\s*,\s*NULL\s*\);',
                         r'DH_generate_parameters_ex(\1, 8192, DH_GENERATOR_2, NULL);',
                         content)

    patch_dir = ensure_output_dir(weak_cipher)
    patched_file = os.path.join(patch_dir, f"patched_{os.path.basename(path)}")
    with open(patched_file, 'w', encoding="utf-8", errors="ignore") as f:
        f.write(content)

    print(f"  [*] Patched file saved to: {patched_file}")


# =============================================================================
#        OUR MASTER DICTIONARY OF VULNERABILITY → FUNCTION MAPPINGS
# =============================================================================

cipher_replacement_funcs = {
    # DES
    "DES": replace_DES,

    # 3DES
    "3DES_1KEY": replace_3DES,
    "3DES_2KEY": replace_3DES,
    "3DES_3KEY": replace_3DES,

    # RC4
    "RC4": replace_RC4,

    # MD5, SHA-1, SHA-256 → SHA-512
    "MD5": replace_MD5_SHA1_SHA256_with_SHA512,
    "SHA-1": replace_MD5_SHA1_SHA256_with_SHA512,
    "SHA-256": replace_MD5_SHA1_SHA256_with_SHA512,

    # ECB_Mode => CBC_Mode
    "ECB_Mode": replace_ECB_Mode,

    # CBC_Static_IV => random/dynamic IV
    "CBC_Static_IV": fix_CBC_Static_IV,

    # AES-128, AES-192 => AES-256
    "AES-128": replace_AES_128_192_with_256,
    "AES-192": replace_AES_128_192_with_256,

    # Blowfish short => AES-256
    "Blowfish_Short_Key": replace_Blowfish_Short_Key,

    # ECDH => RSA-4096
    "ECDH": replace_ECDH_with_RSA4096,

    # RSA short or no-padding => RSA-4096 with proper padding
    "RSA_512_1024": replace_RSA_to_4096,
    "RSA_2048_3072": replace_RSA_to_4096,
    "RSA_no_padding": replace_RSA_to_4096,

    # DH_KE fixes
    "DH_KE_Weak_Parameters": fix_DH_KE,
    "DH_KE_Quantum_Threat": fix_DH_KE,
}


# =============================================================================
#                         MAIN SCRIPT FUNCTIONS
# =============================================================================

def print_scans(scans_collection):
    print("\nExisting scan IDs in the database:")
    for scan in scans_collection.find({}, {"scan_id": 1, "_id": 0}):
        print("  -", scan["scan_id"])


def create_patched_collection(db):
    if "patched" not in db.list_collection_names():
        db.create_collection("patched")
        print("[+] Created 'patched' collection in the DB.")
    else:
        print("[!] 'patched' collection already exists.")


def process_scan(scan, patch_log):
    """
    Iterate over the vulnerabilities in the scan
    and call the appropriate fix function for each.
    """
    print(f"Processing {len(scan['vulnerabilities'])} vulnerabilities...")
    for vulnerability in scan["vulnerabilities"]:
        weak_cipher = vulnerability["vulnerability"]
        file_path   = vulnerability["path"]
        language    = vulnerability["language"]
        lines       = vulnerability["lines"]

        # Retrieve the relevant patch function
        fix_func = cipher_replacement_funcs.get(weak_cipher)

        if fix_func:
            fix_func(weak_cipher, file_path, lines, language, patch_log)
        else:
            print(f"[!] No dedicated fix function for {weak_cipher}. Manual fix required.")


def main():
    # 1) Connect to MongoDB
    client = MongoClient("mongodb://localhost:27017/")
    db = client["cryptographic_inventory"]
    scans_collection = db["scans"]

    create_patched_collection(db)
    patched_coll = db["patched"]
    
    patch_log = []

    # 3) Process the scan with the program argument 
    scan_id = sys.argv[1]
    process_scan(scans_collection.find_one({"scan_id": scan_id}), patch_log)
    
    
    patched_doc = {
        "scan_id": scan_id,
        "date": str(datetime.now()),
        "updates": patch_log
    }
    patched_coll.insert_one(patched_doc)

    
    
    # 4) Close the client
    client.close()


if __name__ == "__main__":
    main()
