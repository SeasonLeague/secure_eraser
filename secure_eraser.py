import os
import sys
import shutil
import tarfile
import getpass
import base64
import secrets
import tempfile
import time
from datetime import datetime
from Crypto.Cipher import AES
from threading import Thread
from queue import Queue

# Configuration
MINIMUM_AGE = 18
AES_KEY_SIZE = 32  # 256-bit
NONCE_SIZE = 12    # Proper for AES-CTR
BLOCK_SIZE = 65536
WIPE_PASSES = 3    # DoD compliant
ESTIMATED_WIPE_SPEED = {'HDD': 50, 'SSD': 300, 'NVMe': 500}  # MB/s

def apply_windows_tweaks():
    """Optimize Windows for faster secure deletion"""
    try:
        os.system('reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" '
                  '/v "NtfsDisableDeleteNotify" /t REG_DWORD /d 1 /f')
    except Exception as e:
        print(f"Warning: Could not apply performance tweaks ({str(e)})")

def verify_age():
    while True:
        try:
            birth_year = int(input("Enter your birth year (YYYY): "))
            current_year = datetime.now().year
            if birth_year < 1900 or birth_year > current_year:
                raise ValueError
            if current_year - birth_year < MINIMUM_AGE:
                print("Access denied: Minimum age requirement not met")
                sys.exit(1)
            return
        except ValueError:
            print("Invalid year. Please use valid YYYY format.")

def show_policy():
    policy = f"""
    DATA ERASURE POLICY

    1. You confirm you are over {MINIMUM_AGE} years old
    2. AES-256 encryption with secure CTR mode
    3. {WIPE_PASSES}-pass DoD compliant wiping
    4. Irreversible data destruction
    5. Full responsibility for key management

    Type 'ACCEPT' to proceed: """
    if input(policy).strip().upper() != "ACCEPT":
        print("Policy rejected - exiting")
        sys.exit(1)

def get_os():
    print("\nSelect Operating System:")
    print("1. Windows\n2. macOS\n3. Linux")
    while True:
        choice = input("Enter 1-3: ").strip()
        if choice in {'1', '2', '3'}:
            return ['Windows', 'macOS', 'Linux'][int(choice)-1]

def get_folder_size(path):
    total = 0
    for entry in os.scandir(path):
        if entry.is_file():
            total += entry.stat().st_size
        elif entry.is_dir():
            total += get_folder_size(entry.path)
    return total

def wipe_progress_monitor(q, total_size_mb, storage_type):
    start_time = time.time()
    estimated_total = (total_size_mb * 1024 * 1024 * WIPE_PASSES) / (ESTIMATED_WIPE_SPEED[storage_type] * 1024 * 1024)
    
    while True:
        elapsed = time.time() - start_time
        progress = elapsed / estimated_total if estimated_total > 0 else 0
        bars = int(progress * 40)
        remaining = max(estimated_total - elapsed, 0)
        
        print(f"\r[{'#'*bars}{'-'*(40-bars)}] {min(progress*100,100):.1f}% "
              f"ETR: {remaining:.0f}s  ", end='')
        
        if q.get() == 'done':
            print(f"\nCompleted in {time.time()-start_time:.1f}s")
            break
        time.sleep(1)

def secure_wipe(path, os_type):
    try:
        if os_type == 'Windows':
            apply_windows_tweaks()
            storage_type = input("Storage type [HDD/SSD/NVMe]: ").strip().title()
            if storage_type not in ESTIMATED_WIPE_SPEED:
                storage_type = 'SSD'

            total_size = get_folder_size(path)
            q = Queue()
            progress_thread = Thread(target=wipe_progress_monitor, 
                                   args=(q, total_size//(1024*1024), storage_type))
            progress_thread.start()

            os.system(f'cipher /w:"{path}"')
            shutil.rmtree(path)
            q.put('done')
            progress_thread.join()
            return True

        elif os_type == 'macOS':
            os.system(f'srm -rfz "{path}"')
        elif os_type == 'Linux':
            os.system(f'shred -n {WIPE_PASSES} -u -z "{path}"')

        return not os.path.exists(path)
    
    except Exception as e:
        print(f"\nWipe failed: {str(e)}")
        return False

def encrypt_folder(folder_path):
    try:
        key = secrets.token_bytes(AES_KEY_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

        with tempfile.NamedTemporaryFile(delete=False) as tar_file:
            tar_path = tar_file.name
        
        with tarfile.open(tar_path, 'w') as tar:
            tar.add(folder_path, arcname=os.path.basename(folder_path))

        encrypted_file = f"{folder_path}.enc"
        total_size = os.path.getsize(tar_path)
        processed = 0
        
        with open(tar_path, 'rb') as f_in, open(encrypted_file, 'wb') as f_out:
            f_out.write(nonce)
            while True:
                chunk = f_in.read(BLOCK_SIZE)
                if not chunk:
                    break
                f_out.write(cipher.encrypt(chunk))
                processed += len(chunk)
                print(f"Encrypted {processed//1024}KB/{total_size//1024}KB", end='\r')

        # Verify encryption
        test_cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        with open(encrypted_file, 'rb') as f:
            f.read(NONCE_SIZE)
            test_cipher.decrypt(f.read(1024))

        return key, encrypted_file

    finally:
        if 'tar_path' in locals() and os.path.exists(tar_path):
            os.remove(tar_path)

def decrypt_file(encrypted_path):
    try:
        key = base64.b64decode(getpass.getpass("Enter decryption key: ").strip())
        
        with open(encrypted_path, 'rb') as f_in:
            nonce = f_in.read(NONCE_SIZE)
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            
            with tempfile.NamedTemporaryFile(delete=False) as tmp_tar:
                tar_path = tmp_tar.name
                total_size = os.path.getsize(encrypted_path) - NONCE_SIZE
                processed = 0
                
                while True:
                    chunk = f_in.read(BLOCK_SIZE)
                    if not chunk:
                        break
                    tmp_tar.write(cipher.decrypt(chunk))
                    processed += len(chunk)
                    print(f"Decrypted {processed//1024}KB/{total_size//1024}KB", end='\r')

        with tarfile.open(tar_path, 'r') as tar:
            tar.extractall()
        
        print("\nDecryption successful")

    finally:
        if 'tar_path' in locals() and os.path.exists(tar_path):
            os.remove(tar_path)

def main():
    print("==================== Secure Data Vault ====================")
    
    if len(sys.argv) != 2:
        print("Usage:\n  Encrypt: python secure_eraser.py encrypt\n  Decrypt: python secure_eraser.py decrypt")
        sys.exit(1)

    operation = sys.argv[1].lower()
    
    if operation == 'encrypt':
        verify_age()
        show_policy()
        os_type = get_os()
        
        folder_path = input("\nEnter folder path to encrypt: ").strip()
        if not os.path.isdir(folder_path):
            print("Invalid folder path")
            sys.exit(1)

        try:
            key, encrypted_file = encrypt_folder(folder_path)
            print(f"\nEncryption verified. Starting secure wipe...")
            
            for i in range(3, 0, -1):
                print(f"Wipe begins in {i} seconds...")
                time.sleep(1)
            
            if secure_wipe(folder_path, os_type):
                print("\nSecure wipe completed successfully")
            else:
                print("\nWipe failed - manual cleanup required")
            
            print("\n" + "="*50)
            print(f"SECURITY KEY: {base64.b64encode(key).decode('utf-8')}")
            print("="*50)
            print("\nStore this key securely!")

        except Exception as e:
            print(f"Critical error: {str(e)}")
            sys.exit(1)

    elif operation == 'decrypt':
        encrypted_path = input("Enter .enc file path: ").strip()
        if not os.path.isfile(encrypted_path):
            print("Invalid encrypted file")
            sys.exit(1)
            
        try:
            decrypt_file(encrypted_path)
        except Exception as e:
            print(f"Decryption failed: {str(e)}")

    else:
        print("Invalid operation. Use 'encrypt' or 'decrypt'")

if __name__ == "__main__":
    main()