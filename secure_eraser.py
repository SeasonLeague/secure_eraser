import os
import sys
import platform
import argparse
import secrets
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, kdf
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from tqdm import tqdm
import psutil

class SecureDelete:
    def __init__(self):
        # DoD 5220.22-M style overwrite patterns
        self.patterns = [
            b'\x00',  # all zeros
            b'\xFF',  # all ones
            b'\x55',  # pattern 01010101
            b'\xAA',  # pattern 10101010
            b'\x92\x49\x24',  # random pattern 1
            b'\x49\x24\x92',  # random pattern 2
            b'\x24\x92\x49'   # random pattern 3
        ]

    def secure_delete_file(self, file_path: str, progress_bar: Optional[tqdm] = None):
        if not os.path.exists(file_path):
            return
            
        file_size = os.path.getsize(file_path)
        chunk_size = 4096

        # Perform 7 passes with different patterns
        with open(file_path, 'rb+') as f:
            for pattern in self.patterns:
                f.seek(0)
                remaining = file_size
                pattern_chunk = pattern * (chunk_size // len(pattern) + 1)
                
                while remaining > 0:
                    write_size = min(chunk_size, remaining)
                    f.write(pattern_chunk[:write_size])
                    if progress_bar:
                        progress_bar.update(write_size)
                    remaining -= write_size
                    
                f.flush()
                os.fsync(f.fileno())

            # Final pass with random data
            f.seek(0)
            remaining = file_size
            while remaining > 0:
                write_size = min(chunk_size, remaining)
                f.write(secrets.token_bytes(write_size))
                if progress_bar:
                    progress_bar.update(write_size)
                remaining -= write_size
                
            f.flush()
            os.fsync(f.fileno())

        os.remove(file_path)

    def secure_delete_folder(self, folder_path: str):
        if not os.path.exists(folder_path):
            return

        for root, dirs, files in os.walk(folder_path, topdown=False):
            for name in files:
                file_path = os.path.join(root, name)
                print(f"Securely deleting file: {file_path}")
                self.secure_delete_file(file_path)

            for name in dirs:
                dir_path = os.path.join(root, name)
                try:
                    os.rmdir(dir_path)
                except OSError:
                    pass

        try:
            os.rmdir(folder_path)
        except OSError:
            pass

class FolderEncryption:
    def __init__(self):
        self.secure_delete = SecureDelete()
        
    def derive_key(self, password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        if salt is None:
            salt = secrets.token_bytes(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt
        
    def encrypt_folder(self, folder_path: str, password: str) -> tuple[str, bytes]:
        if not os.path.exists(folder_path):
            raise FileNotFoundError("Folder not found")
            
        # Generate encryption key and salt
        key, salt = self.derive_key(password)
        iv = secrets.token_bytes(16)
        
        temp_encrypted_folder = folder_path + '.temp_encrypted'
        os.makedirs(temp_encrypted_folder, exist_ok=True)
        
        total_files = sum([len(files) for _, _, files in os.walk(folder_path)])
        with tqdm(total=total_files, desc="Encrypting files") as pbar:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    src_path = os.path.join(root, file)
                    rel_path = os.path.relpath(src_path, folder_path)
                    dst_path = os.path.join(temp_encrypted_folder, rel_path + '.enc')
                    
                    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                    
                    # Create new cipher for each file
                    cipher = Cipher(
                        algorithms.AES(key),
                        modes.CBC(iv),
                        backend=default_backend()
                    )
                    encryptor = cipher.encryptor()
                    
                    with open(src_path, 'rb') as src, open(dst_path, 'wb') as dst:
                        dst.write(iv)
                        
                        padder = padding.PKCS7(128).padder()
                        
                        while True:
                            chunk = src.read(64 * 1024)
                            if not chunk:
                                break
                                
                            padded_data = padder.update(chunk)
                            if padded_data:
                                encrypted_chunk = encryptor.update(padded_data)
                                dst.write(encrypted_chunk)
                            
                        padded_data = padder.finalize()
                        encrypted_chunk = encryptor.update(padded_data) + encryptor.finalize()
                        dst.write(encrypted_chunk)

                    final_path = src_path + '.enc'
                    os.replace(dst_path, final_path)
                    
                    print(f"\nSecurely deleting {src_path} with 7-pass overwrite...")
                    self.secure_delete.secure_delete_file(src_path)
                    pbar.update(1)

        self.secure_delete.secure_delete_folder(temp_encrypted_folder)
        
        return salt.hex(), iv.hex()
        
    def decrypt_folder(self, folder_path: str, salt: str, iv: str, password: str):
        salt = bytes.fromhex(salt)
        iv = bytes.fromhex(iv)
        
        key, _ = self.derive_key(password, salt)
        
        temp_decrypted_folder = folder_path + '.temp_decrypted'
        os.makedirs(temp_decrypted_folder, exist_ok=True)
        
        encrypted_files = []
        for root, _, files in os.walk(folder_path):
            encrypted_files.extend([os.path.join(root, f) for f in files if f.endswith('.enc')])
        
        with tqdm(total=len(encrypted_files), desc="Decrypting files") as pbar:
            for enc_file in encrypted_files:
                dec_file = enc_file[:-4] 
                
                try:
                    with open(enc_file, 'rb') as src, open(dec_file, 'wb') as dst:
                        cipher = Cipher(
                            algorithms.AES(key),
                            modes.CBC(iv),
                            backend=default_backend()
                        )
                        decryptor = cipher.decryptor()
                        
                        unpadder = padding.PKCS7(128).unpadder()
                        
                        src.read(16)
                        
                        while True:
                            chunk = src.read(64 * 1024)
                            if not chunk:
                                break
                                
                            decrypted_chunk = decryptor.update(chunk)
                            try:
                                unpadded_chunk = unpadder.update(decrypted_chunk)
                                if unpadded_chunk:
                                    dst.write(unpadded_chunk)
                            except ValueError as e:
                                print(f"Error decrypting {enc_file}: {str(e)}")
                                break
                        
                        try:
                            decrypted_chunk = decryptor.finalize()
                            unpadded_chunk = unpadder.update(decrypted_chunk) + unpadder.finalize()
                            dst.write(unpadded_chunk)
                        except ValueError as e:
                            print(f"Error finalizing decryption of {enc_file}: {str(e)}")
                            continue
                    
                    print(f"\nSecurely deleting encrypted file: {enc_file}")
                    self.secure_delete.secure_delete_file(enc_file)
                    pbar.update(1)
                    
                except Exception as e:
                    print(f"Error processing {enc_file}: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Secure Folder Encryption Tool")
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Action to perform')
    parser.add_argument('path', help='Path to the folder')
    parser.add_argument('--password', help='Password for encryption/decryption')
    parser.add_argument('--salt', help='Salt value for decryption')
    parser.add_argument('--iv', help='IV value for decryption')
    
    args = parser.parse_args()
    
    encryptor = FolderEncryption()
    
    try:
        if args.action == 'encrypt':
            if not args.password:
                args.password = input("Enter password for encryption: ")
            
            salt, iv = encryptor.encrypt_folder(args.path, args.password)
            print("\nEncryption completed successfully!")
            print("SAVE THESE VALUES SECURELY - YOU WILL NEED THEM TO DECRYPT:")
            print(f"Salt: {salt}")
            print(f"IV: {iv}")
            print("\nWARNING: Without these values and your password, your files cannot be recovered!")
            
        else:  # decrypt
            if not args.password:
                args.password = input("Enter password for decryption: ")
            if not args.salt:
                args.salt = input("Enter salt value: ")
            if not args.iv:
                args.iv = input("Enter IV value: ")
                
            encryptor.decrypt_folder(args.path, args.salt, args.iv, args.password)
            print("\nDecryption completed successfully!")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
