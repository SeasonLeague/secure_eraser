import os
import sys
import argparse
from tqdm import tqdm
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def secure_delete(filepath, passes=100, block_size=4096):
    """
    Securely delete a file by overwriting it with random data for a given number of passes,
    then removing the file. A progress bar is shown for the overwriting passes.
    """
    if not os.path.isfile(filepath):
        print(f"File not found or not a regular file: {filepath}")
        return

    filesize = os.path.getsize(filepath)
    print(f"\nStarting secure deletion of {filepath} ({filesize} bytes) with {passes} passes...")

    try:
        with open(filepath, "r+b") as f:
            # tqdm progress bar for passes.
            for _ in tqdm(range(passes), desc="Overwriting passes", unit="pass"):
                f.seek(0)
                total_written = 0
                while total_written < filesize:
                    chunk_size = min(block_size, filesize - total_written)
                    random_data = os.urandom(chunk_size)
                    f.write(random_data)
                    total_written += chunk_size

                f.flush()
                os.fsync(f.fileno())

        os.remove(filepath)
        print(f"File {filepath} has been securely deleted.\n")
    except Exception as e:
        print(f"Error during secure deletion of {filepath}: {e}")

def encrypt_file(input_filepath, key):
    """
    Encrypt a single file using AES-256 in GCM mode.
    The output file will be saved with a '.enc' extension.
    Format: [12-byte nonce][16-byte tag][ciphertext]
    """
    try:
        with open(input_filepath, "rb") as f:
            plaintext = f.read()
    except Exception as e:
        print(f"Error reading {input_filepath}: {e}")
        return False

    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    output_filepath = input_filepath + ".enc"
    try:
        with open(output_filepath, "wb") as f:
            f.write(nonce)
            f.write(tag)
            f.write(ciphertext)
        print(f"Encrypted {input_filepath} -> {output_filepath}")
    except Exception as e:
        print(f"Error writing encrypted file {output_filepath}: {e}")
        return False

    # Securely delete the original file with progress bar updates.
    secure_delete(input_filepath)
    return True

def decrypt_file(input_filepath, key):
    """
    Decrypt a single file that was encrypted using AES-256 GCM.
    Assumes file format: [12-byte nonce][16-byte tag][ciphertext].
    The decrypted file will be saved without the '.enc' extension.
    """
    try:
        with open(input_filepath, "rb") as f:
            file_data = f.read()
    except Exception as e:
        print(f"Error reading {input_filepath}: {e}")
        return False

    if len(file_data) < 28:
        print(f"File {input_filepath} is too short to be a valid encrypted file.")
        return False

    nonce = file_data[:12]
    tag = file_data[12:28]
    ciphertext = file_data[28:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        print(f"Decryption failed for {input_filepath}: {e}")
        return False

    # Remove the ".enc" extension if present.
    if input_filepath.endswith(".enc"):
        output_filepath = input_filepath[:-4]
    else:
        output_filepath = input_filepath + ".dec"

    try:
        with open(output_filepath, "wb") as f:
            f.write(plaintext)
        print(f"Decrypted {input_filepath} -> {output_filepath}")
    except Exception as e:
        print(f"Error writing decrypted file {output_filepath}: {e}")
        return False

    # Securely delete the encrypted file with progress bar updates.
    secure_delete(input_filepath)
    return True

def process_folder(folder_path, key, mode="encrypt"):
    """
    Recursively process files in a folder.
    For encryption, all files (except those already encrypted) are encrypted.
    For decryption, only files ending with '.enc' are processed.
    A progress bar is displayed during processing.
    """
    file_list = []

    # Walk through the directory and collect files.
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            filepath = os.path.join(root, file)
            if mode == "encrypt":
                if filepath.endswith(".enc"):
                    continue
                file_list.append(filepath)
            elif mode == "decrypt":
                if filepath.endswith(".enc"):
                    file_list.append(filepath)

    total_files = len(file_list)
    if total_files == 0:
        print("No files to process.")
        return

    print(f"\nFound {total_files} file(s) to {mode}.\n")

    # Process each file with a progress bar.
    for filepath in tqdm(file_list, desc=f"Processing files for {mode}", unit="file"):
        if mode == "encrypt":
            if not encrypt_file(filepath, key):
                print(f"Failed to encrypt {filepath}")
        elif mode == "decrypt":
            if not decrypt_file(filepath, key):
                print(f"Failed to decrypt {filepath}")

def main():
    parser = argparse.ArgumentParser(
        description="Folder Encryption Tool using AES-256 with secure deletion (100 overwrite passes) and progress bars."
    )
    parser.add_argument(
        "mode",
        choices=["encrypt", "decrypt"],
        help="Mode: 'encrypt' to encrypt files in a folder, 'decrypt' to decrypt them."
    )
    parser.add_argument(
        "folder",
        help="Path to the folder to process."
    )
    args = parser.parse_args()

    folder_path = os.path.abspath(args.folder)
    if not os.path.isdir(folder_path):
        print(f"Error: {folder_path} is not a valid directory.")
        sys.exit(1)

    if args.mode == "encrypt":
        key = get_random_bytes(32)  # 256-bit key for AES-256
        print("Encryption key (hex encoded):")
        print(key.hex())
        print("\nIMPORTANT: Copy and securely store this encryption key. Without it, you will not be able to decrypt your files!")
        confirmation = input("Proceed with encryption? (yes/no): ").strip().lower()
        if confirmation not in ["yes", "y"]:
            print("Encryption cancelled.")
            sys.exit(0)
        process_folder(folder_path, key, mode="encrypt")
        print("\nEncryption complete.")
    elif args.mode == "decrypt":
        key_hex = input("Enter the 256-bit decryption key (hex encoded): ").strip()
        try:
            key = bytes.fromhex(key_hex)
            if len(key) != 32:
                raise ValueError("Key is not 256-bit long.")
        except Exception as e:
            print(f"Invalid key: {e}")
            sys.exit(1)
        process_folder(folder_path, key, mode="decrypt")
        print("\nDecryption complete.")

if __name__ == "__main__":
    main()
