import os
import base64
from tkinter import *
from tkinter import filedialog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

# Function to get a key from a password
def get_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password)
    return key

# Encryption function
def encrypt_file(file_path, password):
    # Generate a random salt
    salt = os.urandom(16)
    key = get_key_from_password(password.encode(), salt)

    # Create a random IV
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # Read and encrypt the file
    with open(file_path, 'rb') as file:
        data = file.read()
        padder = PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save the encrypted file
    with open(file_path + ".enc", 'wb') as file:
        file.write(salt + iv + encrypted_data)

# Decryption function
def decrypt_file(file_path, password):
    with open(file_path, 'rb') as file:
        data = file.read()

    salt = data[:16]
    iv = data[16:32]
    encrypted_data = data[32:]

    key = get_key_from_password(password.encode(), salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = PKCS7(128).unpadder()
    data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Save the decrypted file
    with open(file_path[:-4], 'wb') as file:
        file.write(data)

# Tkinter UI
def browse_file():
    file_path = filedialog.askopenfilename()
    selected_file.set(file_path)

def encrypt_button_click():
    file_path = selected_file.get()
    password = password_entry.get()
    encrypt_file(file_path, password)

def decrypt_button_click():
    file_path = selected_file.get()
    password = password_entry.get()
    decrypt_file(file_path, password)

# Create a basic Tkinter UI
root = Tk()
root.title("File Encryption Tool")

selected_file = StringVar()

Label(root, text="File:").grid(row=0, column=0)
Entry(root, textvariable=selected_file, width=50).grid(row=0, column=1)
Button(root, text="Browse", command=browse_file).grid(row=0, column=2)

Label(root, text="Password:").grid(row=1, column=0)
password_entry = Entry(root, show="*", width=50)
password_entry.grid(row=1, column=1)

Button(root, text="Encrypt", command=encrypt_button_click).grid(row=2, column=0, pady=10)
Button(root, text="Decrypt", command=decrypt_button_click).grid(row=2, column=1, pady=10)

root.mainloop()
