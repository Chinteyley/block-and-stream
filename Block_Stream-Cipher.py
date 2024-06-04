from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import tkinter as tk
from tkinter import ttk

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = base64.b64encode(cipher.encrypt(pad(plaintext.encode(), AES.block_size)))
    return ciphertext.decode()

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return decrypted.decode()

def rc4_encrypt(plaintext, key):
    S = list(range(256))
    j = 0
    out = []
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))
    return ''.join(out)

def encrypt():
    Answer_entry.delete(0, tk.END)
    key = key_entry.get()
    plaintext = plaintext_entry.get()
    if encryption_type.get() == "AES":
        key.encode()
        ciphertext = aes_encrypt(plaintext, key)
    else:
        key = [ord(c) for c in key]
        ciphertext = rc4_encrypt(plaintext, key)
    Answer_entry.insert(0, ciphertext)

def decrypt():
    Answer_entry.delete(0, tk.END)
    key = key_entry.get()
    ciphertext = ciphertext_entry.get()
    key.encode()
    if encryption_type.get() == "AES":
        decrypted_text = aes_decrypt(ciphertext, key)
    else:
        key = [ord(c) for c in key]
        decrypted_text = rc4_encrypt(ciphertext, key)
    Answer_entry.insert(0, decrypted_text)

root = tk.Tk()
root.title("Encryption/Decryption")

encryption_type = tk.StringVar()
encryption_type.set("AES")

key_label = ttk.Label(root, text="Key:")
key_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
key_entry = ttk.Entry(root)
key_entry.grid(row=0, column=1, padx=5, pady=5)

plaintext_label = ttk.Label(root, text="Plaintext:")
plaintext_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
plaintext_entry = ttk.Entry(root)
plaintext_entry.grid(row=1, column=1, padx=5, pady=5)

ciphertext_label = ttk.Label(root, text="Ciphertext:")
ciphertext_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
ciphertext_entry = ttk.Entry(root)
ciphertext_entry.grid(row=2, column=1, padx=5, pady=5)

encryption_type_label = ttk.Label(root, text="Encryption Type:")
encryption_type_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")
encryption_type_menu = ttk.Combobox(root, textvariable=encryption_type, values=["AES", "RC4"], state="readonly")
encryption_type_menu.grid(row=3, column=1, padx=5, pady=5)

encrypt_button = ttk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.grid(row=4, column=0, padx=5, pady=5)

decrypt_button = ttk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.grid(row=4, column=1, padx=5, pady=5)

Answer = ttk.Label(root, text="Answer:")
Answer.grid(row=5, column=0, padx=5, pady=5, sticky="w")
Answer_entry = ttk.Entry(root)
Answer_entry.grid(row=5, column=1, padx=5, pady=5)
root.mainloop()