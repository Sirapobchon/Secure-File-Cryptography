# 🔐 Secure File Encryption Tool
A simple and secure file encryption and decryption tool with a graphical interface built using `customtkinter`. Supports two modern encryption methods:
- **AES-256-GCM with PBKDF2**
- **ChaCha20-Poly1305 with Argon2**

Choose your preferred method and protect any file with a password.

---

## 🚀 Features
- 🔒 AES-256-GCM & ChaCha20-Poly1305 encryption
- 🧠 Strong password-based key derivation: PBKDF2 or Argon2
- 🖥 User-friendly GUI with customtkinter
- 💾 Encrypt or decrypt any file type (images, docs, PDFs, etc.)
- 📄 Saves last-used encryption mode automatically
- 🛡 Integrity protected (tampered files will fail to decrypt)

---

## 📂 File Structure
```
secure_encryption_project/
├── encryption.py       # Core encryption/decryption logic
├── main.py             # GUI using customtkinter
├── settings.json       # Saves last used encryption mode
└── requirement.txt     # Requirements
```

---

## 📦 Requirements
- Python 3.8+
- Install dependencies:
```bash
pip install -r .\requirement.txt
```
    - cryptography
    - argon2-cffi
    - customtkinter

---

## ▶️ How to Use
### 1. Run the app
```bash
python main.py
```

### 2. In the GUI:
- Select the file you want to encrypt or decrypt
- Enter a password (remember it! 🔑)
- Choose an encryption method from the dropdown
- Click **Encrypt** or **Decrypt**
- Done! 🎉 Output file will be saved (defaults to `.enc` extension on encryption)

---

## 🔄 Supported Encryption Methods
### AES-256-GCM
- Fast and secure block cipher with built-in authentication
- Uses PBKDF2 to derive keys from your password

### ChaCha20-Poly1305
- High-performance stream cipher with built-in authentication
- Uses Argon2 (memory-hard) for key derivation (stronger protection)

---

## ⚠️ Notes
- If you lose your password, **you cannot recover the file**.
- If a file is tampered with, decryption will fail.

---

## 🧪 Testing
Try encrypting:
- `.txt` documents
- `.jpg` images
- `.pdf` files

Then decrypt them back to confirm full recovery. You can also test wrong passwords or tampered files to see error handling.

---

## 🤝 Acknowledgments
- [Cryptography](https://cryptography.io)
- [customtkinter](https://github.com/TomSchimansky/CustomTkinter)
- [Argon2 CFFI](https://github.com/hynek/argon2-cffi)
