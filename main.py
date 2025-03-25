import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import json
import encryption

SETTINGS_FILE = "settings.json"
DEFAULT_METHOD = "AES-256-GCM"

# ========== Save/Load Settings ==========
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r') as f:
            return json.load(f).get("method", DEFAULT_METHOD)
    return DEFAULT_METHOD

def save_settings(method):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump({"method": method}, f)

# ========== Main App Class ==========
class EncryptionApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure File Encryption")
        self.geometry("360x480")
        self.resizable(True, True)

        # Variables
        self.input_path = ctk.StringVar()
        self.output_path = ctk.StringVar()
        self.password = ctk.StringVar()
        self.method = ctk.StringVar(value=load_settings())

        # UI
        self.create_widgets()

    def create_widgets(self):
        ctk.CTkLabel(self, text="Input File:").pack(pady=(20, 5))
        ctk.CTkEntry(self, textvariable=self.input_path, width=350).pack()
        ctk.CTkButton(self, text="Browse", command=self.browse_input).pack(pady=5)

        ctk.CTkLabel(self, text="Output File (optional):").pack(pady=(10, 5))
        ctk.CTkEntry(self, textvariable=self.output_path, width=350).pack()

        ctk.CTkLabel(self, text="Password:").pack(pady=(10, 5))
        ctk.CTkEntry(self, textvariable=self.password, show="*", width=350).pack()

        ctk.CTkLabel(self, text="Encryption Method:").pack(pady=(10, 5))
        ctk.CTkOptionMenu(self, values=["AES-256-GCM", "ChaCha20-Poly1305"], variable=self.method).pack()

        ctk.CTkButton(self, text="Encrypt", command=self.encrypt_file).pack(pady=(15, 5))
        ctk.CTkButton(self, text="Decrypt", command=self.decrypt_file).pack(pady=(15, 5))

    def browse_input(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.input_path.set(file_path)
            if not self.output_path.get():
                self.output_path.set(file_path + ".enc")

    def encrypt_file(self):
        try:
            input_path = self.input_path.get()
            output_path = self.output_path.get() or (input_path + ".enc")
            password = self.password.get()
            method = self.method.get()

            if not input_path or not password:
                raise ValueError("Please provide both input file and password.")

            encryption.encrypt_file(method, input_path, output_path, password)
            save_settings(method)
            messagebox.showinfo("Success", f"File encrypted and saved as:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):
        try:
            input_path = self.input_path.get()
            output_path = self.output_path.get() or self._strip_enc(input_path)
            password = self.password.get()
            method = self.method.get()

            if not input_path or not password:
                raise ValueError("Please provide both input file and password.")

            encryption.decrypt_file(method, input_path, output_path, password)
            save_settings(method)
            messagebox.showinfo("Success", f"File decrypted and saved as:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _strip_enc(self, filename):
        return filename[:-4] if filename.endswith(".enc") else filename + ".dec"

# ========== Run the App ==========
if __name__ == '__main__':
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = EncryptionApp()
    app.mainloop()
