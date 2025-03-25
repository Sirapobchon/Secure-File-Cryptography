import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import json
import encryption
from cryptography.exceptions import InvalidTag

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
        self.full_input_path = ""
        self.full_output_path = ""

        # UI
        self.create_widgets()

    def _strip_enc(self, filename):
        return filename[:-4] if filename.endswith(".enc") else filename + ".dec"

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
        self.decrypt_btn = ctk.CTkButton(self, text="Decrypt", command=self.decrypt_file)
        self.decrypt_btn.pack(pady=(15, 5))

    def blink_button(self, button, color="red"):
        original_color = button.cget("fg_color")

        def toggle(i=0):
            if i < 6:
                new_color = color if i % 2 == 0 else original_color
                button.configure(fg_color=new_color)
                self.after(200, toggle, i + 1)

        toggle()

    def browse_input(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.full_input_path = file_path
            filename = os.path.basename(file_path)
            self.input_path.set(filename)

            if filename.endswith(".enc"):
                # Decryption expected
                default_output = self._strip_enc(filename)
                self.blink_button(self.decrypt_btn)
            else:
                # Encryption expected
                default_output = filename + ".enc"

            self.output_path.set(default_output)
            self.full_output_path = os.path.join(os.path.dirname(file_path), default_output)

    def encrypt_file(self):
        try:
            input_path = self.full_input_path
            output_name = self.output_path.get() or os.path.basename(input_path) + ".enc"
            password = self.password.get()
            method = self.method.get()

            if not input_path or not password:
                raise ValueError("Please provide both input file and password.")

            self.full_output_path = os.path.join(
                os.path.dirname(input_path),
                output_name
            )

            # ❗ Check for same name as input
            if os.path.abspath(self.full_output_path) == os.path.abspath(input_path):
                raise ValueError("Output file name cannot be the same as the input file.")

            # ❗ Check if file already exists
            if os.path.exists(self.full_output_path):
                confirm = messagebox.askyesno(
                    "File Already Exists",
                    f"'{output_name}' already exists. Do you want to overwrite it?"
                )
                if not confirm:
                    return  # Cancel encryption

            encryption.encrypt_file(method, input_path, self.full_output_path, password)
            save_settings(method)
            messagebox.showinfo("Success", f"File encrypted and saved as:\n{self.full_output_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e) or repr(e) or "An unknown error occurred.")

    def decrypt_file(self):
        try:
            input_path = self.full_input_path
            output_name = self.output_path.get() or os.path.basename(self._strip_enc(input_path))
            password = self.password.get()
            method = self.method.get()

            if not input_path or not password:
                raise ValueError("Please provide both input file and password.")

            # 👇 Apply same logic for decrypt
            self.full_output_path = os.path.join(
                os.path.dirname(input_path),
                output_name
            )

            # ❗ Check if file already exists
            if os.path.exists(self.full_output_path):
                confirm = messagebox.askyesno(
                    "File Already Exists",
                    f"'{output_name}' already exists. Do you want to overwrite it?"
                )
                if not confirm:
                    return  # Cancel encryption

            encryption.decrypt_file(method, input_path, self.full_output_path, password)
            save_settings(method)
            messagebox.showinfo("Success", f"File decrypted and saved as:\n{self.full_output_path}")
        except InvalidTag:
            messagebox.showerror("Decryption Failed", "The password is incorrect or the file has been modified.")
        except Exception as e:
            messagebox.showerror("Error", str(e) or repr(e) or "An unknown error occurred.")


# ========== Run the App ==========
if __name__ == '__main__':
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = EncryptionApp()
    app.mainloop()
