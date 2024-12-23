import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
from tkinter.font import Font
import bcrypt
import os
import pickle
import rsa
from SIH import SIH
from blockchain import Blockchain
from util import verify_integrity

# Constants
THEME_COLOR = "#2c3e50"  # Dark blue-gray
ACCENT_COLOR = "#3498db"  # Bright blue
BG_COLOR = "#ecf0f1"     # Light gray
TEXT_COLOR = "#2c3e50"   # Dark blue-gray
BUTTON_BG = "#3498db"    # Bright blue
BUTTON_FG = "white"

class CustomDialog(tk.Toplevel):
    def __init__(self, parent, title, prompt, show=None):
        super().__init__(parent)
        self.result = None
        
        # Window setup
        self.title(title)
        self.geometry("400x200")
        self.configure(bg=BG_COLOR)
        self.resizable(False, False)
        
        self.transient(parent)
        self.grab_set()
        
        frame = ttk.Frame(self, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text=prompt).pack(pady=10)
        
        self.entry = ttk.Entry(frame, show=show)
        self.entry.pack(pady=10, fill=tk.X)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="OK", command=self.ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.cancel).pack(side=tk.LEFT, padx=5)
        
        self.entry.focus_set()
        self.bind("<Return>", lambda e: self.ok())
        self.bind("<Escape>", lambda e: self.cancel())

    def ok(self):
        self.result = self.entry.get()
        self.destroy()

    def cancel(self):
        self.destroy()

class ModernGUI:
    def __init__(self):
        self.setup_files()
        self.setup_blockchain()
        self.setup_keys()
        self.create_styles()
        self.show_auth_screen()

    def setup_files(self):
        self.CREDENTIALS_FILE = "credentials.pkl"

    def setup_blockchain(self):
        self.blockchain = Blockchain()

    def setup_keys(self):
        self.public_key, self.private_key = rsa.newkeys(2048)
        self.symmetric_key = os.urandom(32)

    def create_styles(self):
        self.style = ttk.Style()
        self.style.configure('Custom.TButton',
                           padding=10,
                           font=('Helvetica', 10))
        
        self.style.configure('Title.TLabel',
                           font=('Helvetica', 16, 'bold'),
                           foreground=THEME_COLOR)
        
        self.style.configure('Subtitle.TLabel',
                           font=('Helvetica', 12),
                           foreground=TEXT_COLOR)

    def custom_dialog(self, title, prompt, show=None):
        dialog = CustomDialog(self.current_window, title, prompt, show)
        self.current_window.wait_window(dialog)
        return dialog.result

    def save_credentials(self, credentials):
        with open(self.CREDENTIALS_FILE, "wb") as file:
            pickle.dump(credentials, file)

    def load_credentials(self):
        if os.path.exists(self.CREDENTIALS_FILE):
            with open(self.CREDENTIALS_FILE, "rb") as file:
                return pickle.load(file)
        return {}

    def register_user(self):
        credentials = self.load_credentials()
        
        username = self.custom_dialog("Register", "Enter a username:")
        if not username or username in credentials:
            messagebox.showerror("Error", "Invalid or existing username.")
            return False
        
        password = self.custom_dialog("Register", "Enter a password:", show="*")
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return False

        is_admin = messagebox.askyesno("Role Selection", 
                                     "Is this an admin account?\n(Requires admin code)",
                                     icon='question')
        
        if is_admin:
            admin_code = self.custom_dialog("Admin Verification", 
                                          "Enter admin code:", 
                                          show="*")
            if admin_code != "admin123":
                messagebox.showerror("Error", "Invalid admin code.")
                return False
            role = "admin"
        else:
            role = "user"

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        credentials[username] = {
            "password": hashed_password,
            "role": role
        }
        
        self.save_credentials(credentials)
        messagebox.showinfo("Success", "Registration successful!")
        return True

    def login_user(self):
        credentials = self.load_credentials()
        
        username = self.custom_dialog("Login", "Enter your username:")
        if not username or username not in credentials:
            messagebox.showerror("Error", "Username not found.")
            return False, None
        
        password = self.custom_dialog("Login", "Enter your password:", show="*")
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return False, None

        if bcrypt.checkpw(password.encode(), credentials[username]["password"]):
            role = credentials[username]["role"]
            return True, role
        else:
            messagebox.showerror("Error", "Invalid password.")
            return False, None

    def execute_protocol(self):
        data = self.data_entry.get("1.0", "end").strip()
        if not data:
            self.show_status("Error: Data is required!", "error")
            return

        try:
            sih = SIH(data)
            data_hash = sih.calculate_hash(self.symmetric_key)
            encrypted_data = sih.encrypt_data(self.symmetric_key)
            signature = sih.generate_signature(self.private_key)

            # Ensure all binary data is stored as hex strings
            transaction_data = {
                'data': data,
                'data hash': data_hash,
                'encrypted data': encrypted_data.hex() if isinstance(encrypted_data, bytes) else encrypted_data,
                'symmetric key': self.symmetric_key.hex() if isinstance(self.symmetric_key, bytes) else self.symmetric_key,
                'signature': signature.hex() if isinstance(signature, bytes) else signature
            }
            
            self.blockchain.new_transaction(transaction_data)
            previous_hash = None if not self.blockchain.chain else self.blockchain.hash(self.blockchain.chain[-1])
            self.blockchain.new_block(previous_hash)

            self.show_status("Data stored successfully!", "success")
            self.data_entry.delete(1.0, tk.END)
            
        except Exception as e:
            self.show_status(f"Error: {str(e)}", "error")

    def show_status(self, message, status_type="info"):
        if hasattr(self, 'status_label'):
            color = {
                "error": "#e74c3c",
                "success": "#2ecc71",
                "info": TEXT_COLOR
            }.get(status_type, TEXT_COLOR)
            
            self.status_label.config(text=message, foreground=color)

    def verify_block_data(self, transaction):
        """
        Verify the integrity of a block's data
        """
        try:
            # Helper function to convert to bytes
            def ensure_bytes(data):
                if isinstance(data, str):
                    return bytes.fromhex(data)
                return data if isinstance(data, bytes) else None

            # Convert data to bytes safely
            encrypted_data = ensure_bytes(transaction.get('encrypted data'))
            symmetric_key = ensure_bytes(transaction.get('symmetric key'))
            signature = ensure_bytes(transaction.get('signature'))

            # Check if any required data is missing or invalid
            if not all([encrypted_data, symmetric_key]):
                return False, "Missing or invalid data"

            verification_result, message = verify_integrity(
                transaction['data'],
                self.public_key,
                encrypted_data,
                symmetric_key,
                transaction['data hash'],
                signature
            )
            return verification_result, message
        except Exception as e:
            return False, f"Verification error: {str(e)}"

    def show_records(self):
        records_window = tk.Toplevel(self.current_window)
        records_window.title("Blockchain Records")
        records_window.geometry("800x600")
        records_window.configure(bg=BG_COLOR)

        title_frame = ttk.Frame(records_window, padding="20 20 20 10")
        title_frame.pack(fill=tk.X)
        ttk.Label(title_frame, 
                 text="Blockchain Records", 
                 style='Title.TLabel').pack()

        content_frame = ttk.Frame(records_window, padding="20")
        content_frame.pack(fill=tk.BOTH, expand=True)

        records_text = tk.Text(content_frame,
                             font=('Courier', 10),
                             bg=BG_COLOR,
                             fg=TEXT_COLOR,
                             wrap=tk.WORD,
                             padx=10,
                             pady=10)
        records_text.pack(fill=tk.BOTH, expand=True)

        # Create tags for different verification statuses
        records_text.tag_configure("verified", foreground="#2ecc71")  # Green
        records_text.tag_configure("unverified", foreground="#e74c3c")  # Red
        records_text.tag_configure("heading", font=('Courier', 12, 'bold'))

        scrollbar = ttk.Scrollbar(content_frame, 
                                orient=tk.VERTICAL, 
                                command=records_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        records_text.configure(yscrollcommand=scrollbar.set)

        if self.blockchain.chain:
            for block in self.blockchain.chain:
                records_text.insert(tk.END, f"Block #{block['index']}\n", "heading")
                records_text.insert(tk.END, "-" * 40 + "\n")
                
                for transaction in block['transactions']:
                    # Verify the data
                    is_verified, message = self.verify_block_data(transaction)
                    
                    # Display data with verification status
                    status_tag = "verified" if is_verified else "unverified"
                    status_symbol = "✓" if is_verified else "✗"
                    
                    records_text.insert(tk.END, f"Data: {transaction['data']}\n")
                    records_text.insert(tk.END, 
                                     f"Status: {status_symbol} {message}\n", 
                                     status_tag)
                records_text.insert(tk.END, "\n")
        else:
            records_text.insert(tk.END, "No records found in the blockchain.")

        records_text.configure(state='disabled')

    def create_main_gui(self, user_role):
        self.current_window = tk.Tk()
        self.current_window.title(f"Blockchain Protocol - {user_role.upper()}")
        self.current_window.geometry("800x600")
        self.current_window.configure(bg=BG_COLOR)

        main_frame = ttk.Frame(self.current_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Create top frame for title and logout button
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Add title to the left
        ttk.Label(top_frame, 
                text=f"Blockchain Protocol Interface - {user_role.capitalize()}", 
                style='Title.TLabel').pack(side=tk.LEFT)

        # Add logout button to the right
        def logout():
            self.current_window.destroy()
            self.show_auth_screen()

        ttk.Button(top_frame,
                text="Logout",
                style='Custom.TButton',
                command=logout).pack(side=tk.RIGHT)

        if user_role == "admin":
            data_frame = ttk.LabelFrame(main_frame, text="Data Entry", padding="10")
            data_frame.pack(fill=tk.X, pady=10)

            self.data_entry = tk.Text(data_frame, 
                                    height=5, 
                                    font=('Helvetica', 10),
                                    bg="white",
                                    fg=TEXT_COLOR)
            self.data_entry.pack(fill=tk.X, pady=5)

            btn_frame = ttk.Frame(data_frame)
            btn_frame.pack(fill=tk.X, pady=5)

            ttk.Button(btn_frame, 
                    text="Store Data", 
                    style='Custom.TButton',
                    command=self.execute_protocol).pack(side=tk.LEFT, padx=5)

            self.status_label = ttk.Label(data_frame, 
                                        text="Ready", 
                                        style='Subtitle.TLabel')
            self.status_label.pack(pady=5)

        ttk.Button(main_frame, 
                text="View Blockchain Records",
                style='Custom.TButton',
                command=self.show_records).pack(pady=20)

        self.current_window.mainloop()

    def show_auth_screen(self):
        self.current_window = tk.Tk()
        self.current_window.title("Blockchain Protocol Authentication")
        self.current_window.geometry("400x500")
        self.current_window.configure(bg=BG_COLOR)

        main_frame = ttk.Frame(self.current_window, padding="40")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, 
                 text="Welcome to\nBlockchain Protocol", 
                 style='Title.TLabel',
                 justify='center').pack(pady=(0, 40))

        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=20)

        def login_action():
            success, role = self.login_user()
            if success:
                self.current_window.destroy()
                self.create_main_gui(role)

        ttk.Button(buttons_frame, 
                  text="Login",
                  style='Custom.TButton',
                  command=login_action).pack(fill=tk.X, pady=10)

        ttk.Button(buttons_frame, 
                  text="Register",
                  style='Custom.TButton',
                  command=self.register_user).pack(fill=tk.X, pady=10)

        self.current_window.mainloop()

if __name__ == "__main__":
    app = ModernGUI()