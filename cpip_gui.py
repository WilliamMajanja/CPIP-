#!/usr/bin/env python3
"""CPIP Covert Key Manager - GUI for managing CPIP_COVERT_KEY"""

import base64
import os
import secrets
from pathlib import Path
from tkinter import (
    Tk,
    Frame,
    Label,
    Entry,
    Button,
    messagebox,
    Toplevel,
    StringVar,
    Scrollbar,
    Text,
    LabelFrame,
)
import tkinter.font as tkFont

# Application constants
WINDOW_WIDTH = 600
WINDOW_HEIGHT = 400
KEY_LENGTH = 32
ERROR_COLOR = "#ff6b6b"
SUCCESS_COLOR = "#51cf66"
INFO_COLOR = "#4dabf7"


def generate_secure_key():
    """Generate a secure 32-byte base64-encoded key."""
    return base64.b64encode(secrets.token_bytes(KEY_LENGTH)).decode()


def save_key_to_env(key: str, env_file: str = ".env"):
    """Save the key to environment file."""
    env_path = Path(env_file)
    
    if env_path.exists():
        with open(env_path, 'r') as f:
            lines = f.readlines()
    else:
        lines = []
    
    updated = False
    for i, line in enumerate(lines):
        if line.startswith('CPIP_COVERT_KEY='):
            lines[i] = f'CPIP_COVERT_KEY={key}\n'
            updated = True
            break
    
    if not updated:
        lines.append(f'CPIP_COVERT_KEY={key}\n')
    
    with open(env_path, 'w') as f:
        f.writelines(lines)
    
    # Also set the actual environment variable
    os.environ['CPIP_COVERT_KEY'] = key


def validate_key(key: str) -> tuple[bool, str]:
    """Validate the provided key."""
    if not key:
        return False, "Key cannot be empty"
    
    try:
        decoded = base64.b64decode(key)
        if len(decoded) < 16:
            return False, "Key must be at least 16 bytes"
        if len(decoded) > 64:
            return False, "Key cannot be longer than 64 bytes when encoded"
    except Exception:
        return False, "Key must be valid base64"
    
    return True, "Valid key"


def create_key_display_window(parent, key: str, description: str):
    """Create a window to display a generated key."""
    display_window = Toplevel(parent)
    display_window.title("Generated Secure Key")
    display_window.geometry("500x200")
    display_window.resizable(False, False)
    display_window.configure(bg="#f8f9fa")
    
    # Center the window
    x = (display_window.winfo_screenwidth() - 500) // 2
    y = (display_window.winfo_screenheight() - 200) // 2
    display_window.geometry(f"500x200+{x}+{y}")
    
    # Create styled frame
    main_frame = Frame(display_window, bg="#f8f9fa", padx=20, pady=20)
    main_frame.pack(expand=True, fill="both")
    
    # Title
    title_label = Label(
        main_frame,
        text="Generated Secure Key",
        font=("Arial", 12, "bold"),
        bg="#f8f9fa",
    )
    title_label.pack(pady=(0, 10))
    
    # Info label
    info_label = Label(
        main_frame,
        text=description,
        wraplength=460,
        justify="center",
        bg="#f8f9fa",
        fg="#495057",
    )
    info_label.pack(pady=(0, 15))
    
    # Key entry with copy functionality
    key_frame = Frame(main_frame, bg="#f8f9fa")
    key_frame.pack(fill="x", pady=(0, 15))
    
    key_var = StringVar(value=key)
    
    key_entry = Entry(
        key_frame,
        textvariable=key_var,
        width=50,
        font=("Courier", 10),
        bd=2,
        relief="solid",
    )
    key_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
    
    # Copy button
    def copy_to_clipboard():
        parent.clipboard_clear()
        parent.clipboard_append(key)
        messagebox.showinfo("Info", "Key copied to clipboard")
    
    copy_btn = Button(
        key_frame,
        text="📋 Copy",
        command=copy_to_clipboard,
        bg="#4dabf7",
        fg="white",
        relief="flat",
        padx=10,
    )
    copy_btn.pack(side="left")
    
    # OK button
    ok_btn = Button(
        main_frame,
        text="OK",
        command=display_window.destroy,
        bg="#51cf66",
        fg="white",
        relief="flat",
        padx=15,
        pady=5,
    )
    ok_btn.pack()


class CovertKeyManagerGUI:
    """GUI application for managing CPIP_COVERT_KEY."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("CPIP Covert Key Manager v5.1.1")
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        
        self.root.resizable(False, False)
        self.root.configure(bg="#f8f9fa")
        
        # Center the window
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - WINDOW_WIDTH) // 2
        y = (screen_height - WINDOW_HEIGHT) // 2
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}+{x}+{y}")
        
        self.current_key = self.load_existing_key()
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create the GUI widgets."""
        # Main container with padding
        main_frame = Frame(self.root, bg="#f8f9fa", padx=20, pady=20)
        main_frame.pack(expand=True, fill="both")
        
        # Header section
        header_frame = Frame(main_frame, bg="#f8f9fa")
        header_frame.pack(fill="x", pady=(0, 20))
        
        title_label = Label(
            header_frame,
            text="CPIP Covert Key Manager",
            font=("Arial", 16, "bold"),
            bg="#f8f9fa",
            fg="#2d3436",
        )
        title_label.pack()
        
        subtitle_label = Label(
            header_frame,
            text="Manage your CPIP covert channel encryption key",
            font=("Arial", 10),
            bg="#f8f9fa",
            fg="#636e72",
        )
        subtitle_label.pack(pady=(5, 0))
        
        # Key input section
        key_frame = LabelFrame(
            main_frame,
            text="Current Key",
            font=("Arial", 10, "bold"),
            bg="#f8f9fa",
            fg="#2d3436",
            bd=1,
            relief="solid",
            padx=10,
            pady=10,
        )
        key_frame.pack(fill="x", pady=(0, 15))
        
        key_entry_frame = Frame(key_frame, bg="#f8f9fa")
        key_entry_frame.pack(fill="x")
        
        self.key_var = StringVar(value=self.current_key)
        
        self.key_entry = Entry(
            key_entry_frame,
            textvariable=self.key_var,
            width=50,
            font=("Courier", 10),
            bd=2,
            relief="solid",
        )
        self.key_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Paste button
        paste_btn = Button(
            key_entry_frame,
            text="📥 Paste",
            command=self.paste_from_clipboard,
            bg="#ffa94d",
            fg="white",
            relief="flat",
            padx=10,
        )
        paste_btn.pack(side="left")
        
        # Action buttons section
        button_frame = Frame(main_frame, bg="#f8f9fa")
        button_frame.pack(fill="x", pady=(0, 15))
        
        # Left-aligned buttons
        Button(
            button_frame,
            text="🎲 Generate New Key",
            command=self.generate_new_key,
            bg="#4dabf7",
            fg="white",
            relief="flat",
            padx=15,
            pady=8,
        ).pack(side="left", padx=(0, 10))
        
        Button(
            button_frame,
            text="💾 Save to .env",
            command=self.save_key,
            bg="#51cf66",
            fg="white",
            relief="flat",
            padx=15,
            pady=8,
        ).pack(side="left", padx=(0, 10))
        
        Button(
            button_frame,
            text="✅ Apply Key",
            command=self.apply_key,
            bg="#7950f2",
            fg="white",
            relief="flat",
            padx=15,
            pady=8,
        ).pack(side="left", padx=(0, 10))
        
        Button(
            button_frame,
            text="🔄 Reset",
            command=self.reset_to_auto_generated,
            bg="#f03e3e",
            fg="white",
            relief="flat",
            padx=15,
            pady=8,
        ).pack(side="left")
        
        # Status section
        self.status_frame = LabelFrame(
            main_frame,
            text="Status",
            font=("Arial", 10, "bold"),
            bg="#f8f9fa",
            fg="#2d3436",
            bd=1,
            relief="solid",
            padx=10,
            pady=10,
        )
        self.status_frame.pack(fill="x")
        
        self.status_label = Label(
            self.status_frame,
            text="Status: Ready",
            bg="#f8f9fa",
            fg="#2d3436",
            anchor="w",
        )
        self.status_label.pack(fill="x")
        
        # Help section
        help_text = (
            "💡 Notes:\n"
            "• The key must be 32 bytes (base64 encoded)\n"
            "• Generated keys are automatically saved to .env\n"
            "• Keys need to be reapplied to running servers\n"
            "• Use Ctrl+V to paste from clipboard"
        )
        
        self.help_text = Text(
            main_frame,
            height=4,
            width=60,
            font=("Arial", 8),
            bg="#ffffff",
            fg="#495057",
            bd=1,
            relief="solid",
        )
        self.help_text.pack(pady=(15, 0))
        self.help_text.insert("1.0", help_text)
        self.help_text.config(state="disabled")
    
    def load_existing_key(self) -> str:
        """Load existing key from environment or .env file."""
        # Try environment variable first
        if 'CPIP_COVERT_KEY' in os.environ:
            return os.environ['CPIP_COVERT_KEY']
        
        # Try .env file
        env_path = Path('.env')
        if env_path.exists():
            with open(env_path, 'r') as f:
                for line in f:
                    if line.startswith('CPIP_COVERT_KEY='):
                        key_value = line.strip().split('=', 1)[1]
                        return key_value
        
        return ""
    
    def paste_from_clipboard(self):
        """Paste key from clipboard."""
        try:
            clipboard_text = self.root.clipboard_get()
            self.key_var.set(clipboard_text)
            self.update_status("Pasted key from clipboard", INFO_COLOR)
        except Exception:
            messagebox.showwarning(
                "Warning",
                "No text found in clipboard"
            )
    
    def generate_new_key(self):
        """Generate a new secure key and display it."""
        new_key = generate_secure_key()
        
        description = (
            "A new secure 32-byte key has been generated.\n"
            "\n"
            "Save this key securely - it's required to recover your covert messages!\n"
            "You can copy it now or enter it above."
        )
        
        create_key_display_window(self.root, new_key, description)
        self.key_var.set(new_key)
        
        self.update_status("New key generated", INFO_COLOR)
    
    def apply_key(self):
        """Apply the key to the current server session."""
        key = self.key_var.get()
        
        is_valid, message = validate_key(key)
        if not is_valid:
            self.show_error(f"Invalid key: {message}")
            return
        
        os.environ['CPIP_COVERT_KEY'] = key
        print(f"CPIP_COVERT_KEY applied: {key[:8]}...{key[-8:] if len(key) > 16 else ''}")
        
        self.update_status("Key applied to current session", SUCCESS_COLOR)
        
        # Show helpful information
        messagebox.showinfo(
            "Info",
            "Key applied to current session.\n\n"
            "Note: Server processes must be restarted to use the new key."
        )
    
    def save_key(self):
        """Save the key to .env file."""
        key = self.key_var.get()
        
        is_valid, message = validate_key(key)
        if not is_valid:
            self.show_error(f"Invalid key: {message}")
            return
        
        try:
            save_key_to_env(key)
            self.update_status("Key saved to .env file", SUCCESS_COLOR)
            
            messagebox.showinfo(
                "Success",
                "Key saved to .env file successfully"
            )
        except Exception as e:
            self.show_error(f"Failed to save key: {e}")
    
    def reset_to_auto_generated(self):
        """Reset to auto-generated key."""
        if messagebox.askyesno(
            "Confirm Reset",
            "This will reset the key to auto-generated.\n\n"
            "All existing communication with this key will be lost.\n\n"
            "Continue?"
        ):
            new_key = generate_secure_key()
            self.key_var.set(new_key)
            self.update_status("Reset to auto-generated key", INFO_COLOR)
            
            messagebox.showinfo(
                "Info",
                "Key reset to auto-generated.\n\n"
                "Save this new key if you want to use it."
            )
    
    def update_status(self, message: str, color: str = "#2d3436"):
        """Update the status label with message and color."""
        self.status_label.config(text=f"Status: {message}", fg=color)
        self.root.update()
    
    def show_error(self, message: str):
        """Show an error message."""
        self.update_status(f"Error: {message}", ERROR_COLOR)
        messagebox.showerror("Error", message)


def main():
    """Main entry point."""
    root = Tk()
    app = CovertKeyManagerGUI(root)
    root.mainloop()
if __name__ == "__main__":
    main()
