# Windows Process Creation Logging & Command Line Auditing

**Author:** Jordan Lankster  
**Lab Type:** Windows Security Auditing  
**Tools Used:** PowerShell, Windows Event Viewer, Group Policy, Audit Policy  
**Event ID:** 4688 — Process Creation  

---

## Overview

This lab walks through enabling and querying Windows process creation logging (Event ID 4688) with full command line argument capture. This is a foundational SOC skill used for threat hunting, incident response, and SIEM data collection in real enterprise environments.

---

## What is Event ID 4688?

Event ID 4688 is a Windows Security log event generated every time a new process is created on the system. By default, Windows logs the process name and basic metadata — but not the command line arguments used to launch it.

Enabling command line logging gives visibility into **exactly what was executed**, which is critical for detecting:

- Living off the land (LOLBin) abuse — attackers using built-in Windows tools like `certutil.exe`, `wmic.exe`, `mshta.exe`, `rundll32.exe`
- Encoded PowerShell execution — `powershell.exe -enc <base64>`
- Suspicious parent-child process relationships — e.g., `winword.exe` spawning `cmd.exe`
- Processes executing from unusual locations — `C:\Users\Public\`, `%Temp%\`

---

## Lab Environment

- Windows 10/11 standalone machine (no domain required)
- PowerShell ISE (run as Administrator)
- Local Group Policy

---

## Step 1 — Verify Process Creation Auditing Status

Before enabling anything, check whether process creation auditing is even on:

```powershell
auditpol /get /subcategory:"Process Creation"
```

**Expected output if disabled:**
```
System audit policy
Category/Subcategory          Setting
Detailed Tracking
  Process Creation            No Auditing
```

If it says "No Auditing" — Windows is not generating 4688 events at all. This was the root cause of no results appearing when querying the Security log.

---

## Step 2 — Enable Process Creation Auditing

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

Verify it took effect:

```powershell
auditpol /get /subcategory:"Process Creation"
```

**Expected output:**
```
System audit policy
Category/Subcategory          Setting
Detailed Tracking
  Process Creation            Success
```

---

## Step 3 — Enable Command Line Logging

Process creation auditing alone only captures the process name. To capture the full command line arguments, a separate registry key must be set:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

Verify the key was written correctly:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
```

**Expected output:**
```
ProcessCreationIncludeCmdLine_Enabled    REG_DWORD    0x1
```

---

## Step 4 — Apply Group Policy

Force an immediate Group Policy refresh so the settings take effect without waiting for the automatic 90-minute refresh cycle:

```powershell
gpupdate /force
```

> **Note:** `gpupdate /force` works on standalone machines using Local Group Policy — no Active Directory or domain is required.

---

## Step 5 — Generate Test Events

Run a few commands to create fresh 4688 events with command line data now that logging is active:

```powershell
ipconfig /all
whoami
ping 8.8.8.8 -n 2
```

---

## Step 6 — Query 4688 Events via PowerShell

This script parses the Security event log, extracts 4688 events, and pulls the process name, command line arguments, user, and timestamp from the raw XML data:

```powershell
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4688} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Process     = ($data | Where-Object Name -eq 'NewProcessName').'#text'
        CommandLine = ($data | Where-Object Name -eq 'CommandLine').'#text'
        User        = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
    }
} | Where-Object {$_.CommandLine -ne $null} | Format-List
```

To export results to CSV for further analysis:

```powershell
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4688} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        Process     = ($data | Where-Object Name -eq 'NewProcessName').'#text'
        CommandLine = ($data | Where-Object Name -eq 'CommandLine').'#text'
        User        = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
    }
} | Where-Object {$_.CommandLine -ne $null} | Export-Csv -Path "C:\4688_logs.csv" -NoTypeInformation
```

---

## Step 7 — Threat Hunting with 4688

Use this script to hunt for suspicious processes — filters for known LOLBins and suspicious PowerShell usage:

```powershell
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4688} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    $cmd = ($data | Where-Object Name -eq 'CommandLine').'#text'
    if ($cmd -match "powershell|cmd|wmic|certutil|mshta|rundll32|-enc|-e |iex|Invoke-Expression") {
        [PSCustomObject]@{
            Time        = $_.TimeCreated
            CommandLine = $cmd
        }
    }
} | Format-List
```

---

## Turning Command Line Logging Off

To disable command line logging when no longer needed:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 0 /f
gpupdate /force
```

> **Security note:** Command line logs can capture sensitive data such as passwords passed as arguments. In production environments, restrict access to the Security event log and ensure admins avoid passing credentials via command line.

---

## Key Takeaways

| Concept | What Was Learned |
|---|---|
| Event ID 4688 | Windows logs a new event every time a process is created |
| auditpol | Command-line tool to configure and verify Windows audit policies |
| Command line logging | Separate registry setting required to capture full arguments |
| gpupdate /force | Forces immediate Group Policy refresh on local and domain machines |
| PowerShell XML parsing | 4688 events store data in XML — fields must be extracted by name |
| LOLBins | Legitimate Windows tools abused by attackers — detectable via command line args |

---

## SOC Relevance

In a real SOC environment, 4688 events with command line logging feed directly into a SIEM (Splunk, Microsoft Sentinel, Wazuh) where detection rules alert on suspicious process chains. Understanding the raw event structure — before it hits the SIEM — makes you a better analyst and a better detection engineer.

This lab demonstrates:
- Windows audit policy configuration
- Security event log querying and parsing
- Basic threat hunting logic
- Understanding of attacker techniques (LOLBins, encoded PowerShell)

---

## References

- [MITRE ATT&CK — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK — Living off the Land](https://attack.mitre.org/techniques/T1218/)
- [Microsoft Docs — Audit Process Creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation)
- [Microsoft Docs — Event ID 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)

