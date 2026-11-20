## Privesc

Windows PowerShell script that finds misconfiguration issues which can lead to privilege escalation.</br>

**Requirements**

Windows PowerShell 5.1. The script will not run on PowerShell 7, which no longer has the `Write` and `Sort` aliases or the `Get-WmiObject` cmdlet.

**Usage**

```powershell
. .\privesc.ps1
Invoke-Privesc
```

Print the results and write them to a file at the same time - use this instead of `Out-File`, which sends everything to the file and leaves the console empty:

```powershell
Invoke-Privesc | Tee-Object -FilePath .\output.txt
```

Both `Out-File` and `Tee-Object -FilePath` write UTF-16 by default on Windows PowerShell 5.1, which makes the output harder to grep. Use this to get UTF-8:

```powershell
Invoke-Privesc | Tee-Object -Variable res; $res | Out-File -Encoding UTF8 .\output.txt
```

Run everything, including the lookups that may last a lot longer, and verify permissions against the current user as well as the default groups:

```powershell
Invoke-Privesc -Whoami -Extended -Long
```

Verify permissions against your own list of groups and users:

```powershell
Invoke-Privesc -Groups 'Users,Everyone,Authenticated Users'
```

`Get-Help Invoke-Privesc -Full` describes every parameter.

**Checks**

Looks for objects that a low privileged user can write to and that are later executed by another user or by NT AUTHORITY\SYSTEM:

* services, their binaries and their DLLs, unquoted service paths and service registry keys
* scheduled tasks, their binaries, their definition files and their script arguments
* startup directories of all users and the targets of startup shortcuts
* Run, RunOnce, RunOnceEx, RunServices and policy Run keys in every hive and in Wow6432Node
* Winlogon, Active Setup, Image File Execution Options and SilentProcessExit
* shell folder paths, AppInit_DLLs, AppCertDlls, KnownDLLs, Drivers32, LSA packages, print monitors, print providers, network providers, BootExecute and SafeBoot
* COM servers and their libraries, browser helper objects, shell extensions and open command handlers
* directories in PATH, DLLs loaded by running processes and uninstall registry keys
* AlwaysInstallElevated, unattended install files and other files that may contain credentials
* registry keys and files that may contain passwords, including WSUS, SCCM, VNC, PuTTY and autologin

**Output**

Output of every check is marked:

```
[!] - check that is being performed
[+] - Found: header, followed by the findings listed line by line
[-] - nothing found for this check
```

Errors are suppressed, because paths and keys that do not exist are normal while enumerating. Comment out `$ErrorActionPreference` at the top of the function to see them.

Some checks write their own files to the current directory - `pwds.txt` with possible passwords found on all drives and, with `-Extended`, `systeminfo_for_suggester.txt`.

**Disclaimer**

This repository contains tool developed strictly for educational purposes. Any misuse of the tool for illegal activities is strictly prohibited.

**Legal Notice**

It is important to understand and comply with all local laws and regulations related to cybersecurity and ethical hacking. Unauthorized access to computer systems, networks, or data is illegal and punishable by law. The developer of this repository is not responsible for any misuse of the tools contained herein.

By using the tools in this repository, you agree to use them responsibly and ethically. Always obtain explicit permission before testing or attempting to access any network, system, or data that does not belong to you.
