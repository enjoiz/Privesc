function Invoke-Privesc {

<#
.SYNOPSIS
Finds Windows misconfigurations that may allow for local privilege escalation.
.DESCRIPTION
Looks for objects that a low privileged user can write to and that are later executed
by another user or by NT AUTHORITY\SYSTEM - services and their DLLs, scheduled tasks,
startup directories and shortcuts, Run and RunOnce keys in every hive and in
Wow6432Node, Winlogon, Active Setup, Image File Execution Options, shell folder paths,
AppInit_DLLs, AppCertDlls, KnownDLLs, LSA packages, print monitors, BootExecute, COM
servers, open command handlers, PATH entries, loaded DLLs, uninstall keys and files
that may contain credentials.

Output of every check is marked:
    [!] - check that is being performed
    [+] - Found: header, followed by the findings listed line by line
    [-] - nothing found for this check

Errors are suppressed, because paths and keys that do not exist are normal while
enumerating. Comment out $ErrorActionPreference at the top of the function to see them.

Some checks write their own files to the current directory - pwds.txt with possible
passwords found on all drives and, with -Extended, systeminfo_for_suggester.txt.

IncludeInList
.PARAMETER Groups
Comma separated list of groups and users that ACLs are verified against. A finding is
reported when any of them can write to the object.
Default: 'Users,Everyone,Authenticated Users,Interactive'
.PARAMETER Whoami
Verify permissions related to the current user - the name of the current user is
checked in addition to the groups from -Groups.
.PARAMETER Extended
Switch enables output of additional information - environment variables, current user,
drives, interfaces, routing table, ARP cache, connections, processes, installed
software, drivers, hotfixes, temp files, autorun entries, services and scheduled tasks.
.PARAMETER Long
Switch enables lookups that may last a lot longer - recursive search for sensitive
registry keys and permissions of all HKLM keys.
.EXAMPLE
Invoke-Privesc

Runs the default checks and prints the results to the console.
.EXAMPLE
Invoke-Privesc -Whoami -Extended -Long

Runs everything, including the slow lookups, and verifies ACLs against the current user
as well as the default groups.
.EXAMPLE
Invoke-Privesc -Groups 'Users,Everyone,Authenticated Users' -Whoami -Extended -Long

Runs everything against your own list of groups.
.EXAMPLE
Invoke-Privesc | Tee-Object -FilePath .\output.txt

Prints the results to the console and writes them to a file at the same time. Use this
instead of Out-File, which sends everything to the file and leaves the console empty.
Add -Append to keep the content of an existing file.
.EXAMPLE
Invoke-Privesc | Tee-Object -Variable res; $res | Out-File -Encoding UTF8 .\output.txt

Same as above, but the file is UTF-8. Out-File and Tee-Object -FilePath both write
UTF-16 by default on Windows PowerShell 5.1, which makes the output harder to grep.
.NOTES
Author: Jakub Palaczynski
.LINK
https://github.com/enjoiz/Privesc
#>

    [CmdletBinding()]
    param(
	[String]
	$Groups = 'Users,Everyone,Authenticated Users,Interactive',

	[Switch]
	$Whoami,
		
        [Switch]
	$Extended,

        [Switch]
	$Long
    )

    $ErrorActionPreference = "SilentlyContinue"
    $arguments = $groups.Split(",")
    $whoamiVal = ""
    if ($Whoami) {
	$whoamiVal = whoami
    }

    function resolve($variable) {
        $name = Get-ChildItem Env:$variable
        return $name.Value
    }

    function parsebin($command) {
        Trap { Continue }
        if (($command -eq $null) -or ("$command" -eq "")) { return $null }
        $o = [Environment]::ExpandEnvironmentVariables("$command").Trim()
        if ($o -like '\??\*') { $o = $o.replace('\??\','') }
        if ($o -like '"*') { $o = $o.split('"')[1] }
        else {
            $parts = $o.Split(" ")
            $found = $null
            ForEach ($n in 0..($parts.Length-1)) { $try = ($parts[0..$n] -join " ").Trim(); if ($try -and ($try -notmatch '[*?"<>|]') -and (Test-Path -LiteralPath $try -PathType Leaf)) { return $try } ; if (($found -eq $null) -and ($try -notlike '* -*') -and ($try -notlike '* /*') -and ($try -match '\.(exe|dll|com|bat|cmd|scr|cpl|ocx|sys|ps1|vbs|vbe|js|jse|wsf|hta|msi|msc|jar|py)$')) { $found = $try } }
            if ($found) { $o = $found }
            ElseIf ($o -like '* -*') { $o = $o.split('-')[0].Trim() }
            ElseIf ($o -like '* /*') { $o = $o.split('/')[0].Trim() }
            ElseIf (($o -notlike '*:\*') -and ($o -like '* *')) { $o = $o.split(" ")[0].Trim() }
        }
        if ($o -and ($o -notlike '*:\*')) { ForEach ($dir in "$env:WINDIR\system32","$env:WINDIR","$env:WINDIR\SysWOW64","$env:WINDIR\system32\WindowsPowerShell\v1.0") { if (Test-Path -LiteralPath "$dir\$o" -PathType Leaf) { return "$dir\$o" } ; if (Test-Path -LiteralPath "$dir\$o.exe" -PathType Leaf) { return "$dir\$o.exe" } } }
        return $o
    }

    function parsedir($path) {
        Trap { Continue }
        if (($path -eq $null) -or ("$path" -eq "")) { return $null }
        $o = "$path".Split("\")
        if ($o.Length -lt 2) { return $null }
        return $o[0..($o.Length-2)] -join ("\")
    }

    function parsefiles($command) {
        Trap { Continue }
        if (($command -eq $null) -or ("$command" -eq "")) { return $null }
        $o = [Environment]::ExpandEnvironmentVariables("$command")
        [regex]::Matches($o, '[a-zA-Z]:\\[^"<>|;,\r\n]*?\.(?:ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|sct|exe|dll|cpl|ocx|sys|msi|msp|py|jar|lnk|reg|inf|xml|ini|cfg|conf|config)(?=["\s,;]|$)', 'IgnoreCase') | ForEach-Object { $_.Value.Trim() } | Sort -Unique
    }

    function parseclsid($value) {
        Trap { Continue }
        if (($value -eq $null) -or ("$value" -eq "")) { return $null }
        [regex]::Matches("$value", '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}') | ForEach-Object { $_.Value } | Sort -Unique
    }


    filter ConvertFrom-SDDL
    {
    <#
    .SYNOPSIS
        Author: Matthew Graeber (@mattifestation)
    .LINK
        http://www.exploit-monday.com
    #>

        Param (
            [Parameter( Position = 0, Mandatory = $True, ValueFromPipeline = $True )]
            [ValidateNotNullOrEmpty()]
            [String[]]
            $RawSDDL
        )

        $RawSDDL = $RawSDDL -replace "`n|`r"
        Set-StrictMode -Version 2

        # Get reference to sealed RawSecurityDescriptor class
        $RawSecurityDescriptor = [Int].Assembly.GetTypes() | ? { $_.FullName -eq 'System.Security.AccessControl.RawSecurityDescriptor' }

        # Create an instance of the RawSecurityDescriptor class based upon the provided raw SDDL
        try
        {
            $Sddl = [Activator]::CreateInstance($RawSecurityDescriptor, [Object[]] @($RawSDDL))
        }
        catch [Management.Automation.MethodInvocationException]
        {
            throw $Error[0]
        }
        if ($Sddl.Group -eq $null)
        {
            $Group = $null
        }
        else
        {
            $SID = $Sddl.Group
            $Group = $SID.Translate([Security.Principal.NTAccount]).Value
        }
        if ($Sddl.Owner -eq $null)
        {
            $Owner = $null
        }
        else
        {
            $SID = $Sddl.Owner
            $Owner = $SID.Translate([Security.Principal.NTAccount]).Value
        }
        $ObjectProperties = @{
            Group = $Group
            Owner = $Owner
        }
        if ($Sddl.DiscretionaryAcl -eq $null)
        {
            $Dacl = $null
        }
        else
        {
            $DaclArray = New-Object PSObject[](0)
            $ValueTable = @{}
            $EnumValueStrings = [Enum]::GetNames([System.Security.AccessControl.CryptoKeyRights])
            $CryptoEnumValues = $EnumValueStrings | % {
                    $EnumValue = [Security.AccessControl.CryptoKeyRights] $_
                    if (-not $ValueTable.ContainsKey($EnumValue.value__))
                    {
                        $EnumValue
                    }
                    $ValueTable[$EnumValue.value__] = 1
                }
            $EnumValueStrings = [Enum]::GetNames([System.Security.AccessControl.FileSystemRights])
            $FileEnumValues = $EnumValueStrings | % {
                    $EnumValue = [Security.AccessControl.FileSystemRights] $_
                    if (-not $ValueTable.ContainsKey($EnumValue.value__))
                    {
                        $EnumValue
                    }
                    $ValueTable[$EnumValue.value__] = 1
                }
            $EnumValues = $CryptoEnumValues + $FileEnumValues
            foreach ($DaclEntry in $Sddl.DiscretionaryAcl)
            {
                $SID = $DaclEntry.SecurityIdentifier
                $Account = $SID.Translate([Security.Principal.NTAccount]).Value
                $Values = New-Object String[](0)

                # Resolve access mask
                foreach ($Value in $EnumValues)
                {
                    if (($DaclEntry.Accessmask -band $Value) -eq $Value)
                    {
                        $Values += $Value.ToString()
                    }
                }
                $Access = "$($Values -join ',')"
                $DaclTable = @{
                    Rights = $Access
                    IdentityReference = $Account
                    IsInherited = $DaclEntry.IsInherited
                    InheritanceFlags = $DaclEntry.InheritanceFlags
                    PropagationFlags = $DaclEntry.PropagationFlags
                }
                if ($DaclEntry.AceType.ToString().Contains('Allowed'))
                {
                    $DaclTable['AccessControlType'] = [Security.AccessControl.AccessControlType]::Allow
                }
                else
                {
                    $DaclTable['AccessControlType'] = [Security.AccessControl.AccessControlType]::Deny
                }
                $DaclArray += New-Object PSObject -Property $DaclTable
            }
            $Dacl = $DaclArray
        }
        $ObjectProperties['Access'] = $Dacl
        $SecurityDescriptor = New-Object PSObject -Property $ObjectProperties
        Write-Output $SecurityDescriptor
    }


	Write "[!] Date of last applied patch - just use public exploits if not patched:"
        $result = $null
        $result = Get-HotFix | Where-Object {"$($_.InstalledOn)" -ne ""} | Sort InstalledOn | Select -Last 1 | ForEach-Object { $_.HotFixID + " installed on " + (Get-Date $_.InstalledOn -Format "yyyy-MM-dd") }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result } else { Write "[-] Date of last applied patch could not be determined." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Files that may contain Administrator password - you know what to do with this one:"
        $i = 0
        if (Test-Path $env:SystemDrive\sysprep.inf) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:SystemDrive\sysprep.inf" ; $i = 1}
        if (Test-Path $env:SystemDrive\sysprep\sysprep.xml) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:SystemDrive\sysprep\sysprep.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\Panther\Unattend\Unattended.xml) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:WINDIR\Panther\Unattend\Unattended.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\Panther\Unattended.xml) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:WINDIR\Panther\Unattended.xml" ; $i = 1 }
    	if (Test-Path $env:WINDIR\system32\sysprep\Unattend.xml) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:WINDIR\system32\sysprep\Unattend.xml" ; $i = 1 }
    	if (Test-Path $env:WINDIR\system32\sysprep\Panther\Unattend.xml) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:WINDIR\system32\sysprep\Panther\Unattend.xml" ; $i = 1 }
    	if (Test-Path $env:WINDIR\Panther\Unattend\Unattended.xml) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:WINDIR\Panther\Unattend\Unattended.xml" ; $i = 1 }
    	if (Test-Path $env:WINDIR\Panther\Unattend.xml) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:WINDIR\Panther\Unattend.xml" ; $i = 1 }
    	if (Test-Path $env:SystemDrive\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:SystemDrive\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT" ; $i = 1 }
    	if (Test-Path $env:WINDIR\panther\setupinfo) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:WINDIR\panther\setupinfo" ; $i = 1 }
    	if (Test-Path $env:WINDIR\panther\setupinfo.bak) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:WINDIR\panther\setupinfo.bak" ; $i = 1 }
        if (Test-Path $env:SystemDrive\unattend.xml) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:SystemDrive\unattend.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\system32\sysprep.inf) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:WINDIR\system32\sysprep.inf" ; $i = 1 }
        if (Test-Path $env:WINDIR\system32\sysprep\sysprep.xml) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:WINDIR\system32\sysprep\sysprep.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Config\web.config) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" ; $i = 1 }
        if (Test-Path $env:SystemDrive\inetpub\wwwroot\web.config) { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:SystemDrive\inetpub\wwwroot\web.config" ; $i = 1 }
        if (Test-Path "$env:AllUsersProfile\Application Data\McAfee\Common Framework\SiteList.xml") { if ($i -eq 0) { Write "[+] Found:" } ; Write "$env:AllUsersProfile\Application Data\McAfee\Common Framework\SiteList.xml" ; $i = 1 }
        if (Test-Path HKLM:\SOFTWARE\RealVNC\WinVNC4) { if ($i -eq 0) { Write "[+] Found:" } ; Get-ChildItem -Force -Path HKLM:\SOFTWARE\RealVNC\WinVNC4 ; $i = 1 }
        if (Test-Path HKCU:\Software\SimonTatham\PuTTY\Sessions) { if ($i -eq 0) { Write "[+] Found:" } ; Get-ChildItem -Force -Path HKCU:\Software\SimonTatham\PuTTY\Sessions ; $i = 1 }
        if ($i -eq 0) { Write "[-] Files not found."}


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Checking if SCCM is installed - installers are run with SYSTEM privileges, many are vulnerable to for example DLL hijacking:"
        $result = $null
        $result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | % { if ($_.ApplicabilityState -eq "Applicable") { $_.Name } }
        if ($result) { Write "[+] Found:" ; $result }
        else { Write "[-] Not Installed." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Checking AlwaysInstallElevated - install *.msi files as NT AUTHORITY\SYSTEM - exploit/windows/local/always_install_elevated:"
        $i = 0
        if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer) { if ($i -eq 0) { Write "[+] Found:" } ; Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated ; $i = 1 }
        if (Test-Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer) { if ($i -eq 0) { Write "[+] Found:" } ; Get-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated ; $i = 1 }
        if ($i -eq 0) { Write "[-] Registries not found."}

		
		Write ""
        Write "======================================================================"
        Write ""
		
		
		Write "[!] Check for Windows Autologin credentials:"
		get-item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
		
		
        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Checking user privileges:"
		#findstr /i /C:
		# "SeIm"+"perso"+"natePri"+"vilege","SeA"+"ssignPrima"+"ryPrivi"+"lege","SeT"+"cbPivi"+"lege","S"+"eBac"+"kupPriv"+"ilege","S"+"eRes"+"torePriv"+"ilege","S"+"eCre"+"ateTok"+"enPriv"+"ilege","SeLo"+"adDri"+"verPri"+"vilege","SeT"+"akeOwne"+"rshipPriv"+"ilege","SeDeb"+"ugPri"+"vilege"
        $result = $null
        $result = (whoami /priv | findstr /i /v "Disabled" 2> $null) | Out-String | ForEach-Object { $_.Split("`n") } | ForEach-Object { if ($_ -match "Enabled") { $_.TrimEnd() } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result } else { Write "[-] User privileges do not allow for exploitation." }
            

        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Checking if WSUS uses HTTP - eg. WSUXploit:"
        $i = 0
        if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate) { Write "[+] Found:" ; Write "$((Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name WUServer).WUServer)" ; $i = 1 }
        if ($i -eq 0) { Write "[-] WSUS misconfiguration not found."}


        Write ""
        Write "======================================================================"
        Write ""
        
        
        Write "[!] Services with space in path and not enclosed with quotes - if you have permissions run executable from different directory - exploit/windows/local/trusted_service_path:"
        $result = $null
        $result = Get-WmiObject win32_service | Where-Object {($_.PathName -like '* *') -and ($_.PathName -notlike '*"*') -and ($_.PathName -notlike '*C:\Windows*')} | ForEach-Object { Write $_.PathName }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Weak services were not found." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] PATH variable entries permissions - place binary or DLL to execute before legitimate:"
        $result = $null
        $result = $env:path.split(";") | ForEach { Trap { Continue }; if ($_ -and ($_ -ne $null) -and ($_ -notlike '*\WindowsApps')) { $o = $_ ; (Get-Acl $o).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique ; Write "[!] Full PATH: $env:path" } else { Write "[-] Permissions set for all PATH variable entries are correct for all groups." }
    	

        Write ""
        Write "======================================================================"
        Write ""
     
     
        Write "[!] System32 directory permissions - backdoor windows binaries:"
        $result = $null
        $result = (Get-Acl C:\Windows\system32).Access | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on System32 directory are correct for all groups." }
        

        Write ""
        Write "======================================================================"
        Write ""

        
        Write "[!] System32 files and directories permissions - backdoor windows binaries:"
        $result = $null
        $result = Get-ChildItem C:\Windows\system32 -Force -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on System32 files and directories are correct for all groups." }
        

        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Windows Temp directory read permissions - DLL Sideloading each created directory:"
        $result = $null
        $result = (Get-Acl C:\Windows\Temp).Access 2> $null | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "ChangePermissions|FullControl|Modify|TakeOwnership|ListDirectory" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on Windows Temp directory are correct for all groups." }
            

        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Program Files directory permissions - backdoor windows binaries:"
        $result = $null
        $result = (Get-Acl "$env:ProgramFiles").Access | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        $result += (Get-Acl ${env:ProgramFiles(x86)}).Access | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on Program Files directory are correct for all groups." }
        

        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Program Files files and directories permissions - backdoor windows binaries:"
        $result = $null
        $result = Get-ChildItem "$env:ProgramFiles" -Force -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ChildItem ${env:ProgramFiles(x86)} -Force -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on Program Files files and directories are correct for all groups." }
        

        Write ""
        Write "======================================================================"
        Write ""
	
	
	Write "[!] ProgramData directories permissions - use dll hijacking:"
	$result = $null
	$result = Get-ChildItem "$env:ProgramData" -Directory -Force -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); if (Test-Path $o\*.exe) { Write "Group: $arg, Permissions: $rights on $o" } } } }
	if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on ProgramData directories are correct for all groups." }


	Write ""
	Write "======================================================================"
	Write ""
		
		
        Write "[!] ProgramData files permissions - backdoor windows binaries:"
	$result = $null
	$result = Get-ChildItem "$env:ProgramData" -File -Force -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
	if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on ProgramData files are correct for all groups." }
		

	Write ""
	Write "======================================================================"
	Write ""


        Write "[!] All users startup permissions - execute binary with permissions of logged user:"
        $result = $null
        $result = (Get-Acl "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup").Access | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" } } }
        $result += Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force -Recurse | ForEach-Object { $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on All Users startup files and directories are correct for all groups." }
            

        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Startup executables permissions - backdoor startup binaries and check if they are also run at startup by other users:"
        $result = $null
        $result = Get-ChildItem "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -Force -Recurse | ForEach-Object { $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += (Get-Acl hklm:\Software\Microsoft\Windows\CurrentVersion\Run).Access | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on hklm:\Software\Microsoft\Windows\CurrentVersion\Run" } } }
        $result += (Get-Acl hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce).Access | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce" } } }
        $result += Get-ItemProperty -Path hklm:\Software\Microsoft\Windows\CurrentVersion\Run | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); if ($o) { (Get-Acl $o 2> $null).Access } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ItemProperty -Path hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); if ($o) { (Get-Acl $o 2> $null).Access } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ItemProperty -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\Run | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); if ($o) { (Get-Acl $o 2> $null).Access } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ItemProperty -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\RunOnce | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); if ($o) { (Get-Acl $o 2> $null).Access } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on startup executables are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Startup executables directory permissions - try DLL injection:"
        $result = $null
        $result = Get-ItemProperty -Path hklm:\Software\Microsoft\Windows\CurrentVersion\Run | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); $o = parsedir($o); if ($o) { (Get-Acl $o 2> $null).Access } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ItemProperty -Path hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); $o = parsedir($o); if ($o) { (Get-Acl $o 2> $null).Access } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ItemProperty -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\Run | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); $o = parsedir($o); if ($o) { (Get-Acl $o 2> $null).Access } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ItemProperty -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\RunOnce | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); $o = parsedir($o); if ($o) { (Get-Acl $o 2> $null).Access } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on startup executables directories are correct for all groups." }
            

        Write ""
        Write "======================================================================"
        Write ""


        $mySid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        $autorunkeys = "hklm:\Software\Microsoft\Windows\CurrentVersion\Run","hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce","hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx","hklm:\Software\Microsoft\Windows\CurrentVersion\RunServices","hklm:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce","hklm:\Software\Microsoft\Windows\CurrentVersion\Explorer\Run","hklm:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run","hklm:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run","hklm:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce","hklm:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx","hklm:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices","hklm:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce","hklm:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Run","hklm:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run","hklm:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run","hklm:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce","hklm:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx","hkcu:\Software\Microsoft\Windows\CurrentVersion\Run","hkcu:\Software\Microsoft\Windows\CurrentVersion\RunOnce","hkcu:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx","hkcu:\Software\Microsoft\Windows\CurrentVersion\RunServices","hkcu:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce","hkcu:\Software\Microsoft\Windows\CurrentVersion\Explorer\Run","hkcu:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run","hkcu:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run","hkcu:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        $winlogonkeys = "hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon","hklm:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon","hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify","hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions","hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells","hkcu:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $activesetupkeys = "hklm:\SOFTWARE\Microsoft\Active Setup\Installed Components","hklm:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components","hkcu:\SOFTWARE\Microsoft\Active Setup\Installed Components","hkcu:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components"
        $ifeokeys = "hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options","hklm:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options","hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit","hklm:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"
        $shellfolderkeys = "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders","hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders","hklm:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders","hklm:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders","hkcu:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders","hkcu:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $systemkeys = "hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows","hklm:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows","hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32","hklm:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32","hklm:\System\CurrentControlSet\Control\Session Manager","hklm:\System\CurrentControlSet\Control\Session Manager\AppCertDlls","hklm:\System\CurrentControlSet\Control\Session Manager\KnownDLLs","hklm:\System\CurrentControlSet\Control\SafeBoot","hklm:\System\CurrentControlSet\Control\Lsa","hklm:\System\CurrentControlSet\Control\Lsa\OSConfig","hklm:\System\CurrentControlSet\Control\Print\Monitors","hklm:\System\CurrentControlSet\Control\Print\Providers","hklm:\System\CurrentControlSet\Control\NetworkProvider\Order","hklm:\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd","hklm:\System\CurrentControlSet\Control\BootVerificationProgram"
        $comkeys = "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects","hklm:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects","hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers","hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks","hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler","hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad","hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved","hklm:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers","hklm:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers","hklm:\SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers","hklm:\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers","hklm:\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers","hklm:\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers","hklm:\SOFTWARE\Microsoft\Internet Explorer\Extensions","hklm:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Extensions","hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers","hklm:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
        $opencommandkeys = "hklm:\SOFTWARE\Classes\htmlfile\shell\open\command","hklm:\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command","hklm:\SOFTWARE\Classes\exefile\shell\open\command","hklm:\SOFTWARE\Classes\batfile\shell\open\command","hklm:\SOFTWARE\Classes\cmdfile\shell\open\command","hklm:\SOFTWARE\Classes\comfile\shell\open\command","hklm:\SOFTWARE\Classes\mscfile\shell\open\command","hklm:\SOFTWARE\Classes\ms-settings\shell\open\command","hklm:\SOFTWARE\Classes\regfile\shell\open\command","hklm:\SOFTWARE\Classes\chm.file\shell\open\command","hklm:\SOFTWARE\Classes\lnkfile\shell\open\command","hklm:\SOFTWARE\Classes\Folder\shell\open\command","hkcu:\SOFTWARE\Classes\mscfile\shell\open\command","hkcu:\SOFTWARE\Classes\ms-settings\shell\open\command","hkcu:\SOFTWARE\Classes\exefile\shell\open\command"


        Write "[!] Autorun registry keys and subkeys permissions - add your own entry to execute binary when other users log in:"
        $result = $null
        $result = $autorunkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; $o = $_.Name; (Get-Acl -Path "Registry::$([WildcardPattern]::Escape($o))").Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on autorun registry keys and subkeys are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Autorun executables permissions - backdoor binary that is executed when other users log in:"
        $result = $null
        $result = $autorunkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; Get-ItemProperty -LiteralPath $_.PSPath 2> $null } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); if ($o -and ($o -like '*:\*')) { (Get-Acl $o 2> $null).Access } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on autorun executables are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Autorun scripts and libraries permissions - backdoor script or DLL that is passed as argument to autorun binary:"
        $result = $null
        $result = $autorunkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; Get-ItemProperty -LiteralPath $_.PSPath 2> $null } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } ForEach ($file in parsefiles($obj)) { $o = $file; if ($o) { (Get-Acl $o 2> $null).Access } } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on autorun scripts and libraries are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Autorun executables directory permissions - try DLL injection:"
        $result = $null
        $result = $autorunkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; Get-ItemProperty -LiteralPath $_.PSPath 2> $null } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); if ($o -and ($o -like '*:\*')) { $o = parsedir($o); (Get-Acl $o 2> $null).Access } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on autorun executables directories are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


	Write "[!] Missing autorun binary - put in place your own binary:"
        $result = $null
        $result = $autorunkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; Get-ItemProperty -LiteralPath $_.PSPath 2> $null } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); if ($o -and ($o[1] -eq ":") -and (-Not (Test-Path -LiteralPath $o -PathType Leaf)) -and (-not($o -ilike '*\WINDOWS\*')) -and (-not($o -ilike '*\Program Files*'))) { Write "$o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] All autorun binaries are in place." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Winlogon registry keys and subkeys permissions - change Userinit or Shell value to execute binary as every user that logs in:"
        $result = $null
        $result = $winlogonkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; $o = $_.Name; (Get-Acl -Path "Registry::$([WildcardPattern]::Escape($o))").Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on Winlogon registry keys and subkeys are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Winlogon executables and libraries permissions - backdoor binary that is executed by Winlogon as every user that logs in:"
        $result = $null
        $result = $winlogonkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; Get-ItemProperty -LiteralPath $_.PSPath 2> $null } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } If ($obj.Name -match "Userinit|Shell|DLLName|AppSetup|Taskman|GinaDLL|VmApplet|UIHost|AlternateShell") { ForEach ($part in "$($obj.Value)".Split(',')) { $o = parsebin($part); if ($o -and ($o -like '*:\*')) { (Get-Acl $o 2> $null).Access } } } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on Winlogon executables and libraries are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Active Setup registry keys and subkeys permissions - StubPath command is executed for every user before desktop is loaded:"
        $result = $null
        $result = $activesetupkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; $o = $_.Name; (Get-Acl -Path "Registry::$([WildcardPattern]::Escape($o))").Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on Active Setup registry keys and subkeys are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Active Setup StubPath executables permissions - backdoor binary that is executed before desktop is loaded:"
        $result = $null
        $result = $activesetupkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; Get-ItemProperty -LiteralPath $_.PSPath -Name StubPath 2> $null } | ForEach-Object { Trap { Continue }; $o = parsebin($_.StubPath); if ($o -and ($o -like '*:\*')) { (Get-Acl $o 2> $null).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on Active Setup StubPath executables are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Image File Execution Options and SilentProcessExit permissions - set Debugger or MonitorProcess value to hijack execution of privileged binary:"
        $result = $null
        $result = $ifeokeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; $o = $_.Name; (Get-Acl -Path "Registry::$([WildcardPattern]::Escape($o))").Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on Image File Execution Options and SilentProcessExit keys are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Debugger and MonitorProcess executables permissions - backdoor binary that is executed instead of privileged binary:"
        $result = $null
        $result = $ifeokeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; Get-ItemProperty -LiteralPath $_.PSPath 2> $null } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } If ($obj.Name -match "Debugger|MonitorProcess|VerifierDlls|GlobalFlag") { $o = parsebin($obj.Value); if ($o -and ($o -like '*:\*')) { (Get-Acl $o 2> $null).Access } } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on Debugger and MonitorProcess executables are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Startup directory path registry keys permissions - point Common Startup to directory that you control:"
        $result = $null
        $result = $shellfolderkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null } } | ForEach-Object { Trap { Continue }; $o = $_.Name; (Get-Acl -Path "Registry::$([WildcardPattern]::Escape($o))").Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on startup directory path registry keys are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        $startupdirs = $shellfolderkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-ItemProperty -LiteralPath $_ 2> $null } } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } If ($obj.Name -match "Startup|Start Menu") { [Environment]::ExpandEnvironmentVariables("$($obj.Value)") } } }
        $startupdirs += Get-ChildItem "$env:SystemDrive\Users" -Directory -Force 2> $null | ForEach-Object { "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" }
        $startupdirs += "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

        Write "[!] Startup directories of all users permissions - drop binary that is executed with permissions of other users:"
        $result = $null
        $result = $startupdirs | Sort -Unique | ForEach-Object { Trap { Continue }; if ($_ -and (Test-Path -LiteralPath $_)) { $o = $_; (Get-Acl -LiteralPath $_).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += $startupdirs | Sort -Unique | ForEach-Object { Trap { Continue }; if ($_ -and (Test-Path -LiteralPath $_)) { Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl -LiteralPath $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on startup directories of all users are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Startup shortcuts targets permissions - backdoor binary that is pointed by *.lnk file from startup directory:"
        $result = $null
        $result = $startupdirs | Sort -Unique | ForEach-Object { Trap { Continue }; if ($_ -and (Test-Path -LiteralPath $_)) { Get-ChildItem -LiteralPath $_ -Force -Recurse -Filter *.lnk 2> $null } } | ForEach-Object { Trap { Continue }; $o = (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).TargetPath; if ($o -and ($o -like '*:\*')) { (Get-Acl $o 2> $null).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on startup shortcuts targets are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] AppInit_DLLs, AppCertDlls, KnownDLLs, LSA, Print Monitors and SafeBoot keys permissions - load your DLL or run your shell as NT AUTHORITY\SYSTEM:"
        $result = $null
        $result = $systemkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; $o = $_.Name; (Get-Acl -Path "Registry::$([WildcardPattern]::Escape($o))").Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on AppInit_DLLs, AppCertDlls, KnownDLLs, LSA, Print Monitors and SafeBoot keys are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] AppInit_DLLs, AppCertDlls, LSA packages, print monitors and BootExecute binaries permissions - backdoor DLL or binary loaded by privileged processes:"
        $result = $null
        $result = $systemkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; Get-ItemProperty -LiteralPath $_.PSPath 2> $null } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } If ($obj.Name -match "AppInit_DLLs|AppCertDlls|Driver|Dll|BootExecute|SetupExecute|S0InitialCommand|AlternateShell|Packages|ProviderOrder|Monitor|Shell") { ForEach ($part in "$($obj.Value)".Split(',; ')) { $o = parsebin($part); if ($o -and ($o -like '*:\*')) { (Get-Acl $o 2> $null).Access } } } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on AppInit_DLLs, AppCertDlls, LSA packages, print monitors and BootExecute binaries are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] COM autostart registry keys and subkeys permissions - register your own CLSID to be loaded by Explorer and other processes:"
        $result = $null
        $result = $comkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; $o = $_.Name; (Get-Acl -Path "Registry::$([WildcardPattern]::Escape($o))").Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on COM autostart registry keys and subkeys are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        $comservers = $comkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; parseclsid($_.PSChildName) ; Get-ItemProperty -LiteralPath $_.PSPath 2> $null | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } parseclsid($obj) } } } | Sort -Unique | ForEach-Object { Trap { Continue }; $clsid = $_; ForEach ($hive in "hklm:\SOFTWARE\Classes\CLSID","hklm:\SOFTWARE\Wow6432Node\Classes\CLSID","hklm:\SOFTWARE\Classes\Wow6432Node\CLSID") { ForEach ($srv in "InprocServer32","InprocServer","LocalServer32","InprocHandler32","TreatAs") { if (Test-Path -LiteralPath "$hive\$clsid\$srv") { "$hive\$clsid\$srv" } } } } | Sort -Unique

        Write "[!] COM server registry keys permissions - change InprocServer32 value to load your DLL into Explorer and other privileged processes:"
        $result = $null
        $result = $comservers | ForEach-Object { Trap { Continue }; Get-Item -LiteralPath $_ 2> $null } | ForEach-Object { Trap { Continue }; $o = $_.Name; (Get-Acl -Path "Registry::$([WildcardPattern]::Escape($o))").Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on COM server registry keys are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] COM server libraries permissions - backdoor DLL that is loaded by Explorer and other privileged processes:"
        $result = $null
        $result = $comservers | ForEach-Object { Trap { Continue }; Get-ItemProperty -LiteralPath $_ 2> $null } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); if ($o -and ($o -like '*:\*')) { (Get-Acl $o 2> $null).Access } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on COM server libraries are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


	Write "[!] Missing COM server library - put in place your own DLL:"
        $result = $null
        $result = $comservers | ForEach-Object { Trap { Continue }; Get-ItemProperty -LiteralPath $_ 2> $null } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); if ($o -and ($o[1] -eq ":") -and (-Not (Test-Path -LiteralPath $o -PathType Leaf))) { Write "$o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] All COM server libraries are in place." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Open command registry keys permissions - execute your binary when privileged user opens a file of given type:"
        $result = $null
        $result = $opencommandkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null } } | ForEach-Object { Trap { Continue }; $o = $_.Name; (Get-Acl -Path "Registry::$([WildcardPattern]::Escape($o))").Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += $opencommandkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-ItemProperty -LiteralPath $_ 2> $null } } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); if ($o -and ($o -like '*:\*')) { (Get-Acl $o 2> $null).Access } } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on open command registry keys and binaries are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Other users registry hives permissions - add autorun value to execute binary as that user:"
        $result = $null
        $result = Get-ChildItem Registry::HKEY_USERS -Force 2> $null | ForEach-Object { Trap { Continue }; $sid = $_.PSChildName; if (($sid -ne $mySid) -and ($sid -notlike "$mySid`_*") -and ($sid -like "S-1-5-21*")) { ForEach ($sub in "Software\Microsoft\Windows\CurrentVersion\Run","Software\Microsoft\Windows\CurrentVersion\RunOnce","Software\Microsoft\Windows\CurrentVersion\RunOnceEx","Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run","Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders","Software\Microsoft\Windows NT\CurrentVersion\Windows","Software\Microsoft\Active Setup\Installed Components","Environment") { if (Test-Path -LiteralPath "Registry::HKEY_USERS\$sid\$sub") { Get-Item -LiteralPath "Registry::HKEY_USERS\$sid\$sub" 2> $null } } } } | ForEach-Object { Trap { Continue }; $o = $_.Name; (Get-Acl -Path "Registry::$([WildcardPattern]::Escape($o))").Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on registry hives of other users are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Service DLL permissions - backdoor DLL that is loaded by svchost.exe as NT AUTHORITY\SYSTEM:"
        $result = $null
        $result = Get-ChildItem hklm:\System\CurrentControlSet\services -Force 2> $null | ForEach-Object { Trap { Continue }; Get-ItemProperty -LiteralPath "$($_.PSPath)\Parameters" -Name ServiceDll 2> $null } | ForEach-Object { Trap { Continue }; $o = parsebin($_.ServiceDll); if ($o -and ($o -like '*:\*')) { (Get-Acl $o 2> $null).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on service DLLs are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


	Write "[!] Missing service DLL - put in place your own DLL:"
        $result = $null
        $result = Get-ChildItem hklm:\System\CurrentControlSet\services -Force 2> $null | ForEach-Object { Trap { Continue }; Get-ItemProperty -LiteralPath "$($_.PSPath)\Parameters" -Name ServiceDll 2> $null } | ForEach-Object { Trap { Continue }; $o = parsebin($_.ServiceDll); if ($o -and ($o[1] -eq ":") -and (-Not (Test-Path -LiteralPath $o -PathType Leaf))) { Write "$o" } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] All service DLLs are in place." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Scheduled tasks definition files permissions - change action of a task that is run with higher privileges:"
        $result = $null
        $result = "$env:WINDIR\System32\Tasks","$env:WINDIR\SysWOW64\Tasks","$env:WINDIR\Tasks" | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl -LiteralPath $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on scheduled tasks definition files are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Scheduled process scripts and libraries permissions - backdoor script or DLL that is passed as argument to scheduled binary:"
        $result = $null
        $result = Get-ScheduledTask | ForEach-Object { Trap { Continue }; $tuser = $_.Principal.UserId; ForEach ($file in parsefiles("$($_.Actions.Arguments)")) { $o = $file; if ($o) { (Get-Acl $o 2> $null).Access } } } | ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o run as $tuser" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on scheduled scripts and libraries are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Checking permissions on uninstall registy keys and subkeys (changing binary paths):"
        $result = $null
        $result = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -Force -Recurse 2> $null | ForEach-Object { $o = $_.Name; (Get-Acl -Path Registry::$_).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on uninstall registry keys and subkeys are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Checking services permissions - change BINARY_PATH_NAME of a service:"
        $result = $null
        $result = Get-Service | Select Name | ForEach-Object { ForEach ($name in $_.Name) { Trap { Continue } $privs = ((sc.exe sdshow $name) | Out-String | ConvertFrom-SDDL 2> $null); Write $privs.Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.Rights.tostring() -match "ChangePermissions|FullControl|Modify|TakeOwnership|Write,|Write |WriteData" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg")) -and $_.AccessControlType.tostring() -match "Allow") { $rights = $_.Rights.tostring(); Write "Group: $arg, Permissions: $rights on $name" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on services are correct for all groups. Double check - each part of SDDL should have A as Allow at the beginning." }
        

        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Checking permissions on services registy keys and subkeys (changing ImagePath value of a service):"
        $result = $null
        $result = Get-ChildItem hklm:\System\CurrentControlSet\services -Force -Recurse 2> $null | ForEach-Object { $o = $_.Name; (Get-Acl -Path Registry::$_).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on services registry keys and subkeys are correct for all groups." }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Service binary permissions - backdoor service binary:"
        $result = $null
        $result = Get-ChildItem hklm:\System\CurrentControlSet\services -Force 2> $null | ForEach-Object { Get-ItemProperty -Path Registry::$_ -Name ImagePath 2> $null } | ForEach-Object { Trap { Continue } $obj = $_.ImagePath; If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); if ($o) { (Get-Acl $o 2> $null).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result } else { Write "[-] Permissions set on service binaries are correct for all groups." }
           

        Write ""
        Write "======================================================================"
        Write ""
		
		
	Write "[!] Missing service binary - put in place your own binary:"
        $result = $null
        $result = Get-ChildItem hklm:\System\CurrentControlSet\services -Force 2> $null | ForEach-Object { Get-ItemProperty -Path Registry::$_ -Name ImagePath 2> $null } | ForEach-Object { Trap { Continue } $obj = $_.ImagePath; If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); if ($o -and ($o[1] -eq ":") -and (-Not (Test-Path -LiteralPath $o -PathType Leaf)) -and (-not($o -ilike '*\WINDOWS\*')) -and (-not($o -ilike '*\Program Files*'))) { Write "$o" }}
        if ($result -ne $null) { Write "[+] Found:" ; Write $result } else { Write "[-] All service binaries are in place." }
           

        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Service directory permissions - try DLL injection:"
        $result = $null
        $result = Get-ChildItem hklm:\System\CurrentControlSet\services -Force 2> $null | ForEach-Object { Get-ItemProperty -Path Registry::$_ -Name ImagePath 2> $null } | ForEach-Object { Trap { Continue } $obj = $_.ImagePath; If ($obj -like 'Microsoft.PowerShell.Core*') { Break } $o = parsebin($obj); $o = parsedir($o); if ($o) { (Get-Acl $o 2> $null).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on service directories are correct for all groups." }
            

        Write ""
        Write "======================================================================"
        Write ""

            
        Write "[!] Process binary permissions - backdoor process binary:"
        $result = $null
        $result = Get-Process | ForEach-Object { ForEach ($proc in $_.path) { (Get-Acl $proc).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $proc" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on process binaries are correct for all groups." }
            

        Write ""
        Write "======================================================================"
        Write ""

            
        Write "[!] Process directory permissions - try DLL injection:"
        $result = $null
        $result = Get-Process | ForEach-Object { ForEach ($proc in $_.path) { $o = $proc.Split("\"); $proc = $o[0..($o.Length-2)] -join ("\"); (Get-Acl $proc).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $proc" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on process directories are correct for all groups." }
            

        Write ""
        Write "======================================================================"
        Write ""

            
        Write "[!] Scheduled process binary permissions - backdoor binary:"
        $result = $null
        $result = Get-ScheduledTask | % { Trap { Continue } $tuser = $_.Principal.UserId; $o = parsebin($_.Actions.Execute); if ($o) { (Get-Acl $o 2> $null).Access } } | ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o run as $tuser" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on scheduled binaries are correct for all groups." }
            

        Write ""
        Write "======================================================================"
        Write ""
		
		
	Write "[!] Missing scheduled task binary - put in place your own binary:"
        $result = $null
        $result = Get-ScheduledTask | % { Trap { Continue } $o = parsebin($_.Actions.Execute); if ($o -and ($o[1] -eq ":") -and (-Not (Test-Path -LiteralPath $o -PathType Leaf)) -and (-not($o -ilike '*\WINDOWS\*')) -and (-not($o -ilike '*\Program Files*'))) { Write "$o" }}
        if ($result -ne $null) { Write "[+] Found:" ; Write $result } else { Write "[-] All scheduled task binaries are in place." }
           

        Write ""
        Write "======================================================================"
        Write ""

            
        Write "[!] Scheduled process directory permissions - try DLL injection:"
        $result = $null
        $result = Get-ScheduledTask | % { Trap { Continue } $tuser = $_.Principal.UserId; $o = parsebin($_.Actions.Execute); $o = parsedir($o); if ($o) { (Get-Acl $o 2> $null).Access } } | ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o run as $tuser" } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on scheduled binary directories are correct for all groups." }
            

        Write ""
        Write "======================================================================"
        Write ""

            
        Write "[!] Loaded DLLs permissions - backdoor DLL:"
        $result = $null
        $result = ForEach ($item in (Get-WmiObject -Class CIM_ProcessExecutable)) { [wmi]"$($item.Antecedent)" | Where-Object {$_.Extension -eq 'dll'} | Select Name | ForEach-Object { $o = $_.Name; (Get-Acl $o 2> $null).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } } }
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on loaded DLLs are correct for all groups." }
		
		
	Write ""
	Write "======================================================================"
	Write ""
		
		
	Write "[!] Directories (with exes) permissions on all drives - dll hijacking:"
	$result = $null
	$result = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' } | %{ Get-ChildItem $_.Name -Directory -Force -Recurse 2> $null | Where {$_.FullName -notlike "C:\Users\*"+$whoamiVal.Split('\')[1]+"*\*"} | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); if (Test-Path $o\*.exe) { Write "Group: $arg, Permissions: $rights on $o" } } } } }
	if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on directories on all drives are correct for all groups." }
		
		
	Write ""
	Write "======================================================================"
	Write ""
		
		
	Write "[!] Files permissions on all drives - backdoor:"
	$result = $null
	$result = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' } | %{ Get-ChildItem $_.Name -File -Force -Recurse 2> $null | Where {$_.FullName -notlike "C:\Users\*"+$whoamiVal.Split('\')[1]+"*\*"} | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } } }
	if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on files on other all are correct for all groups." }
            

        Write ""
        Write "======================================================================"
        Write ""
		
		
	$result = $null
	$result = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -ne 'Fixed' } | %{ $_.Name }
	if ($result -ne $null) { Write "[!] Other drives not verified:" ; Write $result | Sort -Unique }
            

        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Possible passwords found in files on all drives are being dumped to pwds.txt."
        [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' } | ForEach-Object { $drive = $_.Name; Get-ChildItem $drive -Force -Include *.xml, *.sysdef, *.hashtable, *.ini, *.cfg, *.config, *.properties, *.ps1, *.vbs, *.bat, *.log -Recurse 2> $null | Select-String -pattern "pwd","passw" 2> $null | Out-File -Append .\pwds.txt }


        Write ""
        Write "======================================================================"
        Write ""


        Write "[!] Files that may include passwords:"
        $result = $null
        $result = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' } | %{Get-ChildItem $_.Name -Force -Include *passw*, *.sysdef, *.hashtable, *pwd*, *.kdbx, *.rtsz, *.rtsx, *.one, *.onetoc2, *.snt, plum.sqlite -Recurse -erroraction silentlycontinue | %{ $_.FullName }}
        if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Files not found." }


        Write ""
        Write "======================================================================"
        Write ""


        if ($Extended) {

            Write "[!] System Information is being dumped to systeminfo_for_suggester.txt (use windows-exploit-suggester.py to check for local exploits)"
            systeminfo > systeminfo_for_suggester.txt
            

            Write ""
            Write "======================================================================"
            Write ""

        
            Write "[!] List environment variables:"
            Get-ChildItem Env: | Format-Table -AutoSize
            

            Write ""
            Write "======================================================================"
            Write ""

        
            Write "[!] List information about current user:"
            $result = $null
            $result = (net user $whoamiVal.Split('\')[1] 2> $null) | Out-String
            $result += (net user $whoamiVal.Split('\')[1] /domain 2> $null) | Out-String
            $result += (whoami /all) | Out-String
            if ($result -like "*" + $whoamiVal.Split('\')[1] + "*") { Write $result } else { Write "[-] User is probably from another domain than this server." }
            

            Write ""
            Write "======================================================================"
            Write ""

        
            Write "[!] List available drives:"
            Get-PSDrive  | Format-Table -AutoSize
            

            Write ""
            Write "======================================================================"
            Write ""

        
            Write "[!] List interfaces:"
            ipconfig /all
            

            Write ""
            Write "======================================================================"
            Write ""

           
            Write "[!] List routing table:"
            route print
            

            Write ""
            Write "======================================================================"
            Write ""

            
            Write "[!] List ARP cache:"
            arp -A
            

            Write ""
            Write "======================================================================"
            Write ""

        
            Write "[!] List connections:"
            netstat -ano | Select-String "listen"
            

            Write ""
            Write "======================================================================"
            Write ""

        
            Write "[!] List running processes:"
            Get-WmiObject Win32_Process | Select Name, @{Name="UserName";Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}} | Sort-Object UserName, Name | Format-Table -AutoSize
            

            Write ""
            Write "======================================================================"
            Write ""

        
            Write "[!] List installed software:"
            Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall -Force | Format-Table -AutoSize
            dir $env:PROGRAMFILES 2> $null
            $path = resolve("ProgramFiles(x86)")
            dir $path 2> $null
            

            Write ""
            Write "======================================================================"
            Write ""

        
            Write "[!] List installed drivers:"
            driverquery
            

            Write ""
            Write "======================================================================"
            Write ""

        
            Write "[!] List applied hotfixes:"
            Get-HotFix | Select HotFixID,Description,InstalledOn,Caption | Format-Table -AutoSize
            

            Write ""
            Write "======================================================================"
            Write ""

        
            Write "[!] List temp files:"
            dir $env:TEMP 2> $null
            dir C:\Temp 2> $null
            dir C:\Windows\Temp 2> $null
            

            Write ""
            Write "======================================================================"
            Write ""

        
            Write "[!] List startup programs:"
            dir $env:APPDATA"\Microsoft\Windows\Start Menu\Programs\Startup" 2> $null
            dir $env:ProgramData"\Microsoft\Windows\Start Menu\Programs\Startup" 2> $null
            Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run 2> $null | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } Write $obj } }
            Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce 2> $null | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } Write $obj } }
            Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run 2> $null | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } Write $obj } }
            Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce 2> $null | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } Write $obj } }
            

            Write ""
            Write "======================================================================"
            Write ""


            Write "[!] List autorun entries from all known locations:"
            Get-WmiObject Win32_StartupCommand 2> $null | ForEach-Object { $sname = $_.Name; $scmd = $_.Command; $sloc = $_.Location; $suser = $_.User; Write $sname" [$sloc] [$suser]: $scmd" }
            $autorunkeys + $winlogonkeys + $activesetupkeys + $ifeokeys + $shellfolderkeys + $systemkeys + $comkeys + $opencommandkeys | ForEach-Object { Trap { Continue }; if (Test-Path -LiteralPath $_) { Get-Item -LiteralPath $_ 2> $null ; Get-ChildItem -LiteralPath $_ -Force -Recurse 2> $null } } | ForEach-Object { Trap { Continue }; $o = $_.Name; Get-ItemProperty -LiteralPath $_.PSPath 2> $null | ForEach-Object { ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } $name = $obj.Name; $val = $obj.Value; Write "Key: $o, Name: $name, Value: $val" } } } | Sort -Unique
            

            Write ""
            Write "======================================================================"
            Write ""


            Write "[!] List services:"
            Get-ChildItem hklm:\System\CurrentControlSet\services -Force 2> $null | ForEach-Object { Get-ItemProperty -Path Registry::$_ -Name ImagePath 2> $null } | ForEach-Object { Trap { Continue } $obj = $_.ImagePath; $sname = $_.PSChildName; If ($obj -like 'Microsoft.PowerShell.Core*') { Break } else {  if ($obj -notlike "*.sys" -and $obj -notlike "*svchost.exe*") {Write "$sname"": ""$obj"} }} | sort -Unique
           

            Write ""
            Write "======================================================================"
            Write ""


            Write "[!] List scheduled tasks:"
            Get-ScheduledTask | % { $tname = $_.TaskName; $taction = $_.Actions.Execute; $targs = $_.Actions.Arguments; $tuser = $_.Principal.UserId; $tlevel = $_.Principal.RunLevel; Write $tname" (run as $tuser, run level $tlevel): $taction $targs" }
                

            Write ""
            Write "======================================================================"
            Write ""

        }

        if ($Long) {

            Write "[!] Looking for sensitive registry keys:"
            $result = $null
            $result = Get-ChildItem hkcu: -Force -Recurse 2> $null | ForEach-Object { Trap { Continue } if ($_.Name -notlike 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes*') { $o = $_; Get-ItemProperty -Path Registry::$o 2> $null } } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } If ($obj.Name -like "*pwd*") { $name = $obj.Name; $val = $obj.Value; Write "Key: $o, Name: $name, Value: $val`r`n" } } }
            $result += Get-ChildItem hkcu: -Force -Recurse 2> $null | ForEach-Object { Trap { Continue } if ($_.Name -notlike 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes*') { $o = $_; Get-ItemProperty -Path Registry::$o 2> $null } } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } If ($obj.Name -like "*passw*") { $name = $obj.Name; $val = $obj.Value; Write "Key: $o, Name: $name, Value: $val`r`n" } } }
            $result += Get-ChildItem hklm: -Force -Recurse 2> $null | ForEach-Object { Trap { Continue } if ($_.Name -notlike 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes*') { $o = $_; Get-ItemProperty -Path Registry::$o 2> $null } } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } If ($obj.Name -like "*pwd*") { $name = $obj.Name; $val = $obj.Value; Write "Key: $o, Name: $name, Value: $val`r`n" } } }
            $result += Get-ChildItem hklm: -Force -Recurse 2> $null | ForEach-Object { Trap { Continue } if ($_.Name -notlike 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes*') { $o = $_; Get-ItemProperty -Path Registry::$o 2> $null } } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } If ($obj.Name -like "*passw*") { $name = $obj.Name; $val = $obj.Value; Write "Key: $o, Name: $name, Value: $val`r`n" } } }
            if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] There were no potentially sensitive registry keys found." }
         

            Write ""
            Write "======================================================================"
            Write ""


            Write "[!] HKLM keys permissions:"
            $result = $null
            $result = Get-ChildItem hklm: -Force -Recurse 2> $null | ForEach-Object { Trap { Continue } if ($_.Name -notlike 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes*') { $o = $_; Get-ItemProperty -Path Registry::$o 2> $null } } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } (Get-Acl -Path Registry::$o).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoamiVal.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and (($_.IdentityReference.tostring() -like "*\$arg") -or ($_.IdentityReference.tostring() -eq "$arg"))) { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o with value $obj" } } }
            if ($result -ne $null) { Write "[+] Found:" ; Write $result | Sort -Unique } else { Write "[-] Permissions set on HKLM registry keys are correct for all groups." }


            Write ""
            Write "======================================================================"
            Write ""

        }

}
