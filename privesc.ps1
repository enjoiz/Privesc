function Invoke-Privesc {

<#
.SYNOPSIS
Author: Jakub Palaczynski
IncludeInList
.DESCRIPTION
Find misconfigurations that may allow for privilege escalation.
.PARAMETER Groups
Groups of our interest when checking ACLs.
.PARAMETER Extended
Switch enables output of additional information.
.PARAMETER Long
Switch enables lookups that may last a lot longer.
.EXAMPLE
Invoke-Privesc -Groups 'Users,Everyone,Authenticated Users' -Extended - Long
#>

    [CmdletBinding()]
    param(
		[String]
		$Groups = 'Users,Everyone,Authenticated Users,Interactive,Guests',

        [Switch]
		$Extended,

        [Switch]
		$Long
    )

	$arguments = $groups.Split(",")
    $whoami = whoami


	function resolve($variable) {
        $name = Get-ChildItem Env:$variable
        return $name.Value
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


		Write "Date of last applied patch - just use public exploits if not patched:"
        wmic qfe get InstalledOn | Sort-Object { $_ -as [datetime] } | Select -Last 1


        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Files that may contain Administrator password - you know what to do with this one:"
        $i = 0
        if (Test-Path $env:SystemDrive\sysprep.inf) { Write "$env:SystemDrive\sysprep.inf" ; $i = 1}
        if (Test-Path $env:SystemDrive\sysprep\sysprep.xml) { Write "$env:SystemDrive\sysprep\sysprep.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\Panther\Unattend\Unattended.xml) { Write "$env:WINDIR\Panther\Unattend\Unattended.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\Panther\Unattended.xml) { Write "$env:WINDIR\Panther\Unattended.xml" ; $i = 1 }
    	if (Test-Path $env:WINDIR\system32\sysprep\Unattend.xml) { Write "$env:WINDIR\system32\sysprep\Unattend.xml" ; $i = 1 }
    	if (Test-Path $env:WINDIR\system32\sysprep\Panther\Unattend.xml) { Write "$env:WINDIR\system32\sysprep\Panther\Unattend.xml" ; $i = 1 }
    	if (Test-Path $env:WINDIR\Panther\Unattend\Unattended.xml) { Write "$env:WINDIR\Panther\Unattend\Unattended.xml" ; $i = 1 }
    	if (Test-Path $env:WINDIR\Panther\Unattend.xml) { Write "$env:WINDIR\Panther\Unattend.xml" ; $i = 1 }
    	if (Test-Path $env:SystemDrive\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT) { Write "$env:SystemDrive\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT" ; $i = 1 }
    	if (Test-Path $env:WINDIR\panther\setupinfo) { Write "$env:WINDIR\panther\setupinfo" ; $i = 1 }
    	if (Test-Path $env:WINDIR\panther\setupinfo.bak) { Write "$env:WINDIR\panther\setupinfo.bak" ; $i = 1 }
        if (Test-Path $env:SystemDrive\unattend.xml) { Write "$env:SystemDrive\unattend.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\system32\sysprep.inf) { Write "$env:WINDIR\system32\sysprep.inf" ; $i = 1 }
        if (Test-Path $env:WINDIR\system32\sysprep\sysprep.xml) { Write "$env:WINDIR\system32\sysprep\sysprep.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Config\web.config) { Write "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" ; $i = 1 }
        if (Test-Path $env:SystemDrive\inetpub\wwwroot\web.config) { Write "$env:SystemDrive\inetpub\wwwroot\web.config" ; $i = 1 }
        if (Test-Path "$env:AllUsersProfile\Application Data\McAfee\Common Framework\SiteList.xml") { Write "$env:AllUsersProfile\Application Data\McAfee\Common Framework\SiteList.xml" ; $i = 1 }
        if (Test-Path $env:SystemDrive\CMSysDef\*.sysdef) { Write "$env:SystemDrive\CMSysDef\*.sysdef" ; $i = 1 }
        if (Test-Path $env:SystemDrive\WMExml\*.hashtable) { Write "$env:SystemDrive\WMExml\*.hashtable" ; $i = 1 }
        if (Test-Path HKLM:\SOFTWARE\RealVNC\WinVNC4) { Get-ChildItem -Force -Path HKLM:\SOFTWARE\RealVNC\WinVNC4 ; $i = 1 }
        if (Test-Path HKCU:\Software\SimonTatham\PuTTY\Sessions) { Get-ChildItem -Force -Path HKCU:\Software\SimonTatham\PuTTY\Sessions ; $i = 1 }
        if ($i -eq 0) { Write "Files not found."}


        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Checking if SCCM is installed - installers are run with SYSTEM privileges, many are vulnerable to for example DLL hijacking:"
        $result = $null
        $result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | % { if ($_.ApplicabilityState -eq "Applicable") { $_.Name } }
        if ($result) { $result }
        else { Write "Not Installed." }


        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Checking AlwaysInstallElevated - install *.msi files as NT AUTHORITY\SYSTEM - exploit/windows/local/always_install_elevated:"
        $i = 0
        if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer) { Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated ; $i = 1 }
        if (Test-Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer) { Get-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated ; $i = 1 }
        if ($i -eq 0) { Write "Registries not found."}


        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Checking user privileges:"
        $result = $null
        $result = (whoami /priv | findstr /i /v "Disabled" | findstr /i /C:"SeImpersonatePrivilege" /C:"SeAssignPrimaryPrivilege" /C:"SeTcbPrivilege" /C:"SeBackupPrivilege" /C:"SeRestorePrivilege" /C:"SeCreateTokenPrivilege" /C:"SeLoadDriverPrivilege" /C:"SeTakeOwnershipPrivilege" /C:"SeDebugPrivilege" 2> $null) | Out-String
        if ($result) { Write $result } else { Write "User privileges do not allow for exploitation." }
            

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Checking if WSUS uses HTTP - eg. WSUXploit:"
        $i = 0
        if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate) { (Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name WUServer).WUServer ; $i = 1 }
        if ($i -eq 0) { Write "WSUS misconfiguration not found."}


        Write ""
        Write "----------------------------------------------------------------------"
        Write ""
        
        
        Write "Services with space in path and not enclosed with quotes - if you have permissions run executable from different directory - exploit/windows/local/trusted_service_path:"
        $result = $null
        $result = Get-WmiObject win32_service | Where-Object {($_.PathName -like '* *') -and ($_.PathName -notlike '*"*') -and ($_.PathName -notlike '*C:\Windows*')} | ForEach-Object { Write $_.PathName }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Weak services were not found." }


        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "PATH variable entries permissions - place binary or DLL to execute before legitimate"
        $result = $null
        $result = $env:path.split(";") | ForEach { Trap { Continue }; if ($_ -and ($_ -ne $null)) { $o = $_ ; (Get-Acl $o).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set for all PATH variable entries are correct for all groups." }
    	

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""
     
     
        Write "System32 directory permissions - backdoor windows binaries:"
        $result = $null
        $result = (Get-Acl C:\Windows\system32).Access | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on System32 directory are correct for all groups." }
        

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""

        
        Write "System32 files and directories permissions - backdoor windows binaries:"
        $result = $null
        $result = Get-ChildItem C:\Windows\system32 -Force -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on System32 files and directories are correct for all groups." }
        

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Windows Temp directory read permissions - DLL Sideloading each created directory:"
        $result = $null
        $result = (Get-Acl C:\Windows\Temp).Access 2> $null | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "ChangePermissions|FullControl|Modify|TakeOwnership|ListDirectory" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on Windows Temp directory are correct for all groups." }
            

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Program Files directory permissions - backdoor windows binaries:"
        $result = $null
        $result = (Get-Acl "$env:ProgramFiles").Access | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        $result += (Get-Acl ${env:ProgramFiles(x86)}).Access | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on Program Files directory are correct for all groups." }
        

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Program Files files and directories permissions - backdoor windows binaries:"
        $result = $null
        $result = Get-ChildItem "$env:ProgramFiles" -Force -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ChildItem ${env:ProgramFiles(x86)} -Force -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on Program Files files and directories are correct for all groups." }
        

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""
	
	
	Write "ProgramData directories permissions - use dll hijacking:"
	$result = $null
	$result = Get-ChildItem "$env:ProgramData" -Directory -Force -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); if (Test-Path $o\*.exe) { Write "Group: $arg, Permissions: $rights on $o" } } } }
	if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on ProgramData directories are correct for all groups." }


	Write ""
	Write "----------------------------------------------------------------------"
	Write ""
		
		
        Write "ProgramData files permissions - backdoor windows binaries:"
	$result = $null
	$result = Get-ChildItem "$env:ProgramData" -File -Force -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
	if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on ProgramData files are correct for all groups." }
		

	Write ""
	Write "----------------------------------------------------------------------"
	Write ""


        Write "All users startup permissions - execute binary with permissions of logged user:"
        $result = $null
        $result = (Get-Acl "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup").Access | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" } } }
        $result += Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force -Recurse | ForEach-Object { $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on All Users startup files and directories are correct for all groups." }
            

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Startup executables permissions - backdoor startup binaries and check if they are also run at startup by other users:"
        $result = $null
        $result = Get-ChildItem "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -Force -Recurse | ForEach-Object { $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += (Get-Acl hklm:\Software\Microsoft\Windows\CurrentVersion\Run).Access | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on hklm:\Software\Microsoft\Windows\CurrentVersion\Run" } } }
        $result += (Get-Acl hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce).Access | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce" } } }
        $result += Get-ItemProperty -Path hklm:\Software\Microsoft\Windows\CurrentVersion\Run | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj } (Get-Acl $o).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ItemProperty -Path hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj } (Get-Acl $o).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ItemProperty -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\Run | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj } (Get-Acl $o).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ItemProperty -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\RunOnce | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj } (Get-Acl $o).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on startup executables are correct for all groups." }


        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Startup executables directory permissions - try DLL injection:"
        $result = $null
        $result = Get-ItemProperty -Path hklm:\Software\Microsoft\Windows\CurrentVersion\Run | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (Get-Acl $o).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ItemProperty -Path hklm:\Software\Microsoft\Windows\CurrentVersion\RunOnce | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (Get-Acl $o).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ItemProperty -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\Run | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (Get-Acl $o).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ItemProperty -Path hkcu:\Software\Microsoft\Windows\CurrentVersion\RunOnce | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (Get-Acl $o).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on startup executables directories are correct for all groups." }
            

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Checking permissions on uninstall registy keys and subkeys (changing binary paths):"
        $result = $null
        $result = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall -Force -Recurse 2> $null | ForEach-Object { $o = $_.Name; (Get-Acl -Path Registry::$_).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on uninstall registry keys and subkeys are correct for all groups." }


        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Checking services permissions - change BINARY_PATH_NAME of a service:"
        $result = $null
        $result = Get-Service | Select Name | ForEach-Object { ForEach ($name in $_.Name) { Trap { Continue } $privs = ((sc.exe sdshow $name) | Out-String | ConvertFrom-SDDL 2> $null); Write $privs.Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.Rights.tostring() -match "ChangePermissions|FullControl|Modify|TakeOwnership|Write,|Write |WriteData" -and $_.IdentityReference.tostring() -like "*\$arg" -and $_.AccessControlType.tostring() -match "Allow") { $rights = $_.Rights.tostring(); Write "Group: $arg, Permissions: $rights on $name" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on services are correct for all groups. Double check - each part of SDDL should have A as Allow at the beginning." }
        

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Checking permissions on services registy keys and subkeys (changing ImagePath value of a service):"
        $result = $null
        $result = Get-ChildItem hklm:\System\CurrentControlSet\services -Force -Recurse 2> $null | ForEach-Object { $o = $_.Name; (Get-Acl -Path Registry::$_).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on services registry keys and subkeys are correct for all groups." }


        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Service binary permissions - backdoor service binary:"
        $result = $null
        $result = Get-ChildItem hklm:\System\CurrentControlSet\services -Force 2> $null | ForEach-Object { Get-ItemProperty -Path Registry::$_ -Name ImagePath 2> $null } | ForEach-Object { Trap { Continue } $obj = $_.ImagePath; If ($obj -like 'Microsoft.PowerShell.Core*') { Break } If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj } (Get-Acl $o 2> $null).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result } else { Write "Permissions set on service binaries are correct for all groups." }
           

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""
		
		
		Write "Missing service binary - put in place your on binary:"
        $result = $null
        $result = Get-ChildItem hklm:\System\CurrentControlSet\services -Force 2> $null | ForEach-Object { Get-ItemProperty -Path Registry::$_ -Name ImagePath 2> $null } | ForEach-Object { Trap { Continue } $obj = $_.ImagePath; If ($obj -like 'Microsoft.PowerShell.Core*') { Break } If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj } if ((-Not (Test-Path $o -PathType Leaf)) -and ($o[1] -eq ":") -and (-not($o -ilike '*\WINDOWS\*')) -and (-not($o -ilike '*\Program Files*'))) { Write "$o" }}
        if ($result -ne $null) { Write $result } else { Write "All service binaries are in place." }
           

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Service directory permissions - try DLL injection:"
        $result = $null
        $result = Get-ChildItem hklm:\System\CurrentControlSet\services -Force 2> $null | ForEach-Object { Get-ItemProperty -Path Registry::$_ -Name ImagePath 2> $null } | ForEach-Object { Trap { Continue } $obj = $_.ImagePath; If ($obj -like 'Microsoft.PowerShell.Core*') { Break } If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj } $o2 = $o.Split("\"); $o = $o2[0..($o2.Length-2)] -join ("\"); (Get-Acl $o 2> $null).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on service directories are correct for all groups." }
            

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""

            
        Write "Process binary permissions - backdoor process binary:"
        $result = $null
        $result = Get-Process | ForEach-Object { ForEach ($proc in $_.path) { (Get-Acl $proc).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $proc" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on process binaries are correct for all groups." }
            

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""

            
        Write "Process directory permissions - try DLL injection:"
        $result = $null
        $result = Get-Process | ForEach-Object { ForEach ($proc in $_.path) { $o = $proc.Split("\"); $proc = $o[0..($o.Length-2)] -join ("\"); (Get-Acl $proc).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $proc" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on process directories are correct for all groups." }
            

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""

            
        Write "Scheduled process binary permissions - backdoor binary:"
        $result = $null
        $result = Get-ScheduledTask | % { Trap { Continue } $o = $_.Actions.Execute ; If ($o -like '*%*%*') { $var = $o.split('%')[1]; $out = resolve($var); $o = $o.replace("%$var%",$out) }; (Get-Acl $o 2> $null).Access } | ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on scheduled binaries are correct for all groups." }
            

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""
		
		
	Write "Missing scheduled task binary - put in place your on binary:"
        $result = $null
        $result = Get-ScheduledTask | % { Trap { Continue } $o = $_.Actions.Execute ; If ($o -like '*%*%*') { $var = $o.split('%')[1]; $out = resolve($var); $o = $o.replace("%$var%",$out) }; If ($o -like '"*"') { $o = $o.split('"')[1] } ; if ((-Not (Test-Path $o -PathType Leaf)) -and ($o[1] -eq ":") -and (-not($o -ilike '*\WINDOWS\*')) -and (-not($o -ilike '*\Program Files*'))) { Write "$o" }}
        if ($result -ne $null) { Write $result } else { Write "All scheduled task binaries are in place." }
           

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""

            
        Write "Scheduled process directory permissions - try DLL injection:"
        $result = $null
        $result = Get-ScheduledTask | % { Trap { Continue } $o = $_.Actions.Execute ; If ($o -like '*%*%*') { $var = $o.split('%')[1]; $out = resolve($var); $o = $o.replace("%$var%",$out) }; $obj = $o.Split("\"); $o = $obj[0..($obj.Length-2)] -join ("\"); (Get-Acl $o 2> $null).Access } | ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on scheduled binary directories are correct for all groups." }
            

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""

            
        Write "Loaded DLLs permissions - backdoor DLL:"
        $result = $null
        $result = ForEach ($item in (Get-WmiObject -Class CIM_ProcessExecutable)) { [wmi]"$($item.Antecedent)" | Where-Object {$_.Extension -eq 'dll'} | Select Name | ForEach-Object { $o = $_.Name; (Get-Acl $o 2> $null).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } } }
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on loaded DLLs are correct for all groups." }
		
		
	Write ""
	Write "----------------------------------------------------------------------"
	Write ""
		
		
	Write "Directories (with exes) permissions on all drives - dll hijacking:"
	$result = $null
	$result = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' } | %{ Get-ChildItem $_.Name -Directory -Force -Recurse 2> $null | Where {$_.FullName -notlike "C:\Users\*"+$whoami.Split('\')[1]+"*\*"} | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); if (Test-Path $o\*.exe) { Write "Group: $arg, Permissions: $rights on $o" } } } } }
	if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on directories on all drives are correct for all groups." }
		
		
	Write ""
	Write "----------------------------------------------------------------------"
	Write ""
		
		
	Write "Files permissions on all drives - backdoor:"
	result = $null
	$result = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' } | %{ Get-ChildItem $_.Name -File -Force -Recurse 2> $null | Where {$_.FullName -notlike "C:\Users\*"+$whoami.Split('\')[1]+"*\*"} | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } } }
	if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on files on other all are correct for all groups." }
            

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""
		
		
	$result = $null
	$result = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -ne 'Fixed' } | %{ $_.Name }
	if ($result -ne $null) { Write "Other drives not verified:" ; Write $result | Sort -Unique }
            

        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Possible passwords found in files on all drives are being dumped to pwds.txt."
        [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' } | ForEach-Object { $drive = $_.Name; Get-ChildItem $drive -Force -Include *.xml, *.ini, *.cfg, *.config, *.properties, *.ps1, *.vbs, *.bat, *.log -Recurse 2> $null | Select-String -pattern "pwd","passw" 2> $null | Out-File -Append .\pwds.txt }


        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        Write "Files that may include passwords:"
        $result = $null
        $result = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' } | %{Get-ChildItem $_.Name -Force -Include *passw*, *pwd*, *.kdbx, *.rtsz, *.rtsx, *.one, *.onetoc2, *.snt, plum.sqlite -Recurse -erroraction silentlycontinue | %{ $_.FullName }}
        if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Files not found." }


        Write ""
        Write "----------------------------------------------------------------------"
        Write ""


        if ($Extended) {

            Write "System Information is being dumped to systeminfo_for_suggester.txt (use windows-exploit-suggester.py to check for local exploits)"
            systeminfo > systeminfo_for_suggester.txt
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        
            Write "List environment variables:"
            Get-ChildItem Env: | Format-Table -AutoSize
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        
            Write "List information about current user:"
            $result = $null
            $result = (net user $whoami.Split('\')[1] 2> $null) | Out-String
            $result += (net user $whoami.Split('\')[1] /domain 2> $null) | Out-String
            $result += (whoami /all) | Out-String
            if ($result -like "*" + $whoami.Split('\')[1] + "*") { Write $result } else { Write "User is probably from another domain than this server." }
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        
            Write "List available drives:"
            Get-PSDrive  | Format-Table -AutoSize
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        
            Write "List interfaces:"
            ipconfig /all
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

           
            Write "List routing table:"
            route print
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

            
            Write "List ARP cache:"
            arp -A
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        
            Write "List connections:"
            netstat -ano | Select-String "listen"
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        
            Write "List running processes:"
            Get-WmiObject Win32_Process | Select Name, @{Name="UserName";Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}} | Sort-Object UserName, Name | Format-Table -AutoSize
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        
            Write "List installed software:"
            Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall -Force | Format-Table -AutoSize
            dir $env:PROGRAMFILES 2> $null
            $path = resolve("ProgramFiles(x86)")
            dir $path 2> $null
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        
            Write "List installed drivers:"
            driverquery
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        
            Write "List applied hotfixes:"
            wmic qfe get Caption","Description","HotFixID","InstalledOn | Out-String
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        
            Write "List temp files:"
            dir $env:TEMP 2> $null
            dir C:\Temp 2> $null
            dir C:\Windows\Temp 2> $null
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        
            Write "List startup programs:"
            dir $env:APPDATA"\Microsoft\Windows\Start Menu\Programs\Startup" 2> $null
            dir $env:ProgramData"\Microsoft\Windows\Start Menu\Programs\Startup" 2> $null
            Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run 2> $null | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } Write $obj } }
            Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce 2> $null | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } Write $obj } }
            Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run 2> $null | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } Write $obj } }
            Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce 2> $null | ForEach-Object { ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } Write $obj } }
            

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""


            Write "List services:"
            Get-ChildItem hklm:\System\CurrentControlSet\services -Force 2> $null | ForEach-Object { Get-ItemProperty -Path Registry::$_ -Name ImagePath 2> $null } | ForEach-Object { Trap { Continue } $obj = $_.ImagePath; $sname = $_.PSChildName; If ($obj -like 'Microsoft.PowerShell.Core*') { Break } else {  if ($obj -notlike "*.sys" -and $obj -notlike "*svchost.exe*") {Write "$sname"": ""$obj"} }} | sort -Unique
           

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""


            Write "List scheduled tasks:"
            Get-ScheduledTask | % { $tname = $_.TaskName; $taction = $_.Actions.Execute; $targs = $_.Actions.Arguments; Write $tname": $taction $targs" }
                

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        }

        if ($Long) {

            Write "Looking for sensitive registry keys:"
            $result = $null
            $result = Get-ChildItem hkcu: -Force -Recurse 2> $null | ForEach-Object { Trap { Continue } if ($_.Name -notlike 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes*') { $o = $_; Get-ItemProperty -Path Registry::$o 2> $null } } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } If ($obj.Name -like "*pwd*") { $name = $obj.Name; $val = $obj.Value; Write "Key: $o, Name: $name, Value: $val`r`n" } } }
            $result += Get-ChildItem hkcu: -Force -Recurse 2> $null | ForEach-Object { Trap { Continue } if ($_.Name -notlike 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes*') { $o = $_; Get-ItemProperty -Path Registry::$o 2> $null } } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } If ($obj.Name -like "*passw*") { $name = $obj.Name; $val = $obj.Value; Write "Key: $o, Name: $name, Value: $val`r`n" } } }
            $result += Get-ChildItem hklm: -Force -Recurse 2> $null | ForEach-Object { Trap { Continue } if ($_.Name -notlike 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes*') { $o = $_; Get-ItemProperty -Path Registry::$o 2> $null } } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } If ($obj.Name -like "*pwd*") { $name = $obj.Name; $val = $obj.Value; Write "Key: $o, Name: $name, Value: $val`r`n" } } }
            $result += Get-ChildItem hklm: -Force -Recurse 2> $null | ForEach-Object { Trap { Continue } if ($_.Name -notlike 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes*') { $o = $_; Get-ItemProperty -Path Registry::$o 2> $null } } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties) { If ($obj.Name -eq 'PSPath') { Break } If ($obj.Name -like "*passw*") { $name = $obj.Name; $val = $obj.Value; Write "Key: $o, Name: $name, Value: $val`r`n" } } }
            if ($result -ne $null) { Write $result | Sort -Unique } else { Write "There were no potentially sensitive registry keys found." }
         

            Write ""
            Write "----------------------------------------------------------------------"
            Write ""


            Write "HKLM keys permissions:"
            $result = $null
            $result = Get-ChildItem hklm: -Force -Recurse 2> $null | ForEach-Object { Trap { Continue } if ($_.Name -notlike 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes*') { $o = $_; Get-ItemProperty -Path Registry::$o 2> $null } } | ForEach-Object { Trap { Continue } ForEach ($obj in $_.psobject.properties.Value) { If ($obj -like 'Microsoft.PowerShell.Core*') { Break } (Get-Acl -Path Registry::$o).Access } } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.RegistryRights.tostring() -match "ChangePermissions|CreateSubKey|FullControl|SetValue|TakeOwnership|WriteKey" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.RegistryRights.tostring(); Write "Group: $arg, Permissions: $rights on $o with value $obj" } } }
            if ($result -ne $null) { Write $result | Sort -Unique } else { Write "Permissions set on HKLM registry keys are correct for all groups." }


            Write ""
            Write "----------------------------------------------------------------------"
            Write ""

        }

}
