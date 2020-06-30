param(
    [Parameter(Mandatory=$True,Position=1)]
    [string] $DomainName,

    [Parameter(Mandatory=$True,Position=2)]
    [string] $Password
)

$ErrorActionPreference = 'SilentlyContinue'

Start-Transcript -Path "D:\YaacHVHostPreTasks.ps1.log" -Force

# Disable IE ESC
Write-Output "Disable IE ESC"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0
Stop-Process -Name Explorer -Force

# Install Chrome
Write-Output "Installing Google Chrome"
$Path = $env:TEMP; 
$Installer = "chrome_installer.exe"
Invoke-WebRequest "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -OutFile $Path\$Installer
Start-Process -FilePath $Path\$Installer -Args "/silent /install" -Verb RunAs -Wait
Remove-Item $Path\$Installer

# Create path
$opsDir = "C:\bfrank"
New-Item -Path $opsDir -ItemType directory -Force

#save domain credentials.
$UserName = "administrator@$DomainName"
$UserPassword = ConvertTo-SecureString "$Password" -AsPlainText -Force
$UserCredential = [System.Management.Automation.PSCredential]::new($UserName, $UserPassword)
$UserCredential | Export-CliXml  "$opsDir\yaac.cred"

# Format data disk
Write-Output "Formatting data disk"
$disk = Get-Disk | Where-Object { $_.PartitionStyle -eq "RAW" }
Initialize-Disk -Number $disk.DiskNumber -PartitionStyle GPT
New-Partition -DiskNumber $disk.DiskNumber -UseMaximumSize -DriveLetter F
Format-Volume -DriveLetter F -FileSystem NTFS -NewFileSystemLabel DATA

$SASToken = "?sv=2018-03-28&si=ReadList&sr=c&sig=tXNvoAxX7oDnsCjgsytckIjQMuj%2FUglqzz9XkJXGRg4%3D"

# Download scripts for nested Hyper-V VMs, and various other files we'll need during the lab
$downloads = @( "https://sabfrankgerwest.blob.core.windows.net/gerwest/scripts/YaacHVHostPostTasks.ps1$SASToken",
    "https://sabfrankgerwest.blob.core.windows.net/gerwest/V5forVM0.zip$SASToken",
    "https://sabfrankgerwest.blob.core.windows.net/gerwest/scripts/YaacHVHostVMsCreate.ps1$SASToken",
    "https://sabfrankgerwest.blob.core.windows.net/gerwest/scripts/YaacHVHostVMs.unattend.psd1$SASToken",
    "https://sabfrankgerwest.blob.core.windows.net/gerwest/scripts/YaacHVHostVMs.psd1$SASToken"  )

Import-Module BitsTransfer
Write-Output "Downlading files"
foreach ($download in $Downloads)
    {
        $downloadPath = $opsDir + "\$($(Split-Path $download -Leaf).Split('?')[0])" # get pure filename...e.g. get rid of sas tokens and 
        if (!(Test-Path $downloadPath ))    #download if not there
        {
            start-bitstransfer "$download" "$downloadPath" -Priority High -RetryInterval 60 -Verbose -TransferType Download #wait until downloaded.
            #Get-BitsTransfer -Verbose -AllUsers
        }
    }
Expand-Archive $($opsDir+"\V5forVM0.zip") -DestinationPath $($opsDir+"\VM0")


# Register task to run post-reboot script once host is rebooted after Hyper-V install
Write-Output "Register task to run post-reboot script"
$action = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe" -Argument "-executionPolicy Bypass -NoProfile -File $opsDir\YaacHVHostPostTasks.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "SetUpVMs" -Action $action -Trigger $trigger -Principal $principal

# Install and configure DHCP service (used by Azure Migrate appliance so DNS lookup of the host works)
Write-Output "Installing DHCP role"
$dnsClient = Get-DnsClient | Where-Object {$_.InterfaceAlias -eq "Ethernet" }
Install-WindowsFeature -Name "DHCP" -IncludeManagementTools

Write-Output "Configuring Migrate DHCP scope..."
Add-DhcpServerv4Scope -Name "Migrate" -StartRange 192.168.1.1 -EndRange 192.168.1.254 -SubnetMask 255.255.255.0 -State Active
Add-DhcpServerv4ExclusionRange -ScopeId 192.168.1.0 -StartRange 192.168.1.1 -EndRange 192.168.1.15
Set-DhcpServerv4OptionValue -DnsDomain $dnsClient.ConnectionSpecificSuffix -DnsServer 168.63.129.16 -ScopeId 192.168.1.0
Set-DhcpServerv4OptionValue -OptionID 3 -Value 192.168.1.1 -ScopeId 192.168.1.0
Set-DhcpServerv4Scope -ScopeId 192.168.1.0 -LeaseDuration 1.00:00:00

Write-Output "Configuring Nested VMs DHCP scope..."
Add-DhcpServerV4Scope -Name "Nested VMs" -StartRange 192.168.0.1 -EndRange 192.168.0.254 -SubnetMask 255.255.255.0 -State Active
Set-DhcpServerV4OptionValue -DnsServer 192.168.0.2 -Router 192.168.0.1 -ScopeId 192.168.0.0 -Force
Remove-DhcpServerv4OptionValue -OptionID 15 -ScopeId 192.168.0.0
# cmad1
#Add-DhcpServerv4Reservation -IPAddress 192.168.0.2 -ClientId "00-15-5D-00-04-02" -Description "cmad1 reservation" -ScopeId 192.168.0.0
# cmdb1
#Add-DhcpServerv4Reservation -IPAddress 192.168.0.3 -ClientId "00-15-5D-00-04-03" -Description "cmdb1 reservation" -ScopeId 192.168.0.0
# cmaweb1
#Add-DhcpServerv4Reservation -IPAddress 192.168.0.4 -ClientId "00-15-5D-00-04-04" -Description "cmaweb1 reservation" -ScopeId 192.168.0.0
# cmaapp1
#Add-DhcpServerv4Reservation -IPAddress 192.168.0.5 -ClientId "00-15-5D-00-04-05" -Description "cmaapp1 reservation" -ScopeId 192.168.0.0
# cmweb1
#Add-DhcpServerv4Reservation -IPAddress 192.168.0.6 -ClientId "00-15-5D-00-04-06" -Description "cmweb1 reservation" -ScopeId 192.168.0.0
# cmapp1
#Add-DhcpServerv4Reservation -IPAddress 192.168.0.7 -ClientId "00-15-5D-00-04-07" -Description "cmapp1 reservation" -ScopeId 192.168.0.0
# cmid1
#Add-DhcpServerv4Reservation -IPAddress 192.168.0.8 -ClientId "00-15-5D-00-04-08" -Description "cmid1 reservation" -ScopeId 192.168.0.0
# IPFire
Add-DhcpServerv4Reservation -IPAddress 192.168.0.100 -ClientId "00-15-5D-00-04-09" -Description "IPFire GREEN reservation" -ScopeId 192.168.0.0
# IPFire RED interface is "00-15-5D-00-04-0A" don't use

Write-Output "Restarting DHCP service"
cmd /c "netsh dhcp add securitygroups"
Restart-Service dhcpserver
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12" -Name "ConfigurationState" -Value 2

# Install Hyper-V and reboot
Write-Output "Installing Hyper-V role"
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart

Stop-Transcript