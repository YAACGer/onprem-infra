#Do a slow start on the scheduled task
Start-Sleep -Seconds 60

Function Expand-Files {
    Param (
        [Object]$Files,
        [string]$Destination
    )

    foreach ($file in $files)
    {
        $fileName = $file.FullName

        write-output "Start unzip: $fileName to $Destination"
        
        #(new-object -com shell.application).namespace($Destination).CopyHere((new-object -com shell.application).namespace($fileName).Items(),16)
        $7zEXE = "$opsDir\7z\7za.exe"

        cmd /c "$7zEXE x -y -o$Destination $fileName" | Add-Content $cmdLogPath
        
        write-output "Finish unzip: $fileName to $Destination"
    }
}

Function Wait-For-Website {
    Param (
        [string]$Url
    )

    $i = 1
    while ($true) {

        try {
            Write-Output "Checking ($i)...please wait"
            $i++

            $response = Invoke-WebRequest -Uri $Url -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            if ($response.StatusCode -eq 200) {
                return;
            }
        } catch {}

        Start-Sleep 2
    }
}

Function Wait-For-VM-Start {
    Param (
        [string]$VMName,
        [int]$AfterStartDelay=30
    )

    Write-Output "Checking state for VM $VMName..."
    while ((Get-VM -Name $VMName).State -ne "Running") {
        Write-Output "Starting VM $VMName..."
        Start-VM -Name $VMName

        for ($i = 1; $i -le $AfterStartDelay; $i++) {
            Write-Progress -Activity "Warming up VM $VMName..." -Status "Progress:" -PercentComplete ($i/$AfterStartDelay*100)
            Start-Sleep -Seconds 1
        }

        Write-Progress -Activity "Warming up VM $VMName..." -Status "Progress:" -Completed
    }
}

Function Optimize-VM-Rearm {
    Param (
        [string]$ComputerName,
        [string]$Username,
        [string]$Password,
        [string]$DomainName = ""
    )

    Write-Output "Getting IP for $ComputerName..."

    $vm = Get-VM -Name $ComputerName

    do {
        Write-Output "Waiting for IP for $ComputerName..."
        Start-Sleep -Seconds 5
    } until ($vm.NetworkAdapters[0].IPAddresses[0].Length -gt 0)

    $ip = $vm.NetworkAdapters[0].IPAddresses[0]
    Write-Output "Found IP $ip..."

    Write-Output "Creating credentials object..."
    if ($DomainName.Length -gt 0) {
        $localusername = "$DomainName\$Username"
    } else {
        $localusername = "$computerName\$Username"
    }

    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $localcredential = New-Object System.Management.Automation.PSCredential ($localusername, $securePassword)

    Write-Output "Re-arm (extend eval license) for VM $ComputerName at $ip..."
    set-item wsman:\localhost\Client\TrustedHosts -value $ip -Force

    Invoke-Command -ComputerName $ip -ScriptBlock { 
        Write-Output $env:COMPUTERNAME; 
        Start-Process "C:\Windows\System32\cscript.exe" -argumentlist "//B ""C:\Windows\System32\slmgr.vbs"" /rearm" -Wait;
        net accounts /maxpwage:unlimited; 
        Start-Sleep -Seconds 60; 
        Restart-Computer -Force 
    } -Credential $localcredential

    Write-Output "Re-arm complete"
}

$SASToken = "?sv=2018-03-28&si=ReadList&sr=c&sig=tXNvoAxX7oDnsCjgsytckIjQMuj%2FUglqzz9XkJXGRg4%3D"

#$ErrorActionPreference = 'SilentlyContinue'
Import-Module BitsTransfer
Import-Module Defender

Start-Transcript -Path "D:\YaacHVHostPostTasks.log"
$cmdLogPath = "D:\YaacHVHostPostTasks.cmd.log"

# Create paths
Write-Output "Creating local directories"
$opsDir = "C:\bfrank"
$vmDir = "F:\VirtualMachines"
$tempDir = "D:\"
New-Item -Path $vmDir -ItemType directory -Force

# Exclude VirtualMachines from Windows Defender scanning
Write-Output "Setting Defender exclusions"
Add-MpPreference -ExclusionPath "F:\VirtualMachines\"

# Unregister scheduled task so this script doesn't run again on next reboot
Write-Output "Unregister SetupVMs scheduled task"
Unregister-ScheduledTask -TaskName "SetUpVMs" -Confirm:$false

# Download 7z
Write-Output "Downloading 7z"
$7zaURL = "https://sabfrankgerwest.blob.core.windows.net/gerwest/7z/7za.exe$SASToken"
$7zaDLLURL = "https://sabfrankgerwest.blob.core.windows.net/gerwest/7z/7za.dll$SASToken"
$7zxaDLLURL = "https://sabfrankgerwest.blob.core.windows.net/gerwest/7z/7zxa.dll$SASToken"


$7zDir = "$opsDir\7z"
New-Item -Path $7zDir -ItemType directory -Force

Start-BitsTransfer -Source $7zaURL -Destination "$7zDir\7za.exe"
Start-BitsTransfer -Source $7zaDLLURL -Destination "$7zDir\7za.dll"
Start-BitsTransfer -Source $7zxaDLLURL -Destination "$7zDir\7zxa.dll"

# Download AzCopy. We won't use the aks.ms/downloadazcopy link in case of breaking changes in later versions
Write-Output "Downloading azcopy"
$azcopyUrl = "https://sabfrankgerwest.blob.core.windows.net/gerwest/azcopy.zip$SASToken"
$azcopyZip = "$opsDir\azcopy.zip"
Start-BitsTransfer -Source $azcopyUrl -Destination $azcopyZip
$azcopyZipfile = Get-ChildItem -Path $azcopyZip
Write-Output "Unzip azcopy"
Expand-Files -Files $azcopyZipfile -Destination $opsDir

$azcopy = "$opsDir\azcopy_windows_amd64_10.1.1\azcopy.exe"

# Download VMs from blob storage
Write-Output "Downloading compressed VMs from sabfrankgerwest"
$container = "https://sabfrankgerwest.blob.core.windows.net/gerwest/VMs/{0}$SASToken"
$vmNames = @("IPFire","W2k19")
foreach ($vmName in $vmNames) {
    $vmZip = "$vmName.zip"

    Write-Output "Downloading $vmZip..."
    cmd /c "$azcopy cp ""$($container -f $vmZip)"" ""$tempDir\$vmZip""" | Add-Content $cmdLogPath
}


$tempDir = "D:\"
$opsDir = "C:\bfrank"
$azcopy = "$opsDir\azcopy_windows_amd64_10.1.1\azcopy.exe"
Write-Output "Downloading AzureMigrateAppliance.zip"
$URI = "https://sabfrankgerwest.blob.core.windows.net/gerwest/VMs/AzureMigrateAppliance.zip$SASToken"
cmd /c "$azcopy cp ""$URI"" ""$tempDir\AzureMigrateAppliance.zip""" | Add-Content $cmdLogPath

# Unzip the VMs
Write-Output "Decompressing VMs"
$zipfiles = Get-ChildItem -Path "$tempDir\*.zip"
#$zipfiles += Get-ChildItem -Path "C:\bfrank\AzureMigrateAppliance.zip"
Expand-Files -Files $zipfiles -Destination $vmDir

#Unzip the Appliance VM

Write-Output "Configuring Hyper-V"

Write-Output "Creating Migrate appliance switch..."
$switchName = 'InternalMigrateSwitch'
New-VMSwitch -Name $switchName -SwitchType Internal
# Connect Azure Migrate switch to the NAT network
Write-Output "Creating migrate network..."
$adapter = Get-NetAdapter | Where-Object { $_.Name -like "*"+$switchName+"*" }
New-NetIPAddress -IPAddress 192.168.1.1 -PrefixLength 24 -InterfaceIndex $adapter.ifIndex

# Create an internal switch with NAT
Write-Output "Creating NAT switch..."
$switchName = 'InternalNATSwitch'
New-VMSwitch -Name $switchName -SwitchType Internal
$adapter = Get-NetAdapter | Where-Object { $_.Name -like "*"+$switchName+"*" }

# Create an internal network (gateway first)
Write-Output "Creating internal network..."
New-NetIPAddress -IPAddress 192.168.0.1 -PrefixLength 24 -InterfaceIndex $adapter.ifIndex

# Create an internal switch with NAT
Write-Output "Creating Perimeter switch..."
$perimeterSwitchName = 'Perimeter'
New-VMSwitch -Name $perimeterSwitchName -SwitchType Internal
$adapter = Get-NetAdapter | Where-Object { $_.Name -like "*"+$perimeterSwitchName+"*" }

# Create an internal network (gateway first)
Write-Output "Creating perimeter network..."
New-NetIPAddress -IPAddress 172.16.1.1 -PrefixLength 24 -InterfaceIndex $adapter.ifIndex


# Add NAT forwarders
Write-Output "Configuring host"

<#Write-Output "Adding NAT forwarders to host..."
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0" -ExternalPort 80   -Protocol TCP -InternalIPAddress "192.168.0.6" -InternalPort 80   -NatName $natName
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0" -ExternalPort 8080 -Protocol TCP -InternalIPAddress "192.168.0.4" -InternalPort 8080 -NatName $natName
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0" -ExternalPort 1433 -Protocol TCP -InternalIPAddress "192.168.0.3" -InternalPort 1433 -NatName $natName
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0" -ExternalPort 500  -Protocol UDP -InternalIPAddress "192.168.0.9" -InternalPort 500  -NatName $natName
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0" -ExternalPort 4500 -Protocol UDP -InternalIPAddress "192.168.0.9" -InternalPort 4500 -NatName $natName
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0" -ExternalPort 1701 -Protocol UDP -InternalIPAddress "192.168.0.9" -InternalPort 1701 -NatName $natName
#>

# Add a firewall rule for HTTP and SQL
Write-Output "Adding firewall rules..."
New-NetFirewallRule -DisplayName "HTTP Inbound" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "HTTP Admin Inbound" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Microsoft SQL Server Inbound" -Direction Inbound -LocalPort 1433 -Protocol TCP -Action Allow

# Installing RAS
Write-Output "Installing and configuring RAS"
Install-WindowsFeature Routing -IncludeManagementTools
Write-Output "Disabling DHCP for RAS..."
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\IP' -Name InitialAddressPoolSize -Type DWORD -Value 0
Write-Output "Enabling legacy management..."
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters' -Name ModernStackEnabled -Type DWORD -Value 0
Write-Output "Installing RAS with VPN disabled..."
Install-RemoteAccess -VpnType RoutingOnly

$externalNIC = "Ethernet"
$internalNIC = "vEthernet (InternalNATSwitch)"
$perimeterNic ="vEthernet (Perimeter)"

cmd.exe /c "netsh routing ip nat install"
cmd.exe /c "netsh routing ip nat add interface ""$externalNIC"""
cmd.exe /c "netsh routing ip nat set interface ""$externalNIC"" mode=full"
cmd.exe /c "netsh routing ip nat add interface ""$internalNIC"""
cmd.exe /c "netsh routing ip nat add interface ""$perimeterNic"""

Write-Output "Configuring NAT services and ports..."
#cmd.exe /c "netsh routing ip nat add portmapping name=""$externalNIC"" tcp 0.0.0.0 80 172.16.1.10 80"
#cmd.exe /c "netsh routing ip nat add portmapping name=""$externalNIC"" tcp 0.0.0.0 8080 172.16.1.10 8080"
#cmd.exe /c "netsh routing ip nat add portmapping name=""$externalNIC"" tcp 0.0.0.0 1433 172.16.1.10 1433"
cmd.exe /c "netsh routing ip nat add portmapping name=""$externalNIC"" udp 0.0.0.0 500 172.16.1.10 500"
cmd.exe /c "netsh routing ip nat add portmapping name=""$externalNIC"" udp 0.0.0.0 1701 172.16.1.10 1701"
cmd.exe /c "netsh routing ip nat add portmapping name=""$externalNIC"" udp 0.0.0.0 4500 172.16.1.10 4500"

# Enable Enhanced Session Mode on Host
Write-Output "Configuring Hyper-V"
Write-Output "Configuring enhanced session mode..."
Set-VMHost -EnableEnhancedSessionMode $true

# Create the nested Windows VMs - from VHDs
Write-Output "Creating VMs"
Write-Output "Creating IPFire..."
Import-VM -Path "F:\VirtualMachines\IPFire\Virtual Machines\55EA6A9E-4BDA-4D63-B680-8291F7D64DCC.vmcx" -Register
#New-VM -Name IPFire -MemoryStartupBytes 1GB -BootDevice VHD -Path "$vmdir\IPFire" -Generation 1 -Switch $switchName -VHDPath "$vmdir\IPFire\IPFire.vhdx"
#Set-VMProcessor IPFire -Count 2
#Write-Output "Setting network config on IPFire..."
#Get-VMNetworkAdapter -VMName IPFire | Remove-VMNetworkAdapter
#Add-VMNetworkAdapter -VMName IPFire -Switch $switchName -Name 'Internal' -DeviceNaming on -StaticMacAddress "00155D000409"
#Set-VMNetworkAdapter -VMName IPFire -DeviceNaming On -Name 'Internal' #-DhcpGuard On
#Add-VMNetworkAdapter -VMName IPFire -Switch $perimeterSwitchName -Name 'External' -DeviceNaming on -StaticMacAddress "00155D00040A"
#Set-VMNetworkAdapter -VMName IPFire -DeviceNaming On -Name 'External' #-DhcpGuard On
Start-Sleep -Seconds 5

Write-Output "VMs created. Pausing for 30 seconds..."
Start-Sleep -Seconds 30

# Configure IP addresses (don't change the IPs! VM config depends on them)
Write-Output "Configuring VMs"


# Disable VMQ on all VMs
Write-Output "Setting VMQ Weight to 0 (disabled) on all network adapters"
Get-VMNetworkAdapter -All | Set-VMNetworkAdapter -VmqWeight 0

# We always want the VMs to start with the host and shut down cleanly with the host
# (If they just save state, which is the default, they can break if the host re-starts on a different CPU architecture)
Write-Output "Setting VMs to automatically start after host reboot"
Get-VM | Set-VM -AutomaticStartAction Start -AutomaticStopAction ShutDown

# Checkpoint all VMs
#Write-Output "Setting bootstrap checkpoint"
#Checkpoint-VM -Name "cmad1" -SnapshotName "Before rearm"
#Checkpoint-VM -Name "cmdb1" -SnapshotName "Before rearm"
#Checkpoint-VM -Name "cmaapp1" -SnapshotName "Before rearm"
#Checkpoint-VM -Name "cmapp1" -SnapshotName "Before rearm"
#Checkpoint-VM -Name "cmaweb1" -SnapshotName "Before rearm"
#Checkpoint-VM -Name "cmweb1" -SnapshotName "Before rearm"
##Checkpoint-VM -Name "cmid1" -SnapshotName "Before rearm"
#Checkpoint-VM -Name "IPFire" -SnapshotName "Before rearm"

# Start all the VMs
Write-Output "VMs present. Waiting for VMs to start..."
Wait-For-VM-Start -VMName "IPFire" -AfterStartDelay 30


# Ping website to warm it up
start-sleep -Seconds 240
#Wait-For-Website('http://172.16.1.10')


#region set startup delays
$vms = @{
    'IPFire'= 10
}
foreach ($vm in $vms.GetEnumerator())
{
    set-vm -Name $($vm.Name) -AutomaticStartDelay  $($vm.Value)
}
#endregion

Write-Output "Creating YaacHVHostVMs..."
& "$opsDir\YaacHVHostVMsCreate.ps1"

Write-Output "Setting LAB start checkpoint"
Checkpoint-VM -Name "IPFire" -SnapshotName "initial Checkpoint"


#cleanup
Write-Output "cleanup..."
#Remove-Item -Path $opsDir -Recurse -Force 
#Remove-Item -Path $tempDir -Recurse -Force -Exclude *.txt -ErrorAction SilentlyContinue

# Config complete
New-Item "D:\PostRebootConfigure_complete.txt"
Set-Content "D:\PostRebootConfigure_complete.txt" 'Configuration complete'

Stop-Transcript