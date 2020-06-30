<#
    This is the script that will create some yaac vms on the hyper-v host.

    it'll read:
     - the vm details from VMs.psd1
     - the unattend details for the vms from unattend.psd1

    by: bfrank
    version: 1.0.0.4
#>


#region variables

$currentPath = ""
#region Get execution directory -> $currentPath
if ($host.name -eq 'ConsoleHost') {
    # or -notmatch 'ISE'
    $currentPath = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent
}
else {
    $currentPath = split-path $psISE.CurrentFile.FullPath -parent
}
#endregion

#Load VMs to create config
$VMConfig = Import-PowerShellDataFile $("$currentPath\YaacHVHostVMs.psd1")

$GoldenImage = "F:\VirtualMachines\W2k19\W2k19.vhdx"
$vmDirectoryPrefix = "F:\VirtualMachines"

$savedCredentials= Import-Clixml $("$currentPath\yaac.cred")
$adminPassword = $savedCredentials.GetNetworkCredential().Password
#filter out domain name.
$savedCredentials.UserName -match "([^@]*)@([^\.]*)(.*)"
$domainName = $Matches[2]+$Matches[3]
$netbios = $Matches[2]
Write-Output "will create Domain: $domainName"

#region Unattend.xml Handling
$unattendConfig = Import-PowerShellDataFile $("$currentPath\YaacHVHostVMs.unattend.psd1")


### Sysprep unattend XML
$unattendSource = [xml]@"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>*</ComputerName>
            <ProductKey>Key</ProductKey> 
            <RegisteredOrganization>Organization</RegisteredOrganization>
            <RegisteredOwner>Owner</RegisteredOwner>
            <TimeZone>TZ</TimeZone>
        </component>
        <component name="Microsoft-Windows-IE-ESC" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <IEHardenAdmin>false</IEHardenAdmin>
        </component>
        <component name="Microsoft-Windows-ErrorReportingCore" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <DisableWER>1</DisableWER>
        </component>
        <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <fDenyTSConnections>false</fDenyTSConnections>
        </component>
        <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <Ipv4Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                    </Ipv4Settings>
                    <UnicastIpAddresses>
                        <IpAddress wcm:action="add" wcm:keyValue="1">127.0.0.1/24</IpAddress>
                    </UnicastIpAddresses>
                    <Identifier>Ethernet</Identifier>
                    <Routes>
                        <Route wcm:action="add">
                            <Identifier>1</Identifier>
                            <Prefix>0.0.0.0/0</Prefix>
                            <NextHopAddress>127.0.0.1</NextHopAddress>
                        </Route>
                    </Routes>
                </Interface>
            </Interfaces>
        </component>
        <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <Interfaces>
                <Interface wcm:action="add">
                    <DNSServerSearchOrder>
                        <IpAddress wcm:action="add" wcm:keyValue="1">127.0.0.1</IpAddress>
                    </DNSServerSearchOrder>
                    <Identifier>Ethernet</Identifier>
                </Interface>
            </Interfaces>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Work</NetworkLocation>
                <ProtectYourPC>1</ProtectYourPC>
            </OOBE>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>password</Value>
                    <PlainText>True</PlainText>
                </AdministratorPassword>
            </UserAccounts>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>en-us</InputLocale>
            <SystemLocale>en-us</SystemLocale>
            <UILanguage>en-us</UILanguage>
            <UILanguageFallback>en-us</UILanguageFallback>
            <UserLocale>en-us</UserLocale>
        </component>
    </settings>
</unattend>
"@

#region Unattend Helper function
function GetUnattendChunk {
    param
    (
        [string] $pass, 
        [string] $component, 
        [xml] $unattend
    ); 
                
    # Helper function that returns one component chunk from the Unattend XML data structure
    return $Unattend.unattend.settings | ? pass -eq $pass `
    | select -ExpandProperty component `
    | ? name -eq $component;
}
#endregion
#endregion

#endregion

function Wait-ForPSDirect([string]$VMName, $cred) {
    while ((Invoke-Command -VMName $VMName -Credential $cred { 'Test' } -ea SilentlyContinue) -ne 'Test') { Start-Sleep -Seconds 5 }
}

# a bunch of VMs
foreach ($vm in $($vmConfig.GetEnumerator() | Sort-Object Name)) {
    $vmProcCount = $vm.Value.vmProcCount                                                                                                                                                                              
    $vmNics = $vm.Value.vmNics                                                                                                                                                                                   
    $vmName = $vm.Value.vmName.Replace("xx", $("{0:00}" -f $i)) 
    $vmMemory = $vm.Value.vmMemory                                                                                                                                                                                 
    $vmGeneration = $vm.Value.vmGeneration                                                                                                                                                                             
    $vmAutomaticStopAction = $vm.Value.vmAutomaticStopAction
    $vmDataDisks = $vm.Value.vmDataDisks

    $vmDirectory = $vmDirectoryPrefix + "{0:00}" -f $i  #e.g. 'D:\VMs\TN01...', 02, 03,...
    
    New-Item -Path $vmDirectory -ItemType Directory -ErrorAction SilentlyContinue
    New-VM -Name $vmName -MemoryStartupBytes $vmMemory -NoVHD  -Path $vmDirectory -Generation $vmGeneration | Set-VM -ProcessorCount $vmProcCount  -AutomaticStopAction $vmAutomaticStopAction 

    $vhdDirectory = $vmDirectory + "\" + $vmName + "\Virtual Hard Disks"
    New-Item -Path $vhdDirectory -ErrorAction SilentlyContinue -ItemType Directory
    $OSVHD = $vhdDirectory + "\" + $(Split-Path -Path $GoldenImage -Leaf)
    Copy-Item -Path $GoldenImage -Destination $OSVHD -Verbose
    $OSVolumes = Mount-VHD -Path $OSVHD –PassThru | Get-Disk | Get-Partition | Get-Volume
    foreach ($Drive in $OSVolumes) {
        if (($Drive.DriveLetter -ne '') -and ($Drive.DriveLetter -ne $Null)) {
                
            if ($unattendConfig[$vm.Name] -ne $null) {
                # unattend for vm found? if yes process it! 
                
                # Reload template - clone is necessary as PowerShell thinks this is a "complex" object
                $unattend = $unattendSource.Clone();
                       
                # Customize unattend XML
                GetUnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | % { $_.ComputerName = $vmName };
                GetUnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | % { $_.RegisteredOrganization = $unattendConfig[$vm.Name].Organization };
                GetUnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | % { $_.RegisteredOwner = $unattendConfig[$vm.Name].Owner };
                GetUnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | % { $_.TimeZone = $unattendConfig[$vm.Name].Timezone };
                GetUnattendChunk 'oobeSystem' 'Microsoft-Windows-Shell-Setup' $unattend | % { $_.UserAccounts.AdministratorPassword.Value = $adminPassword };
                GetUnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | % { $_.ProductKey = $unattendConfig[$vm.Name].WindowsKey };
                GetUnattendChunk 'specialize' 'Microsoft-Windows-TCPIP' $unattend | % { $_.Interfaces.Interface.UnicastIpAddresses.IpAddress.'#text' = $unattendConfig[$vm.Name].IPAddress + "/" + $($unattendConfig[$vm.Name].IPMask) };
                GetUnattendChunk 'specialize' 'Microsoft-Windows-TCPIP' $unattend | % { $_.Interfaces.Interface.Routes.Route.NextHopAddress = $unattendConfig[$vm.Name].IPGateway };
                GetUnattendChunk 'specialize' 'Microsoft-Windows-DNS-Client' $unattend | % { $_.Interfaces.Interface.DNSServerSearchOrder.IpAddress.'#text' = $unattendConfig[$vm.Name].DNSIP };
                GetUnattendChunk 'oobeSystem' 'Microsoft-Windows-International-Core' $unattend | % { $_.InputLocale = $unattendConfig[$vm.Name].InputLocale };
                GetUnattendChunk 'oobeSystem' 'Microsoft-Windows-International-Core' $unattend | % { $_.SystemLocale = $unattendConfig[$vm.Name].SystemLocale };
                GetUnattendChunk 'oobeSystem' 'Microsoft-Windows-International-Core' $unattend | % { $_.UserLocale = $unattendConfig[$vm.Name].UserLocale };
    
                # Write it out to disk
                $UnattendFile = $($Drive.DriveLetter + ':\Unattend.xml')
                $unattend.Save($UnattendFile);
            }

            if ($(Test-Path "$currentPath\$($vm.Name)") -eq $true) {
                #is there any folder named like the VMs in the VMs.psd1 e.g. VM0,VM1... if so copy contents into VM
                $destination = $($Drive.DriveLetter + ':\temp')
                New-Item -Path $destination -ErrorAction SilentlyContinue -ItemType Directory
                Copy-Item -Path "$currentPath\$($vm.Name)\*" -Destination $destination -Verbose -Recurse
            }
        }
    }
    Dismount-VHD -Path $OSVHD
    Add-VMHardDiskDrive -VMName $VmName -Path $OSVHD

    foreach ($vmDataDisk in $vmDataDisks) {
        $DiskPath = $vhdDirectory + "\" + $($vmDataDisk.DiskName)
        New-VHD -Path $DiskPath -SizeBytes $([uint64]$($vmDataDisk.DiskSize)) -Dynamic
        Add-VMHardDiskDrive -VMName $VmName -Path $DiskPath
    }

    Get-VMNetworkAdapter -VMName $vmName | Remove-VMNetworkAdapter
    foreach ($vmNic in $vmNics.GetEnumerator()) {
        Add-VMNetworkAdapter -VMName $VmName -SwitchName $($VMNic.Value.Switch) -Name $($VMNic.Name) -DeviceNaming on
        Set-VMNetworkAdapter -VMName $VmName -DeviceNaming On -Name $($VMNic.Name) #-DhcpGuard On
        if ($VMNic.Value.VLANID -ne '') {
            $internalVLANID = $VMNic.Value.VLANID.Replace("xx", $("{0:00}" -f $i))    #e.g. 1101,1102,...
            "NIC: {0}   Switch: {1}   VLANID: {2}" -f $VMNic.Name, $VMNic.Value.Switch, $internalVLANID
            Set-VMNetworkAdapterVlan -VMName $vmName -VMNetworkAdapterName $($VMNic.Name) -Access -VlanId $internalVLANID
        }
    } 
    Start-Sleep -Seconds 2
    Start-VM $vmName 
}

#now do something with the VMs
$UserName = "Administrator"
$UserPassword = ConvertTo-SecureString $adminPassword -AsPlainText -Force 
$UserCredential = New-Object System.Management.Automation.PSCredential ($UserName, $UserPassword)

#region VM0: e.g. "www" do domain join and other stuff
#$VM = ($vmConfig.GetEnumerator() | Where Name -EQ VM0).Value.vmName.Replace("xx", $("{0:00}" -f $i)) 

Wait-ForPSDirect 'FRA-DC-01' $UserCredential # wait till VM is up and responsive

Invoke-Command -VMName  'FRA-DC-01' -Credential $UserCredential  -ArgumentList $domainName, $adminPassword -ScriptBlock `
{
    #this is the scriptblock to be run on the VM
    param(
        [Parameter(Mandatory = $True, Position = 1)]
        [string] $DomainName,
    
        [Parameter(Mandatory = $True, Position = 2)]
        [string] $Password
    )
        
    $tmpDir = "c:\temp\" 

    #create folder if it doesn't exist
    if (!(Test-Path $tmpDir)) { mkdir $tmpDir -force }
        
    #write a log file with the same name of the script
    Start-Transcript "$tmpDir\PowerShell.log"
        
    Get-Date    # Timestamp 
        
    #open Firewall for RDP
    Enable-NetFirewallRule -DisplayName 'Remote Desktop*'

    #to allow RDP logon to older unpatched Windows Server machines....
    #Harden OS...
    Start-Process "C:\Windows\System32\reg.exe" -ArgumentList "IMPORT c:\temp\dontdisplaylastusername.reg" -Wait
    Remove-Item 'c:\unattend.xml' -Force

    #do domain join
    sleep 5
    
    #To install AD we need PS support for AD first
    Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools
    Import-Module ActiveDirectory
    
    
    #Do we find Data disks (raw by default) in this VM? 
    $RawDisks = Get-Disk | where PartitionStyle -eq "RAW"
    
    $driveLetters = ("f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z")
    
    $i = 0
    foreach ($RawDisk in $RawDisks) {
        $currentDriveLetter = $driveLetters[$i]
    
        New-Volume -DiskNumber $RawDisk.Number -FriendlyName "Data$i" -FileSystem NTFS -DriveLetter $currentDriveLetter
        $i++
    }
    
    #Do Domain install
    #on prem you could install AD database to OS disk - AD in Azure VM this is not recommended!
    #https://docs.microsoft.com/en-us/previous-versions/orphan-topics/azure.100/jj156090(v=azure.100)
    #To Do: for Active Directory database storage You need to change default storage location from C:\ 
    #Store the database, logs, and SYSVOL on the either same data disk or separate data disks e.g.
    #-DatabasePath "e:\NTDS" -SysvolPath "e:\SYSVOL" -LogPath "e:\Logs"
    #Set the Host Cache Preference setting on the Azure data disk for NONE. This prevents issues with write caching for AD DS operations.
    
    $SecurePassword = ConvertTo-SecureString "$Password" -AsPlainText -Force
    
    #Do we have Data Disk? 
    $DataDisk0 = Get-Volume -FileSystemLabel "Data0" -ErrorAction SilentlyContinue
    
    switch ($DataDisk0 -ne $null) {
        'True' { #Active Directory database storage on first Data Disk 
            $drive = "$($DataDisk0.DriveLetter):"
            Install-ADDSForest -DomainName "$DomainName" -DatabasePath "$drive\NTDS" -SysvolPath "$drive\SYSVOL" -LogPath "$drive\Logs" -ForestMode Default -DomainMode Default -InstallDns:$true -SafeModeAdministratorPassword $SecurePassword -CreateDnsDelegation:$false -NoRebootOnCompletion:$true -Force:$true
        }
        
        #nope - not recommended 
        Default {
            Install-ADDSForest -DomainName "$DomainName" -ForestMode Default -DomainMode Default -InstallDns:$true -SafeModeAdministratorPassword $SecurePassword -CreateDnsDelegation:$false -NoRebootOnCompletion:$true -Force:$true
        }
    }
    
    #add some DNS forwarders to our DNS server to enable external name resolution
    Add-DnsServerForwarder -IPAddress 168.63.129.16  #add azure intrinsic Name server - this works when VM is in Azure / when onprem you need DNS proxy in azure
    
    #download the AD connect tool to synch with AAD
    $Downloads = @( `
            "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi")
    
    foreach ($download in $Downloads) {
        $downloadPath = $tmpDir + "\$(Split-Path $download -Leaf)"
        if (!(Test-Path $downloadPath )) { #download if not there
            start-bitstransfer "$download" "$downloadPath" -Priority High -RetryInterval 60 -Verbose -TransferType Download #wait until downloaded.
            Get-BitsTransfer -Verbose -AllUsers
        }
    }
    
    
    #enable-ping
    Get-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" | Enable-NetFirewallRule

    Stop-Transcript

}
Stop-VM 'FRA-DC-01'
do {
    sleep 1  
}
until ((Get-VM 'FRA-DC-01').State -eq 'Off')
Start-VM 'FRA-DC-01' 

sleep 600

Wait-ForPSDirect 'FRA-SRV-01' $UserCredential
Invoke-Command -VMName  'FRA-SRV-01' -Credential $UserCredential  -ArgumentList $netbios, $adminPassword -ScriptBlock `
{
    #this is the scriptblock to be run on the VM
    param(
        [string] $Domain,
        [string] $Password
    )
            
    $tmpDir = "c:\temp\" 

    #create folder if it doesn't exist
    if (!(Test-Path $tmpDir)) { mkdir $tmpDir -force }
            
    #write a log file with the same name of the script
    Start-Transcript "$tmpDir\PowerShell.log"
            
    Get-Date    # Timestamp 
            
    #open Firewall for RDP
    Enable-NetFirewallRule -DisplayName 'Remote Desktop*'

    #to allow RDP logon to older unpatched Windows Server machines....
    #Harden OS...
    Start-Process "C:\Windows\System32\reg.exe" -ArgumentList "IMPORT c:\temp\dontdisplaylastusername.reg" -Wait
    Remove-Item 'c:\unattend.xml' -Force

    #do domain join
    sleep 5
    $SecurePassword = ConvertTo-SecureString "$Password" -AsPlainText -Force
    $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$Domain\Administrator", $SecurePassword
    #keep old computername
    Add-Computer -ComputerName localhost -DomainName $Domain -Credential $credential

    $chromePath = "C:\temp\GoogleChromeStandaloneEnterprise64.msi"
    #unattended install
    start-process -filepath msiexec -ArgumentList "/i ""$chromePath"" /l*v ""$chromePath.log""  /passive ACCEPTEULA=""YES""" -Wait

    $vsCodePath = "C:\temp\VSCodeSetup-x64-1.40.0.exe"
    start-process -filepath $vsCodePath -ArgumentList "/VERYSILENT /LOG=""$vsCodePath.log"" /MERGETASKS=!runcode" -Wait

    #online and format DataDisk
    $disks = Get-Disk
    $driveLetters = ("f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z")
    $i = 1
    foreach ($disk in $disks) {
        if ($disk.PartitionStyle -eq "RAW") {
            $currentDriveLetter = $driveLetters[$i]
            
            New-Volume -DiskNumber $disk.DiskNumber -FriendlyName "Data" -FileSystem NTFS -DriveLetter $currentDriveLetter -AllocationUnitSize 64kB
            Format-Volume -DriveLetter $currentDriveLetter -FileSystem NTFS -NewFileSystemLabel "DataDisk$i"
            $i++
        }
    }
            
    #enable-ping
    Get-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" | Enable-NetFirewallRule

    #Install Latest Nuget Package Provider
    #Install-PackageProvider Nuget –force –verbose
            
    #set-psrepository -Name PSGallery -installationpolicy trusted 
    #Install-Module Az -Force

    Stop-Transcript
}

Stop-VM 'FRA-SRV-01'
do {
    sleep 1  
}
until ((Get-VM 'FRA-SRV-01').State -eq 'Off')
Start-VM 'FRA-SRV-01'
#endregion

