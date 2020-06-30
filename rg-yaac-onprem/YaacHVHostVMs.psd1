@{
    'VM1' = @{
        vmName                = "FRA-DC-01"
        vmPath                = ""
        vmMemory              = 2GB
        vmGeneration          = 2
        vmProcCount           = 2
        vmAutomaticStopAction = "ShutDown"
        vmNics                = @{
            "Intranet" = @{"Switch" = "InternalNATSwitch"; "VLANID" = "" }
        }
        vmDataDisks           = @(
            @{"DiskName" = "DataDisk1.vhdx"; "DiskSize" = 5GB }
        )
    }
    'VM0' = @{
        vmName                = "FRA-SRV-01"
        vmPath                = ""
        vmMemory              = 8GB
        vmGeneration          = 2
        vmProcCount           = 4
        vmAutomaticStopAction = "ShutDown"
        vmNics                = @{
            "Intranet" = @{"Switch" = "InternalNATSwitch"; "VLANID" = "" }
        }
        vmDataDisks           = @(
            @{"DiskName" = "DataDisk1.vhdx"; "DiskSize" = 5GB }
        )
    }
}