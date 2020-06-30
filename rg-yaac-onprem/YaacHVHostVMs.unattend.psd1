@{
    VM1 = @{
        ComputerName  = 'FRA-DC-01'
        Organization  = 'YAAC'
        Owner         = 'YAAC'
        Timezone      = 'W. Europe Standard Time'
        InputLocale   = 'de-DE'
        SystemLocale  = 'en-US'
        UserLocale    = 'de-DE'
        adminPassword = ''
        WindowsKey    = 'H3RNG-8C32Q-Q8FRX-6TDXV-WMBMW' #AVMA Key Windows Server 2019 Datacenter 
        IPAddress     = "192.168.0.10"
        IPMask        = "24"
        IPGateway     = "192.168.0.100"
        DNSIP         = "192.168.0.10"
    }
    VM0 = @{
        ComputerName  = 'FRA-SRV-01'
        Organization  = 'YAAC'
        Owner         = 'YAAC'
        Timezone      = 'W. Europe Standard Time'
        InputLocale   = 'de-DE'
        SystemLocale  = 'en-US'
        UserLocale    = 'de-DE'
        adminPassword = ''
        WindowsKey    = 'H3RNG-8C32Q-Q8FRX-6TDXV-WMBMW' #AVMA Key Windows Server 2019 Datacenter
        IPAddress     = "192.168.0.20"
        IPMask        = "24"
        IPGateway     = "192.168.0.100"
        DNSIP         = "192.168.0.10"
    }
}
        