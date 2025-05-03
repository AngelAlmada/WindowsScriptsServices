# Importar funciones de utils
. .\utils.ps1

Function installDhcp {
    PrintMessage "info" "Instalando servicio DHCP..."
    Install-WindowsFeature -Name DHCP -IncludeManagementTools
    PrintMessage "success" "Servicio DHCP instalado."
}

Function DhcpConfig {
    param (
        [string]$Subred,
        [string]$RangoInicio,
        [string]$RangoFinal,
        [string]$Gateway,
        [string]$DNS
    )

    $Mascara = "255.255.255.0"
    $ScopeName = "Scope_Local"
    $ScopeID = $Subred

    Add-DhcpServerv4Scope -Name $ScopeName -StartRange $RangoInicio -EndRange $RangoFinal -SubnetMask $Mascara -State Active
    Set-DhcpServerv4OptionValue -ScopeId $ScopeID -Router $Gateway -DnsServer $DNS

    Restart-Service DHCPServer
    Set-Service DHCPServer -StartupType Automatic

    PrintMessage "info" "Estado del servicio DHCP:"
    Get-Service DHCPServer
}
