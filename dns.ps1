# Importar funciones de utils
. .\utils.ps1

Function installDns {
    PrintMessage "info" "Instalando servicio DNS..."
    Install-WindowsFeature -Name DNS -IncludeManagementTools
    enableFirewallRules
    PrintMessage "success" "El servicio DNS ha sido instalado con exito."
}

Function createDnsZone {
    param (
        [string]$Domain
    )
    PrintMessage "info" "Creando zona directa para $Domain..."
    Add-DnsServerPrimaryZone -Name $Domain -ZoneFile "$Domain.dns"
    PrintMessage "success" "Zona directa $Domain creada con exito."
}

Function createDnsRecords {
    param (
        [string]$Domain,
        [string]$IpAddress
    )
    PrintMessage "info" "Creando registros A para el dominio $Domain..."
    Add-DnsServerResourceRecordA -Name "@" -ZoneName $Domain -IPv4Address $IpAddress
    Add-DnsServerResourceRecordA -Name "www" -ZoneName $Domain -IPv4Address $IpAddress
    enableFirewallRules
    PrintMessage "success" "Registros A creados con exito para $Domain."
}
