# Importar funciones de utils
. .\utils.ps1

Function setupStaticIp {
    PrintMessage "info" "Configurando IP fija en el servidor..."
    $Interface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

    if ($Interface) {
        $ipAddress = Read-Host "Ingrese la nueva IP del servidor"
        $subnetMask = Read-Host "Ingrese la submascara de red (ejemplo: 255.255.255.0)"
        $gateway = Read-Host "Ingrese la puerta de enlace"

        $prefixLength = (convertFromCidr -SubnetMask $subnetMask)
        if ($prefixLength -eq $null) {
            PrintMessage "error" "Submascara invalida. Intente nuevamente."
            return
        }

        Remove-NetIPAddress -InterfaceIndex $Interface.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
        New-NetIPAddress -InterfaceIndex $Interface.ifIndex -IPAddress $ipAddress -PrefixLength $prefixLength -DefaultGateway $gateway -ErrorAction Stop
        Set-DnsClientServerAddress -InterfaceIndex $Interface.ifIndex -ServerAddresses $gateway
        enableFirewallRules
        PrintMessage "success" "IP configurada correctamente: $ipAddress/$prefixLength con gateway $gateway."
    } else {
        PrintMessage "error" "No se encontro una interfaz de red activa."
    }
}
