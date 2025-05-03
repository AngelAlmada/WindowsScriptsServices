# Importar módulos
. .\utils.ps1
. .\dns.ps1
. .\dhcp.ps1
. .\ipconfig.ps1
. .\ssh.ps1
. .\ftp.ps1
. .\http.ps1


# Submenú: Configuración IP
Function IpConfigMenu {
    do {
        ClearConsole
        PrintMessage "info" "============================"
        PrintMessage "info" "Submenú: Configuración IP"
        PrintMessage "info" "1. Configurar IP Fija"
        PrintMessage "info" "2. Volver al menú principal"
        PrintMessage "info" "============================"
        $choice = Read-Host "Seleccione una opción (1-2)"

        switch ($choice) {
            1 { setupStaticIp }
            2 { break }
            default { PrintMessage "error" "Opción inválida, intente nuevamente." }
        }
        Pause
    } while ($choice -ne 2)
}

# Submenú: Configuración DNS
Function DnsConfigMenu {
    do {
        ClearConsole
        PrintMessage "info" "============================"
        PrintMessage "info" "Submenú: Configuración DNS"
        PrintMessage "info" "1. Instalar DNS"
        PrintMessage "info" "2. Crear Zona y Registros"
        PrintMessage "info" "3. Volver al menú principal"
        PrintMessage "info" "============================"
        $choice = Read-Host "Seleccione una opción (1-3)"

        switch ($choice) {
            1 { installDns }
            2 {
                $domain = Read-Host "Dominio (ej. reprobados.com)"
                $ipAddress = Read-Host "IP del dominio"

                if (-not [System.Net.IPAddress]::TryParse($ipAddress, [ref]$null)) {
                    PrintMessage "error" "IP inválida, intente nuevamente."
                } else {
                    createDnsZone -Domain $domain
                    createDnsRecords -Domain $domain -IpAddress $ipAddress
                }
            }
            3 { break }
            default { PrintMessage "error" "Opción inválida, intente nuevamente." }
        }
        Pause
    } while ($choice -ne 3)
}

# Submenú: Configuración DHCP
Function DhcpConfigMenu {
    do {
        ClearConsole
        PrintMessage "info" "============================"
        PrintMessage "info" "Submenú: Configuración DHCP"
        PrintMessage "info" "1. Instalar DHCP"
        PrintMessage "info" "2. Configurar DHCP"
        PrintMessage "info" "3. Volver al menú principal"
        PrintMessage "info" "============================"
        $choice = Read-Host "Seleccione una opción (1-3)"

        switch ($choice) {
            1 { installDhcp }
            2 {
                $Subred = Read-Host "Introduce la subred (ejemplo: 192.168.1.0)"
                $RangoInicio = Read-Host "Introduce el rango de inicio de IP (ejemplo: 192.168.1.100)"
                $RangoFinal = Read-Host "Introduce el rango final de IP (ejemplo: 192.168.1.200)"
                $Gateway = Read-Host "Introduce la puerta de enlace (ejemplo: 192.168.1.1)"
                $DNS = Read-Host "Introduce los servidores DNS separados por comas (ejemplo: 8.8.8.8,8.8.4.4)"

                DhcpConfig -Subred $Subred -RangoInicio $RangoInicio -RangoFinal $RangoFinal -Gateway $Gateway -DNS $DNS
            }
            3 { break }
            default { PrintMessage "error" "Opción inválida, intente nuevamente." }
        }
        Pause
    } while ($choice -ne 3)
}

# Submenú: Configuración SSH
Function SshConfigMenu {
    do {
        ClearConsole
        PrintMessage "info" "============================"
        PrintMessage "info" "Submenú: Configuración SSH"
        PrintMessage "info" "1. Instalar SSH"
        PrintMessage "info" "2. Cambiar el puerto SSH"
        PrintMessage "info" "3. Activar el servicio SSH"
        PrintMessage "info" "4. Apagar el servicio SSH"
        PrintMessage "info" "5. Ver estado del servicio SSH"
        PrintMessage "info" "6. Volver al menú principal"
        PrintMessage "info" "============================"
        $choice = Read-Host "Seleccione una opción (1-6)"

        switch ($choice) {
            1 { Instalar-SSH }
            2 { Cambiar-Puerto-SSH }
            3 { Activar-SSH }
            4 { Apagar-SSH }
            5 { Ver-Estado-SSH }
            6 { MainMenu }
            default { PrintMessage "error" "Opción inválida, intente nuevamente." }
        }
        Pause
    } while ($choice -ne 3)
}

# Submenú: Configuración FTP
Function FtpConfigMenu {
    do {
        ClearConsole
        PrintMessage "info" "============================"
        PrintMessage "info" "Submenú: Configuración FTP"
        PrintMessage "info" "1. Instalar FTP"
        PrintMessage "info" "2. Agregar usuarios"
        PrintMessage "info" "3. Volver al menú principal"
        PrintMessage "info" "============================"
        $choice = Read-Host "Seleccione una opción (1-3)"

        switch ($choice) {
            1 { configureFtp }
            2 { configureUsers }
            3 { break }
            default { PrintMessage "error" "Opción inválida, intente nuevamente." }
        }
        Pause
    } while ($choice -ne 3)
}

# Menú principal
Function MainMenu {
    do {
        ClearConsole
        PrintMessage "info" "============================"
        PrintMessage "info" "Menú Principal"
        PrintMessage "info" "1. Salir"
        PrintMessage "info" "2. Configuración IP"
        PrintMessage "info" "3. Configuración DNS"
        PrintMessage "info" "4. Configuración DHCP"
        PrintMessage "info" "5. Configuración SSH"
        PrintMessage "info" "6. Configuración FTP"
        PrintMessage "info" "7. Configuración HTTP"
        PrintMessage "info" "============================"
        $choice = Read-Host "Seleccione una opción"

        switch ($choice) {
            1 { PrintMessage "info" "Saliendo..."; break }
            2 { IpConfigMenu }
            3 { DnsConfigMenu }
            4 { DhcpConfigMenu }
            5 { SshConfigMenu }
            6 { FtpConfigMenu }
            7 { configureHttp }
            default { PrintMessage "error" "Opción inválida, intente nuevamente." }
        }
        Pause
    } while ($choice -ne 1)
}

# Ejecutar el menú principal
MainMenu
