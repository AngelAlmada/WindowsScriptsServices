# Configuración del Servidor SSH en Windows Server 2025

function Instalar-SSH {
    Write-Host "Instalando OpenSSH Server..."
    
    # Verificar si OpenSSH ya está instalado
    $sshStatus = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
    
    if ($sshStatus.State -eq "Installed") {
        Write-Host "OpenSSH ya está instalado."
    }
    else {
        # Instalar OpenSSH Server
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
        Write-Host "OpenSSH instalado correctamente."
    }

    # Habilitar el servicio SSH
    Set-Service -Name sshd -StartupType Automatic
    Start-Service sshd
    Write-Host "Servidor SSH habilitado y en ejecución."
}


function Cambiar-Puerto-SSH {
    Write-Host "Atención: Cambiar el puerto SSH puede afectar la conexión."
    $nuevoPuerto = Read-Host "Ingresa el nuevo puerto (ejemplo: 2222)"

    # Verificar si el puerto ingresado es un número válido
    if ($nuevoPuerto -match '^\d+$') {
        # Modificar el archivo de configuración de SSH
        $configPath = "C:\ProgramData\ssh\sshd_config"
        (Get-Content $configPath) -replace '^(#?Port\s+)\d+', "Port $nuevoPuerto" | Set-Content $configPath

        # Reiniciar SSH para aplicar cambios
        Restart-Service sshd
        Write-Host "Puerto cambiado a $nuevoPuerto. Ahora usa: ssh usuario@IP -p $nuevoPuerto"

        # Agregar la regla en el firewall para permitir el nuevo puerto
        New-NetFirewallRule -Name "SSH_$nuevoPuerto" -DisplayName "SSH Custom Port $nuevoPuerto" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort $nuevoPuerto
        Write-Host "Regla de firewall creada para el nuevo puerto."
    }
    else {
        Write-Host "Error: Ingresa un número válido."
    }
}

function Activar-SSH {
    Write-Host "Iniciando el servicio SSH..."
    Set-Service -Name sshd -StartupType Automatic
    Start-Service sshd
    Write-Host "Servidor SSH activado y configurado para iniciar automáticamente."
}

function Apagar-SSH {
    Write-Host "Apagando el servidor SSH..."
    Stop-Service sshd
    Write-Host "Servidor SSH detenido."
}

function Ver-Estado-SSH {
    Write-Host "Estado del Servidor SSH:"
    Get-Service -Name sshd
}