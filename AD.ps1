# Ejecutar como administrador

# Verificar si el rol de AD DS ya está instalado
$rolAD = Get-WindowsFeature -Name AD-Domain-Services

if ($rolAD.Installed) {
    Write-Host " El rol 'Active Directory Domain Services' ya está instalado." -ForegroundColor Green
} else {
    Write-Host "❕ El rol 'Active Directory Domain Services' NO está instalado." -ForegroundColor Yellow

    # Preguntar si se desea instalar
    $respuesta = Read-Host "¿Deseas instalar el rol ahora? (S/N)"

    if ($respuesta -match '^[Ss]') {
        Write-Host " Instalando el rol de AD DS..." -ForegroundColor Cyan
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

        if ($?) {
            Write-Host " Instalación completada con éxito." -ForegroundColor Green
        } else {
            Write-Host " Error durante la instalación del rol." -ForegroundColor Red
        }
    } else {
        Write-Host " Instalación cancelada por el usuario." -ForegroundColor Red
    }
}
