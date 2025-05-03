# Importar funciones de utils
# . .\validaciones_ftp.ps1

function Validate-PasswordComplexity {
    param (
        [string]$Password
    )

    # Verificar si la contraseña es nula o vacía
    if (-not $Password -or $Password.Length -lt 8) {
        Write-Host "Error: La contrasena debe tener al menos 8 caracteres."
        return $false
    }

    # Contadores para validar al menos 3 de las 4 categorías
    $categories = 0
    if ($Password -match "[A-Z]") { $categories++ }   # Mayúscula
    if ($Password -match "[a-z]") { $categories++ }   # Minúscula
    if ($Password -match "\d") { $categories++ }      # Número
    if ($Password -match "[^\w]") { $categories++ }   # Caracter especial

    if ($categories -ge 3) {
        return $true
    } else {
        Write-Host "Error: La contrasena debe contener al menos 3 de estas 4 categorias: mayusculas, minusculas, numeros o caracteres especiales."
        return $false
    }
}

function Validate-UserName {
    param (
        [string]$nombreUsuario
    )

    # Expresión regular para validar el nombre
    $regex = '^[a-zA-Z0-9_][a-zA-Z0-9_-]{1,18}$'


    # Validar si cumple con la expresión regular
    if ($nombreUsuario -match $regex) {
        return $true
    } else {
        Write-Host "Nombre de usuario no valido. Debe tener 2 caracteres al menos. Usa solo letras, numeros y guiones bajos o medios. No debe comenzar con caracteres especiales o numeros."
        return $false
    }
}

function User-Exists {
    param (
        [string]$nombreUsuario
    )

    if (Get-LocalUser -Name $nombreUsuario -ErrorAction SilentlyContinue) {
        Write-Host "El usuario '$nombreUsuario' ya existe en el sistema."
        return $true
    } else {
        return $false
    }
}

function Validate-FTP-Site {
    param (
        [string]$siteName,
        [string]$ftpPath
    )

    # Validar si el sitio FTP ya existe en IIS
    $siteExists = Get-WebSite -Name $siteName -ErrorAction SilentlyContinue
    if ($siteExists) {
        Write-Host "Error: El sitio FTP '$siteName' ya existe en IIS."
        return $false
    }

    # Validar si el directorio existe
    if (-not (Test-Path $ftpPath)) {
        Write-Host "Error: El directorio '$ftpPath' no existe. Creandolo..."
        New-Item -Path $ftpPath -ItemType Directory -Force | Out-Null
    }

    # Validar si el puerto 21 está en uso (o cualquier otro puerto que usarás)
    $portInUse = Get-NetTCPConnection -LocalPort 21 -ErrorAction SilentlyContinue
    if ($portInUse) {
        Write-Host "Error: El puerto 21 ya esta en uso por otro servicio."
        return $false
    }

    return $true
}

function InputNumber {
    param (
        [string]$mensaje = "Ingrese un numero:"
    )

    do {
        $entrada = Read-Host $mensaje
        if ($entrada -match "^\d+(\.\d+)?$") {
            return [double]$entrada  # Devuelve el número convertido
        } else {
            Write-Host "Error: Debe ingresar un valor numerico valido." -ForegroundColor Red
        }
    } while ($true)
}

function InputText {
    param (
        [string]$mensaje = "Ingrese un texto:"
    )

    do {
        $entrada = Read-Host $mensaje
        if ($entrada -match "^\s*$") {
            Write-Host "No puede estar vacio. Intente nuevamente."
        } else {
            return $entrada  # Devuelve el texto ingresado
        }
    } while ($true)
}

function Install-FTP {
    Install-WindowsFeature Web-FTP-Server -IncludeAllSubFeature
    Install-WindowsFeature Web-Server -IncludeManagementTools
    Import-Module WebAdministration

	$global:siteName = "FTPServer"
    $global:iftpPath = "C:\inetpub\ftproot\$global:siteName"

    if (Validate-FTP-Site -siteName $global:siteName -ftpPath $global:iftpPath) {
        New-WebFtpSite -Name $global:siteName -Port 21
        Write-Host "FTP y servidor web IIS instalados correctamente."
        return $true
    } else {
        Write-Host "El sitio FTP ya existe."
        return $false;
    }
}

function Setup-FTP {
     if (-not (Test-Path "$global:iftpPath\general")) {
        mkdir "$global:iftpPath\general"
    } else {
        Write-Host "La carpeta general ya existe."
    }

    if (-not (Test-Path "$global:iftpPath\LocalUser")) {
        mkdir "$global:iftpPath\LocalUser"
    } else {
        Write-Host "La carpeta LocalUser ya existe."
    }

    if (-not (Test-Path "$global:iftpPath\LocalUser\Public")) {
        mkdir "$global:iftpPath\LocalUser\Public"
    } else {
        Write-Host "La carpeta Public ya existe."
    }

    if (-not (Test-Path "$global:iftpPath\LocalUser\Public\general")) {
        cmd /c mklink /j "$global:iftpPath\LocalUser\Public\general" "$global:iftpPath\general"
    } else {
        Write-Host "El enlace simbolico ya existe."
    }
    $path = "$global:iftpPath\general"

    # Otorgar permisos de lectura y escritura a Everyone
    $acl = Get-Acl $path
    $permission = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($permission)
    Set-Acl -Path $path -AclObject $acl

    # También agregar permisos para el usuario anónimo de IIS (si aplica)
    $anonUser = "IUSR"
    $permissionAnon = New-Object System.Security.AccessControl.FileSystemAccessRule($anonUser, "Read", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($permissionAnon)

	# Eliminar permisos de escritura para "anonymous"
$permissionAnonWrite = New-Object System.Security.AccessControl.FileSystemAccessRule($anonUser, "Write", "ContainerInherit,ObjectInherit", "None", "Deny")
$acl.AddAccessRule($permissionAnonWrite)

    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name physicalPath -Value $global:iftpPath

    # Configurar SSL (permitir pero no requerir)
    Import-Module WebAdministration > $null 
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslAllow"
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslAllow"

    # Activar el aislamiento de usuarios
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.userIsolation.mode -Value 3

    # Activar autenticación básica
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true
    Set-ItemProperty "IIS:\Sites\$global:siteName" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true

    Write-Host "Creacion de carpetas y configuraciones terminado."
}

function Setup-Groups {
    Write-Host "Configurando los grupos..."

    $reprobadosGroup = "reprobados"
    $recursadoresGroup = "recursadores"

	# Verificar si los grupos existen antes de crearlos
    if (-not (Get-LocalGroup -Name $reprobadosGroup -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $reprobadosGroup
    } else {
        Write-Host "El grupo '$reprobadosGroup' ya existe."
return

    }

    if (-not (Get-LocalGroup -Name $recursadoresGroup -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $recursadoresGroup
    } else {
        Write-Host "El grupo '$recursadoresGroup' ya existe."
return
    }

    # Conceder permisos exclusivos
    icacls $reprobadosFolder /grant "${reprobadosGroup}:(OI)(CI)F"
    icacls $recursadoresFolder /grant "${recursadoresGroup}:(OI)(CI)F"

    icacls $reprobadosFolder /grant "${reprobadosGroup}:(OI)(CI)F" /T
    icacls $recursadoresFolder /grant "${recursadoresGroup}:(OI)(CI)F" /T

    # Denegar acceso a grupos opuestos
    icacls $reprobadosFolder /deny "${recursadoresGroup}:(OI)(CI)F"
    icacls $recursadoresFolder /deny "${reprobadosGroup}:(OI)(CI)F"

    # Agregar permiso de read, write a todos 
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Location $global:siteName -PSPath IIS:\ -Value @{accessType="Allow";users="*";permissions="Read,Write"}
    Add-WebConfiguration "/system.ftpServer/security/authorization" -Location $global:siteName -PSPath IIS:\ -Value @{accessType="Allow";users="?";permissions="Read,Write"}

    Write-Host "Grupos configurados correctamente."
}

function Get-Username {
    # Bucle para validar el username
    do {
        $userName = InputText "Nombre del usuario"
    } while (-not (Validate-UserName $userName) -or (User-Exists $userName))
    return $userName
}

function Get-Password {
    do {
        $password = InputText "Contrasena"  
    } while (-not (Validate-PasswordComplexity -Password $password))
    return $password
}

function Get-Group {
    $userGroup = $null

    do{
        Write-Host "Grupos:"
        Write-Host "1) reprobados"
        Write-Host "2) recursadores"
        $choice = InputNumber "Seleccione el grupo. Indicandolo con el numero."

        switch ($choice) {
            1 { 
                $userGroup = "reprobados"
                break
            }
            2 { 
                $userGroup = "recursadores" 
                break
            }
            default { 
                Write-Host "Opcion invalida, intente nuevamente."
                continue
            }
        }
        
    } while (-not $userGroup)

    return $userGroup
}

function Create-UserFolders {
    param (
        [string]$localUserPath,
        [string]$userName,
        [string]$userGroup
    )

    $userFolder = "$localUserPath\$userName"
    $userIntraFolder = "$localUserPath\$userName\$userName"

    if (!(Test-Path -Path $userFolder)) {
        New-Item -Path $userFolder -ItemType Directory
    }

    if (!(Test-Path -Path $userIntraFolder)) {
        New-Item -Path $userIntraFolder -ItemType Directory
    }

    # Junction: crear junctions a su grupo y a general
    $groupFolderPath = "$global:iftpPath\$userGroup"
    $generalFolderPath = "$global:iftpPath\general"

    cmd /c mklink /j "$userFolder\$userGroup" $groupFolderPath
    cmd /c mklink /j "$userFolder\general" $generalFolderPath

    # Dar permisos a carpetas
    icacls $userFolder /grant "${userName}:(OI)(CI)F"
    icacls $userFolder /grant "${userName}:(OI)(CI)F" /T

    icacls $userIntraFolder /grant "${userName}:(OI)(CI)F"
    icacls $userIntraFolder /grant "${userName}:(OI)(CI)F" /T

    icacls $groupFolderPath /grant "${userName}:(OI)(CI)F"
    icacls $groupFolderPath /grant "${userName}:(OI)(CI)F" /T

    icacls $generalFolderPath /grant "${userName}:(OI)(CI)F"
    icacls $generalFolderPath /grant "${userName}:(OI)(CI)F" /T

    icacls "$userFolder\$userGroup" /grant "${userName}:(OI)(CI)F"
    icacls "$userFolder\$userGroup" /grant "${userName}:(OI)(CI)F" /T
    
    icacls "$userFolder\general" /grant "${userName}:(OI)(CI)F"
    icacls "$userFolder\general" /grant "${userName}:(OI)(CI)F" /T

    Add-LocalGroupMember -Group $userGroup -Member $userName
   Write-Host "Usuario configurado correctamente"
}

function Setup-Users {
    # Variables iniciales
    $localUserPath = "$global:iftpPath\LocalUser"
    $userCount = InputNumber "Cuantos usuarios desea crear"

    for ($j = 1; $j -le $userCount; $j++) {
        #Write-Host "Para salir de la creacion de usuarios, presione Ctrl+C"

        $userName = Get-Username
        $password = Get-Password
        $userGroup = Get-Group

        $confirmInput = InputText "Seguro que quiere crear al usuario? (Ingrese N para cancelar o una S para seguir (u otro caracter)"
        if ($confirmInput.ToUpper() -eq "N") {
            Write-Host "Usuario cancelado"
            $j--
            continue
        }

        $addUserOutput = net user $userName $password /add

        if ($LASTEXITCODE -ne 0) {
           Write-Host "Error al agregar usuario"
            Write-Host "El proceso de creacion de usuario va a comenzar de nuevo, verifica el usuario y la contraseña"
            $j--
            continue
        }

        # Crear carpetas para el usuario y su grupo
        Create-UserFolders $localUserPath $userName $userGroup
    }

    Write-Host "Usuarios configurados correctamente."
}

function Configure-FTP {
    Setup-FTP
    Setup-Groups
    Restart-WebItem -PSPath "IIS:\Sites\$global:siteName" 
}

function Configure-Users {
    $global:siteName = "FTPServer"
    $global:iftpPath = "C:\inetpub\ftproot\$global:siteName"

    Setup-Users
    Restart-WebItem -PSPath "IIS:\Sites\$global:siteName" 
}