#!/bin/bash

# Verificar si el script se ejecuta como root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "Este script debe ser ejecutado como root." 1>&2
    exit 1
fi

# Función para mostrar mensajes informativos
log() {
    echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1"
}

# Función para mostrar mensajes de error
error() {
    echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1" 1>&2
}

# Función para instalar un paquete y manejar errores
install_package() {
    if ! apt-get install -y "$1"; then
        error "No se pudo instalar $1."
        exit 1
    fi
}

# Función para agregar un repositorio PPA y manejar errores
add_repository() {
    if ! add-apt-repository -y "$1"; then
        error "No se pudo agregar el repositorio $1."
        exit 1
    fi
    if ! apt-get update; then
        error "No se pudo actualizar la lista de paquetes."
        exit 1
    fi
}

# Iniciar el script
log "Iniciando configuración de Kali Linux para ciberseguridad."

# Actualización del sistema
log "Actualizando la lista de paquetes..."
install_package "apt-utils"
if ! apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y; then
    error "No se pudo actualizar el sistema."
    exit 1
fi
if ! apt-get autoremove -y; then
    error "No se pudo eliminar los paquetes innecesarios."
    exit 1
fi

# Función para instalar múltiples paquetes
install_packages() {
    local packages=("$@")
    for package in "${packages[@]}"; do
        log "Instalando $package..."
        install_package "$package"
    done
}

# Listas de paquetes para instalar
declare -a essentials=(git curl wget build-essential)
declare -a recon_tools=(
    "nmap"
    "masscan"
    "theharvester"
    "enum4linux"
    "dnsenum"
    "dnsrecon"
    "sublist3r"
    "amass"
    "assetfinder"
    "httprobe"
    "waybackurls"
    "gau"
    "aquatone"
    "ffuf"
    "dirsearch"
    "gowitness"
)
declare -a exploitation_tools=(
    "metasploit-framework"
    "sqlmap"
    "exploitdb"
    "searchsploit"
    "hydra"
    "john"
    "aircrack-ng"
    "impacket-scripts"
    "crackmapexec"
    "responder"
)
declare -a vuln_management_tools=(
    "nikto"
    "openvas"
    "nessus"
    "burpsuite"
    "zap"
)
declare -a reporting_tools=(
    "reportlab"
    "libreoffice"
    "markdown"
    "pandoc"
)
declare -a api_tools=(
    "shodan"
    "censys"
    "virustotal-cli"
)
declare -a android_tools=(
    "apktool"
    "dex2jar"
    "jd-gui"
    "adb"
    "androguard"
    "mobSF"
)
declare -a ios_tools=(
    "frida"
    "objection"
    "class-dump"
    "cycript"
    "needle"
)

# Instalar todos los paquetes y herramientas
log "Instalando paquetes esenciales..."
install_packages "${essentials[@]}"

log "Instalando herramientas de reconocimiento..."
install_packages "${recon_tools[@]}"

log "Instalando herramientas de explotación..."
install_packages "${exploitation_tools[@]}"

log "Instalando herramientas de gestión de vulnerabilidades..."
install_packages "${vuln_management_tools[@]}"

log "Instalando herramientas de generación de informes..."
install_packages "${reporting_tools[@]}"

log "Instalando herramientas que requieren API keys..."
install_packages "${api_tools[@]}"

log "Instalando herramientas para Android..."
install_packages "${android_tools[@]}"

log "Instalando herramientas para iOS..."
install_packages "${ios_tools[@]}"

# Configuración adicional para herramientas específicas
log "Configurando herramientas adicionales..."

# Configuración de MobSF para Android
log "Configurando MobSF..."
if ! git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git /opt/MobSF; then
    error "No se pudo clonar el repositorio de MobSF."
    exit 1
fi
cd /opt/MobSF || exit
if ! ./setup.sh; then
    error "No se pudo configurar MobSF."
    exit 1
fi
cd - || exit

# Configuración de Needle para iOS
log "Configurando Needle..."
if ! git clone https://github.com/mwrlabs/needle.git /opt/needle; then
    error "No se pudo clonar el repositorio de Needle."
    exit 1
fi
cd /opt/needle || exit
if ! pip install -r requirements.txt; then
    error "No se pudieron instalar los requisitos de Needle."
    exit 1
fi
cd - || exit

log "Configuración de Kali Linux para ciberseguridad completada."
