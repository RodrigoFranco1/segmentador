# 🛡️ Segmentador v5.0 - Network Segmentation Audit Tool

Una herramienta profesional de auditoría de segmentación de red desarrollada en Python para pentesters, auditores de seguridad y administradores de red.

## 📋 Características

- ✅ **Escaneo masivo** de segmentos de red con Nmap
- ✅ **Paralelización granular** con control de concurrencia
- ✅ **Múltiples formatos de export** (CSV, JSON, Markdown, HTML)
- ✅ **Dashboard interactivo** con visualizaciones
- ✅ **Detección automática** de condiciones de red
- ✅ **Reintentos inteligentes** con backoff exponencial
- ✅ **Categorización de servicios** por criticidad
- ✅ **Validación robusta** de rangos de red
- ✅ **Logging estructurado** para auditoría

## 🔧 Requisitos del Sistema

### Software Requerido
- **Python 3.6+** (recomendado Python 3.9+ para mejor compatibilidad)
- **Nmap 7.0+**
- **Permisos de root** (recomendado para escaneos SYN)

### Sistemas Operativos Soportados
- Ubuntu 18.04+
- Debian 9+
- CentOS 7+
- Fedora 30+
- macOS 10.14+

## 📦 Instalación

### Instalación Automática (Recomendada)
```bash
# Clonar repositorio
git clone https://github.com/your-repo/segmentador.git
cd segmentador

# Ejecutar instalador automático
chmod +x install.sh
./install.sh
```

### Instalación Manual

#### 1. Clonar el Repositorio
```bash
git clone https://github.com/your-repo/segmentador.git
cd segmentador
```

#### 2. Verificar Python
```bash
python3 --version
# Debe ser Python 3.6 o superior
```

#### 3. Instalar Nmap
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install nmap

# CentOS/RHEL
sudo yum install nmap

# Fedora
sudo dnf install nmap

# macOS
brew install nmap
```

#### 4. Instalar Dependencias Python
```bash
pip3 install -r requirements.txt
```

#### 5. Hacer Ejecutable
```bash
chmod +x segmentador.py
```

#### 6. Verificar Instalación
```bash
python3 segmentador.py --version
# Output: Segmentador 5.0 - Python Production Edition
```

## 🚀 Uso Básico

### Escaneo Rápido con Rangos Predeterminados
```bash
sudo python3 segmentador.py
```

### Escaneo con Archivo Personalizado
```bash
sudo python3 segmentador.py -f rangos.txt
```

### Escaneo Paralelo (Recomendado)
```bash
sudo python3 segmentador.py -f rangos.txt -j 4 -v
```

### Modo Silencioso para Automatización
```bash
python3 segmentador.py -f rangos.txt -q --no-interactive -e json
```

## 📄 Formato del Archivo de Rangos

Crear un archivo de texto con rangos de red (uno por línea):

```
# Archivo: rangos_auditoria.txt
# Comentarios están permitidos

# Redes en formato CIDR
192.168.1.0/24
192.168.10.0/24
10.0.0.0/16
172.16.0.0/12

# Rangos IP
192.168.50.1-192.168.50.254
10.1.1.1-10.1.1.100
```

### Validar Archivo de Configuración
Antes de ejecutar un escaneo, puedes validar tu archivo de rangos:

```bash
# Validación básica
python3 validate_config.py rangos_auditoria.txt

# Validación con estadísticas detalladas
python3 validate_config.py rangos_auditoria.txt --stats -v
```

### Archivos de Ejemplo Incluidos
- `config_ejemplo.txt` - Ejemplos de diferentes tipos de redes
- `rangos_ejemplo.txt` - Archivo básico generado por el instalador

## 🎯 Opciones de Línea de Comandos

```
Uso: python3 segmentador.py [opciones]

Opciones principales:
  -f, --file FILE           Archivo con rangos personalizados
  -e, --export FORMAT       Formato de exportación (csv|json|markdown|all)
  -j, --jobs N             Número de jobs paralelos (1-10)
  -v, --verbose            Modo verboso con debug
  -q, --quiet              Modo silencioso
  -s, --simple             Output simplificado
  --dashboard              Habilitar dashboard HTML (default)
  --no-dashboard           Deshabilitar dashboard HTML
  --no-interactive         Sin prompts automáticos
  -h, --help               Mostrar ayuda completa
```

## 📁 Estructura del Proyecto

```
segmentador/
├── segmentador.py          # Script principal
├── requirements.txt        # Dependencias Python
├── install.sh             # Instalador automático
├── validate_config.py     # Validador de configuración
├── integration_example.py # Ejemplo de integración con otras herramientas
├── config_ejemplo.txt     # Ejemplos de configuración
├── README.md              # Este archivo
└── LICENSE                # Licencia MIT
```

### Archivos Generados Durante la Ejecución
```
audit_dashboard_YYYYMMDD_HHMMSS.html    # Dashboard interactivo
audit_results_YYYYMMDD_HHMMSS.csv       # Datos en CSV
audit_results_YYYYMMDD_HHMMSS.json      # Datos en JSON
audit_report_YYYYMMDD_HHMMSS.md         # Reporte ejecutivo
audit_log_YYYYMMDD_HHMMSS.log           # Log detallado (con -v)
rangos_ejemplo.txt                       # Creado por install.sh
```

### Archivos de Integración (Opcionales)
```
nessus_targets.txt          # Targets para Nessus
nuclei_targets.txt          # Targets para Nuclei  
metasploit_setup.rc         # Script RC para Metasploit
nmap_verification.sh        # Verificación detallada
burp_targets.txt           # Targets web para Burp Suite
integration_summary.md      # Resumen de integración
```

## 💡 Ejemplos de Uso

### 1. Auditoría Básica
```bash
# Escaneo básico con dashboard
sudo python3 segmentador.py

# Solo exportar a CSV
sudo python3 segmentador.py -e csv

# Sin dashboard, modo simple
python3 segmentador.py -s --no-dashboard
```

### 2. Auditoría con Archivo Personalizado
```bash
# Crear archivo de rangos
cat > mis_rangos.txt << EOF
192.168.1.0/24
10.0.0.0/16
172.16.0.0/12
EOF

# Ejecutar auditoría
sudo python3 segmentador.py -f mis_rangos.txt -e all -v
```

### 3. Escaneo Paralelo Optimizado
```bash
# 8 jobs paralelos con logging detallado
sudo python3 segmentador.py -f rangos.txt -j 8 -v -e json
```

### 4. Modo CI/CD
```bash
# Para integración continua
python3 segmentador.py -f targets.txt -q --no-interactive -e json --no-dashboard
```

### 5. Auditoría de Redes Lentas
```bash
# Para redes con alta latencia (ajuste automático)
sudo python3 segmentador.py -f rangos_remotos.txt -j 2 -v
```

## 🔍 Puertos Escaneados

El script escanea los siguientes puertos críticos:

| Puerto | Servicio | Categoría |
|--------|----------|-----------|
| 21 | FTP | Servicios Mail/FTP |
| 22 | SSH | **Administración** |
| 23 | Telnet | **Administración** |
| 25 | SMTP | Servicios Mail/FTP |
| 53 | DNS | DNS |
| 80, 443 | HTTP/HTTPS | Web Services |
| 110, 143, 993, 995 | Mail (POP3/IMAP) | Servicios Mail/FTP |
| 135, 139 | Windows Services | Windows Services |
| 1433, 1521, 3306, 5432 | **Bases de Datos** | **Base Datos** |
| 3389 | **RDP** | **Administración** |
| 5900 | **VNC** | **Administración** |
| 8080, 8443 | HTTP Alternos | Web Services |

## ⚙️ Configuración Avanzada

### Variables de Entorno
```bash
# Aumentar timeout de Nmap (segundos)
export NMAP_TIMEOUT=7200

# Logs en directorio específico
export SEGMENTADOR_LOG_DIR="/var/log/segmentador"
```

### Integración con Otras Herramientas
```bash
# Exportar para Nessus
python3 segmentador.py -f targets.txt -e csv
# Procesar CSV para importar a Nessus

# Pipeline con Nuclei
python3 segmentador.py -f targets.txt -e json | jq -r '.segments[].hosts[].ip' | nuclei -t vulnerabilities/

# Integración automática con múltiples herramientas
python3 segmentador.py -f targets.txt -e json
python3 integration_example.py audit_results_*.json
# Genera targets para Nessus, Nuclei, Metasploit, Burp Suite automáticamente
```

## 🛠️ Troubleshooting

### Problemas Comunes

#### 1. Error: "Nmap no está instalado"
```bash
# Verificar instalación
which nmap
nmap --version

# Instalar si falta
sudo apt install nmap  # Ubuntu/Debian
```

#### 2. Error: "Permission denied"
```bash
# Ejecutar con sudo para escaneos SYN
sudo python3 segmentador.py -f rangos.txt

# O usar escaneos TCP connect (más lento)
python3 segmentador.py -f rangos.txt  # Sin sudo
```

#### 3. Error: "No se encontraron hosts"
```bash
# Verificar conectividad
ping 8.8.8.8

# Usar modo verbose para debug
sudo python3 segmentador.py -f rangos.txt -v

# Verificar rangos en archivo
cat rangos.txt
```

#### 4. Dashboard no se abre automáticamente
```bash
# Abrir manualmente
firefox audit_dashboard_*.html

# O deshabilitar auto-open
python3 segmentador.py --no-interactive
```

#### 5. Escaneo muy lento
```bash
# Usar paralelización
sudo python3 segmentador.py -j 4

# Verificar latencia de red
ping -c 5 target_network_gateway
```

### Debugging Avanzado

#### Modo Verbose Completo
```bash
sudo python3 segmentador.py -f rangos.txt -v -j 1
```

#### Logs Detallados
```bash
# Los logs se guardan automáticamente con -v
tail -f audit_log_*.log
```

#### Validar Archivo de Rangos
```bash
# Verificar formato
python3 -c "
import ipaddress
with open('rangos.txt') as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if line and not line.startswith('#'):
            try:
                if '-' in line:
                    start, end = line.split('-')
                    ipaddress.ip_address(start.strip())
                    ipaddress.ip_address(end.strip())
                else:
                    ipaddress.ip_network(line, strict=False)
                print(f'✓ Línea {i}: {line}')
            except Exception as e:
                print(f'✗ Línea {i}: {line} - Error: {e}')
"
```

## 🔒 Consideraciones de Seguridad

### ⚖️ Uso Autorizado Únicamente
> **🚨 IMPORTANTE**: Use esta herramienta únicamente en redes donde tenga autorización explícita. El uso no autorizado puede violar leyes locales e internacionales.

### 🛡️ Mejores Prácticas
1. **Obtener autorización por escrito** antes de escanear
2. **Coordinar con equipos SOC/SecOps** para evitar alertas
3. **Usar rangos específicos** en lugar de escaneos amplios
4. **Documentar el alcance** de la auditoría
5. **Ejecutar en horarios de menor tráfico**

### 🔍 Detección
Esta herramienta puede ser detectada por:
- Sistemas IDS/IPS
- Firewalls con DPI
- Sistemas SIEM
- Honeypots/tarpit systems

## 📈 Rendimiento

### Benchmarks Típicos
| Escenario | Tiempo Estimado | Recomendación |
|-----------|----------------|---------------|
| 1 red /24 | 30-60 segundos | `-j 1` |
| 10 redes /24 | 2-5 minutos | `-j 4` |
| 100 redes /24 | 15-30 minutos | `-j 8` |
| 1000+ redes | 2+ horas | `-j 8`, multiple runs |

### Optimización
```bash
# Red rápida (< 50ms latency)
sudo python3 segmentador.py -j 8

# Red normal (50-200ms latency)  
sudo python3 segmentador.py -j 4

# Red lenta (> 200ms latency)
sudo python3 segmentador.py -j 2
```

## 🤝 Contribuir

1. Fork el repositorio
2. Crear branch para feature (`git checkout -b feature/nueva-funcionalidad`)
3. Commit cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. Push al branch (`git push origin feature/nueva-funcionalidad`)
5. Abrir Pull Request

## 📜 Licencia

MIT License - ver archivo `LICENSE` para detalles.

## 📞 Soporte

- **Issues**: [GitHub Issues](https://github.com/your-repo/segmentador/issues)
- **Email**: security@your-domain.com
- **Documentación**: [Wiki del proyecto](https://github.com/your-repo/segmentador/wiki)

---

**⭐ Si este proyecto te resulta útil, considera darle una estrella**

**Desarrollado con ❤️ para la comunidad de seguridad**
