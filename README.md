# 🛡️ Segmentador - Herramienta Profesional de Auditoría de Segmentación de Red

<div align="center">

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![Bash](https://img.shields.io/badge/bash-4.0%2B-orange.svg)

**Una herramienta avanzada para auditorías de segmentación de red con dashboard interactivo y reportes profesionales**

[Características](#-características) • [Instalación](#-instalación) • [Uso](#-uso) • [Ejemplos](#-ejemplos) • [Outputs](#-archivos-generados)

</div>

---

## 📋 Descripción

**Segmentador** es una herramienta profesional de auditoría de segmentación de red diseñada para pentesters, auditores de seguridad y administradores de red. Automatiza el descubrimiento de hosts activos en rangos de red especificados y genera reportes detallados con visualizaciones interactivas.

### 🎯 Casos de Uso

- **Auditorías de Seguridad** - Evaluación de superficie de ataque
- **Pentesting** - Reconocimiento de infraestructura de red  
- **Compliance** - Verificación de segmentación de red
- **Administración de Red** - Inventario de dispositivos activos
- **Arquitectura de Red** - Análisis de distribución de servicios

---

## ✨ Características

### 🚀 **Funcionalidades Core**
- ✅ **Escaneo Masivo** - Soporte para miles de segmentos de red
- ✅ **Detección Inteligente** - Identificación de 20+ servicios críticos
- ✅ **Categorización Automática** - Clasificación por criticidad de servicios
- ✅ **Análisis Temporal** - Métricas de duración y rendimiento

### 📊 **Dashboard Interactivo**
- ✅ **Visualizaciones Modernas** - Gráficos con Chart.js
- ✅ **Mapa de Calor** - Distribución visual de actividad
- ✅ **Tablas Dinámicas** - Datos detallados navegables
- ✅ **Responsive Design** - Compatible con móviles y desktop

### 📈 **Reportes Profesionales**
- ✅ **Múltiples Formatos** - CSV, JSON, Markdown, HTML
- ✅ **Exports Estructurados** - Datos listos para análisis
- ✅ **Resúmenes Ejecutivos** - Para stakeholders no técnicos
- ✅ **Documentación Detallada** - Para equipos técnicos

### 🔧 **Características Técnicas**
- ✅ **Configuración Flexible** - Rangos personalizados y predefinidos
- ✅ **Validación Robusta** - Verificación de formatos CIDR
- ✅ **Manejo de Errores** - Recuperación automática de fallos
- ✅ **Logging Detallado** - Trazabilidad completa del proceso

---

## 🔧 Instalación

### Requisitos del Sistema

```bash
# Sistema Operativo
Ubuntu 18.04+ / Debian 9+ / CentOS 7+ / Fedora 30+

# Dependencias
- Bash 4.0+
- Nmap 7.0+
- Navegador web moderno (para dashboard)
```

### Instalación Rápida

```bash
# 1. Clonar repositorio
git clone https://github.com/tu-usuario/segmentador.git
cd segmentador

# 2. Hacer ejecutable
chmod +x segmentador.sh

# 3. Instalar dependencias (si es necesario)
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install nmap

# CentOS/RHEL
sudo yum install nmap

# Fedora
sudo dnf install nmap

# Arch Linux
sudo pacman -S nmap
```

### Verificación de Instalación

```bash
# Verificar que Nmap está instalado
nmap --version

# Ejecutar help para verificar el script
./segmentador.sh --help
```

---

## 🚀 Uso

### Sintaxis Básica

```bash
./segmentador.sh [opciones]
```

### Opciones Disponibles

| Opción | Descripción | Ejemplo |
|--------|-------------|---------|
| `-f, --file FILE` | Archivo con rangos personalizados | `-f rangos.txt` |
| `-e, --export FORMAT` | Formato de exportación | `-e csv` |
| `-s, --simple` | Output simplificado | `-s` |
| `-d, --dashboard` | Generar dashboard HTML | `-d` |
| `--no-dashboard` | Omitir dashboard | `--no-dashboard` |
| `-h, --help` | Mostrar ayuda | `-h` |

### Formatos de Exportación

- **`csv`** - Archivo CSV para análisis en Excel
- **`json`** - Datos estructurados para APIs
- **`markdown`** - Reporte en formato Markdown
- **`all`** - Todos los formatos (default)

---

## 💡 Ejemplos

### Uso Básico

```bash
# Escaneo con rangos predeterminados (RFC 1918)
sudo ./segmentador.sh

# Escaneo con archivo personalizado
sudo ./segmentador.sh -f mi_red.txt

# Solo exportar a CSV
sudo ./segmentador.sh -e csv
```

### Casos de Uso Avanzados

```bash
# Auditoría completa con todos los exports
sudo ./segmentador.sh -f rangos_auditoria.txt -e all

# Escaneo rápido sin dashboard
sudo ./segmentador.sh -s --no-dashboard -f rangos.txt

# Solo dashboard interactivo
sudo ./segmentador.sh -f rangos.txt -e csv
```

### Archivo de Rangos Personalizado

Crear archivo `rangos.txt`:

```
# Rangos de red para auditoría
192.168.1.0/24
192.168.10.0/24
10.0.0.0/16
172.16.0.0/12

# También soporta rangos IP
192.168.50.1-192.168.50.254
10.1.1.1-10.1.1.100
```

---

## 📁 Archivos Generados

### Dashboard HTML Interactivo
```
audit_dashboard_20250131_143022.html
```
- 📊 Visualizaciones con Chart.js
- 🔥 Mapa de calor de segmentos
- 📋 Tablas interactivas con filtros
- 📱 Diseño responsive

### Exports de Datos
```
audit_results_20250131_143022.csv     # Datos tabulares
audit_results_20250131_143022.json    # API/integración
audit_report_20250131_143022.md       # Reporte ejecutivo
resumen_auditoria_20250131_143022.txt # Resumen técnico
```

### Contenido del Dashboard

#### 📈 Métricas Principales
- Segmentos escaneados
- Hosts activos encontrados  
- Tasa de actividad de red
- Distribución por categorías

#### 🎯 Categorización de Servicios
- **ADMINISTRACION** (SSH, RDP, Telnet, VNC)
- **BASE_DATOS** (MySQL, PostgreSQL, MSSQL, Oracle)
- **WEB_SERVICES** (HTTP, HTTPS, alternos)
- **SERVICIOS_MAIL_FTP** (SMTP, POP3, IMAP, FTP)
- **DNS** (Servicios de resolución)
- **WINDOWS_SERVICES** (RPC, NetBIOS)
- **OTROS** (Servicios no categorizados)

---

## ⚠️ Consideraciones de Seguridad

### ⚖️ **Uso Autorizado Únicamente**

> **🚨 IMPORTANTE**: Esta herramienta debe usarse únicamente en redes donde tengas autorización explícita para realizar auditorías de seguridad. El uso no autorizado puede violar leyes locales e internacionales.

### 🛡️ **Mejores Prácticas**

```bash
# 1. Siempre verificar autorización antes de escanear
echo "¿Tienes autorización para escanear estos rangos? [y/N]"
read -r authorization

# 2. Documentar el alcance de la auditoría
# 3. Coordinar con equipos de SOC/SecOps
# 4. Usar rangos específicos, evitar escaneos amplios
# 5. Revisar políticas organizacionales
```

### 🔐 **Detección y Mitigación**

Esta herramienta puede ser detectada por:
- Sistemas de Detección de Intrusos (IDS)
- Firewalls con capacidades de deep packet inspection
- Sistemas de monitoreo de red (SIEM)

---

## 📊 Ejemplo de Output

### Terminal Output
```bash
🛡️ [INFO] Iniciando auditoría de segmentación: 2025-01-31 14:30:15
✅ [+] Segmentos generados: 156 redes
✅ [+] Hosts activos encontrados: 142
✅ [+] Segmentos con actividad: 23

[SEGMENTO] 192.168.10.0/24
  ├── 192.168.10.1   [22(SSH), 80(HTTP), 443(HTTPS)]
  ├── 192.168.10.5   [3389(RDP), 135(RPC)]
  └── 192.168.10.254 [53(DNS)]

[ADMINISTRACION] (45 servicios encontrados)
  ├── 192.168.10.1:22 (SSH) - Segmento: 192.168.10.0/24
  ├── 192.168.10.5:3389 (RDP) - Segmento: 192.168.10.0/24
```

### Dashboard Preview
![Dashboard Preview](https://via.placeholder.com/800x600/667eea/ffffff?text=Dashboard+Interactivo)

---

## 🔧 Configuración Avanzada

### Variables de Entorno

```bash
# Personalizar puertos a escanear
export SCAN_PORTS="22,80,443,3389,3306,5432"

# Ajustar velocidad de escaneo
export NMAP_RATE="150"

# Configurar timeouts
export NMAP_TIMEOUT="300"
```

### Integración con Otras Herramientas

```bash
# Exportar targets para Nessus
./segmentador.sh -f rangos.txt -e csv
# Procesar CSV para generar archivo .nessus

# Integrar con Metasploit
./segmentador.sh -f rangos.txt -e json
# Importar JSON a workspace de MSF

# Pipeline con Nuclei
./segmentador.sh -f rangos.txt -e csv | nuclei -t vulnerabilities/
```

---

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Por favor:

1. 🍴 Fork el repositorio
2. 🌿 Crea una rama para tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. 💾 Commit tus cambios (`git commit -am 'Agregar nueva funcionalidad'`)
4. 📤 Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. 🔄 Abre un Pull Request

### 💡 Ideas para Contribuir

- 🔌 Plugins para herramientas adicionales
- 🌐 Integración con APIs de threat intelligence
- 📊 Nuevas visualizaciones para dashboard
- 🔧 Optimizaciones de rendimiento
- 📚 Documentación adicional
- 🧪 Tests unitarios

---

## 📞 Soporte

### 🐛 Reportar Bugs
Abre un [issue](https://github.com/tu-usuario/segmentador/issues) con:
- Descripción del problema
- Steps to reproduce
- Output de error
- Información del sistema

### 💬 Discusiones
Únete a las [Discussions](https://github.com/tu-usuario/segmentador/discussions) para:
- Preguntas de uso
- Ideas de mejoras
- Compartir casos de uso
- Networking con la comunidad

### 📧 Contacto
- **Email**: security@tu-dominio.com
- **Twitter**: [@tu_usuario](https://twitter.com/tu_usuario)
- **LinkedIn**: [Tu Perfil](https://linkedin.com/in/tu-perfil)

---

## 📜 Licencia

```
MIT License

Copyright (c) 2025 Tu Nombre

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Créditos

### Herramientas Utilizadas
- **[Nmap](https://nmap.org/)** - Network discovery and security auditing
- **[Chart.js](https://www.chartjs.org/)** - Visualizaciones interactivas
- **[Bash](https://www.gnu.org/software/bash/)** - Scripting shell

### Inspiración
- Metodologías OWASP para testing de seguridad
- Frameworks de pentesting (PTES, NIST)
- Comunidad de seguridad ofensiva

---

<div align="center">

**⭐ Si este proyecto te resulta útil, considera darle una estrella ⭐**

**Desarrollado con ❤️ para la comunidad de seguridad**

[⬆ Volver arriba](#-segmentador---herramienta-profesional-de-auditoría-de-segmentación-de-red)

</div>
