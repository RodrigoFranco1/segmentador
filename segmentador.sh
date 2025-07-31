#!/bin/bash

# ===========================
# Script Profesional de Auditoría de Segmentación de Red
# Versión: 2.0 - Dashboard Edition
# Autor: Security Audit Team
# ===========================

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
WHITE='\033[1;37m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Variables globales
CUSTOM_FILE=""
USE_CUSTOM_FILE=false
EXPORT_FORMAT="all"  # all, csv, json, markdown
DETAILED_OUTPUT=true
GENERATE_DASHBOARD=true

# Función para imprimir mensajes con colores
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Función para mostrar ayuda
show_help() {
    echo "Uso: $0 [opciones]"
    echo ""
    echo "Opciones:"
    echo "  -f, --file FILE        Usar archivo personalizado con rangos CIDR"
    echo "  -e, --export FORMAT    Formato de exportación (csv|json|markdown|all)"
    echo "  -s, --simple           Output simple (sin detalles por IP)"
    echo "  -d, --dashboard        Generar dashboard HTML interactivo (default: true)"
    echo "  --no-dashboard         No generar dashboard HTML"
    echo "  -h, --help             Mostrar esta ayuda"
    echo ""
    echo "Ejemplos:"
    echo "  $0                          # Usar rangos predeterminados, export completo"
    echo "  $0 -f rangos.txt            # Usar rangos desde archivo"
    echo "  $0 -e csv                   # Solo exportar a CSV"
    echo "  $0 -f custom.txt -e json    # Archivo personalizado, export JSON"
    echo "  $0 -s                       # Output simple sin detalles"
    echo "  $0 --no-dashboard           # Sin dashboard HTML"
    echo ""
    echo "Formato del archivo personalizado:"
    echo "  192.168.1.0/24"
    echo "  10.0.0.0/16"
    echo "  172.16.0.0/12"
    echo "  192.168.0.1-192.168.0.254"
    echo ""
}

# Función para convertir segundos a formato legible
format_duration() {
    local duration=$1
    local hours=$((duration / 3600))
    local minutes=$(((duration % 3600) / 60))
    local seconds=$((duration % 60))
    
    if [[ $hours -gt 0 ]]; then
        echo "${hours}h ${minutes}m ${seconds}s"
    elif [[ $minutes -gt 0 ]]; then
        echo "${minutes}m ${seconds}s"
    else
        echo "${seconds}s"
    fi
}

# Función para categorizar puertos por criticidad
categorize_port() {
    local port=$1
    case $port in
        22|23|3389|5900)
            echo "ADMINISTRACION"
            ;;
        1433|1521|3306|5432)
            echo "BASE_DATOS"
            ;;
        21|25|110|143|993|995)
            echo "SERVICIOS_MAIL_FTP"
            ;;
        80|443|8080|8443)
            echo "WEB_SERVICES"
            ;;
        53)
            echo "DNS"
            ;;
        135|139)
            echo "WINDOWS_SERVICES"
            ;;
        *)
            echo "OTROS"
            ;;
    esac
}

# Función para obtener descripción del puerto
get_port_description() {
    local port=$1
    case $port in
        21) echo "FTP" ;;
        22) echo "SSH" ;;
        23) echo "Telnet" ;;
        25) echo "SMTP" ;;
        53) echo "DNS" ;;
        80) echo "HTTP" ;;
        110) echo "POP3" ;;
        135) echo "RPC" ;;
        139) echo "NetBIOS" ;;
        143) echo "IMAP" ;;
        443) echo "HTTPS" ;;
        993) echo "IMAPS" ;;
        995) echo "POP3S" ;;
        1433) echo "MSSQL" ;;
        1521) echo "Oracle" ;;
        3306) echo "MySQL" ;;
        3389) echo "RDP" ;;
        5432) echo "PostgreSQL" ;;
        5900) echo "VNC" ;;
        8080) echo "HTTP-Alt" ;;
        8443) echo "HTTPS-Alt" ;;
        *) echo "Unknown" ;;
    esac
}

# Función para generar HTML Dashboard interactivo
generate_html_dashboard() {
    local dashboard_file="./audit_dashboard_${TIMESTAMP}.html"
    print_message $YELLOW "[INFO] Generando dashboard HTML interactivo: $dashboard_file"
    
    # Preparar datos para JavaScript
    local segments_data=""
    local services_data=""
    
    # Generar datos de segmentos para JSON
    segments_data="["
    first_segment=true
    while IFS= read -r segment; do
        if [[ $first_segment == false ]]; then
            segments_data+=","
        fi
        first_segment=false
        
        host_count=$(grep "^$segment|" "$TEMP_RESULTS" | wc -l)
        port_count=$(grep "^[^|]*|[^|]*|" "$TEMP_RESULTS" | grep "^$segment|" | cut -d'|' -f3 | tr ',' '\n' | wc -l)
        
        segments_data+="{\"network\":\"$segment\",\"hosts\":$host_count,\"ports\":$port_count}"
    done <<< "$(cut -d'|' -f1 "$TEMP_RESULTS" | sort -u)"
    segments_data+="]"
    
    # Generar datos de servicios por categoría
    categories=("ADMINISTRACION" "BASE_DATOS" "WEB_SERVICES" "SERVICIOS_MAIL_FTP" "DNS" "WINDOWS_SERVICES" "OTROS")
    services_data="["
    first_cat=true
    for category in "${categories[@]}"; do
        if [[ $first_cat == false ]]; then
            services_data+=","
        fi
        first_cat=false
        
        count=$(grep "^$category|" "$TEMP_BY_CATEGORY" | wc -l)
        services_data+="{\"category\":\"$category\",\"count\":$count}"
    done
    services_data+="]"
    
    # Crear el archivo HTML
    cat > "$dashboard_file" << 'EOF'
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard de Auditoría de Segmentación</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 1.5rem 2rem;
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
            border-bottom: 3px solid #667eea;
        }
        
        .header h1 {
            color: #2c3e50;
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.1rem;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0,0,0,0.15);
        }
        
        .stat-card h3 {
            color: #2c3e50;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 0.5rem;
            font-weight: 600;
        }
        
        .stat-card .number {
            font-size: 2.5rem;
            font-weight: 700;
            color: #667eea;
            line-height: 1;
            margin-bottom: 0.5rem;
        }
        
        .stat-card .label {
            color: #7f8c8d;
            font-size: 0.85rem;
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .chart-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            height: 350px;
        }
        
        .chart-container h3 {
            color: #2c3e50;
            margin-bottom: 1rem;
            font-size: 1.3rem;
            font-weight: 600;
        }
        
        .table-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            margin-bottom: 2rem;
        }
        
        .table-container h3 {
            color: #2c3e50;
            margin-bottom: 1rem;
            font-size: 1.3rem;
            font-weight: 600;
        }
        
        .heatmap-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
            margin-bottom: 2rem;
        }
        
        .heatmap-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
            gap: 5px;
            margin-top: 1rem;
        }
        
        .heatmap-cell {
            aspect-ratio: 1;
            border-radius: 5px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.7rem;
            font-weight: 600;
            color: white;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
            cursor: pointer;
            transition: transform 0.2s ease;
            text-align: center;
        }
        
        .heatmap-cell:hover {
            transform: scale(1.05);
        }
        
        .heatmap-legend {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-top: 1rem;
            font-size: 0.9rem;
            flex-wrap: wrap;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 3px;
        }
        
        .tabs {
            display: flex;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px 15px 0 0;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .tab {
            padding: 1rem 2rem;
            background: rgba(255, 255, 255, 0.7);
            border: none;
            cursor: pointer;
            font-weight: 600;
            color: #666;
            transition: all 0.3s ease;
            flex: 1;
        }
        
        .tab.active {
            background: #667eea;
            color: white;
        }
        
        .tab-content {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 0 0 15px 15px;
            padding: 2rem;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }
        
        .tab-panel {
            display: none;
        }
        
        .tab-panel.active {
            display: block;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        
        .table th,
        .table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        .table th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .table tr:hover {
            background-color: #f8f9fa;
        }
        
        .critical { background: linear-gradient(45deg, #e74c3c, #c0392b); }
        .high { background: linear-gradient(45deg, #f39c12, #e67e22); }
        .medium { background: linear-gradient(45deg, #f1c40f, #f39c12); }
        .low { background: linear-gradient(45deg, #2ecc71, #27ae60); }
        .none { background: linear-gradient(45deg, #95a5a6, #7f8c8d); }
        
        .status-critical { color: #e74c3c; font-weight: bold; }
        .status-high { color: #f39c12; font-weight: bold; }
        .status-medium { color: #3498db; font-weight: bold; }
        .status-low { color: #2ecc71; font-weight: bold; }
        
        @media (max-width: 768px) {
            .charts-grid {
                grid-template-columns: 1fr;
            }
            
            .container {
                padding: 1rem;
            }
            
            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Dashboard de Auditoría de Segmentación</h1>
        <div class="subtitle">Análisis Completo de Infraestructura de Red - FECHA_PLACEHOLDER</div>
    </div>
    
    <div class="container">
        <!-- Estadísticas principales -->
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Segmentos Escaneados</h3>
                <div class="number" id="totalSegments">TOTAL_SEGMENTOS_PLACEHOLDER</div>
                <div class="label">Redes analizadas</div>
            </div>
            <div class="stat-card">
                <h3>Segmentos Activos</h3>
                <div class="number" id="activeSegments">TOTAL_SEGMENTOS_ACTIVOS_PLACEHOLDER</div>
                <div class="label">Con hosts detectados</div>
            </div>
            <div class="stat-card">
                <h3>Hosts Activos</h3>
                <div class="number" id="activeHosts">TOTAL_IPS_PLACEHOLDER</div>
                <div class="label">Dispositivos encontrados</div>
            </div>
            <div class="stat-card">
                <h3>Tasa de Actividad</h3>
                <div class="number" id="activityRate">ACTIVITY_RATE_PLACEHOLDER%</div>
                <div class="label">Segmentos con actividad</div>
            </div>
        </div>
        
        <!-- Gráficos -->
        <div class="charts-grid">
            <div class="chart-container">
                <h3>📊 Distribución de Servicios</h3>
                <canvas id="servicesChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>🌐 Top 10 Segmentos Más Activos</h3>
                <canvas id="segmentsChart"></canvas>
            </div>
        </div>
        
        <!-- Mapa de calor -->
        <div class="heatmap-container">
            <h3>🔥 Mapa de Calor de Segmentos</h3>
            <div class="heatmap-grid" id="heatmapGrid"></div>
            <div class="heatmap-legend">
                <div class="legend-item">
                    <div class="legend-color critical"></div>
                    <span>Crítico (>20 hosts)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color high"></div>
                    <span>Alto (11-20 hosts)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color medium"></div>
                    <span>Medio (6-10 hosts)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color low"></div>
                    <span>Bajo (1-5 hosts)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color none"></div>
                    <span>Sin actividad</span>
                </div>
            </div>
        </div>
        
        <!-- Tabs para tablas detalladas -->
        <div class="tabs">
            <button class="tab active" onclick="showTab('segments')">Segmentos Detallados</button>
            <button class="tab" onclick="showTab('hosts')">Hosts por Segmento</button>
            <button class="tab" onclick="showTab('services')">Servicios Detectados</button>
        </div>
        
        <div class="tab-content">
            <div id="segments" class="tab-panel active">
                <div id="segmentsTableContent"></div>
            </div>
            <div id="hosts" class="tab-panel">
                <div id="hostsTableContent"></div>
            </div>
            <div id="services" class="tab-panel">
                <div id="servicesTableContent"></div>
            </div>
        </div>
    </div>

    <script>
        // Datos dinámicos (serán reemplazados por el script)
        const segmentsData = SEGMENTS_DATA_PLACEHOLDER;
        const servicesData = SERVICES_DATA_PLACEHOLDER;
        
        // Configuración de colores
        const colors = {
            primary: '#667eea',
            secondary: '#764ba2',
            success: '#2ecc71',
            warning: '#f39c12',
            danger: '#e74c3c',
            info: '#3498db'
        };
        
        // Función para mostrar tabs
        function showTab(tabName) {
            // Ocultar todos los paneles
            document.querySelectorAll('.tab-panel').forEach(panel => {
                panel.classList.remove('active');
            });
            
            // Desactivar todos los tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Mostrar panel seleccionado
            document.getElementById(tabName).classList.add('active');
            
            // Activar tab seleccionado
            event.target.classList.add('active');
        }
        
        // Generar mapa de calor
        function generateHeatmap() {
            const heatmapGrid = document.getElementById('heatmapGrid');
            
            segmentsData.forEach(segment => {
                const cell = document.createElement('div');
                cell.className = 'heatmap-cell';
                
                // Determinar intensidad por número de hosts
                let intensity = 'none';
                if (segment.hosts > 20) intensity = 'critical';
                else if (segment.hosts > 10) intensity = 'high';
                else if (segment.hosts > 5) intensity = 'medium';
                else if (segment.hosts > 0) intensity = 'low';
                
                cell.classList.add(intensity);
                const networkParts = segment.network.split('.');
                const shortNet = networkParts[2] + '.' + networkParts[3].split('/')[0];
                cell.innerHTML = `<div>${shortNet}<br><small>${segment.hosts}h</small></div>`;
                cell.title = `${segment.network}: ${segment.hosts} hosts, ${segment.ports} puertos`;
                
                heatmapGrid.appendChild(cell);
            });
        }
        
        // Gráfico de servicios (Doughnut)
        function createServicesChart() {
            const ctx = document.getElementById('servicesChart').getContext('2d');
            
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: servicesData.map(s => s.category.replace('_', ' ')),
                    datasets: [{
                        data: servicesData.map(s => s.count),
                        backgroundColor: [
                            colors.danger,
                            colors.warning,
                            colors.info,
                            colors.secondary,
                            colors.success,
                            colors.primary,
                            '#95a5a6'
                        ],
                        borderWidth: 3,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 20,
                                usePointStyle: true
                            }
                        }
                    }
                }
            });
        }
        
        // Gráfico de segmentos (Bar)
        function createSegmentsChart() {
            const ctx = document.getElementById('segmentsChart').getContext('2d');
            
            // Tomar solo los top 10 segmentos más activos
            const topSegments = segmentsData
                .sort((a, b) => b.hosts - a.hosts)
                .slice(0, 10);
            
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: topSegments.map(s => s.network),
                    datasets: [{
                        label: 'Hosts Activos',
                        data: topSegments.map(s => s.hosts),
                        backgroundColor: colors.primary,
                        borderColor: colors.secondary,
                        borderWidth: 2,
                        borderRadius: 5
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1
                            }
                        },
                        x: {
                            ticks: {
                                maxRotation: 45
                            }
                        }
                    }
                }
            });
        }
        
        // Generar tablas dinámicamente
        function generateTables() {
            // Tabla de segmentos
            const segmentsTable = document.getElementById('segmentsTableContent');
            let segmentsHtml = '<table class="table"><thead><tr><th>Red</th><th>Hosts Activos</th><th>Puertos Detectados</th><th>Criticidad</th></tr></thead><tbody>';
            
            segmentsData.sort((a, b) => b.hosts - a.hosts).forEach(segment => {
                let criticality = 'Baja';
                let criticalityClass = 'status-low';
                
                if (segment.hosts > 20) { criticality = 'Crítica'; criticalityClass = 'status-critical'; }
                else if (segment.hosts > 10) { criticality = 'Alta'; criticalityClass = 'status-high'; }
                else if (segment.hosts > 5) { criticality = 'Media'; criticalityClass = 'status-medium'; }
                
                segmentsHtml += `<tr>
                    <td>${segment.network}</td>
                    <td><span class="${criticalityClass}">${segment.hosts}</span></td>
                    <td>${segment.ports}</td>
                    <td><span class="${criticalityClass}">${criticality}</span></td>
                </tr>`;
            });
            
            segmentsHtml += '</tbody></table>';
            segmentsTable.innerHTML = segmentsHtml;
        }
        
        // Inicializar dashboard
        document.addEventListener('DOMContentLoaded', function() {
            generateHeatmap();
            createServicesChart();
            createSegmentsChart();
            generateTables();
        });
    </script>
</body>
</html>
EOF

    # Reemplazar placeholders con datos reales
    sed -i "s/FECHA_PLACEHOLDER/$FECHA_INICIO/g" "$dashboard_file"
    sed -i "s/TOTAL_SEGMENTOS_PLACEHOLDER/$TOTAL_SEGMENTOS/g" "$dashboard_file"
    sed -i "s/TOTAL_SEGMENTOS_ACTIVOS_PLACEHOLDER/$TOTAL_SEGMENTOS_ACTIVOS/g" "$dashboard_file"
    sed -i "s/TOTAL_IPS_PLACEHOLDER/$TOTAL_IPS/g" "$dashboard_file"
    sed -i "s/ACTIVITY_RATE_PLACEHOLDER/$(( (TOTAL_SEGMENTOS_ACTIVOS * 100) / TOTAL_SEGMENTOS ))/g" "$dashboard_file"
    sed -i "s/SEGMENTS_DATA_PLACEHOLDER/$segments_data/g" "$dashboard_file"
    sed -i "s/SERVICES_DATA_PLACEHOLDER/$services_data/g" "$dashboard_file"
    
    print_message $GREEN "[+] Dashboard HTML generado: $dashboard_file"
    print_message $CYAN "[INFO] Abre el archivo en tu navegador para ver el dashboard interactivo"
    
    # Intentar abrir automáticamente en el navegador (si está disponible)
    if command -v xdg-open &> /dev/null; then
        print_message $YELLOW "[INFO] Intentando abrir dashboard en navegador..."
        xdg-open "$dashboard_file" 2>/dev/null &
    elif command -v open &> /dev/null; then
        print_message $YELLOW "[INFO] Intentando abrir dashboard en navegador..."
        open "$dashboard_file" 2>/dev/null &
    fi
}

# Procesar argumentos de línea de comandos
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--file)
            CUSTOM_FILE="$2"
            USE_CUSTOM_FILE=true
            shift 2
            ;;
        -e|--export)
            EXPORT_FORMAT="$2"
            if [[ ! "$EXPORT_FORMAT" =~ ^(csv|json|markdown|all)$ ]]; then
                print_message $RED "[ERROR] Formato de exportación inválido: $EXPORT_FORMAT"
                print_message $GRAY "Formatos válidos: csv, json, markdown, all"
                exit 1
            fi
            shift 2
            ;;
        -s|--simple)
            DETAILED_OUTPUT=false
            shift
            ;;
        -d|--dashboard)
            GENERATE_DASHBOARD=true
            shift
            ;;
        --no-dashboard)
            GENERATE_DASHBOARD=false
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            print_message $RED "[ERROR] Opción desconocida: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validar archivo personalizado si se especificó
if [[ $USE_CUSTOM_FILE == true ]]; then
    if [[ ! -f "$CUSTOM_FILE" ]]; then
        print_message $RED "[ERROR] El archivo especificado no existe: $CUSTOM_FILE"
        exit 1
    fi
    
    if [[ ! -r "$CUSTOM_FILE" ]]; then
        print_message $RED "[ERROR] No se puede leer el archivo: $CUSTOM_FILE"
        exit 1
    fi
    
    # Verificar que el archivo no esté vacío
    if [[ ! -s "$CUSTOM_FILE" ]]; then
        print_message $RED "[ERROR] El archivo está vacío: $CUSTOM_FILE"
        exit 1
    fi
    
    print_message $GREEN "[+] Usando archivo personalizado: $CUSTOM_FILE"
fi

# Verificar si Nmap está instalado
if ! command -v nmap &> /dev/null; then
    print_message $RED "[ERROR] Nmap no está instalado"
    print_message $YELLOW "    Ubuntu/Debian: sudo apt-get install nmap"
    print_message $YELLOW "    CentOS/RHEL: sudo yum install nmap"
    print_message $YELLOW "    Fedora: sudo dnf install nmap"
    print_message $YELLOW "    Arch: sudo pacman -S nmap"
    exit 1
fi

# Verificar permisos (recomendado ejecutar como root para mejor rendimiento)
if [[ $EUID -ne 0 ]]; then
    print_message $YELLOW "[AVISO] No se está ejecutando como root. Algunos scans pueden ser más lentos."
    print_message $GRAY "    Para mejor rendimiento: sudo $0"
fi

# Registrar tiempo de inicio
INICIO=$(date +%s)
FECHA_INICIO=$(date '+%Y-%m-%d %H:%M:%S')
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
print_message $CYAN "[INFO] Iniciando auditoría de segmentación: $FECHA_INICIO"

# 1. Generar o usar segmentos personalizados
SEGMENTOS_FILE="./segmentos_comunes.txt"

if [[ $USE_CUSTOM_FILE == true ]]; then
    # Usar archivo personalizado
    print_message $YELLOW "[INFO] Usando rangos del archivo personalizado: $CUSTOM_FILE"
    
    # Validar formato de rangos en el archivo
    print_message $GRAY "[INFO] Validando formato de rangos..."
    
    # Copiar archivo personalizado como archivo de trabajo
    cp "$CUSTOM_FILE" "$SEGMENTOS_FILE"
    
    # Validar que los rangos tengan formato correcto
    INVALID_LINES=0
    while IFS= read -r line; do
        # Ignorar líneas vacías y comentarios
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Validar formato CIDR (ej: 192.168.1.0/24)
        if [[ ! "$line" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]] && 
           [[ ! "$line" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}-[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            print_message $YELLOW "[AVISO] Formato posiblemente inválido en línea: $line"
            ((INVALID_LINES++))
        fi
    done < "$CUSTOM_FILE"
    
    if [[ $INVALID_LINES -gt 0 ]]; then
        print_message $YELLOW "[AVISO] Se encontraron $INVALID_LINES líneas con formato posiblemente inválido"
        print_message $GRAY "[INFO] Formatos soportados:"
        print_message $GRAY "  - CIDR: 192.168.1.0/24"
        print_message $GRAY "  - Rango: 192.168.1.1-192.168.1.254"
    fi
    
else
    # Generar segmentos predeterminados
    print_message $YELLOW "[INFO] Generando segmentos de red predeterminados..."
    
    # Limpiar archivo previo
    > "$SEGMENTOS_FILE"
    
    # 192.168.0.0/16 → 256 segmentos
    for i in {0..255}; do
        echo "192.168.$i.0/24" >> "$SEGMENTOS_FILE"
    done
    
    # 10.0.0.0/16 → 256 segmentos
    for i in {0..255}; do
        echo "10.0.$i.0/24" >> "$SEGMENTOS_FILE"
    done
    
    # 172.16.0.0 - 172.31.255.0 → Segmentos más comunes
    for j in {16..31}; do
        for i in {0..15}; do  # Reducido para pruebas iniciales, puedes cambiar a {0..255}
            echo "172.$j.$i.0/24" >> "$SEGMENTOS_FILE"
        done
    done
fi

# Contar segmentos generados
TOTAL_SEGMENTOS=$(wc -l < "$SEGMENTOS_FILE")

if [[ ! -f "$SEGMENTOS_FILE" ]] || [[ $TOTAL_SEGMENTOS -eq 0 ]]; then
    print_message $RED "[ERROR] No se pudo crear el archivo de segmentos"
    exit 1
fi

print_message $GREEN "[+] Segmentos generados: $TOTAL_SEGMENTOS redes"
print_message $GREEN "[+] Archivo guardado: $SEGMENTOS_FILE"

# 2. Ejecutar Nmap ping scan (solo host discovery)
NMAP_OUTPUT="./barrido_liviano.gnmap"
NMAP_XML_OUTPUT="./barrido_liviano.xml"

print_message $YELLOW "[INFO] Ejecutando Nmap... esto puede tardar varios minutos."
print_message $GRAY "[INFO] Puertos objetivo: 21,22,23,25,53,80,110,135,139,143,443,993,995,1433,1521,3306,3389,5432,5900,8080,8443"

# Ejecutar Nmap con manejo de errores y output XML para análisis detallado
if ! nmap -T4 -iL "$SEGMENTOS_FILE" -p 21,22,23,25,53,80,110,135,139,143,443,993,995,1433,1521,3306,3389,5432,5900,8080,8443 --open --max-retries 2 --min-rate 100 -oG "$NMAP_OUTPUT" -oX "$NMAP_XML_OUTPUT" 2>/dev/null; then
    print_message $RED "[ERROR] Fallo en la ejecución de Nmap"
    print_message $GRAY "[INFO] Verifica conectividad de red y permisos"
    exit 1
fi

# Calcular tiempo transcurrido del escaneo
FIN_SCAN=$(date +%s)
DURACION_SCAN=$((FIN_SCAN - INICIO))
print_message $GREEN "[+] Escaneo terminado en $(format_duration $DURACION_SCAN). Analizando resultados..."

# 3. Verificar que el archivo de salida existe
if [[ ! -f "$NMAP_OUTPUT" ]]; then
    print_message $RED "[ERROR] No se encontró el archivo de salida de Nmap: $NMAP_OUTPUT"
    exit 1
fi

# 4. Análisis detallado de resultados
print_message $YELLOW "[INFO] Procesando resultados detallados..."

# Crear archivos temporales para análisis
TEMP_RESULTS="./temp_detailed_results.txt"
TEMP_BY_SEGMENT="./temp_by_segment.txt"
TEMP_BY_CATEGORY="./temp_by_category.txt"

# Limpiar archivos temporales
> "$TEMP_RESULTS"
> "$TEMP_BY_SEGMENT"
> "$TEMP_BY_CATEGORY"

# Procesar archivo gnmap para extraer información detallada
while IFS= read -r line; do
    if [[ $line =~ Host:\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*Ports:\ (.+) ]]; then
        ip="${BASH_REMATCH[1]}"
        ports_info="${BASH_REMATCH[2]}"
        
        # Extraer segmento /24
        if [[ $ip =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$ ]]; then
            segment="${BASH_REMATCH[1]}.0/24"
        fi
        
        # Procesar puertos abiertos
        IFS=',' read -ra PORT_ARRAY <<< "$ports_info"
        open_ports=""
        
        for port_entry in "${PORT_ARRAY[@]}"; do
            if [[ $port_entry =~ ([0-9]+)/open/ ]]; then
                port="${BASH_REMATCH[1]}"
                if [[ -z "$open_ports" ]]; then
                    open_ports="$port"
                else
                    open_ports="$open_ports,$port"
                fi
                
                # Categorizar puerto
                category=$(categorize_port "$port")
                description=$(get_port_description "$port")
                
                # Guardar en archivo de categorías
                echo "$category|$ip|$port|$description|$segment" >> "$TEMP_BY_CATEGORY"
            fi
        done
        
        # Guardar resultado detallado
        if [[ -n "$open_ports" ]]; then
            echo "$segment|$ip|$open_ports" >> "$TEMP_RESULTS"
        fi
    fi
done < "$NMAP_OUTPUT"

# Verificar si se encontraron hosts activos
if [[ ! -s "$TEMP_RESULTS" ]]; then
    print_message $YELLOW "[AVISO] No se encontraron hosts con puertos abiertos en el escaneo"
    print_message $GRAY "[INFO] Revisa la conectividad de red y los rangos escaneados"
    exit 0
fi

# Contar estadísticas
TOTAL_IPS=$(cut -d'|' -f2 "$TEMP_RESULTS" | sort -u | wc -l)
TOTAL_SEGMENTOS_ACTIVOS=$(cut -d'|' -f1 "$TEMP_RESULTS" | sort -u | wc -l)

print_message $GREEN "[+] Hosts activos encontrados: $TOTAL_IPS"
print_message $GREEN "[+] Segmentos con actividad: $TOTAL_SEGMENTOS_ACTIVOS"

# 5. Mostrar resultados detallados
echo
print_message $CYAN "════════════ RESULTADOS DE AUDITORÍA DE SEGMENTACIÓN ════════════"
echo

if [[ $DETAILED_OUTPUT == true ]]; then
    # Mostrar por segmentos con detalles
    while IFS= read -r segment; do
        print_message $WHITE "[SEGMENTO] $segment"
        
        # Mostrar IPs de este segmento
        while IFS='|' read -r seg ip ports; do
            if [[ "$seg" == "$segment" ]]; then
                port_details=""
                IFS=',' read -ra PORT_LIST <<< "$ports"
                for port in "${PORT_LIST[@]}"; do
                    desc=$(get_port_description "$port")
                    if [[ -z "$port_details" ]]; then
                        port_details="$port($desc)"
                    else
                        port_details="$port_details, $port($desc)"
                    fi
                done
                print_message $GRAY "  ├── $ip   [$port_details]"
            fi
        done < "$TEMP_RESULTS"
        echo
    done <<< "$(cut -d'|' -f1 "$TEMP_RESULTS" | sort -u)"
    
    echo
    print_message $CYAN "════════════ ANÁLISIS POR CATEGORÍA DE SERVICIOS ════════════"
    echo
    
    # Mostrar por categorías
    categories=("ADMINISTRACION" "BASE_DATOS" "WEB_SERVICES" "SERVICIOS_MAIL_FTP" "DNS" "WINDOWS_SERVICES" "OTROS")
    
    for category in "${categories[@]}"; do
        category_hosts=$(grep "^$category|" "$TEMP_BY_CATEGORY" | wc -l)
        if [[ $category_hosts -gt 0 ]]; then
            case $category in
                "ADMINISTRACION") color=$RED ;;
                "BASE_DATOS") color=$MAGENTA ;;
                "WEB_SERVICES") color=$CYAN ;;
                *) color=$YELLOW ;;
            esac
            
            print_message $color "[${category}] ($category_hosts servicios encontrados)"
            
            while IFS='|' read -r cat ip port desc segment; do
                if [[ "$cat" == "$category" ]]; then
                    print_message $GRAY "  ├── $ip:$port ($desc) - Segmento: $segment"
                fi
            done < "$TEMP_BY_CATEGORY"
            echo
        fi
    done
else
    # Output simple - solo segmentos activos
    print_message $CYAN "[SEGMENTOS ACTIVOS] ($TOTAL_SEGMENTOS_ACTIVOS encontrados):"
    cut -d'|' -f1 "$TEMP_RESULTS" | sort -u | while read -r segment; do
        host_count=$(grep "^$segment|" "$TEMP_RESULTS" | wc -l)
        print_message $WHITE "  $segment ($host_count hosts activos)"
    done
fi

# Función para exportar a CSV
export_csv() {
    local csv_file="./audit_results_${TIMESTAMP}.csv"
    print_message $YELLOW "[INFO] Exportando a CSV: $csv_file"
    
    echo "Segmento,IP,Puerto,Servicio,Categoria,Timestamp" > "$csv_file"
    
    while IFS='|' read -r category ip port description segment; do
        echo "$segment,$ip,$port,$description,$category,$FECHA_INICIO" >> "$csv_file"
    done < "$TEMP_BY_CATEGORY"
    
    print_message $GREEN "[+] CSV creado: $csv_file"
}

# Función para exportar a JSON
export_json() {
    local json_file="./audit_results_${TIMESTAMP}.json"
    print_message $YELLOW "[INFO] Exportando a JSON: $json_file"
    
    echo "{" > "$json_file"
    echo "  \"audit_info\": {" >> "$json_file"
    echo "    \"timestamp\": \"$FECHA_INICIO\"," >> "$json_file"
    echo "    \"duration_seconds\": $DURACION_SCAN," >> "$json_file"
    echo "    \"total_segments_scanned\": $TOTAL_SEGMENTOS," >> "$json_file"
    echo "    \"active_segments\": $TOTAL_SEGMENTOS_ACTIVOS," >> "$json_file"
    echo "    \"active_hosts\": $TOTAL_IPS" >> "$json_file"
    echo "  }," >> "$json_file"
    echo "  \"segments\": [" >> "$json_file"
    
    first_segment=true
    while IFS= read -r segment; do
        if [[ $first_segment == false ]]; then
            echo "    }," >> "$json_file"
        fi
        first_segment=false
        
        echo "    {" >> "$json_file"
        echo "      \"network\": \"$segment\"," >> "$json_file"
        echo "      \"hosts\": [" >> "$json_file"
        
        first_host=true
        while IFS='|' read -r seg ip ports; do
            if [[ "$seg" == "$segment" ]]; then
                if [[ $first_host == false ]]; then
                    echo "        }," >> "$json_file"
                fi
                first_host=false
                
                echo "        {" >> "$json_file"
                echo "          \"ip\": \"$ip\"," >> "$json_file"
                echo "          \"open_ports\": [" >> "$json_file"
                
                IFS=',' read -ra PORT_LIST <<< "$ports"
                for i in "${!PORT_LIST[@]}"; do
                    port="${PORT_LIST[$i]}"
                    desc=$(get_port_description "$port")
                    category=$(categorize_port "$port")
                    
                    echo "            {" >> "$json_file"
                    echo "              \"port\": $port," >> "$json_file"
                    echo "              \"service\": \"$desc\"," >> "$json_file"
                    echo "              \"category\": \"$category\"" >> "$json_file"
                    
                    if [[ $i -eq $((${#PORT_LIST[@]} - 1)) ]]; then
                        echo "            }" >> "$json_file"
                    else
                        echo "            }," >> "$json_file"
                    fi
                done
                
                echo "          ]" >> "$json_file"
            fi
        done < "$TEMP_RESULTS"
        
        if [[ $first_host == false ]]; then
            echo "        }" >> "$json_file"
        fi
        echo "      ]" >> "$json_file"
    done <<< "$(cut -d'|' -f1 "$TEMP_RESULTS" | sort -u)"
    
    echo "    }" >> "$json_file"
    echo "  ]" >> "$json_file"
    echo "}" >> "$json_file"
    
    print_message $GREEN "[+] JSON creado: $json_file"
}

# Función para exportar a Markdown
export_markdown() {
    local md_file="./audit_report_${TIMESTAMP}.md"
    print_message $YELLOW "[INFO] Exportando reporte a Markdown: $md_file"
    
    cat > "$md_file" << EOF
# Reporte de Auditoría de Segmentación de Red

**Fecha:** $FECHA_INICIO  
**Duración:** $(format_duration $DURACION_SCAN)  
**Herramienta:** Nmap Network Segmentation Audit Script v2.0

## Resumen Ejecutivo

- **Segmentos escaneados:** $TOTAL_SEGMENTOS
- **Segmentos con actividad:** $TOTAL_SEGMENTOS_ACTIVOS
- **Hosts activos encontrados:** $TOTAL_IPS
- **Tasa de actividad:** $(( (TOTAL_SEGMENTOS_ACTIVOS * 100) / TOTAL_SEGMENTOS ))%

## Detalles por Segmento

EOF

    while IFS= read -r segment; do
        echo "### $segment" >> "$md_file"
        echo "" >> "$md_file"
        echo "| IP | Puertos Abiertos | Servicios |" >> "$md_file"
        echo "|---|---|---|" >> "$md_file"
        
        while IFS='|' read -r seg ip ports; do
            if [[ "$seg" == "$segment" ]]; then
                services=""
                IFS=',' read -ra PORT_LIST <<< "$ports"
                for port in "${PORT_LIST[@]}"; do
                    desc=$(get_port_description "$port")
                    if [[ -z "$services" ]]; then
                        services="$port($desc)"
                    else
                        services="$services, $port($desc)"
                    fi
                done
                echo "| $ip | $ports | $services |" >> "$md_file"
            fi
        done < "$TEMP_RESULTS"
        echo "" >> "$md_file"
    done <<< "$(cut -d'|' -f1 "$TEMP_RESULTS" | sort -u)"
    
    cat >> "$md_file" << EOF

## Análisis por Categoría de Servicios

EOF

    categories=("ADMINISTRACION" "BASE_DATOS" "WEB_SERVICES" "SERVICIOS_MAIL_FTP" "DNS" "WINDOWS_SERVICES" "OTROS")
    
    for category in "${categories[@]}"; do
        category_count=$(grep "^$category|" "$TEMP_BY_CATEGORY" | wc -l)
        if [[ $category_count -gt 0 ]]; then
            echo "### $category ($category_count servicios)" >> "$md_file"
            echo "" >> "$md_file"
            echo "| IP | Puerto | Servicio | Segmento |" >> "$md_file"
            echo "|---|---|---|---|" >> "$md_file"
            
            while IFS='|' read -r cat ip port desc segment; do
                if [[ "$cat" == "$category" ]]; then
                    echo "| $ip | $port | $desc | $segment |" >> "$md_file"
                fi
            done < "$TEMP_BY_CATEGORY"
            echo "" >> "$md_file"
        fi
    done
    
    print_message $GREEN "[+] Markdown creado: $md_file"
}

# 6. Exportar según formato especificado
case $EXPORT_FORMAT in
    "csv")
        export_csv
        ;;
    "json")
        export_json
        ;;
    "markdown")
        export_markdown
        ;;
    "all")
        export_csv
        export_json
        export_markdown
        ;;
esac

# Generar dashboard HTML si está habilitado
if [[ $GENERATE_DASHBOARD == true ]]; then
    generate_html_dashboard
fi

# 7. Crear archivo de resumen mejorado
RESUMEN_FILE="./resumen_auditoria_${TIMESTAMP}.txt"
{
    echo "═══════════════════════════════════════════════════════════════"
    echo "               RESUMEN DE AUDITORÍA DE SEGMENTACIÓN"
    echo "═══════════════════════════════════════════════════════════════"
    echo "Fecha inicio: $FECHA_INICIO"
    echo "Duración: $(format_duration $DURACION_SCAN)"
    if [[ $USE_CUSTOM_FILE == true ]]; then
        echo "Archivo de rangos: $CUSTOM_FILE"
    else
        echo "Rangos: Predeterminados (RFC 1918)"
    fi
    echo "Segmentos escaneados: $TOTAL_SEGMENTOS"
    echo "Hosts activos: $TOTAL_IPS"
    echo "Segmentos con actividad: $TOTAL_SEGMENTOS_ACTIVOS"
    echo "Tasa de actividad: $(( (TOTAL_SEGMENTOS_ACTIVOS * 100) / TOTAL_SEGMENTOS ))%"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    SEGMENTOS ACTIVOS"
    echo "═══════════════════════════════════════════════════════════════"
    
    while IFS= read -r segment; do
        host_count=$(grep "^$segment|" "$TEMP_RESULTS" | wc -l)
        echo "$segment ($host_count hosts)"
        
        while IFS='|' read -r seg ip ports; do
            if [[ "$seg" == "$segment" ]]; then
                echo "  └── $ip [$ports]"
            fi
        done < "$TEMP_RESULTS"
        echo ""
    done <<< "$(cut -d'|' -f1 "$TEMP_RESULTS" | sort -u)"
    
    echo "═══════════════════════════════════════════════════════════════"
    echo "                SERVICIOS POR CATEGORÍA"
    echo "═══════════════════════════════════════════════════════════════"
    
    for category in "${categories[@]}"; do
        category_count=$(grep "^$category|" "$TEMP_BY_CATEGORY" | wc -l)
        if [[ $category_count -gt 0 ]]; then
            echo ""
            echo "[$category] - $category_count servicios:"
            while IFS='|' read -r cat ip port desc segment; do
                if [[ "$cat" == "$category" ]]; then
                    echo "  $ip:$port ($desc) - $segment"
                fi
            done < "$TEMP_BY_CATEGORY"
        fi
    done
    
} > "$RESUMEN_FILE"

print_message $GREEN "[+] Resumen detallado guardado en: $RESUMEN_FILE"

# Calcular tiempo total
FIN=$(date +%s)
DURACION_TOTAL=$((FIN - INICIO))

echo
print_message $CYAN "════════════════════════════════════════════════════════════════"
print_message $GREEN "[AUDITORÍA COMPLETADA]"
print_message $GRAY "Tiempo total: $(format_duration $DURACION_TOTAL)"
print_message $GRAY "Archivos generados en directorio actual:"
if [[ $GENERATE_DASHBOARD == true ]]; then
    print_message $GRAY "  📊 Dashboard: audit_dashboard_${TIMESTAMP}.html"
fi
case $EXPORT_FORMAT in
    "csv"|"all")
        print_message $GRAY "  📊 CSV: audit_results_${TIMESTAMP}.csv"
        ;;
esac
case $EXPORT_FORMAT in
    "json"|"all")
        print_message $GRAY "  📄 JSON: audit_results_${TIMESTAMP}.json"
        ;;
esac
case $EXPORT_FORMAT in
    "markdown"|"all")
        print_message $GRAY "  📝 Markdown: audit_report_${TIMESTAMP}.md"
        ;;
esac
print_message $GRAY "  📋 Resumen: resumen_auditoria_${TIMESTAMP}.txt"
print_message $CYAN "════════════════════════════════════════════════════════════════"

# Limpieza de archivos temporales
rm -f "$TEMP_RESULTS" "$TEMP_BY_SEGMENT" "$TEMP_BY_CATEGORY"

# Opcional: limpiar archivos de nmap
echo
read -p "¿Deseas eliminar archivos temporales de Nmap? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [[ $USE_CUSTOM_FILE == false ]]; then
        rm -f "$SEGMENTOS_FILE"
    fi
    rm -f "$NMAP_OUTPUT" "$NMAP_XML_OUTPUT"
    print_message $GREEN "[+] Archivos temporales de Nmap eliminados"
fi

print_message $GREEN "[INFO] Auditoría de segmentación finalizada exitosamente"
