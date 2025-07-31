#!/usr/bin/env python3
"""
Segmentador - Herramienta Profesional de Auditoría de Segmentación de Red
Versión: 5.0 - Python Production Edition

Autor: Security Audit Team
Licencia: MIT

Mejoras v5.0:
- Parser XML robusto para combinación de resultados
- Paralelización granular con semáforos
- Gestión mejorada de archivos temporales
- Reintentos con backoff exponencial
- Normalización y expansión de rangos IP
- Modelo canónico para exportación
- Escape seguro en templates HTML
- Deduplicación de resultados
"""

import argparse
import csv
import json
import logging
import multiprocessing
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Iterator
import ipaddress

# Configuración de constantes
REQUIRED_NMAP_VERSION = (7, 0)
REQUIRED_PYTHON_VERSION = (3, 6)
MAX_RETRIES = 3
BASE_RETRY_DELAY = 1.0
MAX_CONCURRENT_SCANS = 10

# Configuración de puertos y servicios
PORT_CONFIG = {
    21: {"service": "FTP", "category": "SERVICIOS_MAIL_FTP"},
    22: {"service": "SSH", "category": "ADMINISTRACION"},
    23: {"service": "Telnet", "category": "ADMINISTRACION"},
    25: {"service": "SMTP", "category": "SERVICIOS_MAIL_FTP"},
    53: {"service": "DNS", "category": "DNS"},
    80: {"service": "HTTP", "category": "WEB_SERVICES"},
    110: {"service": "POP3", "category": "SERVICIOS_MAIL_FTP"},
    135: {"service": "RPC", "category": "WINDOWS_SERVICES"},
    139: {"service": "NetBIOS", "category": "WINDOWS_SERVICES"},
    143: {"service": "IMAP", "category": "SERVICIOS_MAIL_FTP"},
    443: {"service": "HTTPS", "category": "WEB_SERVICES"},
    993: {"service": "IMAPS", "category": "SERVICIOS_MAIL_FTP"},
    995: {"service": "POP3S", "category": "SERVICIOS_MAIL_FTP"},
    1433: {"service": "MSSQL", "category": "BASE_DATOS"},
    1521: {"service": "Oracle", "category": "BASE_DATOS"},
    3306: {"service": "MySQL", "category": "BASE_DATOS"},
    3389: {"service": "RDP", "category": "ADMINISTRACION"},
    5432: {"service": "PostgreSQL", "category": "BASE_DATOS"},
    5900: {"service": "VNC", "category": "ADMINISTRACION"},
    8080: {"service": "HTTP-Alt", "category": "WEB_SERVICES"},
    8443: {"service": "HTTPS-Alt", "category": "WEB_SERVICES"},
}

TARGET_PORTS = list(PORT_CONFIG.keys())

@dataclass
class ScanResult:
    """Estructura de datos para resultados de escaneo."""
    ip: str
    ports: List[int]
    segment: str
    
    def __hash__(self):
        return hash((self.ip, tuple(sorted(self.ports)), self.segment))
    
@dataclass
class ServiceInfo:
    """Información de servicio detectado."""
    ip: str
    port: int
    service: str
    category: str
    segment: str
    
    def __hash__(self):
        return hash((self.ip, self.port, self.segment))
    
@dataclass
class AuditStats:
    """Estadísticas de auditoría."""
    start_time: datetime
    end_time: Optional[datetime] = None
    total_segments: int = 0
    active_segments: int = 0
    active_hosts: int = 0
    scan_duration: float = 0.0
    
    @property
    def activity_rate(self) -> float:
        """Calcular tasa de actividad de forma segura."""
        if self.total_segments > 0:
            return (self.active_segments / self.total_segments) * 100
        return 0.0
    
    @property
    def duration_formatted(self) -> str:
        """Formatear duración en formato legible."""
        duration = int(self.scan_duration) if self.scan_duration else 0
        hours = duration // 3600
        minutes = (duration % 3600) // 60
        seconds = duration % 60
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    @property
    def total_duration_formatted(self) -> str:
        """Formatear duración total de la auditoría."""
        if not self.end_time:
            return "En progreso..."
        
        total_duration = (self.end_time - self.start_time).total_seconds()
        return self._format_duration(int(total_duration))
    
    @staticmethod
    def _format_duration(duration: int) -> str:
        """Formatear duración en formato legible (método estático reutilizable)."""
        hours = duration // 3600
        minutes = (duration % 3600) // 60
        seconds = duration % 60
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"

@dataclass 
class CanonicalScanData:
    """Modelo canónico para datos de escaneo - fuente única de verdad."""
    segments: Dict[str, List[ScanResult]]
    services_by_category: Dict[str, List[ServiceInfo]]
    services_by_ip: Dict[str, List[ServiceInfo]]
    all_services: List[ServiceInfo]
    stats: AuditStats
    
    @classmethod
    def from_results(cls, scan_results: List[ScanResult], service_info: List[ServiceInfo], 
                    stats: AuditStats) -> 'CanonicalScanData':
        """Crear modelo canónico desde resultados brutos."""
        # Deduplicar resultados
        unique_results = list(set(scan_results))
        unique_services = list(set(service_info))
        
        # Agrupar por segmento
        segments = {}
        for result in unique_results:
            if result.segment not in segments:
                segments[result.segment] = []
            segments[result.segment].append(result)
        
        # Agrupar servicios por categoría
        services_by_category = {}
        for service in unique_services:
            if service.category not in services_by_category:
                services_by_category[service.category] = []
            services_by_category[service.category].append(service)
        
        # Agrupar servicios por IP
        services_by_ip = {}
        for service in unique_services:
            if service.ip not in services_by_ip:
                services_by_ip[service.ip] = []
            services_by_ip[service.ip].append(service)
        
        return cls(
            segments=segments,
            services_by_category=services_by_category,
            services_by_ip=services_by_ip,
            all_services=unique_services,
            stats=stats
        )

class SegmentadorError(Exception):
    """Excepción base para errores del segmentador."""
    pass

class NetworkValidationError(SegmentadorError):
    """Error de validación de red."""
    pass

class ScanExecutionError(SegmentadorError):
    """Error de ejecución de escaneo."""
    pass

class ExportError(SegmentadorError):
    """Error de exportación."""
    pass

class RetryableError(SegmentadorError):
    """Error que puede reintentar."""
    pass

class Logger:
    """Sistema de logging robusto."""
    
    def __init__(self, verbose: bool = False, quiet: bool = False, log_file: Optional[str] = None):
        self.verbose = verbose
        self.quiet = quiet
        self.errors: List[str] = []
        
        # Configurar logging
        self.logger = logging.getLogger('segmentador')
        # Limpiar handlers previos para evitar duplicación en ejecuciones repetidas
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        
        # Handler para archivo
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        
        # Handler para consola
        if not quiet:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
            console_formatter = logging.Formatter('%(message)s')
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
    
    def info(self, message: str):
        """Log mensaje informativo."""
        self.logger.info(f"[INFO] {message}")
    
    def warn(self, message: str):
        """Log mensaje de advertencia."""
        self.logger.warning(f"[WARN] {message}")
    
    def error(self, message: str):
        """Log mensaje de error."""
        self.errors.append(message)
        self.logger.error(f"[ERROR] {message}")
    
    def debug(self, message: str):
        """Log mensaje de debug."""
        self.logger.debug(f"[DEBUG] {message}")
    
    def success(self, message: str):
        """Log mensaje de éxito."""
        if not self.quiet:
            print(f"\033[0;32m[SUCCESS] {message}\033[0m")
    
    def get_error_summary(self) -> List[str]:
        """Obtener resumen de errores."""
        return self.errors.copy()

class RetryHelper:
    """Helper para reintentos con backoff exponencial."""
    
    @staticmethod
    def retry_with_backoff(func, max_retries: int = MAX_RETRIES, 
                          base_delay: float = BASE_RETRY_DELAY,
                          backoff_factor: float = 2.0,
                          jitter: bool = True,
                          retryable_exceptions: tuple = (RetryableError, subprocess.CalledProcessError)):
        """
        Ejecutar función con reintentos y backoff exponencial.
        
        Args:
            func: Función a ejecutar
            max_retries: Número máximo de reintentos
            base_delay: Delay base en segundos
            backoff_factor: Factor de multiplicación del delay
            jitter: Agregar jitter aleatorio al delay
            retryable_exceptions: Excepciones que permiten reintento
        """
        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                return func()
            except retryable_exceptions as e:
                last_exception = e
                
                if attempt < max_retries:
                    delay = base_delay * (backoff_factor ** attempt)
                    if jitter:
                        delay *= (0.5 + random.random())
                    
                    time.sleep(delay)
                    continue
                else:
                    # Último intento fallido
                    break
            except Exception as e:
                # Excepción no reintentable
                raise e
        
        # Si llegamos aquí, todos los reintentos fallaron
        raise last_exception

class NetworkValidator:
    """Validador y normalizador de redes."""
    
    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        """Validar formato CIDR."""
        try:
            ipaddress.ip_network(cidr, strict=True)
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False
    
    @staticmethod
    def validate_ip_range(ip_range: str) -> bool:
        """Validar rango IP (formato IP1-IP2)."""
        try:
            start_ip, end_ip = ip_range.split('-')
            ipaddress.ip_address(start_ip.strip())
            ipaddress.ip_address(end_ip.strip())
            return True
        except (ValueError, ipaddress.AddressValueError):
            return False
    
    @staticmethod
    def normalize_network(network: str) -> str:
        """Normalizar red a formato estándar."""
        try:
            if '-' in network:
                # Mantener rango original - Nmap lo soporta
                start_ip, end_ip = network.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                return f"{start}-{end}"
            else:
                # Normalizar CIDR
                net = ipaddress.ip_network(network, strict=False)
                return str(net)
        except Exception:
            return network
    
    @staticmethod
    def expand_ip_range(ip_range: str, max_ips: int = 256) -> List[str]:
        """
        Expandir rango IP a lista de IPs individuales.
        
        Args:
            ip_range: Rango en formato "IP1-IP2"
            max_ips: Máximo número de IPs a expandir (límite de seguridad)
        
        Returns:
            Lista de IPs individuales
        """
        try:
            start_str, end_str = ip_range.split('-')
            start_ip = ipaddress.ip_address(start_str.strip())
            end_ip = ipaddress.ip_address(end_str.strip())
            
            if start_ip > end_ip:
                raise NetworkValidationError(f"IP inicial mayor que IP final en rango: {ip_range}")
            
            # Calcular número de IPs en el rango
            ip_count = int(end_ip) - int(start_ip) + 1
            
            if ip_count > max_ips:
                raise NetworkValidationError(
                    f"Rango demasiado grande ({ip_count} IPs). Máximo permitido: {max_ips}"
                )
            
            # Generar lista de IPs
            ips = []
            current = start_ip
            while current <= end_ip:
                ips.append(str(current))
                current += 1
            
            return ips
            
        except ValueError as e:
            raise NetworkValidationError(f"Error expandiendo rango {ip_range}: {e}")
    
    @staticmethod
    def deduplicate_networks(networks: List[str]) -> List[str]:
        """Deduplicar lista de redes manteniendo orden."""
        seen = set()
        result = []
        
        for network in networks:
            normalized = NetworkValidator.normalize_network(network)
            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)
        
        return result

class DependencyChecker:
    """Verificador de dependencias del sistema."""
    
    def __init__(self, logger: Logger):
        self.logger = logger
    
    def check_python_version(self) -> bool:
        """Verificar versión de Python."""
        current = sys.version_info[:2]
        if current < REQUIRED_PYTHON_VERSION:
            self.logger.error(
                f"Python {REQUIRED_PYTHON_VERSION[0]}.{REQUIRED_PYTHON_VERSION[1]}+ "
                f"requerido. Versión actual: {current[0]}.{current[1]}"
            )
            return False
        return True
    
    def check_nmap_version(self) -> bool:
        """Verificar versión de Nmap."""
        try:
            result = subprocess.run(
                ['nmap', '--version'], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            if result.returncode != 0:
                self.logger.error("Nmap no está instalado o no es ejecutable")
                return False
            
            # Extraer versión
            version_match = re.search(r'Nmap version (\d+)\.(\d+)', result.stdout)
            if not version_match:
                self.logger.error("No se pudo determinar la versión de Nmap")
                return False
            
            major, minor = int(version_match.group(1)), int(version_match.group(2))
            current = (major, minor)
            
            if current < REQUIRED_NMAP_VERSION:
                self.logger.error(
                    f"Nmap {REQUIRED_NMAP_VERSION[0]}.{REQUIRED_NMAP_VERSION[1]}+ "
                    f"requerido. Versión actual: {major}.{minor}"
                )
                return False
                
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout al verificar versión de Nmap")
            return False
        except FileNotFoundError:
            self.logger.error("Nmap no está instalado")
            return False
        except Exception as e:
            self.logger.error(f"Error verificando Nmap: {e}")
            return False
    
    def check_permissions(self) -> bool:
        """Verificar permisos de ejecución."""
        if os.geteuid() != 0:
            self.logger.warn("No se está ejecutando como root. El escaneo puede ser más lento")
            return False
        return True
    
    def check_all(self) -> bool:
        """Verificar todas las dependencias."""
        checks = [
            self.check_python_version(),
            self.check_nmap_version()
        ]
        
        self.check_permissions()  # No crítico
        
        return all(checks)

class XMLMerger:
    """Merger robusto de archivos XML de Nmap usando parser XML real."""
    
    def __init__(self, logger: Logger):
        self.logger = logger
    
    def merge_xml_files(self, xml_files: List[str], output_file: str) -> bool:
        """
        Combinar múltiples archivos XML de Nmap de forma robusta.
        
        Args:
            xml_files: Lista de archivos XML a combinar
            output_file: Archivo XML de salida
            
        Returns:
            True si el merge fue exitoso
        """
        try:
            # Crear elemento root
            root = ET.Element("nmaprun")
            root.set("scanner", "segmentador")
            root.set("start", str(int(time.time())))
            root.set("version", "5.0")
            
            # Contadores para estadísticas
            total_hosts = 0
            
            # Procesar cada archivo XML
            for xml_file in xml_files:
                try:
                    tree = ET.parse(xml_file)
                    file_root = tree.getroot()
                    
                    # Extraer hosts del archivo
                    for host in file_root.findall('host'):
                        # Agregar host al XML combinado
                        root.append(host)
                        total_hosts += 1
                    
                    # Preservar scaninfo si no existe
                    if root.find('scaninfo') is None:
                        scaninfo = file_root.find('scaninfo')
                        if scaninfo is not None:
                            root.append(scaninfo)
                    
                except ET.ParseError as e:
                    self.logger.warn(f"Error parseando {xml_file}: {e}")
                    continue
                except Exception as e:
                    self.logger.warn(f"Error procesando {xml_file}: {e}")
                    continue
            
            # Agregar estadísticas finales
            runstats = ET.SubElement(root, "runstats")
            finished = ET.SubElement(runstats, "finished")
            finished.set("time", str(int(time.time())))
            finished.set("timestr", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            hosts_elem = ET.SubElement(runstats, "hosts")
            hosts_elem.set("up", str(total_hosts))
            hosts_elem.set("down", "0")
            hosts_elem.set("total", str(total_hosts))
            
            # Escribir XML combinado
            tree = ET.ElementTree(root)
            # Fallback seguro para ET.indent (solo disponible en Python 3.9+)
            if hasattr(ET, 'indent'):
                ET.indent(tree, space="  ", level=0)  # Formatear para legibilidad
            tree.write(output_file, encoding="utf-8", xml_declaration=True)
            
            self.logger.debug(f"XML merge completado: {total_hosts} hosts combinados")
            return True
            
        except Exception as e:
            # Registrar traceback completo en modo verbose para debugging
            if hasattr(self, 'logger') and hasattr(self.logger, 'verbose') and self.logger.verbose:
                import traceback
                self.logger.debug(f"XML merge error traceback: {traceback.format_exc()}")
            self.logger.error(f"Error en merge XML: {e}")
            return False

class NetworkScanner:
    """Motor de escaneo de red con paralelización granular."""
    
    def __init__(self, logger: Logger, parallel_jobs: int = 1):
        self.logger = logger
        self.parallel_jobs = min(parallel_jobs, MAX_CONCURRENT_SCANS)
        self.temp_files_registry: List[str] = []
        self.semaphore = threading.Semaphore(self.parallel_jobs)
        self.xml_merger = XMLMerger(logger)
    
    def cleanup_temp_files(self):
        """Limpiar archivos temporales registrados."""
        for temp_file in self.temp_files_registry:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                    self.logger.debug(f"Archivo temporal eliminado: {temp_file}")
            except Exception as e:
                self.logger.debug(f"Error eliminando {temp_file}: {e}")
        self.temp_files_registry.clear()
    
    def register_temp_file(self, filepath: str):
        """Registrar archivo temporal para cleanup automático."""
        self.temp_files_registry.append(filepath)
    
    def detect_scan_method(self) -> str:
        """Detectar método óptimo de escaneo basado en latencia."""
        try:
            def ping_test():
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', '8.8.8.8'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode != 0:
                    # Diferenciar claramente fallos de ping vs latencia alta
                    self.logger.debug(f"Ping falló (código {result.returncode}): {result.stderr.strip()}")
                    raise RetryableError("Ping failed - ICMP may be blocked or network unreachable")
                return result.stdout
            
            # Intentar ping con reintentos
            try:
                output = RetryHelper.retry_with_backoff(
                    ping_test, 
                    max_retries=2,
                    retryable_exceptions=(RetryableError, subprocess.CalledProcessError)
                )
            except Exception as ping_error:
                self.logger.warn(f"Ping completamente fallido: {ping_error}. Usando método conservador")
                return "conservative"
            
            # Extraer tiempo de ping
            time_match = re.search(r'time=(\d+\.?\d*)', output)
            if not time_match:
                self.logger.warn("No se pudo extraer tiempo de ping. Usando método conservador")
                return "conservative"
            
            ping_time = float(time_match.group(1))
            
            if ping_time < 50:
                self.logger.debug(f"Red rápida detectada ({ping_time}ms), usando método optimizado")
                return "optimized"
            elif ping_time < 200:
                self.logger.debug(f"Red normal detectada ({ping_time}ms), usando verificación doble")
                return "verified"
            else:
                self.logger.debug(f"Red lenta detectada ({ping_time}ms), usando método conservador")
                return "conservative"
                
        except Exception as e:
            self.logger.debug(f"Error inesperado detectando latencia: {e}")
            return "conservative"
    
    def execute_nmap_scan(self, targets: List[str], scan_type: str) -> Tuple[str, str]:
        """
        Ejecutar escaneo Nmap con reintentos automáticos.
        
        Args:
            targets: Lista de targets (redes o IPs)
            scan_type: Tipo de escaneo (optimized, verified, conservative)
            
        Returns:
            Tupla con paths de archivos gnmap y XML
        """
        # Crear archivo temporal de targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as target_file:
            target_file.write('\n'.join(targets))
            target_file_path = target_file.name
        
        self.register_temp_file(target_file_path)
        
        # Archivos de salida temporales
        gnmap_file = tempfile.NamedTemporaryFile(suffix='.gnmap', delete=False)
        xml_file = tempfile.NamedTemporaryFile(suffix='.xml', delete=False)
        gnmap_path, xml_path = gnmap_file.name, xml_file.name
        gnmap_file.close()
        xml_file.close()
        
        self.register_temp_file(gnmap_path)
        self.register_temp_file(xml_path)
        
        def nmap_scan():
            nmap_cmd = self._build_nmap_command(scan_type, target_file_path, gnmap_path, xml_path)
            
            self.logger.debug(f"Ejecutando: {' '.join(nmap_cmd[:5])}... (targets: {len(targets)})")
            
            result = subprocess.run(
                nmap_cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hora máximo
            )
            
            if result.returncode != 0:
                raise RetryableError(f"Nmap falló con código {result.returncode}: {result.stderr}")
            
            return gnmap_path, xml_path
        
        try:
            # Ejecutar con reintentos
            gnmap_result, xml_result = RetryHelper.retry_with_backoff(
                nmap_scan,
                max_retries=MAX_RETRIES,
                retryable_exceptions=(RetryableError, subprocess.TimeoutExpired)
            )
            
            # Validación de resultados vacíos después del escaneo
            self._validate_scan_results(gnmap_result, xml_result)
            
            return gnmap_result, xml_result
            
        except Exception as e:
            # Registrar traceback completo en modo verbose para debugging crítico
            if hasattr(self.logger, 'verbose') and self.logger.verbose:
                import traceback
                self.logger.debug(f"Nmap scan error traceback: {traceback.format_exc()}")
            raise ScanExecutionError(f"Error ejecutando Nmap después de {MAX_RETRIES} reintentos: {e}")
    
    def _validate_scan_results(self, gnmap_file: str, xml_file: str):
        """Validar que los archivos de resultado no estén vacíos o sin contenido útil."""
        # Validar archivo gnmap
        try:
            if not os.path.exists(gnmap_file) or os.path.getsize(gnmap_file) == 0:
                raise ScanExecutionError("Archivo gnmap está vacío o no existe")
            
            # Verificar contenido mínimo esperado en gnmap
            with open(gnmap_file, 'r') as f:
                content = f.read().strip()
                if not content or 'Nmap done' not in content:
                    raise ScanExecutionError("Archivo gnmap no contiene resultados válidos de Nmap")
                    
        except Exception as e:
            raise ScanExecutionError(f"Error validando archivo gnmap: {e}")
        
        # Validar archivo XML
        try:
            if not os.path.exists(xml_file) or os.path.getsize(xml_file) == 0:
                raise ScanExecutionError("Archivo XML está vacío o no existe")
                
            # Verificar estructura XML básica
            with open(xml_file, 'r') as f:
                content = f.read().strip()
                if not content or '<nmaprun' not in content:
                    raise ScanExecutionError("Archivo XML no contiene estructura válida de Nmap")
                    
        except Exception as e:
            raise ScanExecutionError(f"Error validando archivo XML: {e}")
    
    def _build_nmap_command(self, scan_type: str, target_file: str, gnmap_out: str, xml_out: str) -> List[str]:
        """Construir comando Nmap según tipo de escaneo."""
        base_cmd = [
            'nmap', '-n', '-sS',
            '-p', ','.join(map(str, TARGET_PORTS)),
            '--open',
            '-iL', target_file,
            '-oG', gnmap_out,
            '-oX', xml_out
        ]
        
        # Configuración específica por tipo de escaneo
        scan_configs = {
            "optimized": [
                '-T3', '--max-retries', '3', '--max-rtt-timeout', '3000ms',
                '--initial-rtt-timeout', '800ms', '--min-rate', '50',
                '--max-rate', '200', '--scan-delay', '10ms'
            ],
            "verified_fast": [  # Primera pasada del método verified
                '-T3', '--max-retries', '2', '--max-rtt-timeout', '2000ms',
                '--min-rate', '30', '--max-rate', '150'
            ],
            "verified_slow": [  # Segunda pasada del método verified
                '-T2', '--max-retries', '4', '--max-rtt-timeout', '4000ms',
                '--max-rate', '80', '--scan-delay', '20ms'
            ],
            "conservative": [
                '-T2', '--max-retries', '5', '--max-rtt-timeout', '5000ms',
                '--max-rate', '100', '--scan-delay', '50ms'
            ]
        }
        
        config = scan_configs.get(scan_type, scan_configs["conservative"])
        base_cmd.extend(config)
        
        return base_cmd
    
    def scan_networks_granular(self, networks: List[str]) -> Tuple[str, str]:
        """
        Escanear redes con paralelización granular por trabajo individual.
        
        Args:
            networks: Lista de redes a escanear
            
        Returns:
            Tupla con archivos gnmap y XML combinados
        """
        if self.parallel_jobs == 1 or len(networks) <= 1:
            return self.scan_networks(networks)
        
        # Deduplicar redes antes del escaneo
        networks = NetworkValidator.deduplicate_networks(networks)
        
        self.logger.info(f"Iniciando escaneo paralelo granular con {self.parallel_jobs} workers")
        
        gnmap_files = []
        xml_files = []
        failed_networks = []
        failed_networks_lock = threading.Lock()  # Proteger lista compartida entre hilos
        
        def scan_single_network(network: str) -> Optional[Tuple[str, str]]:
            """Escanear una red individual con control de semáforo."""
            with self.semaphore:
                try:
                    self.logger.debug(f"Escaneando red: {network}")
                    return self.scan_networks([network])
                except Exception as e:
                    self.logger.warn(f"Error escaneando {network}: {e}")
                    # Thread-safe modification of shared list
                    with failed_networks_lock:
                        failed_networks.append(network)
                    return None
        
        # Ejecutar escaneos en paralelo
        with ThreadPoolExecutor(max_workers=self.parallel_jobs) as executor:
            future_to_network = {
                executor.submit(scan_single_network, network): network 
                for network in networks
            }
            
            for future in as_completed(future_to_network):
                network = future_to_network[future]
                try:
                    result = future.result()
                    if result:
                        gnmap_file, xml_file = result
                        gnmap_files.append(gnmap_file)
                        xml_files.append(xml_file)
                except Exception as e:
                    self.logger.warn(f"Error procesando resultado de {network}: {e}")
                    with failed_networks_lock:
                        failed_networks.append(network)
        
        if failed_networks:
            self.logger.warn(f"Falló el escaneo de {len(failed_networks)} redes")
        
        if not gnmap_files:
            raise ScanExecutionError("No se completó ningún escaneo exitosamente")
        
        # Combinar resultados
        return self._merge_scan_results(gnmap_files, xml_files)
    
    def scan_networks(self, networks: List[str]) -> Tuple[str, str]:
        """Escanear lista de redes con método detectado automáticamente."""
        scan_method = self.detect_scan_method()
        self.logger.info(f"Método de escaneo seleccionado: {scan_method}")
        
        if scan_method == "verified":
            return self._scan_with_verification(networks)
        else:
            return self.execute_nmap_scan(networks, scan_method)
    
    def _scan_with_verification(self, networks: List[str]) -> Tuple[str, str]:
        """
        Escaneo con doble verificación.
        
        Estrategia mejorada:
        1. Primera pasada rápida para discovery
        2. Segunda pasada más lenta solo en hosts encontrados para verificación
        """
        self.logger.info("Ejecutando escaneo con verificación doble")
        
        # Primera pasada: discovery rápido
        self.logger.debug("Primera pasada: discovery rápido")
        gnmap_first, xml_first = self.execute_nmap_scan(networks, "verified_fast")
        
        # Extraer hosts encontrados
        active_hosts = self._extract_active_hosts(gnmap_first)
        
        if not active_hosts:
            self.logger.info("No se encontraron hosts en primera pasada")
            return gnmap_first, xml_first
        
        self.logger.info(f"Primera pasada: {len(active_hosts)} hosts encontrados")
        
        # Segunda pasada: verificación lenta solo en hosts activos
        self.logger.debug("Segunda pasada: verificación detallada de hosts activos")
        try:
            gnmap_second, xml_second = self.execute_nmap_scan(active_hosts, "verified_slow")
            
            # Limpiar archivos de primera pasada
            try:
                os.unlink(gnmap_first)
                os.unlink(xml_first)
            except:
                pass
            
            return gnmap_second, xml_second
            
        except Exception as e:
            self.logger.warn(f"Fallo en segunda pasada: {e}. Usando resultados de primera pasada")
            return gnmap_first, xml_first
    
    def _extract_active_hosts(self, gnmap_file: str) -> List[str]:
        """Extraer hosts activos de archivo gnmap."""
        active_hosts = set()
        
        try:
            with open(gnmap_file, 'r') as f:
                for line in f:
                    if 'open' in line and line.startswith('Host:'):
                        match = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            active_hosts.add(match.group(1))
        except Exception as e:
            self.logger.error(f"Error extrayendo hosts activos: {e}")
        
        return list(active_hosts)
    
    def _merge_scan_results(self, gnmap_files: List[str], xml_files: List[str]) -> Tuple[str, str]:
        """Combinar resultados de múltiples escaneos."""
        # Crear archivos finales
        final_gnmap = tempfile.NamedTemporaryFile(suffix='.gnmap', delete=False)
        final_xml = tempfile.NamedTemporaryFile(suffix='.xml', delete=False)
        final_gnmap.close()
        final_xml.close()
        
        self.register_temp_file(final_gnmap.name)
        self.register_temp_file(final_xml.name)
        
        try:
            # Combinar archivos gnmap
            with open(final_gnmap.name, 'w') as outfile:
                for gnmap_file in gnmap_files:
                    try:
                        with open(gnmap_file, 'r') as infile:
                            outfile.write(infile.read())
                    except Exception as e:
                        self.logger.warn(f"Error combinando {gnmap_file}: {e}")
            
            # Combinar archivos XML usando parser robusto
            if not self.xml_merger.merge_xml_files(xml_files, final_xml.name):
                self.logger.warn("Falló merge XML, creando XML vacío")
                self._create_empty_xml(final_xml.name)
            
            return final_gnmap.name, final_xml.name
            
        except Exception as e:
            # Registrar traceback completo en modo verbose para debugging crítico
            if hasattr(self.logger, 'verbose') and self.logger.verbose:
                import traceback
                self.logger.debug(f"Merge scan results error traceback: {traceback.format_exc()}")
            self.logger.error(f"Error combinando resultados: {e}")
            raise ScanExecutionError(f"Error combinando resultados: {e}")
    
    def _create_empty_xml(self, xml_file: str):
        """Crear archivo XML vacío válido."""
        root = ET.Element("nmaprun")
        tree = ET.ElementTree(root)
        tree.write(xml_file, encoding="utf-8", xml_declaration=True)

class ResultProcessor:
    """Procesador de resultados de escaneo."""
    
    def __init__(self, logger: Logger):
        self.logger = logger
    
    def process_gnmap_file(self, gnmap_file: str) -> Tuple[List[ScanResult], List[ServiceInfo]]:
        """Procesar archivo gnmap y extraer resultados."""
        scan_results = []
        service_info = []
        
        try:
            with open(gnmap_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    if line.startswith('Host:') and 'Ports:' in line:
                        try:
                            result, services = self._parse_gnmap_line(line)
                            if result:
                                scan_results.append(result)
                                service_info.extend(services)
                        except Exception as e:
                            self.logger.debug(f"Error parseando línea {line_num}: {e}")
                            continue
        
        except Exception as e:
            self.logger.error(f"Error procesando archivo gnmap: {e}")
            raise
        
        # Deduplicar resultados antes de retornar
        unique_results = list(set(scan_results))
        unique_services = list(set(service_info))
        
        self.logger.debug(f"Procesados {len(unique_results)} resultados únicos y {len(unique_services)} servicios únicos")
        
        return unique_results, unique_services
    
    def _parse_gnmap_line(self, line: str) -> Tuple[Optional[ScanResult], List[ServiceInfo]]:
        """Parsear línea individual de gnmap."""
        # Extraer IP
        ip_match = re.search(r'Host: (\d+\.\d+\.\d+\.\d+)', line)
        if not ip_match:
            return None, []
        
        ip = ip_match.group(1)
        
        # Calcular segmento /24
        try:
            ip_obj = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            segment = str(network)
        except Exception:
            # Fallback manual si falla ipaddress
            ip_parts = ip.split('.')
            segment = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        
        # Extraer puertos
        ports_match = re.search(r'Ports: (.+?)(?:\s+Ignored|$)', line)
        if not ports_match:
            return None, []
        
        ports_info = ports_match.group(1)
        open_ports = []
        services = []
        
        # Parsear cada puerto
        for port_entry in ports_info.split(','):
            port_entry = port_entry.strip()
            if '/open/' in port_entry:
                port_match = re.search(r'(\d+)/open/', port_entry)
                if port_match:
                    port = int(port_match.group(1))
                    open_ports.append(port)
                    
                    # Crear info de servicio
                    port_info = PORT_CONFIG.get(port, {"service": "Unknown", "category": "OTROS"})
                    service = ServiceInfo(
                        ip=ip,
                        port=port,
                        service=port_info["service"],
                        category=port_info["category"],
                        segment=segment
                    )
                    services.append(service)
        
        if open_ports:
            scan_result = ScanResult(ip=ip, ports=open_ports, segment=segment)
            return scan_result, services
        
        return None, []

class DataExporter:
    """Exportador de datos a múltiples formatos usando modelo canónico."""
    
    def __init__(self, logger: Logger, timestamp: str):
        self.logger = logger
        self.timestamp = timestamp
    
    def export_csv(self, canonical_data: CanonicalScanData) -> str:
        """Exportar a formato CSV."""
        filename = f"audit_results_{self.timestamp}.csv"
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                # BOM para Excel
                csvfile.write('\ufeff')
                
                fieldnames = ['Segmento', 'IP', 'Puerto', 'Servicio', 'Categoria', 'Timestamp']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
                
                writer.writeheader()
                for service in canonical_data.all_services:
                    writer.writerow({
                        'Segmento': service.segment,
                        'IP': service.ip,
                        'Puerto': service.port,
                        'Servicio': service.service,
                        'Categoria': service.category,
                        'Timestamp': canonical_data.stats.start_time.isoformat()
                    })
            
            self.logger.info(f"CSV exportado: {filename}")
            return filename
            
        except Exception as e:
            raise ExportError(f"Error exportando CSV: {e}")
    
    def export_json(self, canonical_data: CanonicalScanData) -> str:
        """Exportar a formato JSON usando modelo canónico."""
        filename = f"audit_results_{self.timestamp}.json"
        
        try:
            # Estructura JSON usando modelo canónico
            export_data = {
                "audit_info": {
                    "timestamp": canonical_data.stats.start_time.isoformat(),
                    "end_time": canonical_data.stats.end_time.isoformat() if canonical_data.stats.end_time else None,
                    "scan_duration_seconds": canonical_data.stats.scan_duration,
                    "total_duration_seconds": (canonical_data.stats.end_time - canonical_data.stats.start_time).total_seconds() if canonical_data.stats.end_time else None,
                    "total_segments_scanned": canonical_data.stats.total_segments,
                    "active_segments": canonical_data.stats.active_segments,
                    "active_hosts": canonical_data.stats.active_hosts,
                    "activity_rate": canonical_data.stats.activity_rate
                },
                "segments": []
            }
            
            # Usar datos del modelo canónico
            for segment, scan_results in canonical_data.segments.items():
                segment_data = {
                    "network": segment,
                    "hosts": []
                }
                
                for result in scan_results:
                    host_services = canonical_data.services_by_ip.get(result.ip, [])
                    host_data = {
                        "ip": result.ip,
                        "open_ports": [
                            {
                                "port": service.port,
                                "service": service.service,
                                "category": service.category
                            }
                            for service in host_services
                        ]
                    }
                    segment_data["hosts"].append(host_data)
                
                export_data["segments"].append(segment_data)
            
            # Agregar estadísticas por categoría
            export_data["service_categories"] = {
                category: len(services)
                for category, services in canonical_data.services_by_category.items()
            }
            
            with open(filename, 'w', encoding='utf-8') as jsonfile:
                json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)
            
            self.logger.info(f"JSON exportado: {filename}")
            return filename
            
        except Exception as e:
            raise ExportError(f"Error exportando JSON: {e}")
    
    def export_markdown(self, canonical_data: CanonicalScanData) -> str:
        """Exportar a formato Markdown usando modelo canónico."""
        filename = f"audit_report_{self.timestamp}.md"
        
        try:
            with open(filename, 'w', encoding='utf-8') as mdfile:
                # Header
                mdfile.write("# Reporte de Auditoría de Segmentación de Red\n\n")
                mdfile.write(f"**Fecha:** {canonical_data.stats.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                mdfile.write(f"**Duración escaneo:** {canonical_data.stats.duration_formatted}\n")
                if canonical_data.stats.end_time:
                    mdfile.write(f"**Duración total:** {canonical_data.stats.total_duration_formatted}\n")
                mdfile.write("**Herramienta:** Segmentador v5.0 - Python Production Edition\n\n")
                
                # Resumen ejecutivo
                mdfile.write("## Resumen Ejecutivo\n\n")
                mdfile.write(f"- **Segmentos escaneados:** {canonical_data.stats.total_segments}\n")
                mdfile.write(f"- **Segmentos con actividad:** {canonical_data.stats.active_segments}\n")
                mdfile.write(f"- **Hosts activos encontrados:** {canonical_data.stats.active_hosts}\n")
                mdfile.write(f"- **Tasa de actividad:** {canonical_data.stats.activity_rate:.1f}%\n\n")
                
                # Detalles por segmento usando modelo canónico
                mdfile.write("## Detalles por Segmento\n\n")
                
                for segment in sorted(canonical_data.segments.keys()):
                    scan_results = canonical_data.segments[segment]
                    mdfile.write(f"### {segment}\n\n")
                    mdfile.write("| IP | Puertos Abiertos | Servicios |\n")
                    mdfile.write("|---|---|---|\n")
                    
                    for result in scan_results:
                        ports_str = ','.join(map(str, result.ports))
                        services = canonical_data.services_by_ip.get(result.ip, [])
                        services_str = ', '.join([
                            f"{s.port}({s.service})" for s in services
                        ])
                        mdfile.write(f"| {result.ip} | {ports_str} | {services_str} |\n")
                    
                    mdfile.write("\n")
                
                # Análisis por categoría usando modelo canónico
                mdfile.write("## Análisis por Categoría de Servicios\n\n")
                
                for category in sorted(canonical_data.services_by_category.keys()):
                    services = canonical_data.services_by_category[category]
                    mdfile.write(f"### {category} ({len(services)} servicios)\n\n")
                    mdfile.write("| IP | Puerto | Servicio | Segmento |\n")
                    mdfile.write("|---|---|---|---|\n")
                    
                    for service in services:
                        mdfile.write(f"| {service.ip} | {service.port} | {service.service} | {service.segment} |\n")
                    
                    mdfile.write("\n")
            
            self.logger.info(f"Markdown exportado: {filename}")
            return filename
            
        except Exception as e:
            raise ExportError(f"Error exportando Markdown: {e}")
    
    def export_html_dashboard(self, canonical_data: CanonicalScanData) -> str:
        """Exportar dashboard HTML con escape seguro de datos."""
        filename = f"audit_dashboard_{self.timestamp}.html"
        
        try:
            # Preparar datos de forma segura usando JSON
            segments_data = self._prepare_segments_data_safe(canonical_data)
            services_data = self._prepare_services_data_safe(canonical_data)
            
            # Template HTML con datos JSON escapados de forma segura
            html_content = self._generate_html_template_safe(
                canonical_data.stats, segments_data, services_data
            )
            
            with open(filename, 'w', encoding='utf-8') as htmlfile:
                htmlfile.write(html_content)
            
            self.logger.info(f"Dashboard HTML exportado: {filename}")
            return filename
            
        except Exception as e:
            raise ExportError(f"Error exportando dashboard HTML: {e}")
    
    def _prepare_segments_data_safe(self, canonical_data: CanonicalScanData) -> str:
        """Preparar datos de segmentos de forma segura para JavaScript."""
        segments_list = []
        
        for segment, scan_results in canonical_data.segments.items():
            total_ports = sum(len(result.ports) for result in scan_results)
            segments_list.append({
                "network": segment,
                "hosts": len(scan_results),
                "ports": total_ports
            })
        
        # Usar json.dumps para escape seguro
        return json.dumps(segments_list, ensure_ascii=False)
    
    def _prepare_services_data_safe(self, canonical_data: CanonicalScanData) -> str:
        """Preparar datos de servicios de forma segura para JavaScript."""
        services_list = [
            {"category": category, "count": len(services)}
            for category, services in canonical_data.services_by_category.items()
        ]
        
        # Usar json.dumps para escape seguro
        return json.dumps(services_list, ensure_ascii=False)
    
    def _generate_html_template_safe(self, audit_stats: AuditStats, 
                                   segments_data: str, services_data: str) -> str:
        """Generar template HTML con escape seguro de todas las variables."""
        
        # Escapar todas las variables para HTML de forma segura
        start_time_safe = audit_stats.start_time.strftime('%Y-%m-%d %H:%M:%S')
        total_segments_safe = audit_stats.total_segments
        active_segments_safe = audit_stats.active_segments
        active_hosts_safe = audit_stats.active_hosts
        activity_rate_safe = f"{audit_stats.activity_rate:.1f}"
        
        # Calcular longitud de segments_data de forma segura antes del f-string
        try:
            segments_count = len(json.loads(segments_data))
        except (json.JSONDecodeError, TypeError) as e:
            segments_count = 0  # Fallback seguro si falla el parsing
        
        return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard de Auditoría de Segmentación</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }}
        .header {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 1.5rem 2rem;
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
            border-bottom: 3px solid #667eea;
        }}
        .header h1 {{
            color: #2c3e50;
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-card h3 {{
            color: #2c3e50;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 0.5rem;
        }}
        .stat-card .number {{
            font-size: 2.5rem;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 0.5rem;
        }}
        .charts-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }}
        .chart-container {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            height: 350px;
        }}
        .chart-container h3 {{
            color: #2c3e50;
            margin-bottom: 1rem;
            font-size: 1.3rem;
        }}
        .footer {{
            text-align: center;
            padding: 2rem;
            color: rgba(255, 255, 255, 0.8);
            font-size: 0.9rem;
        }}
        @media (max-width: 768px) {{
            .charts-grid {{ grid-template-columns: 1fr; }}
            .container {{ padding: 1rem; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Dashboard de Auditoría de Segmentación</h1>
        <div class="subtitle">Análisis de Infraestructura - {start_time_safe}</div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Segmentos Escaneados</h3>
                <div class="number">{total_segments_safe}</div>
                <div class="label">Redes analizadas</div>
            </div>
            <div class="stat-card">
                <h3>Segmentos Activos</h3>
                <div class="number">{active_segments_safe}</div>
                <div class="label">Con hosts detectados</div>
            </div>
            <div class="stat-card">
                <h3>Hosts Activos</h3>
                <div class="number">{active_hosts_safe}</div>
                <div class="label">Dispositivos encontrados</div>
            </div>
            <div class="stat-card">
                <h3>Tasa de Actividad</h3>
                <div class="number">{activity_rate_safe}%</div>
                <div class="label">Eficiencia de red</div>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-container">
                <h3>📊 Distribución de Servicios</h3>
                <canvas id="servicesChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>🌐 Segmentos Más Activos</h3>
                <canvas id="segmentsChart"></canvas>
            </div>
        </div>
    </div>
    
    <div class="footer">
        <p>Generado por Segmentador v5.0 - Python Production Edition</p>
        <p>Datos JSON escapados de forma segura • {segments_count} segmentos analizados</p>
    </div>

    <script>
        // Datos seguros parseados desde JSON escapado
        const segmentsData = {segments_data};
        const servicesData = {services_data};
        
        const colors = {{
            primary: '#667eea',
            secondary: '#764ba2',
            success: '#2ecc71',
            warning: '#f39c12',
            danger: '#e74c3c',
            info: '#3498db'
        }};
        
        // Gráfico de servicios
        function createServicesChart() {{
            const ctx = document.getElementById('servicesChart').getContext('2d');
            new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: servicesData.map(s => s.category.replace('_', ' ')),
                    datasets: [{{
                        data: servicesData.map(s => s.count),
                        backgroundColor: [
                            colors.danger, colors.warning, colors.info,
                            colors.secondary, colors.success, colors.primary, '#95a5a6'
                        ],
                        borderWidth: 3,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{ padding: 20, usePointStyle: true }}
                        }}
                    }}
                }}
            }});
        }}
        
        // Gráfico de segmentos
        function createSegmentsChart() {{
            const ctx = document.getElementById('segmentsChart').getContext('2d');
            const topSegments = segmentsData
                .sort((a, b) => b.hosts - a.hosts)
                .slice(0, 10);
            
            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: topSegments.map(s => s.network),
                    datasets: [{{
                        label: 'Hosts Activos',
                        data: topSegments.map(s => s.hosts),
                        backgroundColor: colors.primary,
                        borderColor: colors.secondary,
                        borderWidth: 2,
                        borderRadius: 5
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ display: false }} }},
                    scales: {{
                        y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }},
                        x: {{ ticks: {{ maxRotation: 45 }} }}
                    }}
                }}
            }});
        }}
        
        document.addEventListener('DOMContentLoaded', function() {{
            createServicesChart();
            createSegmentsChart();
        }});
    </script>
</body>
</html>"""

class NetworkSegmentGenerator:
    """Generador y validador de segmentos de red."""
    
    def __init__(self, logger: Logger):
        self.logger = logger
    
    def load_from_file(self, filepath: str) -> List[str]:
        """Cargar y normalizar segmentos desde archivo."""
        try:
            raw_networks = []
            with open(filepath, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Ignorar líneas vacías y comentarios
                    if not line or line.startswith('#'):
                        continue
                    
                    # Validar y normalizar formato
                    if NetworkValidator.validate_cidr(line):
                        normalized = NetworkValidator.normalize_network(line)
                        raw_networks.append(normalized)
                    elif NetworkValidator.validate_ip_range(line):
                        # Para rangos, podemos mantener el formato o expandir
                        # Por ahora mantenemos el formato (Nmap lo soporta)
                        normalized = NetworkValidator.normalize_network(line)
                        raw_networks.append(normalized)
                    else:
                        self.logger.warn(f"Formato inválido en línea {line_num}: {line}")
            
            if not raw_networks:
                raise NetworkValidationError("No se encontraron redes válidas en el archivo")
            
            # Deduplicar y ordenar
            networks = NetworkValidator.deduplicate_networks(raw_networks)
            
            self.logger.info(f"Cargadas {len(networks)} redes únicas desde {filepath}")
            return networks
            
        except FileNotFoundError:
            raise NetworkValidationError(f"Archivo no encontrado: {filepath}")
        except Exception as e:
            raise NetworkValidationError(f"Error leyendo archivo: {e}")
    
    def generate_rfc1918_networks(self) -> List[str]:
        """Generar segmentos RFC 1918 predeterminados."""
        networks = []
        
        # 192.168.0.0/16 → 256 segmentos /24
        for i in range(256):
            networks.append(f"192.168.{i}.0/24")
        
        # 10.0.0.0/16 → 256 segmentos /24  
        for i in range(256):
            networks.append(f"10.0.{i}.0/24")
        
        # 172.16.0.0/12 → Segmentos comunes (limitado para evitar explosión)
        for j in range(16, 32):
            for i in range(16):  # Limitado a primeros 16 para pruebas
                networks.append(f"172.{j}.{i}.0/24")
        
        self.logger.info(f"Generados {len(networks)} segmentos RFC 1918")
        return networks

class Segmentador:
    """Clase principal de la aplicación."""
    
    def __init__(self, args):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Configurar logging
        log_file = f"audit_log_{timestamp}.log" if args.verbose else None
        self.logger = Logger(args.verbose, args.quiet, log_file)
        
        # Inicializar componentes
        self.dependency_checker = DependencyChecker(self.logger)
        self.scanner = NetworkScanner(self.logger, args.jobs)
        self.processor = ResultProcessor(self.logger)
        self.exporter = DataExporter(self.logger, timestamp)
        self.segment_generator = NetworkSegmentGenerator(self.logger)
        
        # Configuración
        self.args = args
        self.timestamp = timestamp
        self.audit_stats = AuditStats(start_time=datetime.now())
        
        # Archivos temporales adicionales
        self.temp_files = []
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
    
    def cleanup(self):
        """Limpiar recursos y archivos temporales."""
        # Limpiar archivos del scanner
        self.scanner.cleanup_temp_files()
        
        # Limpiar archivos adicionales
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                    self.logger.debug(f"Archivo temporal eliminado: {temp_file}")
            except Exception as e:
                self.logger.debug(f"Error eliminando {temp_file}: {e}")
        
        # Mostrar resumen de errores
        errors = self.logger.get_error_summary()
        if errors:
            self.logger.info(f"⚠️  Se encontraron {len(errors)} errores durante la ejecución:")
            for error in errors:
                print(f"  • {error}")
    
    def run(self) -> int:
        """Ejecutar auditoría completa."""
        try:
            # Verificar dependencias
            if not self.dependency_checker.check_all():
                return 1
            
            # Generar/cargar segmentos
            networks = self._load_networks()
            self.audit_stats.total_segments = len(networks)
            
            # Ejecutar escaneo
            scan_results, service_info = self._execute_scan(networks)
            
            # Crear modelo canónico
            canonical_data = self._create_canonical_model(scan_results, service_info)
            
            # Mostrar resultados
            if not self.args.quiet:
                self._display_results(canonical_data)
            
            # Exportar datos
            self._export_results(canonical_data)
            
            # Resumen final
            self._show_final_summary()
            
            return 0
            
        except KeyboardInterrupt:
            self.logger.error("Operación interrumpida por el usuario")
            return 130
        except Exception as e:
            self.logger.error(f"Error inesperado: {e}")
            if self.args.verbose:
                import traceback
                self.logger.debug(traceback.format_exc())
            return 1
    
    def _load_networks(self) -> List[str]:
        """Cargar o generar segmentos de red."""
        if self.args.file:
            return self.segment_generator.load_from_file(self.args.file)
        else:
            return self.segment_generator.generate_rfc1918_networks()
    
    def _execute_scan(self, networks: List[str]) -> Tuple[List[ScanResult], List[ServiceInfo]]:
        """Ejecutar escaneo de red."""
        self.logger.info(f"Iniciando escaneo de {len(networks)} segmentos...")
        self.logger.info(f"Puertos objetivo: {', '.join(map(str, TARGET_PORTS))}")
        
        start_time = time.time()
        
        try:
            # Ejecutar escaneo (con paralelización granular si está configurada)
            if self.args.jobs > 1:
                gnmap_file, xml_file = self.scanner.scan_networks_granular(networks)
            else:
                gnmap_file, xml_file = self.scanner.scan_networks(networks)
            
            self.temp_files.extend([gnmap_file, xml_file])
            
            self.audit_stats.scan_duration = time.time() - start_time
            self.logger.info(f"Escaneo completado en {self.audit_stats.duration_formatted}")
            
            # Procesar resultados
            scan_results, service_info = self.processor.process_gnmap_file(gnmap_file)
            
            return scan_results, service_info
            
        except Exception as e:
            # Registrar traceback completo en modo verbose para debugging crítico
            if self.args.verbose:
                import traceback
                self.logger.debug(f"Execute scan error traceback: {traceback.format_exc()}")
            raise
    
    def _create_canonical_model(self, scan_results: List[ScanResult], 
                               service_info: List[ServiceInfo]) -> CanonicalScanData:
        """Crear modelo canónico y calcular estadísticas finales."""
        self.audit_stats.end_time = datetime.now()
        self.audit_stats.active_hosts = len(set(result.ip for result in scan_results))
        self.audit_stats.active_segments = len(set(result.segment for result in scan_results))
        
        return CanonicalScanData.from_results(scan_results, service_info, self.audit_stats)
    
    def _display_results(self, canonical_data: CanonicalScanData):
        """Mostrar resultados en consola usando modelo canónico."""
        if not canonical_data.all_services:
            self.logger.warn("No se encontraron hosts con puertos abiertos")
            return
        
        print("\n" + "="*60)
        print("RESULTADOS DE AUDITORÍA DE SEGMENTACIÓN")
        print("="*60)
        
        if self.args.simple:
            # Output simple
            print(f"\n[SEGMENTOS ACTIVOS] ({len(canonical_data.segments)} encontrados):")
            for segment in sorted(canonical_data.segments.keys()):
                host_count = len(canonical_data.segments[segment])
                print(f"  {segment} ({host_count} hosts activos)")
        else:
            # Output detallado usando modelo canónico
            for segment in sorted(canonical_data.segments.keys()):
                scan_results = canonical_data.segments[segment]
                print(f"\n[SEGMENTO] {segment}")
                for result in scan_results:
                    services = canonical_data.services_by_ip.get(result.ip, [])
                    services_str = ", ".join([f"{s.port}({s.service})" for s in services])
                    print(f"  ├── {result.ip}   [{services_str}]")
        
        print("\n" + "="*60)
        print("ANÁLISIS POR CATEGORÍA DE SERVICIOS")
        print("="*60)
        
        # Mostrar por categorías usando modelo canónico
        for category in sorted(canonical_data.services_by_category.keys()):
            services = canonical_data.services_by_category[category]
            print(f"\n[{category}] ({len(services)} servicios encontrados)")
            for service in services:
                print(f"  ├── {service.ip}:{service.port} ({service.service}) - {service.segment}")
    
    def _export_results(self, canonical_data: CanonicalScanData):
        """Exportar resultados usando modelo canónico."""
        exported_files = []
        
        try:
            if self.args.export in ['csv', 'all']:
                filename = self.exporter.export_csv(canonical_data)
                exported_files.append(filename)
            
            if self.args.export in ['json', 'all']:
                filename = self.exporter.export_json(canonical_data)
                exported_files.append(filename)
            
            if self.args.export in ['markdown', 'all']:
                filename = self.exporter.export_markdown(canonical_data)
                exported_files.append(filename)
            
            if self.args.dashboard:
                filename = self.exporter.export_html_dashboard(canonical_data)
                exported_files.append(filename)
                
                # Intentar abrir en navegador
                if not self.args.quiet and not self.args.no_interactive:
                    self._try_open_dashboard(filename)
            
        except ExportError as e:
            self.logger.error(f"Error durante exportación: {e}")
        
        return exported_files
    
    def _try_open_dashboard(self, filename: str):
        """Intentar abrir dashboard en navegador."""
        try:
            if sys.platform.startswith('linux'):
                subprocess.run(['xdg-open', filename], check=False, 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys.platform == 'darwin':
                subprocess.run(['open', filename], check=False,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys.platform == 'win32':
                subprocess.run(['start', filename], shell=True, check=False,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass  # Fallo silencioso si no se puede abrir
    
    def _show_final_summary(self):
        """Mostrar resumen final usando formateo consistente."""
        if self.args.quiet:
            return
        
        print("\n" + "="*60)
        print("✅ AUDITORÍA COMPLETADA EXITOSAMENTE")
        print("="*60)
        print(f"⏱️  Tiempo de escaneo: {self.audit_stats.duration_formatted}")
        print(f"⏱️  Tiempo total: {self.audit_stats.total_duration_formatted}")
        print(f"📊 Estadísticas finales:")
        print(f"   • Segmentos escaneados: {self.audit_stats.total_segments}")
        print(f"   • Hosts activos: {self.audit_stats.active_hosts}")
        print(f"   • Segmentos con actividad: {self.audit_stats.active_segments}")
        print(f"   • Tasa de actividad: {self.audit_stats.activity_rate:.1f}%")
        print("="*60)

def create_argument_parser() -> argparse.ArgumentParser:
    """Crear parser de argumentos con flags de dashboard corregidos."""
    parser = argparse.ArgumentParser(
        description="Segmentador - Herramienta profesional de auditoría de segmentación de red",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s                              # Rangos predeterminados, export completo
  %(prog)s -f rangos.txt                # Usar rangos desde archivo
  %(prog)s -e csv --quiet               # Solo CSV, modo silencioso
  %(prog)s -f custom.txt -v -j 4        # Archivo personalizado, verboso, 4 jobs
  %(prog)s --no-dashboard --no-interactive  # Sin dashboard, sin prompts

Formatos de archivo de rangos:
  192.168.1.0/24
  10.0.0.0/16
  172.16.0.0/12
  192.168.0.1-192.168.0.254
        """
    )
    
    parser.add_argument(
        '-f', '--file',
        help='Archivo con rangos de red personalizados'
    )
    
    parser.add_argument(
        '-e', '--export',
        choices=['csv', 'json', 'markdown', 'all'],
        default='all',
        help='Formato de exportación (default: all)'
    )
    
    parser.add_argument(
        '-s', '--simple',
        action='store_true',
        help='Output simple (sin detalles por IP)'
    )
    
    # Flags de dashboard corregidos
    dashboard_group = parser.add_mutually_exclusive_group()
    dashboard_group.add_argument(
        '--dashboard',
        dest='dashboard',
        action='store_true',
        help='Habilitar dashboard HTML'
    )
    dashboard_group.add_argument(
        '--no-dashboard',
        dest='dashboard',
        action='store_false',
        help='Deshabilitar dashboard HTML'
    )
    parser.set_defaults(dashboard=True)
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Modo verboso (más información de debug)'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Modo silencioso (solo errores críticos)'
    )
    
    parser.add_argument(
        '--no-interactive',
        action='store_true',
        help='Modo no interactivo (sin prompts ni auto-open)'
    )
    
    parser.add_argument(
        '-j', '--jobs',
        type=int,
        default=1,
        help=f'Número de jobs paralelos (default: 1, max: {MAX_CONCURRENT_SCANS})'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Segmentador 5.0 - Python Production Edition'
    )
    
    return parser

def main():
    """Función principal."""
    # Verificar versión de Python antes que nada
    if sys.version_info < REQUIRED_PYTHON_VERSION:
        print(f"Error: Python {REQUIRED_PYTHON_VERSION[0]}.{REQUIRED_PYTHON_VERSION[1]}+ requerido")
        sys.exit(1)
    
    # Parsear argumentos
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Validar argumentos mutuamente excluyentes
    if args.verbose and args.quiet:
        parser.error("--verbose y --quiet son mutuamente excluyentes")
    
    if args.jobs < 1 or args.jobs > MAX_CONCURRENT_SCANS:
        parser.error(f"--jobs debe estar entre 1 y {MAX_CONCURRENT_SCANS}")
    
    # Ejecutar aplicación
    try:
        with Segmentador(args) as app:
            return app.run()
    except KeyboardInterrupt:
        print("\nOperación interrumpida por el usuario")
        return 130
    except Exception as e:
        print(f"Error fatal: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
