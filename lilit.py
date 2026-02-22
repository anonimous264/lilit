#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    LILIT v1.0 - PROFESSIONAL EDITION                         ║
║                    Live Intelligent Link Inspection Tool                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  AUTOR: Abdias Samuel R. CH.                                                 ║
║  VERSIÓN: 1.0.0 FIXED                                                        ║
║  LICENCIA: Educational / Authorized Use Only                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# ==============================================================================
# IMPORTACIONES ESTÁNDAR
# ==============================================================================
import argparse
import asyncio
import csv
import ipaddress
import json
import logging
import platform
import random
import re
import socket
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ==============================================================================
# IMPORTACIONES DE TERCEROS
# ==============================================================================
from rich.align import Align
from rich.box import DOUBLE, HEAVY, ROUNDED
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

# ==============================================================================
# CONFIGURACIÓN GLOBAL
# ==============================================================================
console = Console(
    width=120,
    legacy_windows=False,
    force_terminal=True,
    color_system="truecolor",
)

# ==============================================================================
# TEMAS VISUALES PROFESIONALES
# ==============================================================================
class VisualTheme:
    """Gestor de temas visuales para la interfaz de LILIT."""

    CYBERPUNK = {
        "primary": "#00ff9d",
        "secondary": "#bd00ff",
        "accent": "#00d9ff",
        "alert": "#ff0055",
        "warning": "#ffaa00",
        "success": "#00ff9d",
        "info": "#00d9ff",
        "danger": "#ff0055",
        "muted": "#666666",
        "bg": "#0a0a0a",
    }

    MATRIX = {
        "primary": "#00ff00",
        "secondary": "#008800",
        "accent": "#00ff88",
        "alert": "#ff0000",
        "warning": "#ffff00",
        "success": "#00ff00",
        "info": "#00ffff",
        "danger": "#ff0000",
        "muted": "#004400",
        "bg": "#000000",
    }

    CORPORATE = {
        "primary": "#0066cc",
        "secondary": "#003366",
        "accent": "#0099ff",
        "alert": "#cc0000",
        "warning": "#ff9900",
        "success": "#00cc66",
        "info": "#0066cc",
        "danger": "#cc0000",
        "muted": "#666666",
        "bg": "#ffffff",
    }

    THEME = CYBERPUNK

    @classmethod
    def set_theme(cls, theme_name: str) -> None:
        """Establece el tema visual activo."""
        theme_map = {
            "cyberpunk": cls.CYBERPUNK,
            "matrix": cls.MATRIX,
            "corporate": cls.CORPORATE,
        }
        if theme_name not in theme_map:
            raise ValueError(f"Tema '{theme_name}' no válido")
        cls.THEME = theme_map[theme_name]

    @classmethod
    def get_color(cls, color_name: str) -> str:
        """Obtiene el código de color por nombre."""
        return cls.THEME.get(color_name, cls.THEME["muted"])


# ==============================================================================
# CONFIGURACIÓN CENTRALIZADA
# ==============================================================================
class Config:
    """Configuración centralizada de LILIT."""

    VERSION = "1.0.0"
    CODENAME = "NEURAL STORM PRO"
    AUTHOR = "Abdias Samuel R. Ch."
    BUILD_DATE = "2026"

    MAX_PORTS_PER_SCAN = 10000
    MAX_CONCURRENT_CONNECTIONS = 500
    MIN_TIMEOUT = 0.1
    MAX_TIMEOUT = 30.0
    DEFAULT_TIMEOUT = 1.0
    DEFAULT_CONCURRENCY = 300

    COMMON_PORTS = {
        "quick": [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 8080],
        "web": [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000, 9090],
        "database": [3306, 5432, 1433, 27017, 6379, 9042, 11211, 1521],
        "remote": [22, 23, 3389, 5900, 5901, 5985, 5986, 2222],
        "mail": [25, 110, 143, 465, 587, 993, 995, 2525],
        "file": [21, 139, 445, 2049, 135, 137, 138, 139],
        "dns": [53, 853, 5353],
        "industrial": [502, 1911, 1962, 2455, 44818, 50000],
        "iot": [1883, 8883, 18830, 5683, 5684],
        "full": list(range(1, 1025)),
        "top100": [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
        ],
    }

    CRITICAL_PORTS = {
        21: ("FTP", "Transferencia de archivos sin cifrar"),
        22: ("SSH", "Acceso remoto seguro"),
        23: ("Telnet", "Acceso remoto SIN cifrar - CRÍTICO"),
        25: ("SMTP", "Servidor de correo"),
        53: ("DNS", "Servidor de nombres"),
        80: ("HTTP", "Web sin cifrar"),
        443: ("HTTPS", "Web segura"),
        445: ("SMB", "Windows File Sharing - EternalBlue"),
        3306: ("MySQL", "MySQL Database"),
        3389: ("RDP", "Escritorio Remoto - Fuerza bruta"),
        6379: ("Redis", "Redis - Sin auth por defecto"),
        27017: ("MongoDB", "MongoDB - Sin auth por defecto"),
    }

    VULN_PATTERNS = {
        "old_ssh": (r"SSH-1\.\d|SSH-2\.0-OpenSSH_[1-6]\.", "SSH Obsoleto"),
        "old_iis": (r"IIS/(5\.[0-6]|6\.0|7\.0|7\.5)", "IIS Vulnerable"),
        "old_apache": (r"Apache/(1\.\d|2\.[0-3]\.\d+)", "Apache Obsoleto"),
        "ftp_anon": (r"230.*anonymous|Anonymous.*allowed", "FTP Anónimo"),
        "redis_noauth": (r"redis.*noauth|denied.*auth", "Redis Sin Auth"),
    }

    KNOWN_VULNS = {
        "vsftpd": [
            {"version": "2.3.4", "cve": "CVE-2011-2523", "severity": "CRITICAL"}
        ],
        "Apache": [
            {"version": "2.4.49", "cve": "CVE-2021-41773", "severity": "CRITICAL"},
            {"version": "2.4.50", "cve": "CVE-2021-42013", "severity": "CRITICAL"},
        ],
    }

    @classmethod
    def validate_timeout(cls, timeout: float) -> float:
        """Valida y ajusta el timeout dentro de límites seguros."""
        return max(cls.MIN_TIMEOUT, min(timeout, cls.MAX_TIMEOUT))

    @classmethod
    def validate_concurrency(cls, concurrency: int) -> int:
        """Valida y ajusta la concurrencia dentro de límites seguros."""
        return max(1, min(concurrency, cls.MAX_CONCURRENT_CONNECTIONS))


# ==============================================================================
# SISTEMA DE LOGGING PROFESIONAL
# ==============================================================================
def setup_logging(
    verbose: bool = False,
    log_file: Optional[str] = None,
    log_level: int = logging.INFO,
) -> logging.Logger:
    """Configura el sistema de logging profesional con rotación de archivos."""
    if verbose:
        log_level = logging.DEBUG

    handlers = [
        RichHandler(
            rich_tracebacks=True,
            console=console,
            show_path=verbose,
            log_time_format="[%X]",
            markup=True,
            omit_repeated_times=False,
        )
    ]

    if log_file:
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            handlers.append(file_handler)
        except (OSError, PermissionError) as e:
            console.print(f"[yellow]Advertencia: No se pudo crear archivo de log: {e}[/yellow]")

    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
        force=True,
    )

    logger = logging.getLogger("LILIT")
    logger.setLevel(log_level)
    return logger


log = setup_logging()


# ==============================================================================
# VALIDADOR DE SEGURIDAD
# ==============================================================================
class SecurityValidator:
    """Validador de seguridad para todas las entradas del usuario."""

    DOMAIN_PATTERN = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    """ clases de IP A, B, B """
    PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
    ]

    @classmethod
    def validate_target(cls, target: str, allow_public: bool = False) -> Tuple[bool, str]:
        """Valida el target de escaneo (IP o dominio)."""
        if not target or len(target) > 253:
            return False, "Target vacío o demasiado largo (máx 253 caracteres)"

        try:
            ip = ipaddress.ip_address(target)
            if not allow_public and ip.is_global:
                return False, "Escaneo de IPs públicas restringido. Use solo redes privadas."
            return True, "IP válida"
        except ValueError:
            pass

        if cls.DOMAIN_PATTERN.match(target):
            return True, "Dominio válido"

        return False, "Formato de target inválido (IP o dominio esperado)"

    @classmethod
    def validate_ports(cls, ports_spec: str) -> Tuple[bool, List[int], str]:
        """Valida y parsea la especificación de puertos."""
        ports = []
        try:
            for part in ports_spec.split(","):
                part = part.strip()
                if not part:
                    continue

                if "-" in part:
                    range_parts = part.split("-")
                    if len(range_parts) != 2:
                        return False, [], f"Rango inválido: {part}"

                    start, end = map(int, range_parts)
                    if start < 1 or end > 65535:
                        return False, [], "Puertos fuera de rango (1-65535)"
                    if start > end:
                        return False, [], f"Rango inválido: {start} > {end}"
                    if end - start > Config.MAX_PORTS_PER_SCAN:
                        return False, [], f"Rango muy grande (máx {Config.MAX_PORTS_PER_SCAN})"
                    ports.extend(range(start, end + 1))
                else:
                    port = int(part)
                    if port < 1 or port > 65535:
                        return False, [], f"Puerto fuera de rango: {port}"
                    ports.append(port)

            ports = sorted(list(set(ports)))

            if not ports:
                return False, [], "No se especificaron puertos válidos"

            return True, ports, f"{len(ports)} puertos válidos"

        except ValueError as e:
            return False, [], f"Error en formato de puertos: {e}"
        except Exception as e:
            return False, [], f"Error inesperado: {e}"


# ==============================================================================
# ESTRUCTURAS DE DATOS 
# ==============================================================================
@dataclass
class ScanResult:
    """Resultado enriquecido de un escaneo de puerto."""

    port: int
    protocol: str
    status: str
    service: str
    version: str
    banner: str
    timestamp: float
    risk_score: float = 0.0
    vulnerabilities: List[str] = field(default_factory=list)
    cve_matches: List[str] = field(default_factory=list)
    response_time_ms: float = 0.0

    def get_risk_color(self) -> str:
        """Obtiene el color CSS según el score de riesgo."""
        if self.risk_score > 0.7:
            return VisualTheme.get_color("alert")
        elif self.risk_score > 0.4:
            return VisualTheme.get_color("warning")
        return VisualTheme.get_color("success")

    def get_risk_label(self) -> str:
        """Obtiene la etiqueta de riesgo legible."""
        if self.risk_score > 0.7:
            return "CRÍTICO"
        elif self.risk_score > 0.4:
            return "ALERTA"
        elif self.risk_score > 0.2:
            return "ATENCIÓN"
        return "SEGURO"

    def to_dict(self) -> Dict[str, Any]:
        """Convierte el resultado a diccionario para serialización."""
        return asdict(self)


@dataclass
class ScanSession:
    """Sesión completa de escaneo con toda la información contextual."""

    target: str
    target_ip: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    results: List[ScanResult] = field(default_factory=list)
    ports_total: int = 0
    ports_scanned: int = 0
    profile: str = "custom"
    stealth_mode: bool = False
    protocol: str = "tcp"
    os_detection: Optional[str] = None
    hostname: Optional[str] = None
    errors: List[str] = field(default_factory=list)

    def get_statistics(self) -> Dict[str, Any]:
        """Calcula estadísticas completas de la sesión."""
        open_ports = len([r for r in self.results if r.status == "OPEN"])
        high_risk = len([r for r in self.results if r.risk_score > 0.7])
        medium_risk = len([r for r in self.results if 0.4 < r.risk_score <= 0.7])
        low_risk = len([r for r in self.results if r.risk_score <= 0.4])

        services = defaultdict(int)
        for result in self.results:
            services[result.service] += 1

        duration = (self.end_time or time.time()) - self.start_time
        success_rate = (open_ports / self.ports_scanned * 100) if self.ports_scanned > 0 else 0

        return {
            "duration": duration,
            "total_ports": self.ports_total,
            "scanned": self.ports_scanned,
            "open": open_ports,
            "closed": self.ports_scanned - open_ports,
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk,
            "success_rate": success_rate,
            "services": dict(services),
            "unique_services": len(services),
        }

    def get_high_risk_results(self) -> List[ScanResult]:
        """Obtiene solo los resultados de alto riesgo."""
        return [r for r in self.results if r.risk_score > 0.7]

    def get_all_vulnerabilities(self) -> List[Tuple[int, str, str]]:
        """Retorna todas las vulnerabilidades encontradas."""
        vulns = []
        for result in self.results:
            for vuln in result.vulnerabilities:
                vulns.append((result.port, result.service, vuln))
        return vulns

    def finalize(self) -> None:
        """Finaliza la sesión estableciendo el tiempo de fin."""
        self.end_time = time.time()


# ==============================================================================
# MOTOR DE ANÁLISIS IA
# ==============================================================================
class AIAnalyzer:
    """Motor de inteligencia artificial para análisis de riesgos."""

    def __init__(self) -> None:
        """Inicializa el analizador con configuraciones de vulnerabilidad."""
        self.vuln_patterns = Config.VULN_PATTERNS
        self.known_vulns = Config.KNOWN_VULNS
        self.critical_ports = Config.CRITICAL_PORTS
        self.unencrypted_services = [
            "FTP", "Telnet", "HTTP", "SMTP", "POP3", "IMAP", "Redis",
        ]

    def calculate_risk_score(
        self,
        port: int,
        service: str,
        banner: str,
        response_time: float = 0.0,
    ) -> float:
        """Calcula score de riesgo multifactorial."""
        score = 0.0

        if port in self.critical_ports:
            score += 0.3

        if any(s in service.upper() for s in self.unencrypted_services):
            score += 0.2

        for vuln_name, (pattern, description) in self.vuln_patterns.items():
            if re.search(pattern, banner, re.IGNORECASE):
                score += 0.15

        for service_name, vuln_list in self.known_vulns.items():
            if service_name.lower() in service.lower():
                for vuln_info in vuln_list:
                    if vuln_info["version"] in banner:
                        score += 0.25
                        break

        if len(banner) > 100:
            score += 0.1

        if response_time > 2.0:
            score += 0.05

        return min(score, 1.0)

    def detect_vulnerabilities(
        self, service: str, banner: str, port: int
    ) -> List[Tuple[str, str]]:
        """Detecta vulnerabilidades específicas con CVE."""
        vulns = []

        if "FTP" in service.upper() or port == 21:
            if "vsftpd" in banner.lower() and "2.3.4" in banner:
                vulns.append(("vsftpd 2.3.4 Backdoor", "CVE-2011-2523"))
            if "anonymous" in banner.lower():
                vulns.append(("FTP Anonymous Login", "CONFIG"))

        if "Apache" in banner:
            match = re.search(r"Apache/(\d+\.\d+\.\d+)", banner)
            if match:
                version = match.group(1)
                if version in ["2.4.49", "2.4.50"]:
                    vulns.append((f"Apache {version} Path Traversal", "CVE-2021-41773"))

        if port in [3306, 5432, 27017, 6379]:
            db_names = {
                3306: "MySQL",
                5432: "PostgreSQL",
                27017: "MongoDB",
                6379: "Redis",
            }
            vulns.append((f"{db_names.get(port)} expuesto", "CONFIG"))

        if port == 445:
            vulns.append(("SMB expuesto - Verificar EternalBlue", "CVE-2017-0144"))

        return vulns

    def detect_os(self, banners: List[str]) -> Optional[str]:
        """Detección básica de SO basada en banners."""
        os_hints = []
        for banner in banners:
            if "Windows" in banner or "Microsoft" in banner:
                os_hints.append("Windows")
            elif any(x in banner for x in ["Linux", "Ubuntu", "Debian"]):
                os_hints.append("Linux")

        if os_hints:
            return max(set(os_hints), key=os_hints.count)
        return None

    def generate_insight(self, result: ScanResult) -> str:
        """Genera insight inteligente sobre un resultado."""
        if result.risk_score > 0.7:
            return f" {result.service}:{result.port} - Acción inmediata requerida"
        elif result.risk_score > 0.4:
            return f" {result.service}:{result.port} - Revisar configuración"
        return f"✓ {result.service}:{result.port} - Normal"


# ==============================================================================
# MOTOR DE ESCANEO 
# ==============================================================================
class LilitEngine:
    """Motor de escaneo profesional asíncrono."""

    def __init__(
        self,
        target: str,
        ports: List[int],
        protocol: str = "tcp",
        concurrency: int = 300,
        timeout: float = 1.0,
        stealth: bool = False,
        version_detect: bool = True,
        os_detect: bool = True,
    ) -> None:
        """Inicializa el motor de escaneo."""
        self.session: Optional[ScanSession] = None
        self.concurrency = Config.validate_concurrency(concurrency)
        self.target = target
        self.target_ip: Optional[str] = None
        self.ports = ports
        self.protocol = protocol
        self.semaphore = asyncio.Semaphore(self.concurrency)
        self.timeout = Config.validate_timeout(timeout)
        self.stealth = stealth
        self.version_detect = version_detect
        self.os_detect = os_detect
        self.ai = AIAnalyzer()
        self._scan_stats = {"success": 0, "failed": 0, "filtered": 0}

        self.target_ip = self._resolve_target(target)

        self.session = ScanSession(
            target=target,
            target_ip=self.target_ip,
            start_time=time.time(),
            ports_total=len(ports),
            profile="custom",
            stealth_mode=stealth,
            protocol=protocol,
        )

        log.info(f"Motor inicializado para {target} ({len(ports)} puertos)")

    def _resolve_target(self, target: str) -> Optional[str]:
        """Resuelve dominio a dirección IP."""
        try:
            ip = socket.gethostbyname(target)
            if self.session:
                self.session.hostname = target
            log.debug(f"Target {target} resuelto a {ip}")
            return ip
        except socket.gaierror as e:
            log.error(f"Error resolviendo {target}: {e}")
            return None

    async def _stealth_delay(self) -> None:
        """Añade delay aleatorio para modo sigiloso."""
        if self.stealth:
            delay = random.uniform(0.3, 1.5)
            await asyncio.sleep(delay)

    async def scan_tcp(self, port: int) -> Optional[ScanResult]:
        """Escaneo TCP avanzado con banner grabbing."""
        async with self.semaphore:
            await self._stealth_delay()
            start_time = time.time()

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_ip or self.target, port),
                    timeout=self.timeout,
                )

                response_time = (time.time() - start_time) * 1000
                banner = ""

                if self.version_detect:
                    probes = [
                        b"\r\n",
                        b"GET / HTTP/1.0\r\n\r\n",
                        b"HEAD / HTTP/1.0\r\n\r\n",
                        b"\x00",
                    ]
                    for probe in probes:
                        try:
                            writer.write(probe)
                            await writer.drain()
                            data = await asyncio.wait_for(
                                reader.read(2048), timeout=0.5
                            )
                            if data:
                                banner += data.decode("utf-8", errors="ignore")
                                break
                        except Exception:
                            continue

                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

                service = self._identify_service(port, banner)
                version = self._extract_version(banner)
                risk_score = self.ai.calculate_risk_score(
                    port, service, banner, response_time / 1000
                )
                vuln_tuples = self.ai.detect_vulnerabilities(service, banner, port)

                self._scan_stats["success"] += 1

                return ScanResult(
                    port=port,
                    protocol="TCP",
                    status="OPEN",
                    service=service,
                    version=version,
                    banner=banner[:100].replace("\n", " ").replace("\r", " "),
                    timestamp=time.time(),
                    risk_score=risk_score,
                    vulnerabilities=[v[0] for v in vuln_tuples],
                    cve_matches=[v[1] for v in vuln_tuples if v[1] != "CONFIG"],
                    response_time_ms=response_time,
                )

            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                self._scan_stats["failed"] += 1
                return None
            except Exception as e:
                log.debug(f"Error TCP puerto {port}: {type(e).__name__}: {e}")
                return None

    async def scan_udp(self, port: int) -> Optional[ScanResult]:
        """Escaneo UDP mejorado."""
        async with self.semaphore:
            await self._stealth_delay()
            start_time = time.time()

            try:
                transport, _ = await asyncio.get_event_loop().create_datagram_endpoint(
                    lambda: asyncio.DatagramProtocol(),
                    remote_addr=(self.target_ip or self.target, port),
                )

                probes = {
                    53: b"\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
                    123: b"\x1b" + b"\x00" * 47,
                }
                probe = probes.get(port, b"\x00")
                transport.sendto(probe)
                await asyncio.sleep(1.0)
                transport.close()

                response_time = (time.time() - start_time) * 1000
                service = self._identify_service(port, "")

                self._scan_stats["success"] += 1

                return ScanResult(
                    port=port,
                    protocol="UDP",
                    status="OPEN/FILTERED",
                    service=service,
                    version="",
                    banner="",
                    timestamp=time.time(),
                    risk_score=0.3,
                    response_time_ms=response_time,
                )

            except Exception as e:
                log.debug(f"Error UDP puerto {port}: {e}")
                self._scan_stats["failed"] += 1
                return None

    def _identify_service(self, port: int, banner: str) -> str:
        """Identificación inteligente de servicios."""
        banner_upper = banner.upper()

        banner_checks = [
            ("SSH", "SSH"),
            ("HTTP", "HTTP"),
            ("FTP", "FTP"),
            ("MYSQL", "MySQL"),
            ("POSTGRESQL", "PostgreSQL"),
            ("REDIS", "Redis"),
            ("MONGODB", "MongoDB"),
            ("MICROSOFT", "SMB"),
            ("SMTP", "SMTP"),
        ]
        for check, service_name in banner_checks:
            if check in banner_upper:
                return service_name

        services = {
            20: "FTP-DATA",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
        }
        return services.get(port, "Unknown")

    def _extract_version(self, banner: str) -> str:
        """Extracción de versión desde banner."""
        patterns = [
            r"(\d+\.\d+\.\d+)",
            r"v(\d+\.\d+)",
            r"Version (\d+\.\d+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        return ""

    async def run(self, progress: Progress, task_id: int) -> None:
        """Ejecuta escaneo completo."""
        if not self.session:
            raise RuntimeError("Sesión no inicializada")

        log.info(f"Iniciando escaneo de {len(self.ports)} puertos")

        tasks = []
        for port in self.ports:
            if self.protocol == "udp":
                tasks.append(asyncio.create_task(self.scan_udp(port)))
            else:
                tasks.append(asyncio.create_task(self.scan_tcp(port)))

        for coro in asyncio.as_completed(tasks):
            try:
                result = await coro
                if result and self.session:
                    self.session.results.append(result)
                    self.session.ports_scanned += 1
                    progress.update(task_id, advance=1)
            except Exception as e:
                if self.session:
                    self.session.errors.append(str(e))
                    self.session.ports_scanned += 1
                    progress.update(task_id, advance=1)
                log.error(f"Error en tarea de escaneo: {e}")

        if self.session:
            self.session.finalize()

            if self.os_detect and self.session.results:
                banners = [r.banner for r in self.session.results if r.banner]
                self.session.os_detection = self.ai.detect_os(banners)

        log.info(f"Escaneo completado: {self.session.ports_scanned} puertos")


# ==============================================================================
# INTERFAZ DE USUARIO
# ==============================================================================
class LilitUI:
    """Interfaz de usuario profesional con animaciones Rich."""

    def __init__(
        self,
        engine: LilitEngine,
        output_file: Optional[str] = None,
        verbose: bool = False,
        no_ui: bool = False,
        theme: str = "cyberpunk",
    ) -> None:
        """Inicializa la interfaz de usuario."""
        self.engine = engine
        self.output_file = output_file
        self.verbose = verbose
        self.no_ui = no_ui
        self.ai = AIAnalyzer()
        self.layout = Layout()
        self.progress = None

        if not hasattr(engine, "session") or engine.session is None:
            raise RuntimeError("Engine no tiene sesión inicializada")

        if not no_ui:
            self._setup_layout()

    def _setup_layout(self) -> None:
        """Configura el layout profesional de la UI."""
        self.layout.split(
            Layout(name="header", size=16),
            Layout(name="body"),
            Layout(name="footer", size=5),
        )
        self.layout["body"].split_row(
            Layout(name="main", ratio=3),
            Layout(name="sidebar", ratio=1),
        )
        self.layout["body"]["sidebar"].split(
            Layout(name="ai_panel", ratio=2),
            Layout(name="stats_panel", ratio=1),
        )

    def make_header(self) -> Panel:
        """Crea el panel de cabecera con logo."""
        p = VisualTheme.get_color("primary")
        a = VisualTheme.get_color("accent")
        s = VisualTheme.get_color("secondary")
        i = VisualTheme.get_color("info")
        m = VisualTheme.get_color("muted")

        target_ip = self.engine.target_ip or "Resolviendo..."

        logo = Text()
        logo.append("╔══════════════════════════════════════════════════════════╗\n", style=p)
        logo.append("║", style=p)
        logo.append("  LILIT v", style=p)
        logo.append(Config.VERSION, style=a)
        logo.append(" - ", style=p)
        logo.append(Config.CODENAME, style=s)
        logo.append("                         ║\n", style=p)
        logo.append("║", style=p)
        logo.append("  Live Intelligent Link Inspection Tool                        ║\n", style=m)
        logo.append("║", style=p)
        logo.append(f"  Target: {self.engine.target:<50}", style=i)
        logo.append("║\n", style=p)
        logo.append("║", style=p)
        logo.append(f"  IP: {target_ip:<58}", style=i)
        logo.append("║\n", style=p)
        logo.append("╚══════════════════════════════════════════════════════════╝", style=p)

        return Panel(logo, border_style=p, box=HEAVY)

    def make_results_table(self) -> Table:
        """Crea la tabla de resultados profesional."""
        table = Table(
            title=f"Resultados del Escaneo ({self.engine.protocol.upper()})",
            expand=True,
            border_style=VisualTheme.get_color("info"),
            box=ROUNDED,
            header_style=f"bold {VisualTheme.get_color('primary')}",
        )

        table.add_column("Port", style="cyan", width=8, justify="right")
        table.add_column("Proto", style="magenta", width=6)
        table.add_column("Service", style="yellow", width=15)
        table.add_column("Version", style="white", width=12)
        table.add_column("Risk", justify="right", width=12)
        table.add_column("Banner", style="dim", width=35)

        if not self.engine.session or not self.engine.session.results:
            table.add_row("", "", " Escaneando...", "", "", "")
            return table

        sorted_results = sorted(
            self.engine.session.results,
            key=lambda x: x.risk_score,
            reverse=True,
        )

        for res in sorted_results[:50]:
            risk_color = res.get_risk_color()
            risk_label = res.get_risk_label()
            banner_display = (
                res.banner[:30] + "..."
                if len(res.banner) > 30
                else res.banner
            )
            table.add_row(
                str(res.port),
                res.protocol,
                res.service,
                res.version or "-",
                f"[{risk_color}]{risk_label}[/{risk_color}]",
                banner_display,
            )

        if len(sorted_results) > 50:
            table.add_row("", "", "", "", f"⋯ +{len(sorted_results) - 50} más", "")

        return table

    def make_ai_panel(self) -> Panel:
        """Crea el panel de análisis IA."""
        if not self.engine.session or not self.engine.session.results:
            content = "[dim] Analizando datos...[/dim]"
        else:
            insights = []
            for res in self.engine.session.results[-7:]:
                insight = self.ai.generate_insight(res)
                insights.append(insight)
            content = "\n".join(insights) if insights else "[dim] Analizando datos...[/dim]"

        ai_text = Text()
        ai_text.append("IA", style="bold")
        ai_text.append("AI Analysis Engine\n", style=VisualTheme.get_color("secondary"))
        ai_text.append(content, style="")

        return Panel(
            ai_text,
            title="Inteligencia Artificial",
            border_style=VisualTheme.get_color("secondary"),
            box=ROUNDED,
        )

    def make_stats_panel(self) -> Panel:
        """Crea el panel de estadísticas en tiempo real."""
        if not self.engine.session:
            content = "[dim]Iniciando...[/dim]"
        else:
            elapsed = time.time() - self.engine.session.start_time
            open_count = len(self.engine.session.results)
            high_risk = len(
                [r for r in self.engine.session.results if r.risk_score > 0.7]
            )

            stats_text = Text()
            stats_text.append(" ", style="bold")
            stats_text.append("Estadísticas\n", style=VisualTheme.get_color("primary"))
            stats_text.append("  Tiempo:     ", style="")
            stats_text.append(f"{elapsed:.1f}s\n", style=VisualTheme.get_color("accent"))
            stats_text.append(" Escaneados:  ", style="")
            stats_text.append(
                f"{self.engine.session.ports_scanned}/{self.engine.session.ports_total}\n",
                style=VisualTheme.get_color("info"),
            )
            stats_text.append(" Abiertos:    ", style="")
            stats_text.append(f"{open_count}\n", style=VisualTheme.get_color("success"))
            stats_text.append("  Alto Riesgo: ", style="")
            stats_text.append(f"{high_risk}\n", style=VisualTheme.get_color("alert"))
            stats_text.append("  Modo:       ", style="")
            mode = "SIGILO" if self.engine.stealth else "NORMAL"
            stats_text.append(f"{mode}\n", style=VisualTheme.get_color("warning"))

            progress_pct = (
                (self.engine.session.ports_scanned / self.engine.session.ports_total * 100)
                if self.engine.session.ports_total > 0
                else 0
            )
            stats_text.append("\n", style="")
            stats_text.append(" Progreso:    ", style="")
            stats_text.append(f"{progress_pct:.0f}%", style=VisualTheme.get_color("primary"))

            content = stats_text

        return Panel(
            content,
            title="Estado",
            border_style=VisualTheme.get_color("primary"),
            box=ROUNDED,
        )

    def make_footer(self, progress: Progress) -> Panel:
        """Crea el footer con información del sistema."""
        footer_text = Text()
        footer_text.append(
            f" LILIT v{Config.VERSION} ",
            style=f"bold {VisualTheme.get_color('primary')}",
        )
        footer_text.append("│", style="dim")
        footer_text.append(
            f" {platform.system()} {platform.release()} ", style="dim"
        )
        footer_text.append("│", style="dim")
        footer_text.append(f" Python {platform.python_version()} ", style="dim")
        footer_text.append("│", style="dim")
        footer_text.append(
            " Presiona Ctrl+C para cancelar ",
            style=VisualTheme.get_color("warning"),
        )

        return Panel(
            Align.center(footer_text),
            style=f"bold white on {VisualTheme.get_color('bg')}",
            box=DOUBLE,
        )

    def update_layout(self, progress: Progress) -> None:
        """Actualiza todo el layout."""
        if self.no_ui:
            return

        self.progress = progress
        self.layout["header"].update(self.make_header())
        self.layout["body"]["main"].update(self.make_results_table())
        self.layout["body"]["sidebar"]["ai_panel"].update(self.make_ai_panel())
        self.layout["body"]["sidebar"]["stats_panel"].update(self.make_stats_panel())
        self.layout["footer"].update(self.make_footer(progress))


# ==============================================================================
# GENERADOR DE REPORTES
# ==============================================================================
class ReportGenerator:
    """Generador de reportes multi-formato."""

    @staticmethod
    def generate_json(session: ScanSession, filename: str) -> bool:
        """Genera reporte JSON estructurado."""
        try:
            data = {
                "metadata": {
                    "tool": "LILIT",
                    "version": Config.VERSION,
                    "codename": Config.CODENAME,
                    "author": Config.AUTHOR,
                    "generated_at": datetime.now().isoformat(),
                    "build_date": Config.BUILD_DATE,
                },
                "target": {
                    "hostname": session.target,
                    "ip": session.target_ip,
                    "os_detected": session.os_detection,
                },
                "scan_info": {
                    "start_time": datetime.fromtimestamp(session.start_time).isoformat(),
                    "end_time": (
                        datetime.fromtimestamp(session.end_time).isoformat()
                        if session.end_time
                        else None
                    ),
                    "duration": (session.end_time or time.time()) - session.start_time,
                    "profile": session.profile,
                    "protocol": session.protocol.upper(),
                    "stealth_mode": session.stealth_mode,
                },
                "statistics": session.get_statistics(),
                "high_risk_findings": [asdict(r) for r in session.get_high_risk_results()],
                "vulnerabilities": session.get_all_vulnerabilities(),
                "all_results": [asdict(r) for r in session.results],
            }

            Path(filename).parent.mkdir(parents=True, exist_ok=True)
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)

            log.info(f"Reporte JSON generado: {filename}")
            return True

        except Exception as e:
            log.error(f"Error generando JSON: {e}")
            console.print(f"[bold red] Error JSON: {e}[/bold red]")
            return False

    @staticmethod
    def generate_html(session: ScanSession, filename: str) -> bool:
        """Genera reporte HTML dashboard profesional."""
        try:
            stats = session.get_statistics()
            html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>LILIT Report - {session.target}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0a0a0a; 
               color: #00ff9d; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #00ff9d, #bd00ff); 
                   padding: 40px; border-radius: 15px; margin-bottom: 30px; }}
        .header h1 {{ color: #000; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, 
                      minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: rgba(255,255,255,0.05); padding: 25px; 
                     border-radius: 12px; border-left: 4px solid #00ff9d; }}
        .stat-value {{ font-size: 2.5em; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: rgba(0,255,157,0.1); color: #00ff9d; }}
        .risk-critical {{ color: #ff0055; }}
        .risk-high {{ color: #ffaa00; }}
        .risk-low {{ color: #00ff9d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1> LILIT v{Config.VERSION}</h1>
            <p>Target: {session.target} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats['duration']:.1f}s</div>
                <div>Duración</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['scanned']}</div>
                <div>Escaneados</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats['open']}</div>
                <div>Abiertos</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color:#ff0055;">
                    {stats['high_risk']}
                </div>
                <div>Alto Riesgo</div>
            </div>
        </div>
        <h2> Resultados</h2>
        <table>
            <thead>
                <tr>
                    <th>Puerto</th><th>Protocolo</th><th>Servicio</th>
                    <th>Versión</th><th>Riesgo</th><th>Banner</th>
                </tr>
            </thead>
            <tbody>
"""
            for res in sorted(session.results, key=lambda x: x.risk_score, reverse=True):
                risk_class = (
                    "risk-critical"
                    if res.risk_score > 0.7
                    else "risk-high" if res.risk_score > 0.4 else "risk-low"
                )
                html += (
                    f"<tr><td>{res.port}</td><td>{res.protocol}</td>"
                    f"<td>{res.service}</td><td>{res.version or '-'}</td>"
                    f"<td class='{risk_class}'>{res.risk_score:.2f}</td>"
                    f"<td>{res.banner[:50]}</td></tr>"
                )

            html += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""

            Path(filename).parent.mkdir(parents=True, exist_ok=True)
            with open(filename, "w", encoding="utf-8") as f:
                f.write(html)

            log.info(f"Reporte HTML generado: {filename}")
            return True

        except Exception as e:
            log.error(f"Error generando HTML: {e}")
            console.print(f"[bold red] Error HTML: {e}[/bold red]")
            return False

    @staticmethod
    def generate_csv(session: ScanSession, filename: str) -> bool:
        """Genera reporte CSV para análisis externo."""
        try:
            Path(filename).parent.mkdir(parents=True, exist_ok=True)
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(
                    ["Port", "Protocol", "Service", "Version", "Risk Score", "Banner"]
                )
                for res in session.results:
                    writer.writerow(
                        [
                            res.port,
                            res.protocol,
                            res.service,
                            res.version,
                            f"{res.risk_score:.2f}",
                            res.banner,
                        ]
                    )

            log.info(f"Reporte CSV generado: {filename}")
            return True

        except Exception as e:
            log.error(f"Error generando CSV: {e}")
            console.print(f"[bold red] Error CSV: {e}[/bold red]")
            return False


# ==============================================================================
# FUNCIONES DE UTILIDAD
# ==============================================================================
def show_banner() -> None:
    """Muestra el logo de bienvenida de LILIT."""
    p = VisualTheme.get_color("primary")
    a = VisualTheme.get_color("accent")
    s = VisualTheme.get_color("secondary")
    w = VisualTheme.get_color("warning")

    logo = f"""
[bold {p}]╔══════════════════════════════════════════════════════════════════════════════╗[/bold {p}]
[bold {p}]║[/bold {p}]  ██╗     ██╗██╗     ██╗████████╗
[bold {p}]║[/bold {p}]  ██║     ██║██║     ██║╚══██╔══╝
[bold {p}]║[/bold {p}]  ██║     ██║██║     ██║   ██║
[bold {p}]║[/bold {p}]  ██║     ██║██║     ██║   ██║
[bold {p}]║[/bold {p}]  ███████╗██║███████╗██║   ██║
[bold {p}]║[/bold {p}]  ╚══════╝╚═╝╚══════╝╚═╝   ╚═╝
[bold {p}]║[/bold {p}]  [bold {a}]L I L I T   v{Config.VERSION}[/bold {a}]  "[bold {s}]{Config.CODENAME}[/bold {s}]"
[bold {p}]╚══════════════════════════════════════════════════════════════════════════════╝[/bold {p}]
"""
    console.print(logo)
    console.print(f"  [dim]Autor:[/dim] [bold]{Config.AUTHOR}[/bold]")
    console.print(f"  [{w}]  Solo uso autorizado[/{w}]", style="italic")


def show_help() -> None:
    """Muestra la guía de uso completa."""
    i = VisualTheme.get_color("info")

    help_text = f"""
[bold {i}]═══════════════════════════════════════════════════════════════════════════════[/bold {i}]
[bold {i}]                             GUÍA DE USO LILIT v{Config.VERSION}[/bold {i}]
[bold {i}]═══════════════════════════════════════════════════════════════════════════════[/bold {i}]

[bold cyan] ESCANEO BÁSICO:[/bold cyan]
  python lilit.py <target> -p 80,443,8080
  python lilit.py 192.168.1.1 -p 1-1024

[bold cyan] PERFILES PREDEFINIDOS:[/bold cyan]
  --profile quick      Puertos comunes (12 puertos)
  --profile web        Servidores web (10 puertos)
  --profile database   Bases de datos (8 puertos)
  --profile full       Puertos 1-1024 (1024 puertos)

[bold cyan]  OPCIONES AVANZADAS:[/bold cyan]
  -u, --udp            Escaneo UDP
  --stealth            Modo sigiloso (delays aleatorios)
  --threads <n>        Hilos concurrentes (default: 300)
  --timeout <n>        Timeout por conexión (default: 1.0)
  --theme <name>       Tema: cyberpunk, matrix, corporate

[bold cyan] REPORTES:[/bold cyan]
  -o, --output <file>  Archivo de salida
  --report json/html/csv  Formato de reporte

[bold {i}]═══════════════════════════════════════════════════════════════════════════════[/bold {i}]
[bold {i}]                                    EJEMPLOS[/bold {i}]
[bold {i}]═══════════════════════════════════════════════════════════════════════════════[/bold {i}]

[green]python lilit.py target.com --profile web -o reporte.html --report html[/green]
[green]python lilit.py 192.168.1.1 --profile full --stealth --timeout 2.0[/green]
[green]sudo python lilit.py 192.168.1.1 -p 53 -u -o dns_scan.json[/green]

[bold {i}]═══════════════════════════════════════════════════════════════════════════════[/bold {i}]
"""
    console.print(Panel(help_text, title=" AYUDA", border_style=i, box=ROUNDED))


# ==============================================================================
# FUNCIÓN PRINCIPAL
# ==============================================================================
async def main() -> None:
    """Función principal de la aplicación."""
    show_banner()

    parser = argparse.ArgumentParser(
        description=f"LILIT v{Config.VERSION} - {Config.CODENAME}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )

    parser.add_argument("target", nargs="?", help="IP o Dominio objetivo")
    parser.add_argument(
        "-p", "--ports", default="21-25,80,443", help="Rango de puertos"
    )
    parser.add_argument("-u", "--udp", action="store_true", help="Modo UDP")
    parser.add_argument(
        "--profile",
        choices=["quick", "web", "database", "remote", "full", "top100"],
        help="Perfil predefinido",
    )
    parser.add_argument(
        "--threads", type=int, default=300, help="Hilos (default: 300)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0, help="Timeout (default: 1.0)"
    )
    parser.add_argument("--stealth", action="store_true", help="Modo sigiloso")
    parser.add_argument("-o", "--output", help="Archivo de salida")
    parser.add_argument(
        "--report",
        choices=["json", "html", "csv"],
        default="json",
        help="Formato de reporte",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Modo verbose"
    )
    parser.add_argument("--no-ui", action="store_true", help="Sin UI interactiva")
    parser.add_argument("--log-file", help="Archivo de log")
    parser.add_argument(
        "--theme",
        choices=["cyberpunk", "matrix", "corporate"],
        default="cyberpunk",
        help="Tema visual",
    )
    parser.add_argument(
        "--no-version-detect", action="store_true", help="Sin detección de versión"
    )
    parser.add_argument(
        "--no-os-detect", action="store_true", help="Sin detección de SO"
    )
    parser.add_argument("-h", "--help", action="store_true", help="Mostrar ayuda")

    args = parser.parse_args()

    # Aplicar tema visual
    try:
        VisualTheme.set_theme(args.theme)
    except ValueError as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        sys.exit(1)

    # Configurar logging
    if args.log_file:
        global log
        log = setup_logging(args.verbose, args.log_file)

    # Mostrar ayuda si se solicita
    if args.help or len(sys.argv) == 1:
        show_help()
        return

    # Validar target
    if not args.target:
        console.print(
            f"[bold {VisualTheme.get_color('alert')}] Error: Debes especificar un target[/bold {VisualTheme.get_color('alert')}]"
        )
        console.print(
            f"[{VisualTheme.get_color('warning')}]Ejemplo: python lilit.py 192.168.1.1 -p 80,443[/{VisualTheme.get_color('warning')}]"
        )
        return

    valid, msg = SecurityValidator.validate_target(args.target)
    if not valid:
        console.print(
            f"[bold {VisualTheme.get_color('alert')}] Error: {msg}[/bold {VisualTheme.get_color('alert')}]"
        )
        return

    # Procesar puertos
    ports = []
    if args.profile:
        if args.profile in Config.COMMON_PORTS:
            ports = Config.COMMON_PORTS[args.profile]
            console.print(
                f"[bold {VisualTheme.get_color('info')}]✓ Perfil '{args.profile}' cargado: {len(ports)} puertos[/bold {VisualTheme.get_color('info')}]"
            )
        else:
            console.print(
                f"[bold {VisualTheme.get_color('alert')}] Perfil '{args.profile}' no existe[/bold {VisualTheme.get_color('alert')}]"
            )
            return
    else:
        valid, ports, msg = SecurityValidator.validate_ports(args.ports)
        if not valid:
            console.print(
                f"[bold {VisualTheme.get_color('alert')}] Error: {msg}[/bold {VisualTheme.get_color('alert')}]"
            )
            return
        console.print(
            f"[bold {VisualTheme.get_color('info')}]✓ {msg}[/bold {VisualTheme.get_color('info')}]"
        )

    protocol = "udp" if args.udp else "tcp"

    # Información inicial
    console.print(
        f"\n[bold {VisualTheme.get_color('primary')}] INICIANDO ESCANEO {protocol.upper()}[/bold {VisualTheme.get_color('primary')}]"
    )

    info_table = Table(
        show_header=False, box=ROUNDED, border_style=VisualTheme.get_color("info")
    )
    info_table.add_row("Target", args.target)
    info_table.add_row("Puertos", str(len(ports)))
    info_table.add_row("Concurrencia", f"{args.threads} hilos")
    info_table.add_row("Timeout", f"{args.timeout}s")
    info_table.add_row("Modo", "SIGILOSO" if args.stealth else "NORMAL")
    info_table.add_row("Tema", args.theme.upper())
    console.print(info_table)

    # Ejecutar escaneo
    try:
        engine = LilitEngine(
            target=args.target,
            ports=ports,
            protocol=protocol,
            concurrency=args.threads,
            timeout=args.timeout,
            stealth=args.stealth,
            version_detect=not args.no_version_detect,
            os_detect=not args.no_os_detect,
        )

        if not engine.session:
            raise RuntimeError("Failed to initialize engine session")

        engine.session.profile = args.profile or "custom"

        # Inicializar UI
        ui = LilitUI(engine, args.output, args.verbose, args.no_ui, args.theme)

        # Ejecutar escaneo con progreso
        if args.no_ui:
            with Progress(
                SpinnerColumn(spinner_name="dots"),
                TextColumn("[bold]{task.description}"),
                BarColumn(bar_width=40, complete_style=VisualTheme.get_color("primary")),
                TaskProgressColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console,
                refresh_per_second=10,
            ) as progress:
                task_id = progress.add_task("Scanning...", total=len(ports))
                await engine.run(progress, task_id)
        else:
            with Progress(
                SpinnerColumn(spinner_name="dots"),
                TextColumn("[bold]{task.description}"),
                BarColumn(
                    bar_width=40, complete_style=VisualTheme.get_color("primary")
                ),
                console=console,
                refresh_per_second=10,
            ) as progress:
                task_id = progress.add_task("Scanning...", total=len(ports))
                ui.update_layout(progress)

                with Live(
                    ui.layout,
                    console=console,
                    refresh_per_second=5,
                    screen=True,
                    redirect_stdout=False,
                    redirect_stderr=False,
                ):
                    await engine.run(progress, task_id)

        # Generar reportes
        if args.output:
            ext_map = {"json": ".json", "html": ".html", "csv": ".csv"}
            ext = ext_map.get(args.report, ".json")
            if not args.output.endswith(ext):
                args.output += ext

            if args.report == "json":
                ReportGenerator.generate_json(engine.session, args.output)
            elif args.report == "html":
                ReportGenerator.generate_html(engine.session, args.output)
            elif args.report == "csv":
                ReportGenerator.generate_csv(engine.session, args.output)

        # Resumen final
        if engine.session:
            stats = engine.session.get_statistics()
            console.print(
                f"\n[bold {VisualTheme.get_color('primary')}] ESCANEO COMPLETADO[/bold {VisualTheme.get_color('primary')}]"
            )

            summary_table = Table(
                show_header=False,
                box=ROUNDED,
                border_style=VisualTheme.get_color("success"),
            )
            summary_table.add_row("Duración", f"{stats['duration']:.2f}s")
            summary_table.add_row(
                "Escaneados", f"{stats['scanned']}/{stats['total_ports']}"
            )
            summary_table.add_row("Abiertos", str(stats["open"]))
            summary_table.add_row(
                "Alto Riesgo",
                f"[bold {VisualTheme.get_color('alert')}]{stats['high_risk']}[/bold {VisualTheme.get_color('alert')}]",
            )
            summary_table.add_row("🟡 Medio Riesgo", str(stats["medium_risk"]))
            summary_table.add_row("🟢 Bajo Riesgo", str(stats["low_risk"]))
            console.print(summary_table)

            # Vulnerabilidades
            all_vulns = engine.session.get_all_vulnerabilities()
            if all_vulns:
                console.print(
                    f"\n[bold {VisualTheme.get_color('alert')}] VULNERABILIDADES DETECTADAS ({len(all_vulns)})[/bold {VisualTheme.get_color('alert')}]"
                )
                for port, service, vuln in all_vulns[:10]:
                    console.print(
                        f"  [{VisualTheme.get_color('alert')}]•[/bold {VisualTheme.get_color('alert')}] Puerto {port} ({service}): {vuln}"
                    )
                if len(all_vulns) > 10:
                    console.print(
                        f"  [{VisualTheme.get_color('muted')}]... y {len(all_vulns) - 10} más[/bold {VisualTheme.get_color('muted')}]"
                    )

            if args.output:
                console.print(
                    f"\n[bold green] Reporte guardado: {args.output}[/bold green]"
                )

    except RuntimeError as e:
        console.print(
            f"\n[bold {VisualTheme.get_color('alert')}] Error de inicialización: {e}[/bold {VisualTheme.get_color('alert')}]"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        console.print(
            f"\n[bold {VisualTheme.get_color('alert')}]  Interrumpido por usuario[/bold {VisualTheme.get_color('alert')}]"
        )
    except PermissionError as e:
        console.print(
            f"\n[bold {VisualTheme.get_color('alert')}] Error de permisos: {e}[/bold {VisualTheme.get_color('alert')}]"
        )
        console.print(
            f"[{VisualTheme.get_color('warning')}]Ejecuta como administrador para escaneo UDP[/{VisualTheme.get_color('warning')}]"
        )
    except Exception as e:
        console.print(
            f"\n[bold {VisualTheme.get_color('alert')}] Error crítico: {e}[/bold {VisualTheme.get_color('alert')}]"
        )
        log.exception("Detalle del error:")


# ==============================================================================
# PUNTO DE ENTRADA
# ==============================================================================
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print(
            f"\n[bold {VisualTheme.get_color('alert')}]🛑 LILIT TERMINADO[/bold {VisualTheme.get_color('alert')}]"
        )
    except Exception as e:
        console.print(f"\n[bold red] Error fatal: {e}[/bold red]")
        sys.exit(1)