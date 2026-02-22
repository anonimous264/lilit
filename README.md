# MANUAL DE USO PROFESIONAL - LILIT 1.0

**Live Intelligent Link Inspection Tool**

---

## **PÁGINA DE TÍTULO**

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    MANUAL DE USO OFICIAL - LILIT                             ║
║                                                                              ║
║                    Live Intelligent Link Inspection Tool                     ║
║                                                                              ║
║                    Versión del Documento: 1.0                                ║
║                    Fecha: Enero 2026                                         ║
║                    Clasificación: USO INTERNO AUTORIZADO                     ║
║                                                                              ║
║                    Autor: Abdias Samuel                                      ║
║                    Equipo:SAM                                                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## **TABLA DE CONTENIDOS**

1. [Introducción](#1-introducción)
2. [Descripción de la Herramienta](#2-descripción-de-la-herramienta)
3. [Requisitos del Sistema](#3-requisitos-del-sistema)
4. [Instalación y Configuración](#4-instalación-y-configuración)
5. [Sintaxis y Referencia de Comandos](#5-sintaxis-y-referencia-de-comandos)
6. [Perfiles de Escaneo](#6-perfiles-de-escaneo)
7. [Opciones Avanzadas](#7-opciones-avanzadas)
8. [Generación e Interpretación de Reportes](#8-generación-e-interpretación-de-reportes)
9. [Temas Visuales y Personalización](#9-temas-visuales-y-personalización)
10. [Ejemplos Prácticos de Uso](#10-ejemplos-prácticos-de-uso)
11. [Solución de Problemas](#11-solución-de-problemas)
12. [Consideraciones Legales y Éticas](#12-consideraciones-legales-y-éticas)
13. [Apéndices](#13-apéndices)

---

## **1. INTRODUCCIÓN**

### 1.1 Propósito del Documento

El presente manual proporciona instrucciones completas, estructuradas y profesionales para la instalación, configuración y operación de **LILIT (Live Intelligent Link Inspection Tool)**, una herramienta avanzada de escaneo de puertos y análisis de vulnerabilidades diseñada para auditorías de seguridad informática autorizadas.

### 1.2 Audiencia Objetivo

Este documento está dirigido a:

| Rol | Responsabilidad |
|-----|----------------|
| Auditores de Seguridad | Ejecución de evaluaciones de vulnerabilidades |
| Pentesters | Pruebas de penetración autorizadas |
| Administradores de Sistemas | Evaluación de infraestructura propia |
| Analistas SOC | Reconocimiento en respuesta a incidentes |
| Estudiantes de Ciberseguridad | Aprendizaje y práctica educativa |

### 1.3 Convenciones del Documento

| Símbolo | Significado |
|---------|-------------|
| `` | Consejo o recomendación |
| `` | Advertencia importante |
| `` | Requisito cumplido / Funcionalidad disponible |
| `` | Limitación / Funcionalidad no disponible |
| `` | Comando o procedimiento técnico |
| `` | Ejemplo de código o salida |

---

## **2. DESCRIPCIÓN DE LA HERRAMIENTA**

### 2.1 Visión General

LILIT es un escáner de puertos asíncrono de alto rendimiento desarrollado en Python que incorpora capacidades avanzadas de análisis de seguridad:

```
┌─────────────────────────────────────────────────────────────────┐
│                    ARQUITECTURA DE LILIT                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐                                           │
│  │   Interfaz UI   │ ← Rich Library (Terminal interactiva)    │
│  └────────┬────────┘                                           │
│           │                                                    │
│  ┌────────▼────────┐                                           │
│  │   LilitEngine   │ ← Motor de escaneo asíncrono             │
│  │   • TCP/UDP     │                                           │
│  │   • Banner Grab │                                           │
│  │   • Stealth     │                                           │
│  └────────┬────────┘                                           │
│           │                                                    │
│  ┌────────▼────────┐                                           │
│  │   AIAnalyzer    │ ← Análisis de riesgos con IA             │
│  │   • Risk Score  │                                           │
│  │   • CVE Match   │                                           │
│  │   • OS Detect   │                                           │
│  └────────┬────────┘                                           │
│           │                                                    │
│  ┌────────▼────────┐                                           │
│  │ ReportGenerator │ ← Exportación multi-formato              │
│  │   • JSON        │                                           │
│  │   • HTML        │                                           │
│  │   • CSV         │                                           │
│  └─────────────────┘                                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Características Principales

| Categoría | Característica | Descripción |
|-----------|---------------|-------------|
| **Escaneo** | TCP/UDP Asíncrono | Conexiones concurrentes de alto rendimiento |
| **Detección** | Banner Grabbing | Obtención de información de servicios |
| **Análisis** | AI Risk Scoring | Evaluación multifactorial de riesgos (0.0-1.0) |
| **Vulnerabilidades** | CVE Matching | Identificación de vulnerabilidades conocidas |
| **Reportes** | Multi-formato | JSON, HTML (dashboard), CSV |
| **UI** | Terminal Interactiva | Visualización en tiempo real con Rich |
| **Personalización** | Temas Visuales | Cyberpunk, Matrix, Corporate |
| **Seguridad** | Validaciones | Restricción de IPs públicas, límites de concurrencia |

### 2.3 Alcance y Limitaciones

**Usos Autorizados:**
- Auditorías de seguridad con consentimiento escrito del propietario
- Pruebas de penetración en sistemas bajo responsabilidad del auditor
- Investigación de seguridad en entornos de laboratorio propios
- Evaluación de infraestructura corporativa con autorización formal

**Usos No Autorizados:**
- Escaneo de sistemas sin autorización explícita del propietario
- Actividades maliciosas, ilegales o no éticas
- Violación de términos de servicio de terceros
- Ataques a infraestructura crítica sin autorización gubernamental

---

## **3. REQUISITOS DEL SISTEMA**

### 3.1 Requisitos de Hardware

| Componente | Requisito Mínimo | Requisito Recomendado | Justificación |
|------------|------------------|----------------------|---------------|
| Procesador | 2 núcleos | 4+ núcleos | Escaneo asíncrono requiere paralelismo |
| Memoria RAM | 4 GB | 8+ GB | Manejo de múltiples conexiones simultáneas |
| Almacenamiento | 500 MB libres | 1+ GB libres | Logs, reportes y base de datos de vulnerabilidades |
| Conexión de Red | 100 Mbps | 1 Gbps | Velocidad de escaneo proporcional al ancho de banda |

### 3.2 Requisitos de Software

| Componente | Versión Mínima | Versión Recomendada | Notas |
|------------|----------------|---------------------|-------|
| Python | 3.8 | 3.10+ | Requiere soporte para dataclasses y asyncio |
| pip | 20.0 | 23.0+ | Gestión de dependencias |
| Sistema Operativo | Windows 10 / Linux / macOS | Windows 11 / Ubuntu 22.04 LTS | Compatibilidad multiplataforma |
| Librería Rich | 12.0.0 | 13.0.0+ | Interfaz de usuario terminal |

### 3.3 Dependencias de Python

```bash
# Dependencia principal
rich>=12.0.0

# Dependencias incluidas en Python estándar (no requieren instalación):
# - asyncio, argparse, json, logging, socket, re, ipaddress, etc.
```

### 3.4 Verificación de Requisitos

```bash
# Verificar versión de Python
python --version
# Salida esperada: Python 3.8.0 o superior

# Verificar pip
pip --version
# Salida esperada: pip 20.0 o superior

# Verificar conectividad de red
ping 8.8.8.8

# Verificar permisos de administrador (para escaneo UDP)
# Windows:
whoami /groups | findstr Administrators
# Linux/macOS:
sudo whoami
```

---

## **4. INSTALACIÓN Y CONFIGURACIÓN**

### 4.1 Descarga de la Herramienta

**Opción A: Copia Local (Recomendada para entornos aislados)**
```bash
# Copiar archivo lilit.py al directorio de trabajo
copy lilit.py C:\PENTESTING\tools\
# O en Linux/macOS:
cp lilit.py ~/pentesting/tools/
```

**Opción B: Descarga desde Repositorio**
```bash
# Usar wget o curl
wget https://github.com/nexus-core/lilit/releases/download/v4.0.0/lilit.py
# O:
curl -O https://github.com/nexus-core/lilit/releases/download/v4.0.0/lilit.py
```

### 4.2 Configuración del Entorno Virtual (Recomendado)

```bash
# Crear entorno virtual aislado
python -m venv lilit_env

# Activar entorno virtual
# Windows:
lilit_env\Scripts\activate
# Linux/macOS:
source lilit_env/bin/activate

# Verificar activación
# El prompt debe mostrar (lilit_env) al inicio
```

### 4.3 Instalación de Dependencias

```bash
# Instalar librería Rich (única dependencia externa)
pip install rich

# Verificar instalación exitosa
pip list | findstr rich
# Salida esperada: rich    13.0.0 (o versión superior)
```

### 4.4 Verificación de Instalación

```bash
# Ejecutar prueba de instalación
python lilit.py --help

# Salida esperada: Banner de LILIT + menú de ayuda
# Si aparece el banner y la ayuda, la instalación es exitosa
```

### 4.5 Configuración de Logging (Opcional)

```bash
# Habilitar logging a archivo para auditoría
python lilit.py 192.168.1.1 --log-file audit.log

# Modo verbose para debugging detallado
python lilit.py 192.168.1.1 -v --log-file debug.log

# Ubicación de archivos de log:
# Windows: C:\Users\<usuario>\lilit\logs\
# Linux: /home/<usuario>/lilit/logs/
```

### 4.6 Configuración de Temas Visuales

LILIT ofrece tres temas profesionales personalizables:

| Tema | Código de Color | Uso Recomendado | Ejemplo Visual |
|------|-----------------|-----------------|----------------|
| `cyberpunk` | Verde neón (#00ff9d) | Default, presentaciones | Terminal futurista |
| `matrix` | Verde clásico (#00ff00) | Auditorías técnicas | Estilo terminal clásico |
| `corporate` | Azul (#0066cc) | Informes ejecutivos | Estilo profesional |

```bash
# Establecer tema cyberpunk (default)
python lilit.py 192.168.1.1 --theme cyberpunk

# Establecer tema matrix
python lilit.py 192.168.1.1 --theme matrix

# Establecer tema corporate
python lilit.py 192.168.1.1 --theme corporate
```

---

## **5. SINTAXIS Y REFERENCIA DE COMANDOS**

### 5.1 Sintaxis General

```bash
python lilit.py <target> [opciones]
```

### 5.2 Argumentos Posicionales

| Argumento | Descripción | Requerido | Ejemplo |
|-----------|-------------|-----------|---------|
| `target` | Dirección IP o nombre de dominio objetivo | Sí (excepto --help) | `192.168.1.1`, `empresa.com` |

### 5.3 Argumentos de Escaneo

| Argumento | Corto | Tipo | Default | Descripción | Ejemplo |
|-----------|-------|------|---------|-------------|---------|
| `--ports` | `-p` | String | `21-25,80,443` | Especificación de puertos a escanear | `-p 80,443,8080` |
| `--udp` | `-u` | Flag | `False` | Habilitar modo de escaneo UDP | `-u` |
| `--profile` | - | Choice | `None` | Perfil predefinido de puertos | `--profile web` |

**Formatos válidos para `--ports`:**
```bash
# Puerto individual
-p 80

# Múltiples puertos
-p 80,443,8080

# Rango de puertos
-p 1-1024

# Combinación
-p 21-25,80,443,8000-8100
```

### 5.4 Argumentos de Rendimiento

| Argumento | Tipo | Default | Rango Seguro | Descripción | Recomendación |
|-----------|------|---------|--------------|-------------|---------------|
| `--threads` | Integer | 300 | 100-500 | Número de conexiones simultáneas | Reducir en redes lentas |
| `--timeout` | Float | 1.0 | 0.5-5.0 | Timeout por conexión (segundos) | Aumentar para redes con alta latencia |
| `--stealth` | Flag | `False` | On/Off | Modo sigiloso con delays aleatorios | Usar en entornos productivos sensibles |

### 5.5 Argumentos de Salida y Reportes

| Argumento | Corto | Tipo | Default | Descripción | Ejemplo |
|-----------|-------|------|---------|-------------|---------|
| `--output` | `-o` | String | `None` | Ruta del archivo de salida | `-o resultado.json` |
| `--report` | - | Choice | `json` | Formato del reporte (json/html/csv) | `--report html` |

### 5.6 Argumentos de Configuración Avanzada

| Argumento | Corto | Tipo | Default | Descripción | Caso de Uso |
|-----------|-------|------|---------|-------------|-------------|
| `--verbose` | `-v` | Flag | `False` | Habilitar modo detallado con debug | Troubleshooting |
| `--no-ui` | - | Flag | `False` | Deshabilitar interfaz gráfica interactiva | Automatización/CI-CD |
| `--log-file` | - | String | `None` | Ruta del archivo de logging | Auditoría y trazabilidad |
| `--theme` | - | Choice | `cyberpunk` | Tema visual de la interfaz | Personalización |
| `--no-version-detect` | - | Flag | `False` | Deshabilitar detección de versiones | Escaneo más rápido |
| `--no-os-detect` | - | Flag | `False` | Deshabilitar detección de sistema operativo | Reducción de ruido |
| `--help` | `-h` | Flag | `False` | Mostrar menú de ayuda | Consulta rápida |

---

## **6. PERFILES DE ESCANEO**

### 6.1 Perfiles Predefinidos Disponibles

| Perfil | Puertos Incluídos | Cantidad | Uso Recomendado | Tiempo Estimado* |
|--------|------------------|----------|-----------------|-----------------|
| `quick` | 21,22,23,25,80,110,143,443,445,3306,3389,8080 | 12 | Reconocimiento inicial rápido | < 30 segundos |
| `web` | 80,443,8080,8443,3000,5000,8000,8888,9000,9090 | 10 | Auditoría de servidores web | < 25 segundos |
| `database` | 3306,5432,1433,27017,6379,9042,11211,1521 | 8 | Evaluación de bases de datos | < 20 segundos |
| `remote` | 22,23,3389,5900,5901,5985,5986,2222 | 8 | Servicios de acceso remoto | < 20 segundos |
| `mail` | 25,110,143,465,587,993,995,2525 | 8 | Servicios de correo electrónico | < 20 segundos |
| `file` | 21,139,445,2049,135,137,138,139 | 8 | Servicios de archivos compartidos | < 20 segundos |
| `dns` | 53,853,5353 | 3 | Servidores de nombres de dominio | < 10 segundos |
| `industrial` | 502,1911,1962,2455,44818,50000 | 6 | Sistemas SCADA/Industrial | < 15 segundos |
| `iot` | 1883,8883,18830,5683,5684 | 5 | Dispositivos IoT/Embedded | < 15 segundos |
| `full` | 1-1024 | 1024 | Escaneo completo de puertos bien conocidos | 3-10 minutos |
| `top100` | 100 puertos más comunes según estadísticas | 100 | Balance velocidad/cobertura | 1-3 minutos |

*\*Tiempos estimados con configuración default (300 threads, timeout 1.0s) en red local.*

### 6.2 Uso de Perfiles

```bash
# Escaneo rápido de reconocimiento
python lilit.py 192.168.1.1 --profile quick

# Auditoría específica de servidores web
python lilit.py target.com --profile web

# Evaluación de infraestructura de bases de datos
python lilit.py 192.168.1.50 --profile database

# Escaneo completo para auditoría exhaustiva
python lilit.py 192.168.1.1 --profile full
```

### 6.3 Creación de Perfiles Personalizados

 **Consejo:** Para necesidades específicas, combine el argumento `-p` con rangos personalizados:

```bash
# Perfil personalizado para entorno cloud
python lilit.py 10.0.0.0/24 -p 22,80,443,3000-3100,8080,8443

# Perfil para auditoría de contenedores
python lilit.py k8s-node.local -p 2379,2380,6443,10250,30000-32767
```

---

## **7. OPCIONES AVANZADAS**

### 7.1 Escaneo UDP

```bash
# Escaneo UDP de puerto DNS (53)
python lilit.py 192.168.1.1 -p 53 -u

# Escaneo UDP de múltiples puertos
python lilit.py 192.168.1.1 -p 53,123,161 -u
```

 **Advertencia:** El escaneo UDP requiere privilegios de administrador:
- **Windows:** Ejecutar terminal como "Administrador"
- **Linux/macOS:** Usar `sudo` o ejecutar como root

### 7.2 Modo Sigiloso (Stealth)

```bash
# Activar modo sigiloso con delays aleatorios
python lilit.py 192.168.1.1 --stealth

# Combinar con threads reducidos para mayor discreción
python lilit.py 192.168.1.1 --stealth --threads 100
```

**Características del modo stealth:**
- Delays aleatorios entre 0.3-1.5 segundos por conexión
- Reduce probabilidad de detección por IDS/IPS
- Ideal para entornos productivos sensibles
- Incrementa tiempo total de escaneo

### 7.3 Ajuste de Concurrencia

```bash
# Reducir threads para evitar saturación de red
python lilit.py 192.168.1.1 --threads 150

# Aumentar threads para redes de alta capacidad
python lilit.py 192.168.1.1 --threads 500

# Valor máximo permitido: 500 (límite de seguridad)
```

 **Recomendación:** Ajuste `--threads` según:
- Ancho de banda disponible
- Capacidad del target para manejar conexiones
- Políticas de tasa de la organización

### 7.4 Ajuste de Timeout

```bash
# Timeout aumentado para redes con alta latencia
python lilit.py 192.168.1.1 --timeout 3.0

# Timeout reducido para redes locales rápidas
python lilit.py 192.168.1.1 --timeout 0.5
```

**Impacto del timeout:**
| Valor | Ventaja | Desventaja |
|-------|---------|------------|
| Bajo (0.5s) | Escaneo más rápido | Posibles falsos negativos |
| Default (1.0s) | Balance óptimo | - |
| Alto (3.0s+) | Mayor precisión | Escaneo más lento |

### 7.5 Logging y Auditoría

```bash
# Logging básico a archivo
python lilit.py 192.168.1.1 --log-file audit.log

# Logging detallado con modo verbose
python lilit.py 192.168.1.1 -v --log-file debug.log

# Combinar con reporte para trazabilidad completa
python lilit.py 192.168.1.1 --log-file audit.log -o resultado.json
```

**Estructura de logs:**
```
[HH:MM:SS] - LILIT - INFO - Motor inicializado para 192.168.1.1 (1024 puertos)
[HH:MM:SS] - LILIT - DEBUG - Target 192.168.1.1 resuelto a 192.168.1.1
[HH:MM:SS] - LILIT - INFO - Escaneo completado: 1024 puertos
```

### 7.6 Deshabilitar Detecciones para Mayor Velocidad

```bash
# Sin detección de versión de servicios (más rápido)
python lilit.py 192.168.1.1 --no-version-detect

# Sin detección de sistema operativo
python lilit.py 192.168.1.1 --no-os-detect

# Sin interfaz gráfica (modo CLI puro para automatización)
python lilit.py 192.168.1.1 --no-ui
```

---

## **8. GENERACIÓN E INTERPRETACIÓN DE REPORTES**

### 8.1 Formatos de Reporte Disponibles

| Formato | Extensión | Tamaño Promedio | Uso Recomendado | Ventajas |
|---------|-----------|-----------------|-----------------|----------|
| **JSON** | `.json` | 50-500 KB | Integración con SIEM/SOAR, procesamiento automatizado | Estructurado, parseable, ligero |
| **HTML** | `.html` | 100-800 KB | Presentación a clientes, informes ejecutivos | Dashboard visual, interactivo, profesional |
| **CSV** | `.csv` | 10-100 KB | Análisis en Excel, hojas de cálculo, importación | Compatible universal, fácil de filtrar |

### 8.2 Comandos de Generación

```bash
# Reporte JSON (formato por defecto)
python lilit.py 192.168.1.1 -o resultado.json --report json

# Reporte HTML con dashboard visual
python lilit.py 192.168.1.1 -o informe.html --report html

# Reporte CSV para análisis en Excel
python lilit.py 192.168.1.1 -o datos.csv --report csv

# Combinar con logging para trazabilidad completa
python lilit.py 192.168.1.1 -o resultado.json --report json --log-file audit.log
```

### 8.3 Estructura del Reporte JSON

```json
{
  "metadata": {
    "tool": "LILIT",
    "version": "4.0.0",
    "codename": "NEURAL STORM PRO",
    "author": "Nexus Core Security Team",
    "generated_at": "2025-01-15T10:30:00",
    "build_date": "2025"
  },
  "target": {
    "hostname": "192.168.1.1",
    "ip": "192.168.1.1",
    "os_detected": "Linux"
  },
  "scan_info": {
    "start_time": "2025-01-15T10:30:00",
    "end_time": "2025-01-15T10:35:00",
    "duration": 300.5,
    "profile": "web",
    "protocol": "TCP",
    "stealth_mode": false
  },
  "statistics": {
    "total_ports": 10,
    "scanned": 10,
    "open": 3,
    "closed": 7,
    "high_risk": 1,
    "medium_risk": 1,
    "low_risk": 1,
    "success_rate": 30.0
  },
  "vulnerabilities": [
    [21, "FTP", "FTP Anonymous Login"],
    [445, "SMB", "SMB expuesto - Verificar EternalBlue"]
  ],
  "all_results": [
    {
      "port": 21,
      "protocol": "TCP",
      "status": "OPEN",
      "service": "FTP",
      "version": "vsftpd 2.3.4",
      "banner": "220 vsftpd 2.3.4",
      "risk_score": 0.85,
      "vulnerabilities": ["FTP Anonymous Login"],
      "cve_matches": ["CVE-2011-2523"]
    }
  ]
}
```

### 8.4 Interpretación de Resultados

#### 8.4.1 Niveles de Riesgo

| Nivel | Score | Color | Icono | Acción Recomendada |
|-------|-------|-------|-------|-------------------|
| **CRÍTICO** | > 0.7 | 🔴 Rojo | ⚠️ | Acción inmediata requerida. Parchear o aislar. |
| **ALERTA** | 0.4 - 0.7 | 🟠 Naranja | ⚡ | Revisar configuración. Priorizar en próximas 72h. |
| **ATENCIÓN** | 0.2 - 0.4 | 🟡 Amarillo | ⚠️ | Monitorear. Incluir en roadmap de hardening. |
| **SEGURO** | ≤ 0.2 | 🟢 Verde | ✓ | Normal. Mantener buenas prácticas. |

#### 8.4.2 Vulnerabilidades Comunes Detectadas

| Vulnerabilidad | Puerto(s) | CVE | Severidad | Remediation Recomendada |
|----------------|-----------|-----|-----------|------------------------|
| vsftpd 2.3.4 Backdoor | 21 | CVE-2011-2523 | 🔴 CRÍTICA | Actualizar a vsftpd 3.0+ |
| Apache Path Traversal | 80/443 | CVE-2021-41773 | 🔴 CRÍTICA | Actualizar a Apache 2.4.51+ |
| SMB EternalBlue | 445 | CVE-2017-0144 | 🔴 CRÍTICA | Aplicar parche MS17-010 |
| FTP Anonymous Login | 21 | CONFIG | 🟠 ALTA | Deshabilitar acceso anónimo |
| Redis Sin Auth | 6379 | CONFIG | 🟠 ALTA | Configurar `requirepass` |
| MongoDB Sin Auth | 27017 | CONFIG | 🟠 ALTA | Habilitar autenticación |
| Telnet Expuesto | 23 | CONFIG | 🟠 ALTA | Migrar a SSH, deshabilitar Telnet |

#### 8.4.3 Métricas de Estadísticas Clave

| Métrica | Campo JSON | Descripción | Interpretación | Acción |
|---------|------------|-------------|----------------|--------|
| `duration` | `scan_info.duration` | Tiempo total del escaneo | Menor = más eficiente | Optimizar threads/timeout |
| `scanned` | `statistics.scanned` | Puertos procesados exitosamente | Debe igualar `total_ports` | Investigar discrepancias |
| `open` | `statistics.open` | Puertos respondiendo como OPEN | Mayor = mayor superficie de ataque | Revisar necesidad de cada servicio |
| `high_risk` | `statistics.high_risk` | Puertos con score > 0.7 | Prioridad máxima de remediation | Parchear/aislar inmediatamente |
| `success_rate` | `statistics.success_rate` | Porcentaje de respuestas exitosas | Mayor = mejor visibilidad | Ajustar timeout si es baja |

---

## **9. TEMAS VISUALES Y PERSONALIZACIÓN**

### 9.1 Temas Disponibles

| Tema | Paleta de Colores | Uso Recomendado | Ejemplo de Contexto |
|------|-------------------|-----------------|-------------------|
| **`cyberpunk`** | Verde neón (#00ff9d), Púrpura (#bd00ff), Cian (#00d9ff) | Default, presentaciones técnicas, entornos de desarrollo | Terminal futurista con alto contraste |
| **`matrix`** | Verde clásico (#00ff00), Negro (#000000) | Auditorías técnicas, entornos tipo terminal clásico | Estilo "hacker" tradicional |
| **`corporate`** | Azul profesional (#0066cc), Blanco (#ffffff) | Informes ejecutivos, presentaciones a stakeholders | Estilo limpio y profesional |

### 9.2 Comandos de Aplicación de Temas

```bash
# Tema cyberpunk (default)
python lilit.py 192.168.1.1 --theme cyberpunk

# Tema matrix
python lilit.py 192.168.1.1 --theme matrix

# Tema corporate
python lilit.py 192.168.1.1 --theme corporate
```

### 9.3 Personalización Avanzada (v5.0 Enterprise)

 **Para usuarios de LILIT v5.0 Enterprise:** Los temas pueden personalizarse editando el archivo de configuración `~/.lilit/config.json`:

```json
{
  "theme": {
    "name": "custom",
    "colors": {
      "primary": "#00ff9d",
      "secondary": "#bd00ff",
      "alert": "#ff0055"
    }
  }
}
```

---

## **10. EJEMPLOS PRÁCTICOS DE USO**

### 10.1 Auditoría Web Completa

```bash
# Escaneo de servidores web con reporte HTML profesional
python lilit.py empresa.com --profile web -o web_audit.html --report html --theme corporate
```

**Resultado esperado:**
- Dashboard HTML interactivo con estadísticas visuales
- Tabla de puertos abiertos con niveles de riesgo codificados por color
- Listado de vulnerabilidades detectadas con CVEs asociados

### 10.2 Escaneo de Base de Datos con Logging

```bash
# Auditoría de infraestructura de BD con trazabilidad completa
python lilit.py 192.168.1.50 --profile database --stealth -o db_scan.json --log-file db_audit.log
```

**Características:**
- Modo sigiloso para evitar alertas en producción
- Logging detallado para cumplimiento de auditoría
- Reporte JSON para integración con SIEM

### 10.3 Auditoría DNS (UDP)

```bash
# Windows (ejecutar como Administrador):
python lilit.py 192.168.1.1 -p 53 -u -o dns_audit.json

# Linux/macOS:
sudo python lilit.py 192.168.1.1 -p 53 -u -o dns_audit.json
```

**Notas:**
- Requiere privilegios elevados para sockets UDP raw
- Útil para evaluar exposición de servicios DNS internos

### 10.4 Escaneo Sigiloso de Producción

```bash
# Escaneo completo con máxima discreción
python lilit.py 192.168.1.1 --profile full --stealth --threads 200 --timeout 1.5 -o full_audit.html --report html
```

**Parámetros optimizados:**
- `--stealth`: Delays aleatorios para evadir detección
- `--threads 200`: Concurrencia moderada para no saturar
- `--timeout 1.5`: Balance entre precisión y velocidad

### 10.5 Escaneo Rápido de Reconocimiento

```bash
# Reconocimiento inicial sin UI para automatización
python lilit.py target.com --profile quick --no-ui -o quick_scan.json
```

**Casos de uso:**
- Integración en pipelines CI/CD
- Scripts de monitoreo automatizado
- Evaluaciones periódicas programadas

### 10.6 Escaneo con Logging Completo para Compliance

```bash
# Auditoría con trazabilidad completa para ISO 27001 / PCI-DSS
python lilit.py 192.168.1.1 --profile web -v --log-file audit.log -o resultado.json --theme corporate
```

**Elementos de compliance:**
- Logging detallado (`-v`) para trazabilidad
- Reporte JSON estructurado para evidencia documental
- Tema corporate para presentación ejecutiva

---

## **11. SOLUCIÓN DE PROBLEMAS**

### 11.1 Errores Comunes y Soluciones

| Error | Causa Probable | Solución | Prevención |
|-------|----------------|----------|------------|
| `NameError: name 'ScanResult' is not defined` | Orden incorrecto de definición de clases en código | Asegurar que `ScanResult` y `ScanSession` estén definidos ANTES de `LilitEngine` | Usar versión oficial corregida |
| `PermissionError: [Errno 13] Permission denied` | Sin privilegios para escaneo UDP o binding de puertos bajos | Ejecutar como Administrador (Windows) o con `sudo` (Linux) | Verificar permisos antes de escaneo UDP |
| `Target inválido` | Formato incorrecto de IP o dominio | Verificar sintaxis: `192.168.1.1` o `empresa.com` | Usar `SecurityValidator.validate_target()` |
| `Timeout` | Red lenta, firewall bloqueando, target no responde | Aumentar `--timeout 3.0` o reducir `--threads` | Testear conectividad con `ping` primero |
| `Sin resultados` | Firewall bloqueando, target offline, puertos filtrados | Verificar conectividad, probar con `-p 80` primero | Incluir check de conectividad en script |
| `MarkupError` (Rich) | Tags de formato mal cerrados en código | Actualizar a versión corregida o revisar strings con formato Rich | Usar f-strings con cuidado en mensajes |
| `ModuleNotFoundError: No module named 'rich'` | Dependencia no instalada | Ejecutar `pip install rich` | Incluir `requirements.txt` en distribución |

### 11.2 Comandos de Diagnóstico

```bash
# Verificar conectividad básica al target
ping 192.168.1.1

# Verificar resolución DNS
nslookup target.com
# O en Linux:
dig target.com

# Probar escaneo mínimo para validar instalación
python lilit.py 192.168.1.1 -p 80 --no-ui

# Verificar versión de Python y pip
python --version
pip --version

# Verificar instalación de dependencias
pip list | findstr rich
# O en Linux:
pip list | grep rich

# Verificar permisos de administrador
# Windows:
whoami /groups | findstr Administrators
# Linux/macOS:
sudo whoami
```

### 11.3 Procedimiento de Troubleshooting Paso a Paso

```
DIAGNÓSTICO DE PROBLEMAS EN LILIT

Paso 1: Verificar instalación de Python
        → Ejecutar: python --version
        → Esperado: Python 3.8.0 o superior
        → Si falla: Instalar Python 3.8+ desde python.org

Paso 2: Verificar dependencias
        → Ejecutar: pip install rich
        → Verificar: pip list | findstr rich
        → Si falla: Activar entorno virtual primero

Paso 3: Probar comando básico
        → Ejecutar: python lilit.py --help
        → Esperado: Menú de ayuda con banner
        → Si falla: Revisar permisos de ejecución del archivo

Paso 4: Verificar conectividad al target
        → Ejecutar: ping <target>
        → Esperado: Respuestas ICMP exitosas
        → Si falla: Verificar firewall, routing, target online

Paso 5: Probar escaneo mínimo
        → Ejecutar: python lilit.py 127.0.0.1 -p 80 --no-ui
        → Esperado: Resultado de escaneo de localhost
        → Si falla: Revisar logs con -v --log-file debug.log

Paso 6: Revisar logs de error
        → Ejecutar: python lilit.py <target> -v --log-file debug.log
        → Analizar: Archivo debug.log para stack trace
        → Acción: Buscar patrones de error conocidos en Sección 11.1

Paso 7: Contactar soporte (si persiste)
        → Email: abdiassamuel15@gmail.com
        → GitHub: https://github.com/anonimous264
        → Incluir: Versión de LILIT, SO, Python, comando ejecutado, log de error
```

### 11.4 Contacto de Soporte Técnico

| Canal | Información | Horario de Atención |
|-------|-------------|---------------------|
| **Email** | abdiassamuel15@gmail.com | Lunes-Viernes, 9:00-18:00 UTC |
| **GitHub Issues** | https://github.com/anonimous264 | 24/7 (asíncrono) |
| **Documentación** | https://github.com/anonimous264 Actualizada continuamente |
| **Comunidad** | Discord: nexus-core.security | Comunidad global, horarios variables |

---

## **12. CONSIDERACIONES LEGALES Y ÉTICAS**

### 12.1 Marco Legal Aplicable

| Jurisdicción | Legislación | Artículo/Sección | Sanción Potencial |
|--------------|-------------|------------------|-------------------|
| **España** | Ley Orgánica 10/1995 (Código Penal) | Art. 197-201 (Delitos informáticos) | 1-5 años de prisión + multa |
| **Estados Unidos** | Computer Fraud and Abuse Act (CFAA) | 18 U.S.C. § 1030 | Hasta 10 años de prisión + multa |
| **Unión Europea** | Directiva NIS2 | 2022/2555 | Multas hasta 10M€ o 2% de facturación |
| **Internacional** | Convención de Budapest | ETS No. 185 | Variable según país signatario |

### 12.2 Requisitos de Autorización Previa

Antes de ejecutar LILIT contra cualquier sistema, el auditor **DEBE** obtener:

```
 CHECKLIST DE AUTORIZACIÓN

□ 1. Consentimiento por escrito del propietario legal del sistema
   → Documento firmado con nombre, cargo, fecha y alcance

□ 2. Alcance definido explícitamente
   → IPs/domains autorizados, puertos permitidos, ventanas de tiempo

□ 3. Ventana de mantenimiento acordada
   → Horario de menor impacto operacional, notificación a stakeholders

□ 4. Contacto de emergencia identificado
   → Nombre, teléfono, email de responsable técnico para incidentes

□ 5. Plan de rollback preparado
   → Procedimiento para revertir cambios en caso de impacto no deseado

□ 6. Registro de auditoría habilitado
   → Uso de --log-file para trazabilidad de todas las acciones ejecutadas
```

### 12.3 Código de Ética Profesional Nexus Core

```
┌─────────────────────────────────────────────────────────────────┐
│              PRINCIPIOS ÉTICOS OBLIGATORIOS                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1 CONFIDENCIALIDAD                                          │
│     • No divulgar información obtenida durante auditorías      │
│     • Proteger reportes con cifrado y control de acceso        │
│     • Destruir datos temporales post-auditoría                 │
│                                                                 │
│  2 INTEGRIDAD                                                │
│     • No modificar sistemas sin autorización explícita         │
│     • Reportar hallazgos de forma objetiva y verificable       │
│     • No exagerar ni minimizar riesgos por intereses externos  │
│                                                                 │
│  3 LEGALIDAD                                                 │
│     • Operar estrictamente dentro del marco jurídico aplicable │
│     • Obtener y conservar documentación de autorización        │
│     • Consultar asesoría legal en casos de duda jurídica       │
│                                                                 │
│  4 RESPONSABILIDAD                                           │
│     • Reportar hallazgos críticos de manera oportuna           │
│     • Asumir responsabilidad por acciones ejecutadas           │
│     • Documentar decisiones técnicas y sus fundamentos         │
│                                                                 │
│  5 PROFESIONALISMO                                           │
│     • Mantener estándares técnicos de la industria             │
│     • Actualizar conocimientos y herramientas continuamente    │
│     • Colaborar con la comunidad de seguridad de forma ética   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 12.4 Descargo de Responsabilidad Legal

```
ADVERTENCIA LEGAL OFICIAL

LOS AUTORES Y COLABORADORES DE LILIT NO SE RESPONSABILIZAN POR:

• El uso indebido, malicioso o no autorizado de esta herramienta
• Daños directos o indirectos derivados de su ejecución
• Consecuencias legales derivadas de su uso sin consentimiento
• Pérdida de datos, interrupción de servicios o impactos operacionales

EL USUARIO ASUME TODA LA RESPONSABILIDAD LEGAL, CIVIL Y PENAL POR:

• Las acciones ejecutadas con LILIT
• Los sistemas contra los cuales se dirige la herramienta
• El cumplimiento de legislaciones locales, nacionales e internacionales

EL USO NO AUTORIZADO DE ESTA HERRAMIENTA PUEDE CONSTITUIR UN DELITO
SEGÚN LAS LEYES APLICABLES EN SU JURISDICCIÓN. CONSULTE CON ASESORÍA
LEGAL ANTES DE SU IMPLEMENTACIÓN EN ENTORNOS PRODUCTIVOS.
```

---

## **13. APÉNDICES**

### Apéndice A: Checklist Pre-Auditoría

```
 LISTA DE VERIFICACIÓN PRE-AUDITORÍA LILIT

□ 1. AUTORIZACIÓN Y ALCANCE
   □ Consentimiento por escrito firmado y archivado
   □ Lista de IPs/domains autorizados documentada
   □ Puertos y protocolos permitidos especificados
   □ Ventana de tiempo acordada y comunicada

□ 2. PREPARACIÓN TÉCNICA
   □ Entorno de ejecución configurado (Python 3.8+, rich instalada)
   □ Herramienta LILIT actualizada a última versión estable
   □ Prueba de conectividad al target ejecutada exitosamente
   □ Escaneo de prueba en entorno de laboratorio validado

□ 3. CONFIGURACIÓN DE EJECUCIÓN
   □ Perfil de escaneo seleccionado según objetivos
   □ Parámetros de rendimiento ajustados (threads, timeout)
   □ Modo stealth habilitado si aplica a entorno productivo
   □ Logging habilitado con --log-file para trazabilidad

□ 4. SEGURIDAD OPERACIONAL
   □ Plan de rollback documentado y probado
   □ Contacto de emergencia identificado y disponible
   □ Notificación a stakeholders ejecutada según política
   □ Backup de sistemas críticos verificado (si aplica)

□ 5. POST-EJECUCIÓN
   □ Reporte generado en formato requerido (JSON/HTML/CSV)
   □ Hallazgos críticos comunicados inmediatamente al responsable
   □ Logs archivados según política de retención organizacional
   □ Evidencia de auditoría protegida con controles de acceso
```

### Apéndice B: Glosario de Términos Técnicos

| Término | Definición | Contexto en LILIT |
|---------|------------|-------------------|
| **Banner Grabbing** | Técnica para obtener información de servicios mediante conexión y lectura de respuesta inicial | LILIT envía probes y analiza respuestas para identificar servicio/versión |
| **CVE** | Common Vulnerabilities and Exposures: Identificador único para vulnerabilidades de seguridad públicas | LILIT matchea banners contra base de datos CVE para alertar vulnerabilidades conocidas |
| **Risk Score** | Puntuación numérica (0.0-1.0) que cuantifica el nivel de riesgo de un hallazgo | Calculado multifactorialmente: puerto crítico, servicio sin cifrar, CVE conocido, etc. |
| **Stealth Mode** | Modo de operación que introduce delays aleatorios para reducir probabilidad de detección | Útil en entornos productivos con IDS/IPS sensibles |
| **CPE** | Common Platform Enumeration: Esquema estandarizado para identificar productos/software | Base para búsqueda de vulnerabilidades en base de datos (v1.0 Enterprise) |
| **Compliance Framework** | Conjunto de controles y requisitos para cumplimiento normativo (PCI-DSS, ISO27001, etc.) | LILIT v1.0 incluye motor de evaluación contra frameworks predefinidos |

### Apéndice C: Plantilla de Autorización de Escaneo

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                 AUTORIZACIÓN DE ESCANEO DE SEGURIDAD                         ║
║                              LILIT v1.0                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║ Yo, ________________________________, en mi calidad de                      ║
║ ________________________________ de la organización                         ║
║ ________________________________, autorizo expresamente                     ║
║ al auditor ________________________________ a realizar                      ║
║ escaneos de seguridad con la herramienta LILIT en los siguientes sistemas:  ║
║                                                                              ║
║  SISTEMAS AUTORIZADOS:                                                       ║
║  1. ________________________________ (IP: _______________)                  ║
║  2. ________________________________ (IP: _______________)                  ║
║  3. ________________________________ (IP: _______________)                  ║
║                                                                              ║
║  ALCANCE DEL ESCANEO:                                                        ║
║  □ Puertos: ________________________________                                ║
║  □ Protocolos: □ TCP  □ UDP  □ Ambos                                        ║
║  □ Perfiles: □ quick  □ web  □ database  □ full  □ custom                   ║
║                                                                              ║
║  VENTANA DE TIEMPO AUTORIZADA:                                               ║
║  Desde: ________________ Hasta: ________________                            ║
║  Zona Horaria: ________________                                             ║
║                                                                              ║
║  CONTACTO DE EMERGENCIA:                                                     ║
║  Nombre: ________________________________                                   ║
║  Teléfono: ________________________________                                 ║
║  Email: ________________________________                                    ║
║                                                                              ║
║  DECLARACIÓN DE RESPONSABILIDAD:                                             ║
║  El firmante declara que tiene autoridad legal para autorizar este escaneo   ║
║  y asume responsabilidad por las consecuencias de su ejecución dentro del    ║
║  alcance definido.                                                           ║
║                                                                              ║
║  Firma: ________________________________                                    ║
║  Nombre: ________________________________                                   ║
║  Cargo: ________________________________                                    ║
║  Fecha: ________________________________                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```