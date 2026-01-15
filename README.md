# sharkAnalyzer

Herramienta avanzada para análisis de tráfico de red con detección de anomalías mediante:
- **Detección tradicional**: Comparación contra baseline de tráfico normal
- **Detección por IA**: Agente basado en Isolation Forest para patrones complejos

## Instalación

```bash
# Crear y activar entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

## Uso

### 1. Crear baseline y ejecutar análisis básico

```bash
# Primer análisis (crea baseline automáticamente)
python main.py

# Análisis subsecuentes detectarán anomalías respecto al baseline
python main.py
```

### 2. Generar archivos .pcap de prueba (opcional)

```bash
# Crea 3 archivos .pcap con tráfico normal y anómalo en data/pcaps/
python generate_test_pcaps.py
```

### 3. Entrenar agente de IA con archivos .pcap

```bash
# Entrena el agente leyendo archivos .pcap de una carpeta
python demo_agent_training.py data/pcaps

# Opcionalmente limitar a N archivos (default: 5)
python demo_agent_training.py data/pcaps 10

# O usar la carpeta por defecto (PCAP_DIR en config.py)
python demo_agent_training.py

# El modelo se guarda en: models/anomaly_agent.pkl
```

**Nota:** Para archivos .pcap muy grandes, el script procesa máximo 10,000 paquetes por archivo para evitar exceso de memoria.

### 4. Usar agente entrenado en análisis en tiempo real

```bash
# Analiza nuevos pcaps usando el agente entrenado
python main.py train  # Reentrenar con nuevos datos si es necesario
```

## Cómo funciona el AnomalyAgent

El agente utiliza **Isolation Forest** (un algoritmo no supervisado) para detectar anomalías basadas en patrones estadísticos:

### Features utilizadas:
- `total`: Total de paquetes por IP
- `tcp`: Número de paquetes TCP
- `udp`: Número de paquetes UDP
- `port_count`: Cantidad de puertos únicos contactados
- `avg_port_traffic`: Promedio de tráfico por puerto

### Flujo en main.py:

1. **Parsear PCAP**: `parse_pcap()` extrae estadísticas de tráfico
2. **Convertir a registros**: `stats_to_records()` genera dicts con features
3. **Extraer features**: `extract_features_from_records()` crea DataFrame numérico
4. **Predecir**: `agent.predict()` devuelve 1 (anómalo) o 0 (normal)
5. **Loguear alertas**: Anómalías se escriben en `data/alerts.log`

### Archivos clave:

- `anomaly_agent.py`: Clase `AnomalyAgent` con métodos fit/predict/save/load
- `main.py`: Flujo principal que integra detección tradicional + IA
- `demo_agent_training.py`: **Lee archivos .pcap de una carpeta y entrena el agente**
- `generate_test_pcaps.py`: Genera archivos .pcap de prueba con tráfico normal + anómalo
- `config.py`: Configuración con rutas (MI_IP, PCAP_DIR, BASELINE_FILE)
- `models/anomaly_agent.pkl`: Modelo entrenado (creado tras ejecutar `demo_agent_training.py`)

## Flujo de trabajo típico

```
1. Colocar archivos .pcap → data/pcaps/
2. Ejecutar: python demo_agent_training.py data/pcaps [max_files]
3. Verificar modelo en: models/anomaly_agent.pkl
4. Usar en tiempo real: python main.py
```

El agente automáticamente:
- Lee los archivos .pcap de la carpeta especificada
- Extrae IPs y estadísticas de tráfico (total, TCP, UDP, puertos únicos)
- Detecta patrones anómalos (IPs con tráfico desusual, escaneo de puertos, etc.)
- Genera alertas combinadas con detección tradicional

## Configuración

Editar `config.py`:
- **MI_IP**: Tu dirección IP de red (debe coincidir con la de los pcaps)
- **PCAP_DIR**: Carpeta con archivos .pcap (default: `data/pcaps`)
- **BASELINE_FILE**: Archivo JSON con tráfico normal (default: `data/baseline.json`)
```