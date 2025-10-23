# Analizador de Contratos Inteligentes

Herramienta en Rust para analizar contratos inteligentes de Ethereum y detectar posibles estafas o comportamientos maliciosos.

## Características

- Detección de patrones comunes en contratos maliciosos
- Análisis de código de contratos inteligentes
- Puntuación de riesgo basada en hallazgos
- Soporte para salida en formato texto y JSON
- Fácil integración con nodos Ethereum

## Requisitos

- Rust 1.70 o superior
- Un nodo Ethereum (o acceso a uno a través de Infura, Alchemy, etc.)

## Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/quantumvortex369/smart-contract-analyzer.git
   cd smart-contract-analyzer
   ```

2. Construye el proyecto:
   ```bash
   cargo build --release
   ```

## Uso

### Analizar un contrato

```bash
./target/release/smart_contract_analyzer --address 0x1234... --rpc-url TU_URL_RPC
```

### Opciones

- `-a, --address`: Dirección del contrato a analizar (requerido)
- `-r, --rpc-url`: URL del nodo Ethereum RPC (por defecto: Infura mainnet)
- `-o, --output`: Formato de salida (`text` o `json`)

### Ejemplo de salida

```
Análisis de Contrato Inteligente
Contrato: 0x1234...
Verificado: Sí
Puntuación de riesgo: 75.00% (Alto)

¡Advertencia! ⚠️ Este contrato ha sido marcado como sospechoso

Hallazgos:

[1] Posible transferencia forzada detectada
Severidad: ALTO
Descripción: Se encontró un patrón sospechoso: transferFrom\(address,address,uint256\)
Código: function transferFrom(address from, address to, uint256 amount) public returns (bool)
```

## Patrones detectados

El analizador busca los siguientes patrones sospechosos:

- Transferencias forzadas (`transferFrom`)
- Auto-aprobaciones (`approve`)
- Direcciones hardcodeadas
- Uso de `selfdestruct`
- Llamadas `delegatecall` con entrada de usuario
- Contratos no verificados

## Contribución

Las contribuciones son bienvenidas. Por favor, abre un issue para discutir los cambios propuestos antes de hacer un pull request.
