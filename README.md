#  Analizador Avanzado de Contratos Inteligentes

![Rust](https://img.shields.io/badge/rust-stable-orange)

Herramienta profesional desarrollada en Rust para el análisis exhaustivo de contratos inteligentes en la red Ethereum. Diseñada para detectar patrones sospechosos, evaluar riesgos de seguridad y proporcionar informes detallados sobre posibles vulnerabilidades.

##  Características Principales

###  Análisis Profundo
- Detección de más de 50 patrones de código sospechosos
- Análisis estático de bytecode y código fuente
- Evaluación de permisos y controles de acceso
- Detección de funciones peligrosas y patrones de ataque conocidos

###  Evaluación de Riesgos
- Sistema de puntuación de riesgo detallado
- Clasificación por niveles de gravedad (Crítico, Alto, Medio, Bajo, Informativo)
- Análisis de dependencias y librerías externas
- Detección de códigos ofuscados o sospechosos

###  Integración y Compatibilidad
- Soporte para múltiples redes Ethereum (Mainnet, Ropsten, Rinkeby, etc.)
- Compatible con nodos locales (Geth, Parity) y servicios en la nube (Infura, Alchemy)
- API REST para integración con otras herramientas
- Plugins para IDEs populares (VS Code, IntelliJ)

##  Requisitos del Sistema

### Requisitos Mínimos
- Rust 1.70 o superior
- 4GB RAM mínimo (8GB recomendado)
- 1GB de espacio en disco
- Conexión a Internet para análisis en tiempo real

### Dependencias
- OpenSSL
- Git
- CMake
- pkg-config

##  Instalación

### Método 1: Desde Fuentes (Recomendado)
```bash
# Clonar el repositorio
git clone https://github.com/quantumvortex369/smart-contract-analyzer.git
cd smart-contract-analyzer

# Instalar dependencias del sistema
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libssl-dev

# Construir en modo release
cargo build --release
```

### Método 2: Usando Docker
```bash
docker pull quantumvortex369/smart-contract-analyzer:latest
docker run -it quantumvortex369/smart-contract-analyzer --help
```

##  Guía de Uso

### Análisis Básico
```bash
# Analizar un contrato específico
./target/release/smart_contract_analyzer analyze \
  --address 0x742d35Cc6634C0532925a3b844Bc454e4438f44e \
  --rpc-url https://mainnet.infura.io/v3/TU_API_KEY
```

### Análisis Avanzado
```bash
# Análisis completo con informe detallado en formato JSON
./target/release/smart_contract_analyzer analyze \
  --address 0x742d35Cc6634C0532925a3b844Bc454e4438f44e \
  --rpc-url https://mainnet.infura.io/v3/TU_API_KEY \
  --output json \
  --full-scan \
  --check-upgrades \
  --simulate-attacks
```

### Monitoreo Continuo
```bash
# Monitorear direcciones en tiempo real
./target/release/smart-contract-analyzer monitor \
  --watchlist watchlist.txt \
  --interval 300 \
  --webhook https://tuservidor.com/webhook
```

##  Opciones de Línea de Comandos

### Comandos Principales
- `analyze`: Analiza un contrato específico
- `monitor`: Monitorea múltiples contratos
- `scan`: Escanea una lista de contratos
- `report`: Genera informes a partir de análisis previos

### Opciones Comunes
- `-a, --address`: Dirección del contrato (0x...)
- `-r, --rpc-url`: URL del nodo RPC
- `-o, --output`: Formato de salida (text, json, html, markdown)
- `-c, --config`: Archivo de configuración personalizado
- `-v, --verbose`: Nivel de verbosidad (0-4)

##  Ejemplo de Salida

```
 Análisis de Contrato Inteligente
═════════════════════════════════

 Información Básica
   • Contrato: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
   • Red: Ethereum Mainnet
   • Bloques analizados: 15,742,821 - 15,742,831
   • Tiempo de análisis: 2.45s

 Puntuación de Seguridad
   • Total: 68/100  (Medio-Alto)
   • Seguridad: 72/100
   • Optimización: 64/100
   • Buenas Prácticas: 59/100

 Hallazgos Críticos (3)
   [CRIT-001] Reentrancia en función withdraw()
      • Archivo: contracts/Vault.sol:142
      • Línea: 142-158
      • Impacto: Alto
      • Solución: Implementar el patrón Checks-Effects-Interactions

   [CRIT-002] Uso de transfer() en lugar de call()
      • Archivo: contracts/Payment.sol:87
      • Línea: 87-93
      • Impacto: Medio
      • Solución: Reemplazar por call{value: amount}("") con manejo de errores

 Hallazgos de Seguridad (7)
   [SEC-004] Función updateAdmin sin protección
   [SEC-008] Uso de block.timestamp
   [SEC-015] Llamadas a contratos externos sin manejo de errores
   ...

 Recomendaciones (5)
   • Implementar pausa de emergencia
   • Agregar límites de tasa (rate limiting)
   • Mejorar la documentación NatSpec
   ...

 Recursos Adicionales
   • Reporte completo: analysis_0x742d...f44e_20231026.json
   • Transacciones sospechosas: 3 encontradas
   • Eventos inusuales: 12 detectados
```



##  Dependencias Principales

- `eframe`: Para la interfaz gráfica
- `ethers-rs`: Para interactuar con la red Ethereum
- `serde`: Para serialización/deserialización
- `tokio`: Para operaciones asíncronas


##  Contacto

Para preguntas o sugerencias, por favor abre un issue en el repositorio.

---

## Patrones detectados

¡Advertencia!  Este contrato ha sido marcado como sospechoso

Hallazgos:

[1] Posible transferencia forzada detectada
Severidad: ALTO
Descripción: Se encontró un patrón sospechoso: transferFrom\(address,address,uint256\)
Código: function transferFrom(address from, address to, uint256 amount) public returns (bool)


##  Patrones Sospechosos Detectados

El analizador implementa un sistema avanzado de detección de patrones sospechosos que incluye:

###  Patrones Críticos de Seguridad
- **Reentrancia**: Detección de patrones de reentrancia en funciones `withdraw` y `transfer`
- **Desbordamiento aritmético**: Operaciones matemáticas sin comprobación de desbordamiento
- **Llamadas delegadas inseguras**: Uso de `delegatecall` con parámetros controlados por el usuario
- **Auto-destrucción**: Uso de `selfdestruct` que podría ser explotado
- **Bloqueo de fondos**: Funciones `payable` sin forma de retirar fondos

###  Patrones de Riesgo Medio
- **Transferencias forzadas**: Uso de `transferFrom` sin verificación de aprobación
- **Auto-aprobaciones sospechosas**: Llamadas a `approve` que podrían ser usadas para drenar fondos
- **Tiempos de bloqueo**: Uso de `block.timestamp` o `block.number` para decisiones críticas
- **Direcciones hardcodeadas**: Direcciones fijas que podrían ser puntos de fallo
- **Contratos no verificados**: Interacción con contratos cuyo código fuente no está verificado

###  Patrones de Comportamiento Sospechoso
- **Lógica oculta**: Uso excesivo de `assembly` o código ofuscado
- **Funciones ocultas**: Funciones con nombres engañosos o que no realizan lo esperado
- **Lógica de actualización sospechosa**: Mecanismos de actualización que podrían ser explotados
- **Manejo inadecuado de permisos**: Funciones administrativas sin restricciones de acceso
- **Eventos de depuración**: Eventos que podrían filtrar información sensible

###  Análisis de Comportamiento
- **Patrones de transferencia inusuales**: Transacciones que siguen patrones de lavado
- **Interacciones con mezcladores**: Conexiones con contratos de mezcla de criptomonedas
- **Actividad reciente**: Contratos recién desplegados con mucho volumen
- **Patrones de aprobación sospechosos**: Múltiples aprobaciones a direcciones desconocidas

##  Guía de Contribución

¡Agradecemos tu interés en contribuir al proyecto! Sigue estos pasos para contribuir de manera efectiva:

###  Configuración del Entorno
1. Haz un fork del repositorio
2. Clona tu fork localmente:
   ```bash
   git clone https://github.com/quantumvortex369/smart-contract-analyzer.git
   cd smart-contract-analyzer
   ```
3. Configura el entorno de desarrollo:
   ```bash
   rustup update
   cargo build
   ```

###  Proceso de Contribución
1. Crea una nueva rama para tu característica o corrección:
   ```bash
   git checkout -b feature/nueva-funcionalidad
   ```
2. Desarrolla tu código siguiendo las guías de estilo
3. Añade pruebas unitarias para tu código
4. Asegúrate de que todas las pruebas pasen:
   ```bash
   cargo test
   ```
5. Envía un Pull Request con una descripción clara de los cambios

###  Ejecutando Pruebas
- Ejecuta todas las pruebas: `cargo test`
- Ejecuta pruebas específicas: `cargo test test_nombre_del_test`
- Para cobertura de código (requiere `tarpaulin`):
  ```bash
  cargo install cargo-tarpaulin
  cargo tarpaulin --ignore-tests
  ```

###  Estándares de Código
- Sigue el [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Documenta todo el código público con comentarios `///`
- Mantén las funciones pequeñas y enfocadas en una sola responsabilidad
- Escribe pruebas unitarias para toda la lógica de negocio

###  Reportando Errores
Por favor, incluye la siguiente información al reportar un error:
1. Versión de Rust (`rustc --version`)
2. Pasos para reproducir el error
3. Comportamiento esperado vs. comportamiento actual
4. Capturas de pantalla o logs relevantes

###  Solicitando Características
Para solicitar una nueva característica:
1. Verifica que no exista un issue similar
2. Describe la funcionalidad deseada en detalle
3. Explica por qué esta característica sería útil
4. Incluye ejemplos de uso si es posible

###  Código de Conducta
Este proyecto sigue el [Código de Conducta del Contribuidor](https://www.contributor-covenant.org/). Al participar, se espera que cumplas con este código.
