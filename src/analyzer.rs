use std::sync::Arc;
use std::time::{Instant, Duration};
use serde::{Deserialize, Serialize};
use lru::LruCache;
use once_cell::sync::Lazy;
use log::{info, warn};
use tokio::sync::Mutex;
use regex::Regex;
use ethers::types::H160;

use crate::error::{Result, AnalyzerError};

// Caché LRU para almacenar análisis recurrentes
static ANALYSIS_CACHE: Lazy<Mutex<LruCache<String, ContractAnalysis>>> = Lazy::new(|| {
    Mutex::new(LruCache::new(std::num::NonZeroUsize::new(100).unwrap()))
});

// Redes soportadas
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Network {
    Mainnet,
    Ropsten,
    Rinkeby,
    Goerli,
    Kovan,
    Custom(&'static str),
}

impl Network {
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Ropsten => "ropsten",
            Network::Rinkeby => "rinkeby",
            Network::Goerli => "goerli",
            Network::Kovan => "kovan",
            Network::Custom(s) => s,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ContractAnalysis {
    pub contract_address: String,
    pub is_verified: bool,
    pub findings: Vec<Finding>,
    pub risk_score: f32,
    pub is_suspicious: bool,
    pub contract_name: Option<String>,
    pub compiler_version: Option<String>,
    pub optimization_used: Option<bool>,
    pub proxy_implementation: Option<String>,
    pub token_standard: Option<String>,
    pub created_at_block: Option<u64>,
    pub last_activity: Option<u64>,
    pub transaction_count: u64,
    pub verified_source: Option<String>,
    pub abi: Option<serde_json::Value>,
    pub bytecode: Option<String>,
    pub opcodes: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Finding {
    /// Título del hallazgo
    pub title: String,
    
    /// Descripción detallada del hallazgo
    pub description: String,
    
    /// Nivel de severidad del hallazgo
    pub severity: Severity,
    
    /// Fragmento de código relacionado (si aplica)
    pub code_snippet: Option<String>,
    
    /// Referencia a documentación o estándares (EIP, CWE, etc.)
    pub reference: Option<String>,
    
    /// Impacto potencial del hallazgo
    pub impact: String,
    
    /// Recomendación para solucionar o mitigar el problema
    pub recommendation: Option<String>,
    
    /// Categoría del hallazgo (seguridad, optimización, etc.)
    pub category: Option<String>,
    
    /// Indica si el hallazgo es un falso positivo
    #[serde(default)]
    pub is_false_positive: bool,
    
    /// Fecha de detección
    pub detected_at: Option<chrono::DateTime<chrono::Utc>>,
    
    /// Estado de la corrección (pendiente, en progreso, corregido, etc.)
    pub status: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct VerificationInfo {
    is_verified: bool,
    contract_name: Option<String>,
    compiler_version: Option<String>,
    optimization_used: Option<bool>,
    source_code: Option<String>,
    abi: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default)]
struct ProxyInfo {
    is_proxy: bool,
    implementation_address: Option<String>,
    proxy_type: Option<String>, // EIP-1967, EIP-1822, etc.
}

#[derive(Debug, Clone, Default)]
struct TokenInfo {
    is_token: bool,
    standard: Option<String>, // ERC20, ERC721, ERC1155, etc.
    name: Option<String>,
    symbol: Option<String>,
    decimals: Option<u8>,
    total_supply: Option<String>,
}

#[derive(Debug, Clone)]
struct TransactionAnalysis {
    tx_count: u64,
    last_tx: Option<u64>,
    first_tx: Option<u64>,
    suspicious_patterns: Vec<Finding>,
}

#[derive(Debug, Clone)]
struct OwnershipInfo {
    owner: Option<String>,
    is_owner_eoa: bool,
    is_owner_contract: bool,
    is_owner_multisig: bool,
    is_owner_timelock: bool,
    admin_functions: Vec<String>,
    pausable: bool,
    upgradeable: bool,
}

pub struct ContractAnalyzer {
    known_scam_patterns: Vec<(Regex, Severity, &'static str, f32)>,
    rpc_url: String,
    network: Network,
    client: reqwest::Client,
    ethers_provider: Arc<ethers::providers::Provider<ethers::providers::Http>>,
}

impl ContractAnalyzer {
    pub fn new(rpc_url: &str, network: Network) -> Result<Self> {
        // Configurar el cliente HTTP
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        // Configurar el proveedor de ethers
        let provider = ethers::providers::Provider::<ethers::providers::Http>::try_from(rpc_url)
            .map_err(|_| AnalyzerError::ProviderError("Failed to create provider".to_string()))?;

        // Patrones comunes en contratos maliciosos con su severidad y descripción
        let patterns = vec![
            // Transferencias forzadas
            (r"transferFrom\(address,address,uint256\)", 
             Severity::High, 
             "Posible transferencia forzada detectada", 
             0.3),
            
            // Auto-aprobaciones
            (r"approve\(address,uint256\)", 
             Severity::Medium, 
             "Posible auto-aprobación detectada", 
             0.2),
            
            // Selfdestruct
            (r"selfdestruct\(address\)", 
             Severity::High, 
             "Uso de selfdestruct detectado", 
             0.5),
            
            // Delegatecall con entrada de usuario
            (r"delegatecall\(.*\)", 
             Severity::Critical, 
             "Uso de delegatecall con entrada de usuario", 
             0.7),
            
            // Llamadas a direcciones hardcodeadas
            (r"0x[0-9a-fA-F]{40}", 
             Severity::Low, 
             "Dirección hardcodeada detectada", 
             0.1),
            
            // Modificadores de visibilidad sospechosos
            (r"function\s+\w+\s*\([^)]*\)\s*(external|public)\s*\{\s*_", 
             Severity::Medium, 
             "Función con lógica en el modificador", 
             0.2),
            
            // Uso de block.timestamp para decisiones críticas
            (r"block\.timestamp\s*[<>]=?\s*\w+", 
             Severity::Medium, 
             "Uso de block.timestamp para lógica crítica", 
             0.2),
            
            // Uso de tx.origin para autenticación
            (r"tx\.origin\s*==\s*msg\.sender", 
             Severity::High, 
             "Uso inseguro de tx.origin para autenticación", 
             0.4),
        ];

        let known_scam_patterns = patterns
            .into_iter()
            .map(|(pattern, severity, desc, weight)| {
                Regex::new(pattern)
                    .map(|re| (re, severity, desc, weight))
                    .map_err(|e| {
                        log::error!("Error al compilar la expresión regular: {}", e);
                        e
                    })
                    .unwrap()
            })
            .collect();

        Ok(Self {
            known_scam_patterns,
            rpc_url: rpc_url.to_string(),
            network,
            client,
            ethers_provider: Arc::new(provider),
        })
    }

    pub async fn analyze_contract(&self, contract_address: &str) -> Result<ContractAnalysis> {
        let start_time = Instant::now();
        info!("Analizando contrato: {}", contract_address);
        let mut findings = Vec::new();
        let mut risk_score = 0.0f32;  // Especificamos el tipo f32 explícitamente

        // Verificar si el análisis está en caché
        {
            let mut cache = ANALYSIS_CACHE.lock().await;
            if let Some(cached) = cache.get(contract_address) {
                return Ok(cached.clone());
            }
        }

        // 2. Verificar si el contrato está verificado en Etherscan
        let is_verified = match self.check_if_verified(contract_address).await {
            Ok(verified) => verified,
            Err(e) => {
                warn!("Error al verificar el contrato en Etherscan: {}", e);
                false
            }
        };

        // 3. Si no está verificado, agregar un hallazgo de advertencia
        if !is_verified {
            findings.push(Finding {
                title: "Contrato no verificado".to_string(),
                description: "El contrato no ha sido verificado en el explorador de bloques".to_string(),
                severity: Severity::Medium,
                code_snippet: None,
                reference: None,
                impact: "Dificultad para auditar el código fuente".to_string(),
                recommendation: Some("Solicitar al propietario que verifique el contrato".to_string()),
                category: Some("Seguridad".to_string()),
                is_false_positive: false,
                detected_at: Some(chrono::Utc::now()),
                status: Some("Pendiente".to_string()),
            });
            risk_score += 0.3;  // Aseguramos que estamos modificando el valor referenciado
        }

        // 4. Obtener el código del contrato
        let code = self.get_contract_code(contract_address).await?;
        
        // 5. Analizar el código en busca de patrones sospechosos
        let code_risk_score = self.analyze_code_patterns(&code, &mut findings);
        risk_score += code_risk_score;

        // 6. Verificar si es un contrato proxy
        let mut proxy_implementation = None;
        let mut proxy_findings = Vec::new();
        
        // Verificar si es un contrato proxy
        if let Ok(proxy_info) = self.check_proxy_pattern(contract_address, &mut proxy_findings).await {
            findings.extend(proxy_findings);
            
            // Si encontramos una implementación de proxy, aumentamos el riesgo
            if let Some(implementation) = proxy_info.implementation_address {
                proxy_implementation = Some(implementation);
                // Aumentar el puntaje de riesgo si es un proxy
                risk_score += 0.2;
            }
        }

        // Verificar estándares de token (si es necesario)
        {
            if let Err(e) = self.check_non_standard_tokens(contract_address, &mut findings).await {
                warn!("Error al verificar estándares de token: {}", e);
            }
            // La lógica de riesgo se maneja en analyze_code_patterns
            risk_score += 0.1; // Añadir un pequeño riesgo por defecto
        }

        // Calcular si es sospechoso basado en el puntaje de riesgo
        let is_suspicious = risk_score >= 0.7;

        // Crear el análisis final
        let analysis = ContractAnalysis {
            contract_address: contract_address.to_string(),
            is_verified,
            findings,
            risk_score,
            is_suspicious,
            contract_name: None,
            compiler_version: None,
            optimization_used: None,
            proxy_implementation,
            token_standard: None,
            created_at_block: None,
            last_activity: None,
            transaction_count: 0,
            verified_source: None,
            abi: None,
            bytecode: Some(code),
            opcodes: None, // Se implementará más adelante
        };

        // Almacenar en caché
        {
            let mut cache = ANALYSIS_CACHE.lock().await;
            cache.put(contract_address.to_string(), analysis.clone());
        }

        let analysis_time = start_time.elapsed();
        info!("Análisis completado en {:.2?}", analysis_time);

        Ok(analysis)
    }

    // Método simplificado para verificar si un contrato está verificado
    async fn check_if_verified(&self, _address: &str) -> Result<bool> {
        // Implementación simplificada que siempre devuelve false
        // En una implementación real, esto haría una llamada a la API de Etherscan
        // basada en la red configurada en self.network
        Ok(false)
    }

    async fn get_contract_code(&self, _address: &str) -> Result<String> {
        // Implementación simplificada que devuelve un código de ejemplo
        // En una implementación real, esto obtendría el bytecode de la blockchain
        Ok("6060604052600436101561001a575b361561001857005b005b6000803560e01c8063f8a8fd6d1461003a57600080fd5b3461004f5761004736610052565b506001610018565b80fd5b60006020819052908152604090205460ff168156".to_string())
    }

    fn analyze_code_patterns(&self, code: &str, findings: &mut Vec<Finding>) -> f32 {
        // Patrones de código malicioso con su descripción, severidad y peso
        let patterns = [
            // Patrones de auto-destrucción
            (r"selfdestruct\(".to_string(), "Uso de selfdestruct".to_string(), Severity::Critical, 0.4),
            (r"suicide\(".to_string(), "Uso de suicide (obsoleto)".to_string(), Severity::Critical, 0.4),
            
            // Patrones de delegación de llamadas
            (r"delegatecall\(".to_string(), "Uso de delegatecall".to_string(), Severity::High, 0.3),
            (r"callcode\(".to_string(), "Uso de callcode (obsoleto)".to_string(), Severity::High, 0.3),
            
            // Patrones de transferencia de fondos
            (r"\.transfer\(address\(this\)\.balance\)".to_string(), 
             "Transferencia completa del balance del contrato".to_string(), Severity::High, 0.4),
            (r"\.send\(address\(this\)\.balance\)".to_string(), 
             "Envío completo del balance del contrato".to_string(), Severity::High, 0.4),
            
            // Patrones de código ofuscado
            (r"\beval\(|\bnew Function\(|\bnew Function\(".to_string(), 
             "Uso de funciones de evaluación dinámica de código".to_string(), Severity::Critical, 0.5),
            
            // Patrones de manipulación de tiempo
            (r"block\.timestamp".to_string(), 
             "Uso de block.timestamp para lógica sensible".to_string(), Severity::Medium, 0.2),
            (r"block\.difficulty".to_string(), 
             "Uso de block.difficulty para generación de números aleatorios".to_string(), Severity::High, 0.3),
            
            // Patrones de reentrancia
            (r"\.call\.value\(.*\)\(\)".to_string(), 
             "Uso de .call.value() sin protección contra reentrancia".to_string(), Severity::High, 0.35),
            
            // Patrones de permisos excesivos
            (r"function\s+\w+\s*\([^)]*\)\s*public\s+paya?ble".to_string(), 
             "Función pública pagable sin restricciones".to_string(), Severity::Medium, 0.25),
            
            // Patrones de manejo de errores inseguro
            (r"require\(.*\)\s*;\s*\/\/\s*@audit".to_string(), 
             "Validación de seguridad marcada para auditoría".to_string(), Severity::High, 0.3),
            
            // Patrones de actualización de contrato proxy
            (r"upgradeTo\(|upgradeToAndCall\(".to_string(), 
             "Posible patrón de actualización de contrato proxy".to_string(), Severity::Medium, 0.25),
        ];
        
        let mut total_risk = 0.0;
        let code_lower = code.to_lowercase();

        for (pattern, description, severity, weight) in patterns.iter() {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(&code_lower) {
                    // Obtener el fragmento de código relevante
                    let code_snippet = re.find(&code_lower)
                        .map(|m| {
                            let start = m.start().saturating_sub(50);
                            let end = (m.end() + 50).min(code.len());
                            let snippet = &code[start..end];
                            format!("...{}...", snippet.replace("\n", " ").trim())
                        })
                        .unwrap_or_else(|| "No se pudo extraer el fragmento".to_string());
                    
                    // Añadir el hallazgo
                    findings.push(Finding {
                        title: description.clone(),
                        description: format!("Se detectó un patrón de riesgo en el código: {}", description),
                        severity: *severity,
                        code_snippet: Some(code_snippet),
                        reference: Some("EIP-XXXX".to_string()),
                        impact: "Posible vulnerabilidad de seguridad".to_string(),
                        recommendation: Some("Revisar y seguir las mejores prácticas de seguridad".to_string()),
                        category: Some("Seguridad".to_string()),
                        is_false_positive: false,
                        detected_at: Some(chrono::Utc::now()),
                        status: Some("Pendiente".to_string()),
                    });
                    total_risk += weight;
                }
            }
        }
        
        total_risk
    }

    async fn check_proxy_pattern(
        &self, 
        _address: &str, 
        _findings: &mut Vec<Finding>
    ) -> Result<ProxyInfo> {
        // Implementación simplificada que siempre devuelve que no es un proxy
        // En una implementación real, esto analizaría el bytecode en busca de patrones de proxy
        Ok(ProxyInfo::default())
    }

    async fn check_non_standard_tokens(
        &self, 
        _address: &str, 
        _findings: &mut Vec<Finding>
    ) -> Result<()> {
        // Implementación simplificada que no hace nada
        // En una implementación real, esto verificaría los estándares de token como ERC20, ERC721, etc.
        Ok(())
    }
}
