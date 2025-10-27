use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityFinding {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub code_snippet: Option<String>,
    pub reference: Option<String>,
    pub impact: String,
    pub recommendation: Option<String>,
    pub category: Option<String>,
    pub is_false_positive: bool,
    pub detected_at: chrono::DateTime<chrono::Utc>,
    pub status: String,
}

lazy_static! {
    static ref MALICIOUS_PATTERNS: Vec<(&'static str, &'static str, Severity, &'static str)> = vec![
        // Inyección de código
        ("assembly", "Uso de ensamblador en línea (assembly) que podría ser malicioso", Severity::High, "https://swcregistry.io/docs/SWC-127"),
        
        // Patrones de estafas
        ("transfer\\(.*address\\(this\\)\\.balance", 
         "Posible patrón de drenaje de fondos: transferencia de todo el balance", Severity::Critical, "https://swcregistry.io/docs/SWC-105"),
        
        // Detección de código ofuscado
        ("eval\\(", "Uso de eval() que podría ejecutar código arbitrario", Severity::High, "https://swcregistry.io/docs/SWC-127"),
        
        // Funciones sospechosas
        ("selfdestruct\\(msg\\.sender\\)",
         "Función que permite la autodestrucción del contrato", Severity::Critical, "https://swcregistry.io/docs/SWC-106"),
        
        // Patrones de permisos inseguros
        ("onlyOwner\\(", 
         "Uso de modificadores de solo propietario que podrían ser explotados", Severity::Medium, "https://swcregistry.io/docs/SWC-105"),
        
        // Uso de delegatecall
        ("\\.delegatecall\\(", 
         "Uso de delegatecall que podría ser peligroso", Severity::High, "https://swcregistry.io/docs/SWC-112"),
        
        // Transferencias forzadas
        ("transferFrom\\(", "Posible transferencia forzada de tokens", Severity::High, "https://swcregistry.io/docs/SWC-114"),
        
        // Auto-aprobaciones
        ("approve\\(.*type\\(uint256\\)\\.max", "Auto-aprobación de cantidad ilimitada", Severity::High, "https://swcregistry.io/docs/SWC-104"),
        
        // Funciones de emergencia
        ("emergencyWithdraw", "Función de emergencia que podría drenar fondos", Severity::High, ""),
        
        // Funciones de actualización
        ("upgradeTo\\(", "Función de actualización que podría ser explotada", Severity::High, "https://swcregistry.io/docs/SWC-107"),
        
        // Timelocks
        ("disableTimelock", "Función para deshabilitar períodos de espera", Severity::High, ""),
    ];
}

pub struct SecurityAnalyzer {
    api_key: String,
}

impl SecurityAnalyzer {
    pub fn new(api_key: &str) -> Self {
        SecurityAnalyzer {
            api_key: api_key.to_string(),
        }
    }

    pub async fn analyze_contract(&self, address: &str) -> Result<Vec<SecurityFinding>, Box<dyn Error>> {
        // Obtener el código fuente del contrato
        let source_code = self.get_contract_source(address).await?;
        
        // Analizar el código en busca de patrones maliciosos
        let findings = self.analyze_source_code(&source_code);
        
        // Si no se encontraron patrones maliciosos, agregar un hallazgo informativo
        let mut all_findings = findings;
        if all_findings.is_empty() {
            all_findings.push(self.create_info_finding(
                "Análisis de seguridad completado",
                "No se encontraron patrones maliciosos obvios en el código del contrato.",
            ));
        }
        
        Ok(all_findings)
    }

    async fn get_contract_source(&self, address: &str) -> Result<String, Box<dyn Error>> {
        let url = format!(
            "https://api.etherscan.io/api?module=contract&action=getsourcecode&address={}&apikey={}",
            address, self.api_key
        );

        #[derive(Debug, Deserialize)]
        struct ApiResponse {
            status: String,
            result: Vec<ContractSource>,
        }

        #[derive(Debug, Deserialize)]
        struct ContractSource {
            #[serde(rename = "SourceCode")]
            source_code: String,
        }

        let response = reqwest::get(&url).await?.json::<ApiResponse>().await?;
        
        if response.status == "1" && !response.result.is_empty() {
            Ok(response.result[0].source_code.clone())
        } else {
            Err("No se pudo obtener el código fuente del contrato".into())
        }
    }

    fn analyze_source_code(&self, code: &str) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        for (pattern, description, severity, reference) in MALICIOUS_PATTERNS.iter() {
            let re = match Regex::new(pattern) {
                Ok(re) => re,
                Err(_) => continue,
            };

            if let Some(captures) = re.captures(code) {
                let code_snippet = captures.get(0).map(|m| m.as_str().to_string());
                
                findings.push(SecurityFinding {
                    title: "Posible vulnerabilidad de seguridad".to_string(),
                    description: description.to_string(),
                    severity: severity.clone(),
                    code_snippet,
                    reference: if reference.is_empty() { None } else { Some(reference.to_string()) },
                    impact: "Este patrón podría ser explotado para realizar acciones no deseadas en el contrato".to_string(),
                    recommendation: Some("Revise cuidadosamente esta parte del código y considere implementar medidas de seguridad adicionales".to_string()),
                    category: Some("Seguridad".to_string()),
                    is_false_positive: false,
                    detected_at: chrono::Utc::now(),
                    status: "Pendiente de revisión".to_string(),
                });
            }
        }

        findings
    }

    fn create_info_finding(&self, title: &str, description: &str) -> SecurityFinding {
        SecurityFinding {
            title: title.to_string(),
            description: description.to_string(),
            severity: Severity::Info,
            code_snippet: None,
            reference: None,
            impact: "Informativo".to_string(),
            recommendation: None,
            category: Some("Información".to_string()),
            is_false_positive: false,
            detected_at: chrono::Utc::now(),
            status: "Completado".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_source_code() {
        let analyzer = SecurityAnalyzer::new("test_key");
        
        // Test con código malicioso
        let malicious_code = r#"
            contract Malicious {
                function stealFunds(address victim) public {
                    victim.transfer(address(this).balance);
                }
                
                function backdoor() public onlyOwner {
                    // Código malicioso
                }
            }
        "#;
        
        let findings = analyzer.analyze_source_code(malicious_code);
        assert!(!findings.is_empty(), "Debería detectar patrones maliciosos");
        
        // Test con código limpio
        let clean_code = r#"
            contract Clean {
                function transfer(address to, uint amount) public {
                    // Transferencia segura
                    to.transfer(amount);
                }
            }
        "#;
        
        let findings = analyzer.analyze_source_code(clean_code);
        assert!(findings.is_empty(), "No debería detectar patrones maliciosos");
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "Crítico"),
            Severity::High => write!(f, "Alto"),
            Severity::Medium => write!(f, "Medio"),
            Severity::Low => write!(f, "Bajo"),
            Severity::Info => write!(f, "Informativo"),
        }
    }
}

impl fmt::Display for SecurityFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Título: {}", self.title)?;
        writeln!(f, "Severidad: {}", self.severity)?;
        writeln!(f, "Descripción: {}", self.description)?;
        
        if let Some(snippet) = &self.code_snippet {
            writeln!(f, "\nCódigo relacionado:
```solidity
{}
```", snippet)?;
        }
        
        if let Some(ref reference) = self.reference {
            writeln!(f, "\nReferencia: {}", reference)?;
        }
        
        writeln!(f, "\nImpacto: {}", self.impact)?;
        
        if let Some(ref recommendation) = self.recommendation {
            writeln!(f, "\nRecomendación: {}", recommendation)?;
        }
        
        if let Some(ref category) = self.category {
            writeln!(f, "\nCategoría: {}", category)?;
        }
        
        writeln!(f, "\nDetectado el: {}", self.detected_at)?;
        writeln!(f, "Estado: {}", self.status)
    }
}
