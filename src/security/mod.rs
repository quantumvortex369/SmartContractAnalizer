//! Módulo principal de seguridad que integra todos los analizadores

use serde::{Deserialize, Serialize};
use thiserror::Error;
use regex::Regex;
use lazy_static::lazy_static;

// Importar los submódulos
pub mod taint_analyzer;
pub mod control_flow_analyzer;
pub mod gas_optimizer;

// Re-exportar los tipos importantes
pub use taint_analyzer::{TaintAnalyzer, TaintFinding};
pub use control_flow_analyzer::{ControlFlowAnalyzer, ControlFlowFinding};
pub use gas_optimizer::{GasOptimizer, GasOptimization};
pub use crate::models::vulnerability::Severity;

/// Integrar los analizadores en el analizador principal
#[derive(Debug, Clone)]
pub struct SecurityAudit {
    pub taint_analyzer: TaintAnalyzer,
    pub control_flow_analyzer: ControlFlowAnalyzer,
    pub gas_optimizer: GasOptimizer,
}

impl SecurityAudit {
    /// Crea una nueva instancia del auditor de seguridad con configuraciones predeterminadas
    pub fn new() -> Self {
        Self {
            taint_analyzer: TaintAnalyzer::new(),
            control_flow_analyzer: ControlFlowAnalyzer::default(),
            gas_optimizer: GasOptimizer::default(),
        }
    }
    
    /// Realiza un análisis completo de seguridad en el código fuente
    pub fn analyze(&self, source: &str) -> SecurityAuditResult {
        let taint_findings = self.taint_analyzer.analyze(source);
        let control_flow_findings = self.control_flow_analyzer.analyze(source);
        let gas_optimizations = self.gas_optimizer.analyze(source);
        
        // Combinar todos los hallazgos
        let mut findings = Vec::new();
        
        // Convertir hallazgos de taint analysis
        for finding in taint_findings {
            let severity = match finding.severity.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            };
            
            findings.push(SecurityFinding::new(
                &finding.title,
                &finding.description,
                severity,
                None,
                None,
                "Revisar el flujo de datos y aplicar las validaciones necesarias"
            ));
        }
        
        // Convertir hallazgos de control flow
        for finding in control_flow_findings {
            let severity = match finding.severity.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            };
            
            findings.push(SecurityFinding::new(
                &finding.title,
                &finding.description,
                severity,
                None,
                None,
                "Revisar la lógica de control del contrato"
            ));
        }
        
        // Convertir optimizaciones de gas
        for opt in gas_optimizations {
            findings.push(SecurityFinding::new(
                &opt.title,
                &opt.description,
                match opt.severity.as_str() {
                    "Alta" => Severity::High,
                    "Media" => Severity::Medium,
                    _ => Severity::Low,
                },
                None,
                None,
                "Aplicar las optimizaciones sugeridas para reducir el consumo de gas"
            ));
        }
        
        let score = self.calculate_security_score(&findings);
        SecurityAuditResult {
            findings,
            score,
        }
    }
    
    /// Calcula un puntaje de seguridad basado en los hallazgos
    fn calculate_security_score(&self, findings: &[SecurityFinding]) -> f32 {
        let mut score: f32 = 100.0;
        
        // Penalizar según la severidad de los hallazgos
        for finding in findings {
            let penalty = match finding.severity {
                Severity::Critical => 20.0,
                Severity::High => 10.0,
                Severity::Medium => 5.0,
                Severity::Low => 1.0,
                Severity::Info => 0.1,
            };
            score -= penalty;
        }
        
        // Asegurarse de que el puntaje no sea menor que 0
        score.max(0.0)
    }
}

/// Resultado del análisis de seguridad
#[derive(Debug)]
pub struct SecurityAuditResult {
    pub findings: Vec<SecurityFinding>,
    pub score: f32,
}

impl SecurityAuditResult {
    /// Filtra los hallazgos por severidad
    pub fn filter_by_severity(&self, severity: Severity) -> Vec<&SecurityFinding> {
        self.findings.iter()
            .filter(|f| f.severity == severity)
            .collect()
    }
    
    /// Genera un resumen del análisis
    pub fn summary(&self) -> String {
        let critical = self.filter_by_severity(Severity::Critical).len();
        let high = self.filter_by_severity(Severity::High).len();
        let medium = self.filter_by_severity(Severity::Medium).len();
        let low = self.filter_by_severity(Severity::Low).len();
        let info = self.filter_by_severity(Severity::Info).len();
        
        format!(
            "Puntaje de seguridad: {:.1}/100\n\
            Hallazgos:\n\
            - Críticos: {}\n\
            - Altos: {}\n\
            - Medios: {}\n\
            - Bajos: {}\n\
            - Informativos: {}",
            self.score, critical, high, medium, low, info
        )
    }
}

// Severity is already re-exported at the top of the file

/// Representa un hallazgo de seguridad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub line: Option<usize>,
    pub code_snippet: Option<String>,
    pub recommendation: String,
}

impl SecurityFinding {
    /// Crea un nuevo hallazgo de seguridad
    pub fn new(
        title: &str,
        description: &str,
        severity: Severity,
        line: Option<usize>,
        code_snippet: Option<&str>,
        recommendation: &str,
    ) -> Self {
        Self {
            title: title.to_string(),
            description: description.to_string(),
            severity,
            line,
            code_snippet: code_snippet.map(|s| s.to_string()),
            recommendation: recommendation.to_string(),
        }
    }
}

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Error de análisis de seguridad: {0}")]
    AnalysisError(String),
    #[error("Error de validación: {0}")]
    ValidationError(String),
    #[error("Error en el formato del código: {0}")]
    FormatError(String),
    #[error("Severidad no válida: {0}")]
    InvalidSeverity(String),
}

pub type Result<T> = std::result::Result<T, SecurityError>;

lazy_static! {
    static ref DANGEROUS_CALLS: Vec<(&'static str, Severity)> = vec![
        (r"\.call\(.*\)", Severity::High),
        (r"\.delegatecall\(.*\)", Severity::Critical),
        (r"\.send\(.*\)", Severity::High),
        (r"\.transfer\(.*\)", Severity::Medium),
        (r"suicide\(.*\)", Severity::Critical),
        (r"selfdestruct\(.*\)", Severity::Critical),
        (r"tx\.origin", Severity::High),
        (r"block\.timestamp", Severity::Medium),
        (r"block\.number", Severity::Medium),
        (r"\.callcode\(.*\)", Severity::Critical),
    ];
}

pub struct SecurityAnalyzer {
    findings: Vec<SecurityFinding>,
    contract_source: String,
}

impl SecurityAnalyzer {
    pub fn new(contract_source: &str) -> Self {
        Self {
            findings: Vec::new(),
            contract_source: contract_source.to_string(),
        }
    }

    pub fn analyze(&mut self) -> &[SecurityFinding] {
        self.findings.clear();
        
        self.detect_dangerous_calls();
        self.detect_reentrancy();
        self.detect_integer_overflow();
        self.detect_unprotected_functions();
        self.detect_visibility_violations();
        
        &self.findings
    }

    fn detect_dangerous_calls(&mut self) {
        for (pattern, severity) in DANGEROUS_CALLS.iter() {
            let re = Regex::new(pattern).unwrap();
            for (line_number, line) in self.contract_source.lines().enumerate() {
                if re.is_match(line) {
                    let title = match severity {
                        Severity::Critical => "Llamada peligrosa detectada (Crítica)",
                        Severity::High => "Llamada peligrosa detectada (Alto riesgo)",
                        Severity::Medium => "Llamada potencialmente insegura detectada",
                        _ => "Posible problema de seguridad detectado",
                    };
                    
                    self.findings.push(SecurityFinding::new(
                        title,
                        &format!("Se detectó un patrón de código potencialmente inseguro: {}", pattern),
                        severity.clone(),
                        Some(line_number + 1),
                        Some(line.trim()),
                        "Revise esta llamada y asegúrese de que no introduce vulnerabilidades de seguridad.",
                    ));
                }
            }
        }
    }

    fn detect_reentrancy(&mut self) {
        // Implementación simplificada de detección de reentrancia
        // En una implementación real, se necesitaría un análisis más profundo del flujo de control
        let re = Regex::new(r"\.(call|send|transfer)\(.*\)").unwrap();
        
        for (line_number, line) in self.contract_source.lines().enumerate() {
            if re.is_match(line) {
                // Verificar si hay cambios de estado después de la llamada externa
                let next_lines: Vec<&str> = self.contract_source.lines()
                    .skip(line_number + 1)
                    .take_while(|l| !l.trim().is_empty() && !l.trim().starts_with('}'))
                    .collect();
                
                let has_state_changes = next_lines.iter().any(|l| 
                    l.contains("=") || 
                    l.contains("delete") || 
                    l.contains("push") || 
                    l.contains("pop")
                );
                
                if !has_state_changes {
                    self.findings.push(SecurityFinding::new(
                        "Posible vulnerabilidad de reentrancia",
                        "Se detectó una llamada externa seguida de cambios de estado, lo que podría permitir ataques de reentrancia.",
                        Severity::High,
                        Some(line_number + 1),
                        Some(line.trim()),
                        "Implemente el patrón Checks-Effects-Interactions: realice los cambios de estado antes de realizar llamadas externas.",
                    ));
                }
            }
        }
    }

    fn detect_integer_overflow(&mut self) {
        // Detección básica de posibles desbordamientos
        let patterns = [
            (r"\+\s*\w+", "suma sin verificación de desbordamiento"),
            (r"-\s*\w+", "resta sin verificación de desbordamiento"),
            (r"\*\s*\w+", "multiplicación sin verificación de desbordamiento"),
        ];

        for (pattern, operation) in patterns.iter() {
            let re = Regex::new(pattern).unwrap();
            for (line_number, line) in self.contract_source.lines().enumerate() {
                if re.is_match(line) && !line.contains("SafeMath") && !line.contains("using SafeMath") {
                    self.findings.push(SecurityFinding::new(
                        "Posible desbordamiento aritmético",
                        &format!("Operación {} detectada sin verificación de desbordamiento", operation),
                        Severity::High,
                        Some(line_number + 1),
                        Some(line.trim()),
                        "Utilice SafeMath o implemente comprobaciones de desbordamiento manualmente.",
                    ));
                }
            }
        }
    }

    fn detect_unprotected_functions(&mut self) {
        // Detección de funciones sin modificadores de acceso o sin controles de acceso
        let re = Regex::new(r"function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)?").unwrap();
        let mut current_function: Option<String> = None;
        let mut in_function = false;
        let mut function_start_line = 0;

        for (line_number, line) in self.contract_source.lines().enumerate() {
            let trimmed = line.trim();
            
            if trimmed.starts_with("function") {
                if let Some(captures) = re.captures(trimmed) {
                    current_function = captures.get(1).map(|m| m.as_str().to_string());
                    in_function = true;
                    function_start_line = line_number + 1;
                    
                    // Verificar si la función tiene modificadores de acceso
                    if !(trimmed.contains("public") || trimmed.contains("external")) {
                        self.findings.push(SecurityFinding::new(
                            "Función sin especificador de visibilidad",
                            "Las funciones sin especificador de visibilidad son públicas por defecto",
                            Severity::Medium,
                            Some(function_start_line),
                            Some(trimmed),
                            "Especifique explícitamente la visibilidad (public, external, internal, private).",
                        ));
                    }
                    
                    // Verificar si es una función de inicialización sin protección
                    if let Some(name) = &current_function {
                        if (name == "initialize" || name.starts_with("init")) && 
                           !trimmed.contains("initializer") && 
                           !trimmed.contains("onlyOwner") {
                            self.findings.push(SecurityFinding::new(
                                "Función de inicialización sin protección",
                                "Las funciones de inicialización deben estar protegidas contra llamadas no autorizadas",
                                Severity::High,
                                Some(function_start_line),
                                Some(trimmed),
                                "Proteja esta función con un modificador como onlyOwner o initializer de OpenZeppelin.",
                            ));
                        }
                    }
                }
            } else if in_function && trimmed == "}" {
                in_function = false;
                current_function = None;
            } else if in_function {
                // Verificar dentro de la función por patrones inseguros
                if trimmed.contains("tx.origin == msg.sender") {
                    self.findings.push(SecurityFinding::new(
                        "Uso inseguro de tx.origin para autenticación",
                        "El uso de tx.origin para autenticación puede ser peligroso en contratos que pueden ser llamados por otros contratos",
                        Severity::High,
                        Some(line_number + 1),
                        Some(trimmed),
                        "Utilice msg.sender para la autenticación en lugar de tx.origin.",
                    ));
                }
            }
        }
    }

    fn detect_visibility_violations(&mut self) {
        // Detección de variables de estado sin especificador de visibilidad
        let re = Regex::new(r"^(\s*)(mapping|uint|bool|address|string|bytes)\s+(\w+)\s*[;=]").unwrap();
        
        for (line_number, line) in self.contract_source.lines().enumerate() {
            if let Some(captures) = re.captures(line) {
                let var_name = captures.get(3).unwrap().as_str();
                if !(line.contains("public") || line.contains("private") || 
                     line.contains("internal") || line.contains("constant") ||
                     line.contains("immutable") || line.contains("constant")) {
                    
                    self.findings.push(SecurityFinding::new(
                        "Variable de estado sin especificador de visibilidad",
                        &format!("La variable de estado '{}' no tiene un especificador de visibilidad", var_name),
                        Severity::Medium,
                        Some(line_number + 1),
                        Some(line.trim()),
                        "Especifique explícitamente la visibilidad (public, private, internal) para todas las variables de estado.",
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_calls_detection() {
        let code = r#"
            contract Test {
                function transfer(address payable to) public {
                    to.transfer(1 ether);
                    to.call{value: 1 ether}("");
                    to.delegatecall(abi.encodeWithSignature(""));
                }
            }
        "#;

        let mut analyzer = SecurityAnalyzer::new(code);
        let findings = analyzer.analyze();
        
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| 
            f.title.contains("Llamada peligrosa") && 
            f.severity == Severity::Critical
        ));
    }

    #[test]
    fn test_reentrancy_detection() {
        let code = r#"
            contract Test {
                mapping(address => uint) public balances;
                
                function withdraw() public {
                    uint amount = balances[msg.sender];
                    (bool success, ) = msg.sender.call{value: amount}("");
                    require(success, "Transfer failed");
                    balances[msg.sender] = 0;
                }
            }
        "#;

        let mut analyzer = SecurityAnalyzer::new(code);
        let findings = analyzer.analyze();
        
        assert!(findings.iter().any(|f| 
            f.title.contains("reentrancia") && 
            f.severity == Severity::High
        ));
    }
}

// Implementación de utilidades adicionales
impl SecurityAnalyzer {
    pub fn get_findings_by_severity(&self, severity: Severity) -> Vec<&SecurityFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect()
    }

    pub fn has_critical_issues(&self) -> bool {
        self.findings.iter().any(|f| matches!(f.severity, Severity::Critical))
    }

    pub fn generate_report(&self) -> String {
        use std::fmt::Write;
        
        let mut report = String::new();
        
        for finding in &self.findings {
            writeln!(
                report,
                "[{}] {} (Línea: {})\nDescripción: {}\nRecomendación: {}\n",
                match finding.severity {
                    Severity::Critical => "CRÍTICO",
                    Severity::High => "ALTO",
                    Severity::Medium => "MEDIO",
                    Severity::Low => "BAJO",
                    Severity::Info => "INFORMACIÓN",
                },
                finding.title,
                finding.line.unwrap_or(0),
                finding.description,
                finding.recommendation
            ).unwrap();
        }
        
        report
    }
}
