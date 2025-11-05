use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use super::vulnerability::Vulnerability;
use super::issue::Issue;
use super::metadata::ContractMetadata;

/// Represents a smart contract and its analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAnalysis {
    /// Contract metadata (name, address, compiler version, etc.)
    pub metadata: ContractMetadata,
    
    /// List of detected vulnerabilities
    pub vulnerabilities: Vec<Vulnerability>,
    
    /// List of potential issues and warnings
    pub warnings: Vec<Issue>,
    
    /// Code quality metrics
    pub metrics: CodeMetrics,
    
    /// Gas usage analysis
    pub gas_analysis: GasAnalysis,
    
    /// Dependencies and their versions
    pub dependencies: HashMap<String, String>,
    
    /// Timestamp of the analysis
    pub analyzed_at: DateTime<Utc>,
    
    /// Overall risk score (0-100)
    pub risk_score: f64,
    
    /// Risk level based on the score
    pub risk_level: RiskLevel,
}

impl Default for ContractAnalysis {
    fn default() -> Self {
        Self {
            metadata: ContractMetadata::default(),
            vulnerabilities: Vec::new(),
            warnings: Vec::new(),
            metrics: CodeMetrics::default(),
            gas_analysis: GasAnalysis::default(),
            dependencies: HashMap::new(),
            analyzed_at: Utc::now(),
            risk_score: 0.0,
            risk_level: RiskLevel::None,
        }
    }
}

impl ContractAnalysis {
    /// Create a new ContractAnalysis with default values
    pub fn new(metadata: ContractMetadata) -> Self {
        Self {
            metadata,
            ..Default::default()
        }
    }
    
    /// Add a vulnerability to the analysis
    pub fn add_vulnerability(&mut self, vulnerability: Vulnerability) {
        self.vulnerabilities.push(vulnerability);
        self.calculate_risk_score();
    }
    
    /// Add a warning to the analysis
    pub fn add_warning(&mut self, warning: Issue) {
        self.warnings.push(warning);
        self.calculate_risk_score();
    }
    
    /// Calculate the overall risk score based on vulnerabilities and warnings
    pub fn calculate_risk_score(&mut self) {
        // Calculate score based on vulnerabilities (weighted by severity)
        let vuln_score: f64 = self.vulnerabilities.iter()
            .map(|v| v.severity.weight() * 25.0) // Max 25 points per vulnerability
            .sum();
            
        // Calculate score based on warnings (weighted by severity)
        let warning_score: f64 = self.warnings.iter()
            .map(|w| w.severity.weight() * 5.0) // Max 5 points per warning
            .sum();
            
        // Combine scores (capped at 100)
        self.risk_score = (vuln_score + warning_score).min(100.0);
        self.risk_level = RiskLevel::from_score(self.risk_score);
    }
    
    /// Check if the contract has any critical or high severity issues
    pub fn has_critical_issues(&self) -> bool {
        self.vulnerabilities.iter().any(|v| v.severity.is_critical() || v.severity.is_high()) ||
        self.warnings.iter().any(|w| w.severity.is_critical() || w.severity.is_high())
    }
    
    /// Get a summary of the analysis
    pub fn summary(&self) -> AnalysisSummary {
        AnalysisSummary {
            contract_name: self.metadata.name.clone(),
            address: self.metadata.address.clone(),
            risk_score: self.risk_score,
            risk_level: self.risk_level,
            critical_vulnerabilities: self.vulnerabilities.iter()
                .filter(|v| v.severity.is_critical())
                .count(),
            high_vulnerabilities: self.vulnerabilities.iter()
                .filter(|v| v.severity.is_high())
                .count(),
            medium_vulnerabilities: self.vulnerabilities.iter()
                .filter(|v| v.severity.is_medium())
                .count(),
            low_vulnerabilities: self.vulnerabilities.iter()
                .filter(|v| v.severity.is_low())
                .count(),
            warnings: self.warnings.len(),
        }
    }
}

/// Summary of the contract analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub contract_name: String,
    pub address: Option<String>,
    pub risk_score: f64,
    pub risk_level: RiskLevel,
    pub critical_vulnerabilities: usize,
    pub high_vulnerabilities: usize,
    pub medium_vulnerabilities: usize,
    pub low_vulnerabilities: usize,
    pub warnings: usize,
}

/// Code quality metrics for the contract
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CodeMetrics {
    /// Number of lines of code
    pub lines_of_code: usize,
    
    /// Number of functions
    pub function_count: usize,
    
    /// Number of state variables
    pub state_variables: usize,
    
    /// Number of external calls
    pub external_calls: usize,
    
    /// Cyclomatic complexity
    pub complexity: f64,
    
    /// Code coverage percentage (if available)
    pub coverage: Option<f64>,
}

/// Gas usage analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GasAnalysis {
    /// Estimated gas usage for deployment
    pub deployment_gas: Option<u64>,
    
    /// Gas usage by function
    pub function_gas: HashMap<String, u64>,
    
    /// Gas optimization opportunities
    pub optimizations: Vec<GasOptimization>,
}

/// Gas optimization suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasOptimization {
    /// Description of the optimization
    pub description: String,
    
    /// Estimated gas savings
    pub estimated_savings: u64,
    
    /// Location in the code (file:line)
    pub location: Option<String>,
}

/// Risk level based on the analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Get risk level from a score (0-100)
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 80.0 => RiskLevel::Critical,
            s if s >= 60.0 => RiskLevel::High,
            s if s >= 30.0 => RiskLevel::Medium,
            s if s > 0.0 => RiskLevel::Low,
            _ => RiskLevel::None,
        }
    }
    
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::None => "None",
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Critical => "Critical",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::vulnerability::Severity;
    
    #[test]
    fn test_risk_score_calculation() {
        let mut analysis = ContractAnalysis::default();
        
        // Add a critical vulnerability (25 points)
        analysis.add_vulnerability(Vulnerability {
            title: "Reentrancy".to_string(),
            description: "Possible reentrancy vulnerability".to_string(),
            severity: Severity::Critical,
            location: Some("contract.sol:42".to_string()),
            recommendation: Some("Use checks-effects-interactions pattern".to_string()),
            references: vec!["https://swcregistry.io/docs/SWC-107".to_string()],
        });
        
        // Add a high severity warning (5 points)
        analysis.add_warning(Issue {
            title: "Unsafe low-level call".to_string(),
            description: "Using low-level calls can be dangerous".to_string(),
            severity: Severity::High,
            location: Some("contract.sol:15".to_string()),
            recommendation: None,
            references: vec![],
        });
        
        // Critical (25) + High (5) = 30
        assert!((analysis.risk_score - 30.0).abs() < f64::EPSILON);
        assert_eq!(analysis.risk_level, RiskLevel::Medium);
    }
    
    #[test]
    fn test_has_critical_issues() {
        let mut analysis = ContractAnalysis::default();
        assert!(!analysis.has_critical_issues());
        
        // Add a critical vulnerability
        analysis.add_vulnerability(Vulnerability {
            title: "Reentrancy".to_string(),
            description: String::new(),
            severity: Severity::Critical,
            location: None,
            recommendation: None,
            references: vec![],
        });
        
        assert!(analysis.has_critical_issues());
    }
}
