use crate::models::contract::ContractAnalysis;
use crate::models::vulnerability::VulnerabilityLevel;
use async_trait::async_trait;
use std::path::Path;
use thiserror::Error;

mod bytecode_analyzer;
mod source_analyzer;
mod gas_analyzer;
mod security_analyzer;
mod dependency_analyzer;

pub use bytecode_analyzer::BytecodeAnalyzer;
pub use source_analyzer::SourceAnalyzer;
pub use gas_analyzer::GasAnalyzer;
pub use security_analyzer::SecurityAnalyzer;
pub use dependency_analyzer::DependencyAnalyzer;

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Analysis error: {0}")]
    AnalysisError(String),
    
    #[error("Unsupported contract format")]
    UnsupportedFormat,
    
    #[error("Timeout while analyzing contract")]
    Timeout,
}

#[async_trait]
pub trait ContractAnalyzer: Send + Sync {
    /// Analyze a smart contract and return the analysis results
    async fn analyze(&self, contract_path: &Path) -> Result<ContractAnalysis, AnalyzerError>;
    
    /// Get the name of the analyzer
    fn name(&self) -> &'static str;
}

/// Main analyzer that combines multiple analyzers
pub struct SmartContractAnalyzer {
    analyzers: Vec<Box<dyn ContractAnalyzer>>,
}

impl Default for SmartContractAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl SmartContractAnalyzer {
    /// Create a new SmartContractAnalyzer with default analyzers
    pub fn new() -> Self {
        Self {
            analyzers: vec![
                Box::new(BytecodeAnalyzer::new()),
                Box::new(SourceAnalyzer::new()),
                Box::new(GasAnalyzer::new()),
                Box::new(SecurityAnalyzer::new()),
                Box::new(DependencyAnalyzer::new()),
            ],
        }
    }
    
    /// Add a custom analyzer to the analyzer pipeline
    pub fn with_analyzer<A: ContractAnalyzer + 'static>(mut self, analyzer: A) -> Self {
        self.analyzers.push(Box::new(analyzer));
        self
    }
    
    /// Analyze a smart contract using all registered analyzers
    pub async fn analyze(&self, contract_path: &Path) -> Result<ContractAnalysis, AnalyzerError> {
        let mut combined_analysis = ContractAnalysis::default();
        
        for analyzer in &self.analyzers {
            match analyzer.analyze(contract_path).await {
                Ok(analysis) => {
                    combined_analysis.merge(analysis);
                }
                Err(e) => {
                    log::warn!("Analyzer {} failed: {}", analyzer.name(), e);
                }
            }
        }
        
        // Calculate overall risk score
        combined_analysis.calculate_risk_score();
        
        Ok(combined_analysis)
    }
    
    /// Get a list of all available analyzers
    pub fn get_analyzers(&self) -> Vec<&'static str> {
        self.analyzers.iter().map(|a| a.name()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs::File;
    use std::io::Write;
    
    #[tokio::test]
    async fn test_analyze_contract() {
        // Create a temporary directory and a sample contract
        let temp_dir = tempdir().unwrap();
        let contract_path = temp_dir.path().join("sample.sol");
        let mut file = File::create(&contract_path).unwrap();
        writeln!(
            file,
            r#"// SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            
            contract Sample {{
                uint256 public value;
                
                function setValue(uint256 _value) public {{
                    value = _value;
                }}
            }}"#
        ).unwrap();
        
        // Create analyzer and analyze the contract
        let analyzer = SmartContractAnalyzer::new();
        let analysis = analyzer.analyze(&contract_path).await;
        
        // Verify the analysis contains expected results
        assert!(analysis.is_ok());
        let analysis = analysis.unwrap();
        assert!(!analysis.vulnerabilities.is_empty() || !analysis.warnings.is_empty());
    }
}
