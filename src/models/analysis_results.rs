use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents the result of a contract analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// The contract address that was analyzed
    pub contract_address: String,
    /// The network the contract is deployed on
    pub network: String,
    /// The timestamp of the analysis
    pub timestamp: u64,
    /// The analysis findings
    pub findings: Vec<crate::models::vulnerability::Vulnerability>,
    /// Additional metadata about the analysis
    pub metadata: HashMap<String, String>,
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self {
            contract_address: String::new(),
            network: String::new(),
            timestamp: 0,
            findings: Vec::new(),
            metadata: HashMap::new(),
        }
    }
}
