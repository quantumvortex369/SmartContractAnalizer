use serde::{Deserialize, Serialize};

/// Severity levels for analysis findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnalyzerSeverity {
    /// Critical severity - immediate action required
    Critical,
    /// High severity - important issue that should be addressed
    High,
    /// Medium severity - issue that should be addressed
    Medium,
    /// Low severity - minor issue or informational
    Low,
    /// Informational - no direct security impact
    Info,
}

/// Represents a finding from the smart contract analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Title of the finding
    pub title: String,
    /// Description of the finding
    pub description: String,
    /// Severity of the finding
    pub severity: AnalyzerSeverity,
    /// Source location (file:line)
    pub location: Option<String>,
    /// Code snippet related to the finding
    pub code_snippet: Option<String>,
    /// Additional context or recommendations
    pub recommendation: Option<String>,
    /// Category of the finding (e.g., "Security", "Gas", "Best Practice")
    pub category: Option<String>,
    /// Reference to additional documentation or CVE
    pub reference: Option<String>,
    /// Whether this finding is a false positive
    pub is_false_positive: bool,
    /// When the finding was detected
    pub detected_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Status of the finding (e.g., "Pending", "Confirmed", "Fixed")
    pub status: Option<String>,
}

/// Represents the result of a contract analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAnalysis {
    /// Contract address that was analyzed
    pub address: String,
    /// Whether the contract was verified
    pub is_verified: bool,
    /// Whether the contract is suspicious
    pub is_suspicious: bool,
    /// List of findings from the analysis
    pub findings: Vec<Finding>,
    /// Timestamp of when the analysis was performed
    pub analyzed_at: chrono::DateTime<chrono::Utc>,
    /// The contract's bytecode (if available)
    pub bytecode: Option<String>,
    /// The contract's source code (if available)
    pub source_code: Option<String>,
    /// Contract name (if available)
    pub contract_name: Option<String>,
    /// Compiler version used (if available)
    pub compiler_version: Option<String>,
    /// Whether optimization was used during compilation
    pub optimization_used: Option<bool>,
    /// Address of the proxy implementation (if this is a proxy)
    pub proxy_implementation: Option<String>,
    /// Token standard (if applicable, e.g., "ERC20", "ERC721")
    pub token_standard: Option<String>,
    /// Block number when the contract was created (if available)
    pub created_at_block: Option<u64>,
    /// Timestamp of the last activity (if available)
    pub last_activity: Option<u64>,
    /// Number of transactions (if available)
    pub transaction_count: Option<u64>,
    /// Source of verification (if verified)
    pub verified_source: Option<String>,
    /// Contract ABI (if available)
    pub abi: Option<serde_json::Value>,
    /// Contract opcodes (if available)
    pub opcodes: Option<Vec<String>>,
}

/// Check if a string is a valid Ethereum address
pub fn is_valid_ethereum_address(address: &str) -> bool {
    use regex::Regex;
    let re = Regex::new(r"^0x[0-9a-fA-F]{40}$").unwrap();
    re.is_match(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_ethereum_address() {
        assert!(is_valid_ethereum_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44e"));
        assert!(!is_valid_ethereum_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44")); // Too short
        assert!(!is_valid_ethereum_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44e1")); // Too long
        assert!(!is_valid_ethereum_address("0x742d35Cc6634C0532925a3b844Bc454e4438f44g")); // Invalid character 'g'
    }
}
