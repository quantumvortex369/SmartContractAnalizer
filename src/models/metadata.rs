use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Metadata about a smart contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMetadata {
    /// Contract name
    pub name: String,
    
    /// Contract version (if available)
    pub version: Option<String>,
    
    /// Contract address (if deployed)
    pub address: Option<String>,
    
    /// Path to the contract source file
    pub source_path: Option<PathBuf>,
    
    /// Compiler version used
    pub compiler_version: Option<String>,
    
    /// Optimization settings
    pub optimization: Option<OptimizationSettings>,
    
    /// EVM version (if specified)
    pub evm_version: Option<String>,
    
    /// License identifier (SPDX)
    pub license: Option<String>,
    
    /// Contract ABI (if available)
    pub abi: Option<serde_json::Value>,
    
    /// Bytecode (if available)
    pub bytecode: Option<String>,
    
    /// Deployed bytecode (if available)
    pub deployed_bytecode: Option<String>,
    
    /// Source code hash
    pub source_hash: Option<String>,
    
    /// Creation code hash
    pub creation_code_hash: Option<String>,
    
    /// Runtime code hash
    pub runtime_code_hash: Option<String>,
    
    /// Constructor arguments (if any)
    pub constructor_arguments: Option<String>,
    
    /// Whether the contract is a proxy
    pub is_proxy: bool,
    
    /// Implementation address (for proxies)
    pub implementation: Option<String>,
    
    /// Additional metadata
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

impl Default for ContractMetadata {
    fn default() -> Self {
        Self {
            name: "unknown".to_string(),
            version: None,
            address: None,
            source_path: None,
            compiler_version: None,
            optimization: None,
            evm_version: None,
            license: None,
            abi: None,
            bytecode: None,
            deployed_bytecode: None,
            source_hash: None,
            creation_code_hash: None,
            runtime_code_hash: None,
            constructor_arguments: None,
            is_proxy: false,
            implementation: None,
            extra: serde_json::json!({}),
        }
    }
}

/// Compiler optimization settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSettings {
    /// Whether optimization is enabled
    pub enabled: bool,
    
    /// Number of optimization runs
    pub runs: u32,
    
    /// Optimization details
    pub details: Option<serde_json::Value>,
}

/// Source file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    /// File path
    pub path: PathBuf,
    
    /// File content
    pub content: String,
    
    /// File checksum
    pub checksum: String,
    
    /// Source unit name
    pub source_unit_name: Option<String>,
    
    /// License
    pub license: Option<String>,
}

/// Contract ABI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractABI {
    /// ABI methods
    pub methods: Vec<ABIMethod>,
    
    /// ABI events
    pub events: Vec<ABIEvent>,
    
    /// ABI errors
    pub errors: Vec<ABIError>,
    
    /// ABI constructor
    pub constructor: Option<ABIMethod>,
    
    /// ABI fallback
    pub fallback: Option<ABIFallback>,
    
    /// ABI receive
    pub receive: bool,
}

/// ABI method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIMethod {
    /// Method name
    pub name: String,
    
    /// Method type (function, constructor, fallback, etc.)
    #[serde(rename = "type")]
    pub method_type: String,
    
    /// Input parameters
    pub inputs: Vec<ABIParam>,
    
    /// Output parameters
    pub outputs: Vec<ABIParam>,
    
    /// State mutability
    pub state_mutability: String,
    
    /// Whether the function is payable
    pub payable: bool,
    
    /// Whether the function is constant
    pub constant: bool,
    
    /// Gas estimate
    pub gas: Option<u64>,
}

/// ABI event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIEvent {
    /// Event name
    pub name: String,
    
    /// Input parameters
    pub inputs: Vec<ABIEventParam>,
    
    /// Whether the event is anonymous
    pub anonymous: bool,
}

/// ABI error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIError {
    /// Error name
    pub name: String,
    
    /// Input parameters
    pub inputs: Vec<ABIParam>,
}

/// ABI fallback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIFallback {
    /// Whether the fallback is payable
    pub payable: bool,
}

/// ABI parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIParam {
    /// Parameter name
    pub name: String,
    
    /// Parameter type
    #[serde(rename = "type")]
    pub param_type: String,
    
    /// Components (for tuple types)
    pub components: Option<Vec<ABIParam>>,
    
    /// Internal type (for more detailed type information)
    pub internal_type: Option<String>,
}

/// ABI event parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIEventParam {
    /// Parameter name
    pub name: String,
    
    /// Parameter type
    #[serde(rename = "type")]
    pub param_type: String,
    
    /// Whether the parameter is indexed
    pub indexed: bool,
    
    /// Components (for tuple types)
    pub components: Option<Vec<ABIEventParam>>,
    
    /// Internal type (for more detailed type information)
    pub internal_type: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_contract_metadata_default() {
        let metadata = ContractMetadata::default();
        assert_eq!(metadata.name, "unknown");
        assert!(metadata.address.is_none());
        assert!(metadata.source_path.is_none());
        assert!(!metadata.is_proxy);
    }
    
    #[test]
    fn test_optimization_settings() {
        let settings = OptimizationSettings {
            enabled: true,
            runs: 200,
            details: None,
        };
        
        assert!(settings.enabled);
        assert_eq!(settings.runs, 200);
    }
    
    #[test]
    fn test_abi_method() {
        let method = ABIMethod {
            name: "transfer".to_string(),
            method_type: "function".to_string(),
            inputs: vec![
                ABIParam {
                    name: "to".to_string(),
                    param_type: "address".to_string(),
                    components: None,
                    internal_type: Some("address".to_string()),
                },
                ABIParam {
                    name: "amount".to_string(),
                    param_type: "uint256".to_string(),
                    components: None,
                    internal_type: Some("uint256".to_string()),
                },
            ],
            outputs: vec![ABIParam {
                name: "".to_string(),
                param_type: "bool".to_string(),
                components: None,
                internal_type: Some("bool".to_string()),
            }],
            state_mutability: "nonpayable".to_string(),
            payable: false,
            constant: false,
            gas: None,
        };
        
        assert_eq!(method.name, "transfer");
        assert_eq!(method.inputs.len(), 2);
        assert_eq!(method.outputs.len(), 1);
    }
}
