use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents the severity level of a vulnerability or issue
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Informational - No direct security impact
    Info,
    
    /// Low severity - Minor issues that should be addressed
    Low,
    
    /// Medium severity - Issues that could lead to problems
    Medium,
    
    /// High severity - Serious issues that should be fixed
    High,
    
    /// Critical severity - Severe issues that must be fixed immediately
    Critical,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Info
    }
}

impl Severity {
    /// Get the string representation of the severity
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
    
    /// Get the weight of the severity (used for risk scoring)
    pub fn weight(&self) -> f64 {
        match self {
            Severity::Info => 0.1,
            Severity::Low => 0.3,
            Severity::Medium => 0.6,
            Severity::High => 0.8,
            Severity::Critical => 1.0,
        }
    }
    
    /// Check if the severity is critical
    pub fn is_critical(&self) -> bool {
        matches!(self, Severity::Critical)
    }
    
    /// Check if the severity is high or critical
    pub fn is_high(&self) -> bool {
        matches!(self, Severity::High | Severity::Critical)
    }
    
    /// Check if the severity is medium, high, or critical
    pub fn is_medium(&self) -> bool {
        matches!(self, Severity::Medium | Severity::High | Severity::Critical)
    }
    
    /// Check if the severity is low, medium, high, or critical
    pub fn is_low(&self) -> bool {
        !matches!(self, Severity::Info)
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Represents a security vulnerability in a smart contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Short title of the vulnerability
    pub title: String,
    
    /// Detailed description of the vulnerability
    pub description: String,
    
    /// Severity level
    pub severity: Severity,
    
    /// Location in the source code (file:line)
    pub location: Option<String>,
    
    /// Recommended fix or mitigation
    pub recommendation: Option<String>,
    
    /// References (URLs to more information)
    pub references: Vec<String>,
}

impl Vulnerability {
    /// Create a new vulnerability
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            title: title.into(),
            description: description.into(),
            severity,
            location: None,
            recommendation: None,
            references: Vec::new(),
        }
    }
    
    /// Set the location of the vulnerability
    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }
    
    /// Set the recommendation for fixing the vulnerability
    pub fn with_recommendation(mut self, recommendation: impl Into<String>) -> Self {
        self.recommendation = Some(recommendation.into());
        self
    }
    
    /// Add a reference URL
    pub fn add_reference(&mut self, reference: impl Into<String>) {
        self.references.push(reference.into());
    }
    
    /// Add multiple reference URLs
    pub fn with_references(mut self, references: impl IntoIterator<Item = String>) -> Self {
        self.references.extend(references);
        self
    }
}

/// Common vulnerability types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VulnerabilityType {
    // Common vulnerabilities
    Reentrancy,
    IntegerOverflow,
    IntegerUnderflow,
    UncheckedCallReturnValue,
    UnprotectedSelfDestruct,
    UnprotectedEtherWithdrawal,
    UnprotectedSELFDESTRUCT,
    UnprotectedUpgradeableContract,
    UninitializedStoragePointer,
    UninitializedStorage,
    UninitializedMemoryPointer,
    UninitializedFunctionPointer,
    UninitializedLocalVariable,
    UninitializedStateVariable,
    UninitializedStorageVariable,
    UninitializedMemoryVariable,
    UninitializedFunctionPointerInConstructor,
    UninitializedStoragePointerInConstructor,
    UninitializedMemoryPointerInConstructor,
    UninitializedLocalVariableInConstructor,
    UninitializedStateVariableInConstructor,
    UninitializedStorageVariableInConstructor,
    UninitializedMemoryVariableInConstructor,
    UninitializedFunctionPointerInFunction,
    UninitializedStoragePointerInFunction,
    UninitializedMemoryPointerInFunction,
    UninitializedLocalVariableInFunction,
    UninitializedStateVariableInFunction,
    UninitializedStorageVariableInFunction,
    UninitializedMemoryVariableInFunction,
    
    // Access control issues
    UnprotectedFunction,
    UnprotectedUpgrade,
    UnprotectedInitializer,
    UnprotectedSetOwner,
    UnprotectedSetAdmin,
    UnprotectedSetOperator,
    UnprotectedSetController,
    UnprotectedSetGovernance,
    
    // Oracle related
    BadOraclePriceFeed,
    StaleOraclePrice,
    ManipulableOracle,
    
    // Other
    TimestampDependence,
    BlockNumberDependence,
    BlockHashDependence,
    BlockCoinbaseDependence,
    BlockDifficultyDependence,
    BlockGasLimitDependence,
    BlockNumberManipulation,
    TimestampManipulation,
    ReplayAttack,
    FrontRunning,
    
    // Custom vulnerability type
    Custom(&'static str),
}

impl VulnerabilityType {
    /// Get the default severity for this vulnerability type
    pub fn default_severity(&self) -> Severity {
        match self {
            // Critical severity
            Self::Reentrancy => Severity::Critical,
            Self::UnprotectedSelfDestruct => Severity::Critical,
            Self::UnprotectedEtherWithdrawal => Severity::Critical,
            Self::UnprotectedSELFDESTRUCT => Severity::Critical,
            
            // High severity
            Self::IntegerOverflow => Severity::High,
            Self::IntegerUnderflow => Severity::High,
            Self::UncheckedCallReturnValue => Severity::High,
            Self::UnprotectedUpgradeableContract => Severity::High,
            
            // Medium severity
            Self::UninitializedStoragePointer => Severity::Medium,
            Self::UninitializedStorage => Severity::Medium,
            Self::UninitializedMemoryPointer => Severity::Medium,
            Self::UninitializedFunctionPointer => Severity::Medium,
            
            // Low severity
            _ => Severity::Low,
        }
    }
    
    /// Get a description for this vulnerability type
    pub fn description(&self) -> &'static str {
        match self {
            Self::Reentrancy => "Reentrancy vulnerability allows recursive calls to modify state after external calls",
            Self::IntegerOverflow => "Integer overflow can lead to unexpected behavior when arithmetic operations exceed the maximum value",
            Self::IntegerUnderflow => "Integer underflow can lead to unexpected behavior when arithmetic operations go below zero",
            Self::UncheckedCallReturnValue => "Unchecked call return value can lead to failed transactions being treated as successful",
            Self::UnprotectedSelfDestruct => "Unprotected self-destruct can lead to loss of funds if called by an attacker",
            Self::UnprotectedEtherWithdrawal => "Unprotected ether withdrawal can lead to loss of funds if called by an attacker",
            Self::UnprotectedSELFDESTRUCT => "Unprotected SELFDESTRUCT can lead to contract destruction by an attacker",
            Self::UnprotectedUpgradeableContract => "Unprotected upgradeable contract can lead to malicious code execution",
            Self::UninitializedStoragePointer => "Uninitialized storage pointer can lead to unexpected behavior",
            _ => "Security vulnerability detected",
        }
    }
    
    /// Get references (URLs) for this vulnerability type
    pub fn references(&self) -> Vec<&'static str> {
        match self {
            Self::Reentrancy => vec![
                "https://swcregistry.io/docs/SWC-107",
                "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/"
            ],
            Self::IntegerOverflow | Self::IntegerUnderflow => vec![
                "https://swcregistry.io/docs/SWC-101",
                "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/integer-arithmetic/"
            ],
            Self::UncheckedCallReturnValue => vec![
                "https://swcregistry.io/docs/SWC-104",
                "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/"
            ],
            _ => vec!["https://swcregistry.io"],
        }
    }
}

impl fmt::Display for VulnerabilityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reentrancy => write!(f, "Reentrancy"),
            Self::IntegerOverflow => write!(f, "Integer Overflow"),
            Self::IntegerUnderflow => write!(f, "Integer Underflow"),
            Self::UncheckedCallReturnValue => write!(f, "Unchecked Call Return Value"),
            Self::UnprotectedSelfDestruct => write!(f, "Unprotected Self-Destruct"),
            Self::UnprotectedEtherWithdrawal => write!(f, "Unprotected Ether Withdrawal"),
            Self::UnprotectedSELFDESTRUCT => write!(f, "Unprotected SELFDESTRUCT"),
            Self::UnprotectedUpgradeableContract => write!(f, "Unprotected Upgradeable Contract"),
            Self::UninitializedStoragePointer => write!(f, "Uninitialized Storage Pointer"),
            Self::UninitializedStorage => write!(f, "Uninitialized Storage"),
            Self::UninitializedMemoryPointer => write!(f, "Uninitialized Memory Pointer"),
            Self::UninitializedFunctionPointer => write!(f, "Uninitialized Function Pointer"),
            Self::Custom(name) => write!(f, "{}", name),
            _ => write!(f, "{:?}", self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
    
    #[test]
    fn test_vulnerability_creation() {
        let vuln = Vulnerability::new(
            "Reentrancy",
            "Possible reentrancy vulnerability in withdraw function",
            Severity::High,
        )
        .with_location("contracts/Vault.sol:42")
        .with_recommendation("Use the checks-effects-interactions pattern");
        
        assert_eq!(vuln.title, "Reentrancy");
        assert_eq!(vuln.severity, Severity::High);
        assert!(vuln.location.is_some());
        assert!(vuln.recommendation.is_some());
    }
    
    #[test]
    fn test_vulnerability_type_defaults() {
        assert_eq!(VulnerabilityType::Reentrancy.default_severity(), Severity::Critical);
        assert_eq!(VulnerabilityType::IntegerOverflow.default_severity(), Severity::High);
        assert_eq!(VulnerabilityType::UninitializedStoragePointer.default_severity(), Severity::Medium);
    }
}
