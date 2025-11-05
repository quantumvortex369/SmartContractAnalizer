use serde::{Deserialize, Serialize};
use std::fmt;
use super::vulnerability::Severity;

/// Represents a non-critical issue or warning in the smart contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    /// Short title of the issue
    pub title: String,
    
    /// Detailed description of the issue
    pub description: String,
    
    /// Severity level of the issue
    pub severity: Severity,
    
    /// Location in the source code (file:line)
    pub location: Option<String>,
    
    /// Optional recommendation to fix the issue
    pub recommendation: Option<String>,
    
    /// Optional references (URLs to more information)
    pub references: Vec<String>,
}

impl Issue {
    /// Create a new issue
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
    
    /// Set the location of the issue
    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }
    
    /// Set the recommendation for fixing the issue
    pub fn with_recommendation(mut self, recommendation: impl Into<String>) -> Self {
        self.recommendation = Some(recommendation.into());
        self
    }
    
    /// Add a reference URL
    pub fn add_reference(&mut self, reference: impl Into<String>) {
        self.references.push(reference.into());
    }
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f, 
            "[{}] {}: {}",
            self.severity,
            self.title,
            self.description
        )?;
        
        if let Some(loc) = &self.location {
            write!(f, " (at {})", loc)?;
        }
        
        Ok(())
    }
}

/// Common issue types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IssueType {
    // Code style issues
    UnusedVariable,
    UnusedFunction,
    UnusedImport,
    UnusedReturnValue,
    UnusedEvent,
    UnusedParameter,
    UnusedLocalVariable,
    UnusedStateVariable,
    UnusedStruct,
    UnusedEnum,
    UnusedContract,
    UnusedInterface,
    UnusedLibrary,
    UnusedError,
    UnusedModifier,
    UnusedUsingFor,
    
    // Code quality issues
    ComplexFunction,
    LongFunction,
    DeepNesting,
    HighCyclomaticComplexity,
    TooManyParameters,
    TooManyLocalVariables,
    TooManyStateVariables,
    TooManyFunctions,
    TooManyEvents,
    TooManyModifiers,
    TooManyErrors,
    
    // Security-related issues (non-critical)
    BlockTimestamp,
    BlockNumber,
    BlockHash,
    BlockCoinbase,
    BlockDifficulty,
    BlockGasLimit,
    GasPrice,
    Now,
    
    // Other issues
    MissingZeroAddressCheck,
    MissingZeroValueCheck,
    MissingReentrancyGuard,
    MissingAccessControl,
    MissingPausable,
    MissingInitializer,
    MissingConstructor,
    MissingFallback,
    MissingReceive,
    MissingNatspec,
    MissingEvents,
    MissingChecksEffectsInteractions,
    MissingSafeMath,
    
    // Custom issue type
    Custom(&'static str),
}

impl IssueType {
    /// Get the default severity for this issue type
    pub fn default_severity(&self) -> Severity {
        match self {
            // Info severity
            Self::UnusedVariable
            | Self::UnusedFunction
            | Self::UnusedImport
            | Self::UnusedReturnValue
            | Self::UnusedEvent
            | Self::UnusedParameter
            | Self::UnusedLocalVariable
            | Self::UnusedStateVariable
            | Self::UnusedStruct
            | Self::UnusedEnum
            | Self::UnusedContract
            | Self::UnusedInterface
            | Self::UnusedLibrary
            | Self::UnusedError
            | Self::UnusedModifier
            | Self::UnusedUsingFor => Severity::Info,
            
            // Low severity
            Self::ComplexFunction
            | Self::LongFunction
            | Self::DeepNesting
            | Self::HighCyclomaticComplexity
            | Self::TooManyParameters
            | Self::TooManyLocalVariables
            | Self::TooManyStateVariables
            | Self::TooManyFunctions
            | Self::TooManyEvents
            | Self::TooManyModifiers
            | Self::TooManyErrors
            | Self::MissingNatspec
            | Self::MissingEvents => Severity::Low,
            
            // Medium severity
            Self::BlockTimestamp
            | Self::BlockNumber
            | Self::BlockHash
            | Self::BlockCoinbase
            | Self::BlockDifficulty
            | Self::BlockGasLimit
            | Self::GasPrice
            | Self::Now
            | Self::MissingZeroAddressCheck
            | Self::MissingZeroValueCheck
            | Self::MissingReentrancyGuard
            | Self::MissingAccessControl
            | Self::MissingPausable
            | Self::MissingInitializer
            | Self::MissingConstructor
            | Self::MissingFallback
            | Self::MissingReceive
            | Self::MissingChecksEffectsInteractions
            | Self::MissingSafeMath => Severity::Medium,
            
            // Default to info
            _ => Severity::Info,
        }
    }
    
    /// Get a description for this issue type
    pub fn description(&self) -> &'static str {
        match self {
            Self::UnusedVariable => "Unused variable",
            Self::UnusedFunction => "Unused function",
            Self::UnusedImport => "Unused import",
            Self::UnusedReturnValue => "Unused return value",
            Self::UnusedEvent => "Unused event",
            Self::UnusedParameter => "Unused parameter",
            Self::UnusedLocalVariable => "Unused local variable",
            Self::UnusedStateVariable => "Unused state variable",
            Self::UnusedStruct => "Unused struct",
            Self::UnusedEnum => "Unused enum",
            Self::UnusedContract => "Unused contract",
            Self::UnusedInterface => "Unused interface",
            Self::UnusedLibrary => "Unused library",
            Self::UnusedError => "Unused error",
            Self::UnusedModifier => "Unused modifier",
            Self::UnusedUsingFor => "Unused using for directive",
            Self::ComplexFunction => "Function is too complex",
            Self::LongFunction => "Function is too long",
            Self::DeepNesting => "Deep nesting of control structures",
            Self::HighCyclomaticComplexity => "High cyclomatic complexity",
            Self::TooManyParameters => "Too many parameters",
            Self::TooManyLocalVariables => "Too many local variables",
            Self::TooManyStateVariables => "Too many state variables",
            Self::TooManyFunctions => "Too many functions in contract",
            Self::TooManyEvents => "Too many events in contract",
            Self::TooManyModifiers => "Too many modifiers in contract",
            Self::TooManyErrors => "Too many custom errors in contract",
            Self::BlockTimestamp => "Using block.timestamp for time-based logic",
            Self::BlockNumber => "Using block.number for time-based logic",
            Self::BlockHash => "Using blockhash for random number generation",
            Self::BlockCoinbase => "Using block.coinbase which can be influenced by miners",
            Self::BlockDifficulty => "Using block.difficulty which can be influenced by miners",
            Self::BlockGasLimit => "Using block.gaslimit which can be influenced by miners",
            Self::GasPrice => "Using tx.gasprice which can be influenced by users",
            Self::Now => "Using now for time-based logic",
            Self::MissingZeroAddressCheck => "Missing zero-address check",
            Self::MissingZeroValueCheck => "Missing zero-value check",
            Self::MissingReentrancyGuard => "Missing reentrancy guard",
            Self::MissingAccessControl => "Missing access control",
            Self::MissingPausable => "Missing pausable functionality",
            Self::MissingInitializer => "Missing initializer function",
            Self::MissingConstructor => "Missing constructor",
            Self::MissingFallback => "Missing fallback function",
            Self::MissingReceive => "Missing receive function",
            Self::MissingNatspec => "Missing NatSpec documentation",
            Self::MissingEvents => "Missing events for important state changes",
            Self::MissingChecksEffectsInteractions => "Not following checks-effects-interactions pattern",
            Self::MissingSafeMath => "Not using SafeMath for arithmetic operations",
            Self::Custom(desc) => desc,
        }
    }
    
    /// Get references (URLs) for this issue type
    pub fn references(&self) -> Vec<&'static str> {
        match self {
            Self::BlockTimestamp | Self::BlockNumber | Self::Now => vec![
                "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/timestamp-dependence/"
            ],
            Self::BlockHash => vec![
                "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/randomness/"
            ],
            Self::MissingChecksEffectsInteractions => vec![
                "https://docs.soliditylang.org/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern"
            ],
            Self::MissingSafeMath => vec![
                "https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeMath"
            ],
            _ => vec!["https://docs.soliditylang.org/en/latest/"],
        }
    }
}

impl fmt::Display for IssueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnusedVariable => write!(f, "Unused Variable"),
            Self::UnusedFunction => write!(f, "Unused Function"),
            Self::UnusedImport => write!(f, "Unused Import"),
            Self::UnusedReturnValue => write!(f, "Unused Return Value"),
            Self::UnusedEvent => write!(f, "Unused Event"),
            Self::UnusedParameter => write!(f, "Unused Parameter"),
            Self::UnusedLocalVariable => write!(f, "Unused Local Variable"),
            Self::UnusedStateVariable => write!(f, "Unused State Variable"),
            Self::UnusedStruct => write!(f, "Unused Struct"),
            Self::UnusedEnum => write!(f, "Unused Enum"),
            Self::UnusedContract => write!(f, "Unused Contract"),
            Self::UnusedInterface => write!(f, "Unused Interface"),
            Self::UnusedLibrary => write!(f, "Unused Library"),
            Self::UnusedError => write!(f, "Unused Error"),
            Self::UnusedModifier => write!(f, "Unused Modifier"),
            Self::UnusedUsingFor => write!(f, "Unused Using For"),
            Self::ComplexFunction => write!(f, "Complex Function"),
            Self::LongFunction => write!(f, "Long Function"),
            Self::DeepNesting => write!(f, "Deep Nesting"),
            Self::HighCyclomaticComplexity => write!(f, "High Cyclomatic Complexity"),
            Self::TooManyParameters => write!(f, "Too Many Parameters"),
            Self::TooManyLocalVariables => write!(f, "Too Many Local Variables"),
            Self::TooManyStateVariables => write!(f, "Too Many State Variables"),
            Self::TooManyFunctions => write!(f, "Too Many Functions"),
            Self::TooManyEvents => write!(f, "Too Many Events"),
            Self::TooManyModifiers => write!(f, "Too Many Modifiers"),
            Self::TooManyErrors => write!(f, "Too Many Errors"),
            Self::BlockTimestamp => write!(f, "Block Timestamp Usage"),
            Self::BlockNumber => write!(f, "Block Number Usage"),
            Self::BlockHash => write!(f, "Block Hash Usage"),
            Self::BlockCoinbase => write!(f, "Block Coinbase Usage"),
            Self::BlockDifficulty => write!(f, "Block Difficulty Usage"),
            Self::BlockGasLimit => write!(f, "Block Gas Limit Usage"),
            Self::GasPrice => write!(f, "Gas Price Usage"),
            Self::Now => write!(f, "Now Usage"),
            Self::MissingZeroAddressCheck => write!(f, "Missing Zero Address Check"),
            Self::MissingZeroValueCheck => write!(f, "Missing Zero Value Check"),
            Self::MissingReentrancyGuard => write!(f, "Missing Reentrancy Guard"),
            Self::MissingAccessControl => write!(f, "Missing Access Control"),
            Self::MissingPausable => write!(f, "Missing Pausable"),
            Self::MissingInitializer => write!(f, "Missing Initializer"),
            Self::MissingConstructor => write!(f, "Missing Constructor"),
            Self::MissingFallback => write!(f, "Missing Fallback Function"),
            Self::MissingReceive => write!(f, "Missing Receive Function"),
            Self::MissingNatspec => write!(f, "Missing NatSpec Documentation"),
            Self::MissingEvents => write!(f, "Missing Events"),
            Self::MissingChecksEffectsInteractions => write!(f, "Missing Checks-Effects-Interactions Pattern"),
            Self::MissingSafeMath => write!(f, "Missing SafeMath"),
            Self::Custom(name) => write!(f, "{}", name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_issue_creation() {
        let issue = Issue::new(
            "Unused Variable",
            "Variable 'x' is declared but never used",
            Severity::Info,
        )
        .with_location("contracts/Token.sol:42")
        .with_recommendation("Remove the unused variable or use it in the code");
        
        assert_eq!(issue.title, "Unused Variable");
        assert_eq!(issue.severity, Severity::Info);
        assert!(issue.location.is_some());
        assert!(issue.recommendation.is_some());
    }
    
    #[test]
    fn test_issue_type_default_severity() {
        assert_eq!(IssueType::UnusedVariable.default_severity(), Severity::Info);
        assert_eq!(IssueType::ComplexFunction.default_severity(), Severity::Low);
        assert_eq!(IssueType::BlockTimestamp.default_severity(), Severity::Medium);
    }
    
    #[test]
    fn test_issue_type_description() {
        assert_eq!(IssueType::UnusedVariable.description(), "Unused variable");
        assert_eq!(IssueType::ComplexFunction.description(), "Function is too complex");
        assert_eq!(IssueType::BlockTimestamp.description(), "Using block.timestamp for time-based logic");
    }
}
