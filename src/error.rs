use std::fmt;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
use std::sync::Arc;
use thiserror::Error;

// Re-export AnalyzerSeverity from types module
pub use crate::types::AnalyzerSeverity;

/// Custom result type for the analyzer
pub type Result<T> = std::result::Result<T, AnalyzerError>;

/// Errors that can occur during contract analysis
#[derive(Error, Debug, Clone)]
pub enum AnalyzerError {
    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),
    
    /// Invalid format
    #[error("Invalid format: {0}")]
    Format(String),
    
    /// Contract-related error
    #[error("Contract error: {0}")]
    Contract(String),
    
    /// Network error
    #[error("Network error: {0}")]
    Network(String),
    
    /// Web3 error
    #[error("Web3 error: {0}")]
    Web3(String),
    
    /// Code error
    #[error("Code error: {0}")]
    Code(String),
    
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] Arc<std::io::Error>),
    
    /// UTF-8 encoding error
    #[error("UTF-8 encoding error: {0}")]
    Utf8(#[from] FromUtf8Error),
    
    /// Parse int error
    #[error("Parse int error: {0}")]
    ParseInt(#[from] Arc<ParseIntError>),
    
    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] Arc<serde_json::Error>),
    
    /// Invalid nonce
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),
    
    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    
    /// Unsupported network
    #[error("Unsupported network: {0}")]
    UnsupportedNetwork(String),
    
    /// Block not found
    #[error("Block not found: {0}")]
    BlockNotFound(String),
    
    /// Transaction not found
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),
    
    /// Function not found
    #[error("Function not found: {0}")]
    FunctionNotFound(String),
    
    /// Event not found
    #[error("Event not found: {0}")]
    EventNotFound(String),
    
    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),
    
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
    
    /// Unknown error
    #[error("Unknown error: {0}")]
    Unknown(String),
    
    /// Provider error
    #[error("Provider error: {0}")]
    Provider(String),
}

// Implementation of From for String
impl From<String> for AnalyzerError {
    fn from(err: String) -> Self {
        AnalyzerError::Format(err)
    }
}

// Implementation of From for &str
impl From<&str> for AnalyzerError {
    fn from(err: &str) -> Self {
        AnalyzerError::Format(err.to_string())
    }
}

// Implementation of From for Box<dyn std::error::Error + Send + Sync + 'static>>
impl From<Box<dyn std::error::Error + Send + Sync + 'static>> for AnalyzerError {
    fn from(err: Box<dyn std::error::Error + Send + Sync + 'static>) -> Self {
        AnalyzerError::Internal(err.to_string())
    }
}

// Implement From for Arc-wrapped errors
impl From<std::io::Error> for AnalyzerError {
    fn from(err: std::io::Error) -> Self {
        AnalyzerError::Io(Arc::new(err))
    }
}

impl From<serde_json::Error> for AnalyzerError {
    fn from(err: serde_json::Error) -> Self {
        AnalyzerError::Json(Arc::new(err))
    }
}

impl From<ParseIntError> for AnalyzerError {
    fn from(err: ParseIntError) -> Self {
        AnalyzerError::ParseInt(Arc::new(err))
    }
}

// Implementation of From for ethers::providers::ProviderError
#[cfg(feature = "ethers")]
impl From<ethers::providers::ProviderError> for AnalyzerError {
    fn from(err: ethers::providers::ProviderError) -> Self {
        AnalyzerError::Web3(err.to_string())
    }
}

// Implementation of From for reqwest::Error
#[cfg(feature = "reqwest")]
impl From<reqwest::Error> for AnalyzerError {
    fn from(err: reqwest::Error) -> Self {
        AnalyzerError::Network(err.to_string())
    }
}

/// Helper function to create a validation error
pub fn validation_error(field: &str, message: &str) -> AnalyzerError {
    AnalyzerError::Validation(format!("Field '{}': {}", field, message))
}

/// Helper function to create multiple validation errors
pub fn validation_errors(errors: Vec<(&str, &str)>) -> AnalyzerError {
    let error_messages: Vec<String> = errors
        .into_iter()
        .map(|(field, msg)| format!("{}: {}", field, msg))
        .collect();
    
    AnalyzerError::Validation(error_messages.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_string_conversion() {
        let err = AnalyzerError::from("test error");
        assert_eq!(
            err.to_string(),
            "Invalid format: test error"
        );
    }
    
    #[test]
    fn test_validation_error() {
        let err = validation_error("email", "invalid format");
        assert_eq!(
            err.to_string(),
            "Validation error: Field 'email': invalid format"
        );
    }
    
    #[test]
    fn test_validation_errors() {
        let errors = vec![
            ("email", "invalid format"),
            ("password", "too short"),
        ];
        let err = validation_errors(errors);
        assert!(
            err.to_string().contains("email: invalid format") &&
            err.to_string().contains("password: too short")
        );
    }
}
