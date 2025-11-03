//! Smart Contract Analyzer
//! 
//! A comprehensive tool for analyzing smart contracts with support for multiple blockchains
//! and vulnerability detection.

#![warn(missing_docs)]

pub mod analyzer;
pub mod error;
pub mod gui;
pub mod security;
pub mod types;

// Re-exports
pub use analyzer::*;
pub use error::{AnalyzerError, Result};
pub use security::{SecurityAnalyzer, SecurityFinding, Severity};
pub use types::*;
