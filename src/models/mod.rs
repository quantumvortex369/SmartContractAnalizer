//! Data models for the smart contract analyzer

pub mod analysis_result;
pub mod contract;
pub mod issue;
pub mod metadata;
pub mod vulnerability;

// Re-export the main types for easier access
pub use self::{
    analysis_result::AnalysisResult,
    contract::ContractAnalysis,
    issue::{Issue, IssueType},
    metadata::ContractMetadata,
    vulnerability::{Severity, Vulnerability, VulnerabilityType},
};
