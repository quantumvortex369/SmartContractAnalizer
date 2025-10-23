use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnalyzerError {
    #[error("Error de conexión: {0}")]
    ConnectionError(String),
    
    #[error("Error de formato: {0}")]
    FormatError(String),
    
    #[error("Error de contrato: {0}")]
    ContractError(String),
    
    #[error("Error de red: {0}")]
    NetworkError(String),
    
    #[error("Error de Web3: {0}")]
    Web3Error(String),
    
    #[error("Error de código: {0}")]
    CodeError(String),
}

// Tipo de resultado personalizado para el analizador
pub type Result<T> = std::result::Result<T, AnalyzerError>;
