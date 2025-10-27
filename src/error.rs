    #[error("Error de código: {0}")]
    CodeError(String),
    
    #[error("Dirección inválida: {0}")]
    InvalidAddress(String),
    
    #[error("No es un contrato: {0}")]
    NotAContract(String),
    
    #[error("Error del proveedor: {0}")]
    ProviderError(String),
    
    #[error("Error de solicitud HTTP: {0}")]
    HttpError(#[from] ReqwestError),
    
    #[error("Error de serialización: {0}")]
    SerializationError(#[from] SerdeError),
    
    #[error("Error de análisis: {0}")]
    ParseError(#[from] ParseIntError),
    
    #[error("Error de codificación UTF-8: {0}")]
    Utf8Error(#[from] FromUtf8Error),
    
    #[error("Error del proveedor de Ethereum: {0}")]
    EthersProviderError(#[from] ProviderError),
    
    #[error("Error de validación: {0}")]
    ValidationError(String),
    
    #[error("Error de caché: {0}")]
    CacheError(String),
    
    #[error("Error de autenticación: {0}")]
    AuthError(String),
    
    #[error("Error de límite de tasa: {0}")]
    RateLimitError(String),
    
    #[error("Error de tiempo de espera: {0}")]
    TimeoutError(String),
    
    #[error("Error desconocido: {0}")]
    Unknown(String),
}

// Implementación de conversión para errores de ethers
impl From<ethers::prelude::ContractError<ethers::providers::Provider<ethers::providers::Http>>> for AnalyzerError {
    fn from(err: ethers::prelude::ContractError<ethers::providers::Provider<ethers::providers::Http>>) -> Self {
        AnalyzerError::ContractError(format!("Error de contrato: {}", err))
    }
}

// Implementación de conversión para errores de cadena
impl From<String> for AnalyzerError {
    fn from(err: String) -> Self {
        AnalyzerError::Unknown(err)
    }
}

// Implementación de conversión para errores de &str
impl From<&str> for AnalyzerError {
    fn from(err: &str) -> Self {
        AnalyzerError::Unknown(err.to_string())
    }
}

// Tipo de resultado personalizado para el analizador
pub type Result<T> = std::result::Result<T, AnalyzerError>;

// Estructura para errores detallados de validación
#[derive(Debug)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error de validación en campo '{}': {}", self.field, self.message)
    }
}

// Implementación de Error para ValidationError
impl std::error::Error for ValidationError {}

// Función de ayuda para crear errores de validación
pub fn validation_error(field: &str, message: &str) -> AnalyzerError {
    AnalyzerError::ValidationError(format!("{}: {}", field, message))
}
use std::fmt;
use thiserror::Error;
use ethers::providers::ProviderError;
use reqwest::Error as ReqwestError;
use serde_json::Error as SerdeError;
use std::num::ParseIntError;
use std::string::FromUtf8Error;

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
    
