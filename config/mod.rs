use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{env, fs};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),
    
    #[error("Invalid configuration: {0}")]
    ValidationError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: PathBuf,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub rpc_url: String,
    pub ws_url: Option<String>,
    pub chain_id: u64,
    pub gas_price_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerConfig {
    pub max_workers: usize,
    pub timeout_seconds: u64,
    pub max_contract_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub cors_origins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,
    pub network: NetworkConfig,
    pub analyzer: AnalyzerConfig,
    pub api: ApiConfig,
}

impl Default for Config {
    fn default() -> Self {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let db_path = home_dir.join(".smart_contract_analyzer/db");

        Self {
            database: DatabaseConfig {
                path: db_path,
                max_connections: 10,
            },
            network: NetworkConfig {
                rpc_url: "https://mainnet.infura.io/v3/YOUR-API-KEY".to_string(),
                ws_url: Some("wss://mainnet.infura.io/ws/v3/YOUR-API-KEY".to_string()),
                chain_id: 1,
                gas_price_multiplier: 1.2,
            },
            analyzer: AnalyzerConfig {
                max_workers: num_cpus::get(),
                timeout_seconds: 30,
                max_contract_size: 1024 * 1024 * 5, // 5MB
            },
            api: ApiConfig {
                enabled: true,
                host: "127.0.0.1".to_string(),
                port: 8080,
                cors_origins: vec!["*".to_string()],
            },
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        let config_path = env::current_dir()?.join("config.toml");
        
        if config_path.exists() {
            let config_content = fs::read_to_string(&config_path)?;
            let mut config: Config = toml::from_str(&config_content)?;
            
            // Validar la configuración
            if config.analyzer.max_workers == 0 {
                return Err(ConfigError::ValidationError(
                    "max_workers must be greater than 0".to_string()
                ));
            }
            
            Ok(config)
        } else {
            // Si no existe el archivo, crear uno por defecto
            let default_config = Config::default();
            let config_content = toml::to_string_pretty(&default_config)?;
            
            // Crear directorios si no existen
            if let Some(parent) = config_path.parent() {
                fs::create_dir_all(parent)?;
            }
            
            fs::write(&config_path, config_content)?;
            Ok(default_config)
        }
    }
    
    pub fn save(&self) -> Result<(), ConfigError> {
        let config_path = env::current_dir()?.join("config.toml");
        let config_content = toml::to_string_pretty(self)?;
        fs::write(config_path, config_content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.analyzer.max_workers > 0);
        assert!(!config.network.rpc_url.is_empty());
    }
    
    #[test]
    fn test_load_save_config() {
        let temp_dir = tempdir().unwrap();
        env::set_current_dir(&temp_dir).unwrap();
        
        // Test creating default config
        let config = Config::load().unwrap();
        assert!(config.analyzer.max_workers > 0);
        
        // Test loading existing config
        let loaded_config = Config::load().unwrap();
        assert_eq!(config.analyzer.max_workers, loaded_config.analyzer.max_workers);
        
        // Test saving config
        let mut modified_config = loaded_config;
        modified_config.analyzer.max_workers = 42;
        modified_config.save().unwrap();
        
        let reloaded_config = Config::load().unwrap();
        assert_eq!(reloaded_config.analyzer.max_workers, 42);
    }
}
