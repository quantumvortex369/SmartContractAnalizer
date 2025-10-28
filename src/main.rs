//! Smart Contract Analyzer - Command Line Interface
//! 
//! This module provides the command-line interface for the Smart Contract Analyzer.

use smart_contract_analyzer::{
    error::Result,
    analyzer::{ContractAnalysis, Finding, Severity, Network},
};

#[cfg(feature = "clap")]
use clap::Parser;
use colored::*;
use serde_json::json;
use std::process;

#[cfg(feature = "gui")]
use smart_contract_analyzer::gui::start_gui;

#[cfg_attr(feature = "clap", derive(Parser, Debug))]
#[cfg_attr(feature = "clap", clap(author, version, about, long_about = None))]
struct Args {
    /// Dirección del contrato a analizar (opcional para modo GUI)
    #[cfg_attr(feature = "clap", clap(short, long))]
    address: Option<String>,

    /// URL del nodo Ethereum RPC (por defecto: infura mainnet)
    #[cfg_attr(feature = "clap", clap(short, long, default_value = "https://mainnet.infura.io/v3/YOUR-INFURA-KEY"))]
    rpc_url: String,

    /// Clave API de Etherscan (por defecto: YOUR-ETHERSCAN-API-KEY)
    #[cfg_attr(feature = "clap", clap(short, long, default_value = "YOUR-ETHERSCAN-API-KEY"))]
    etherscan_key: String,

    /// Formato de salida (texto o json)
    #[cfg_attr(feature = "clap", clap(short, long, default_value = "text"))]
    output: String,

    /// Usar interfaz gráfica
    #[cfg_attr(feature = "clap", clap(short, long))]
    gui: bool,
}

fn main() -> Result<()> {
    #[cfg(feature = "clap")]
    let args = Args::parse();
    
    #[cfg(not(feature = "clap"))]
    let args = Args {
        address: None,
        rpc_url: "https://mainnet.infura.io/v3/YOUR-INFURA-KEY".to_string(),
        etherscan_key: "YOUR-ETHERSCAN-API-KEY".to_string(),
        output: "text".to_string(),
        gui: true,
    };

    // Si se especificó la opción de GUI o no se proporcionó una dirección, iniciar la interfaz gráfica
    if args.gui || args.address.is_none() {
        #[cfg(feature = "gui")] {
            return start_gui(args.rpc_url).map_err(Into::into);
        }
        #[cfg(not(feature = "gui"))] {
            eprintln!("GUI feature is not enabled. Please enable it in Cargo.toml");
            std::process::exit(1);
        }
    }

    // Modo línea de comandos
    let address = args.address.unwrap();
    
    if !is_valid_ethereum_address(&address) {
        eprintln!("{}: Dirección de contrato inválida", "Error".red().bold());
        process::exit(1);
    }

    // Create a new tokio runtime
    let rt = tokio::runtime::Runtime::new().unwrap();
    
    // Create the analyzer with the mainnet
    let analyzer = rt.block_on(async {
        smart_contract_analyzer::analyzer::ContractAnalyzer::new(&args.rpc_url, smart_contract_analyzer::Network::Mainnet).await
    })?;

    // Run the analysis
    match rt.block_on(analyzer.analyze_contract(&address)) {
        Ok(analysis) => {
            if args.output.to_lowercase() == "json" {
                print_json(&analysis);
            } else {
                print_human_readable(&analysis);
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("{}: {}", "Error".red().bold(), e);
            process::exit(1);
        }
    }
}

// Función para validar direcciones Ethereum
pub fn is_valid_ethereum_address(address: &str) -> bool {
    if !address.starts_with("0x") || address.len() != 42 {
        return false;
    }
    
    // Verificar que solo contenga caracteres hexadecimales
    address[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn print_human_readable(analysis: &smart_contract_analyzer::analyzer::ContractAnalysis) {
    println!("\n{}", "Análisis de Contrato Inteligente".bold().underline());
    println!("{}: {}", "Contrato".bold(), analysis.contract_address);
    println!("{}: {}", "Verificado".bold(), if analysis.is_verified { "Sí" } else { "No" });
    
    // Calculate risk level based on findings
    let has_critical = analysis.findings.iter().any(|f| f.severity == Severity::Critical);
    let has_high = analysis.findings.iter().any(|f| f.severity == Severity::High);
    let has_medium = analysis.findings.iter().any(|f| f.severity == Severity::Medium);
    let has_low = analysis.findings.iter().any(|f| f.severity == Severity::Low);
    
    let risk_level = if has_critical {
        "Crítico".red().bold()
    } else if has_high {
        "Alto".red().bold()
    } else if has_medium {
        "Medio".yellow().bold()
    } else if has_low {
        "Bajo".green().bold()
    } else {
        "Mínimo".green()
    };
    
    // Calculate a simple risk score based on findings
    let risk_score = if has_critical { 1.0 }
        else if has_high { 0.7 }
        else if has_medium { 0.5 }
        else if has_low { 0.3 }
        else { 0.1 };
    
    println!("{}: {:.2}% ({})", "Puntuación de riesgo".bold(), risk_score * 100.0, risk_level);
    
    if analysis.is_suspicious {
        println!("\n{}: {} {}", "¡Advertencia!".bold().red(), "⚠️ ", "Este contrato ha sido marcado como sospechoso".bold());
    }
    
    if !analysis.findings.is_empty() {
        println!("\n{}", "Hallazgos:".bold().underline());
        for (i, finding) in analysis.findings.iter().enumerate() {
            let severity = match finding.severity {
                Severity::Critical => "CRÍTICO".red().bold(),
                Severity::High => "ALTO".red().bold(),
                Severity::Medium => "MEDIO".yellow().bold(),
                Severity::Low => "BAJO".yellow(),
                Severity::Info => "INFO".blue(),
            };
            
            println!("\n{} {}", format!("[{}]", i + 1).bold(), finding.title);
            println!("{} {}", "Severidad:".dimmed(), severity);
            println!("{} {}", "Descripción:".dimmed(), finding.description);
            
            if let Some(snippet) = &finding.code_snippet {
                println!("{} {}", "Código:".dimmed(), snippet);
            }
        }
    } else {
        println!("\n{}", "No se encontraron problemas de seguridad relevantes.".green().bold());
    }
}

fn print_json(analysis: &smart_contract_analyzer::analyzer::ContractAnalysis) {
    // Calculate risk score from findings
    let has_critical = analysis.findings.iter().any(|f| f.severity == Severity::Critical);
    let has_high = analysis.findings.iter().any(|f| f.severity == Severity::High);
    let has_medium = analysis.findings.iter().any(|f| f.severity == Severity::Medium);
    let has_low = analysis.findings.iter().any(|f| f.severity == Severity::Low);
    
    let risk_score = if has_critical { 1.0 }
        else if has_high { 0.7 }
        else if has_medium { 0.5 }
        else if has_low { 0.3 }
        else { 0.1 };

    let json = json!({
        "contract_address": &analysis.contract_address,
        "is_verified": analysis.is_verified,
        "is_suspicious": analysis.is_suspicious,
        "risk_score": risk_score,
        "findings": analysis.findings.iter().map(|f| {
            json!({
                "title": f.title,
                "description": f.description,
                "severity": match f.severity {
                    Severity::Critical => "critical",
                    Severity::High => "high",
                    Severity::Medium => "medium",
                    Severity::Low => "low",
                    Severity::Info => "info",
                },
                "code_snippet": f.code_snippet
            })
        }).collect::<Vec<_>>()
    });
    
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}
