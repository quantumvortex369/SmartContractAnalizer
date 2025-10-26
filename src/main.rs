mod analyzer;
mod error;
mod gui;

use clap::Parser;
use colored::*;
use eframe::egui;
use serde_json::json;
use std::process;
use crate::analyzer::{ContractAnalyzer, ContractAnalysis};
use crate::gui::start_gui;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Dirección del contrato a analizar (opcional para modo GUI)
    #[clap(short, long)]
    address: Option<String>,

    /// URL del nodo Ethereum RPC (por defecto: infura mainnet)
    #[clap(short, long, default_value = "https://mainnet.infura.io/v3/YOUR-INFURA-KEY")]
    rpc_url: String,

    /// Formato de salida (texto o json)
    #[clap(short, long, default_value = "text")]
    output: String,

    /// Usar interfaz gráfica
    #[clap(short, long)]
    gui: bool,
}

#[tokio::main]
async fn main() -> Result<(), eframe::Error> {
    let args = Args::parse();

    // Si se especificó la opción de GUI o no se proporcionó una dirección, iniciar la interfaz gráfica
    if args.gui || args.address.is_none() {
        return start_gui(args.rpc_url);
    }

    // Modo línea de comandos
    let address = args.address.unwrap();
    
    if !is_valid_ethereum_address(&address) {
        eprintln!("{}: Dirección de contrato inválida", "Error".red().bold());
        process::exit(1);
    }

    let analyzer = ContractAnalyzer::new(&args.rpc_url);

    match analyzer.analyze_contract(&address).await {
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

fn print_human_readable(analysis: &ContractAnalysis) {
    println!("\n{}", "Análisis de Contrato Inteligente".bold().underline());
    println!("{}: {}", "Contrato".bold(), analysis.contract_address);
    println!("{}: {}", "Verificado".bold(), if analysis.is_verified { "Sí" } else { "No" });
    
    // Calcular el nivel de riesgo
    let risk_level = if analysis.risk_score > 0.7 {
        "Alto".red().bold()
    } else if analysis.risk_score > 0.4 {
        "Medio".yellow().bold()
    } else {
        "Bajo".green().bold()
    };
    
    println!("{}: {:.2}% ({})", "Puntuación de riesgo".bold(), analysis.risk_score * 100.0, risk_level);
    
    if analysis.is_suspicious {
        println!("\n{}: {} {}", "¡Advertencia!".bold().red(), "⚠️ ", "Este contrato ha sido marcado como sospechoso".bold());
    }
    
    if !analysis.findings.is_empty() {
        println!("\n{}", "Hallazgos:".bold().underline());
        for (i, finding) in analysis.findings.iter().enumerate() {
            let severity = match finding.severity {
                crate::analyzer::Severity::High => "ALTO".red().bold(),
                crate::analyzer::Severity::Medium => "MEDIO".yellow().bold(),
                crate::analyzer::Severity::Low => "BAJO".yellow(),
                crate::analyzer::Severity::Info => "INFO".blue(),
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

fn print_json(analysis: &ContractAnalysis) {
    let json = json!({
        "contract_address": analysis.contract_address,
        "is_verified": analysis.is_verified,
        "risk_score": analysis.risk_score,
        "is_suspicious": analysis.is_suspicious,
        "findings": analysis.findings.iter().map(|f| {
            json!({
                "title": f.title,
                "description": f.description,
                "severity": match f.severity {
                    crate::analyzer::Severity::High => "high",
                    crate::analyzer::Severity::Medium => "medium",
                    crate::analyzer::Severity::Low => "low",
                    crate::analyzer::Severity::Info => "info",
                },
                "code_snippet": f.code_snippet
            })
        }).collect::<Vec<_>>()
    });
    
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}
