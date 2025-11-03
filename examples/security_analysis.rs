use smart_contract_analyzer::{
    security::{SecurityAnalyzer, Severity},
    Result,
};

fn main() -> Result<()> {
    // Contrato de ejemplo con varias vulnerabilidades
    let contract_source = r#"
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;
        
        contract InsecureContract {
            mapping(address => uint) public balances;
            address public owner;
            
            constructor() {
                owner = msg.sender;
            }
            
            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }
            
            function withdraw() public {
                // Vulnerabilidad de reentrancia
                uint amount = balances[msg.sender];
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
                balances[msg.sender] = 0;
            }
            
            function transfer(address to, uint amount) public {
                // Posible desbordamiento
                balances[msg.sender] -= amount;
                balances[to] += amount;
            }
            
            function getBalance() public view returns (uint) {
                return address(this).balance;
            }
            
            // Función sin especificador de visibilidad (pública por defecto)
            function changeOwner(address newOwner) {
                // Uso inseguro de tx.origin
                if (tx.origin == owner) {
                    owner = newOwner;
                }
            }
        }
    "#;

    println!("🔍 Analizando contrato en busca de vulnerabilidades...\n");
    
    // Crear y ejecutar el analizador de seguridad
    let mut analyzer = SecurityAnalyzer::new(contract_source);
    let findings = analyzer.analyze();
    
    // Mostrar resultados
    if findings.is_empty() {
        println!(" No se encontraron vulnerabilidades en el contrato.");
    } else {
        println!("  Se encontraron {} posibles vulnerabilidades:\n", findings.len());
        
        // Agrupar hallazgos por severidad
        let critical: Vec<_> = findings.iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .collect();
            
        let high: Vec<_> = findings.iter()
            .filter(|f| matches!(f.severity, Severity::High))
            .collect();
            
        let medium: Vec<_> = findings.iter()
            .filter(|f| matches!(f.severity, Severity::Medium))
            .collect();
            
        let low: Vec<_> = findings.iter()
            .filter(|f| matches!(f.severity, Severity::Low))
            .collect();
        
        // Mostrar hallazgos por nivel de severidad
        if !critical.is_empty() {
            println!(" CRÍTICO ({}):", critical.len());
            for finding in &critical {
                println!("  • {} (Línea: {})", finding.title, finding.line.unwrap_or(0));
                println!("    {}\n", finding.recommendation);
            }
        }
        
        if !high.is_empty() {
            println!("  ALTO ({}):", high.len());
            for finding in &high {
                println!("  • {} (Línea: {})", finding.title, finding.line.unwrap_or(0));
                println!("    {}\n", finding.recommendation);
            }
        }
        
        if !medium.is_empty() {
            println!("🔍 MEDIO ({}):", medium.len());
            for finding in &medium {
                println!("  • {} (Línea: {})", finding.title, finding.line.unwrap_or(0));
                println!("    {}\n", finding.recommendation);
            }
        }
        
        if !low.is_empty() {
            println!("  BAJO ({}):", low.len());
            for finding in &low {
                println!("  • {} (Línea: {})", finding.title, finding.line.unwrap_or(0));
                println!("    {}\n", finding.recommendation);
            }
        }
        
        // Generar resumen
        println!("\n Resumen de seguridad:");
        println!("  • Críticos: {}", critical.len());
        println!("  • Altos: {}", high.len());
        println!("  • Medios: {}", medium.len());
        println!("  • Bajos: {}", low.len());
    }
    
    Ok(())
}
