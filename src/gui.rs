use eframe::egui;
use std::sync::mpsc;
use crate::analyzer::ContractAnalysis;
use std::sync::Arc;
use tokio::runtime::Runtime;
use crate::is_valid_ethereum_address;

pub struct SmartContractAnalyzerApp {
    rpc_url: String,
    contract_address: String,
    is_analyzing: bool,
    analysis_result: Option<Result<ContractAnalysis, String>>,
    rt: Arc<Runtime>,
    result_receiver: Option<mpsc::Receiver<Result<ContractAnalysis, String>>>,
}

impl SmartContractAnalyzerApp {
    pub fn new(rpc_url: String, _cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            rpc_url,
            contract_address: String::new(),
            is_analyzing: false,
            analysis_result: None,
            rt: Arc::new(Runtime::new().expect("No se pudo crear el runtime de Tokio")),
            result_receiver: None,
        }
    }
    
    fn analyze_contract(&mut self) {
        if self.contract_address.trim().is_empty() {
            self.analysis_result = Some(Err("Por favor ingresa una dirección de contrato".to_string()));
            return;
        }
        
        if !is_valid_ethereum_address(&self.contract_address) {
            self.analysis_result = Some(Err("Dirección de contrato inválida".to_string()));
            return;
        }
        
        self.is_analyzing = true;
        
        // Simulación de análisis (en una implementación real, esto sería asíncrono)
        self.analysis_result = Some(Ok(ContractAnalysis {
            contract_address: self.contract_address.clone(),
            is_verified: true,
            risk_score: 0.3,
            findings: vec![
                crate::analyzer::Finding {
                    title: "Ejemplo de hallazgo".to_string(),
                    description: "Este es un ejemplo de hallazgo de seguridad".to_string(),
                    severity: crate::analyzer::Severity::Medium,
                    code_snippet: Some("function transfer(address to, uint amount) {".to_string()),
                },
            ],
            is_suspicious: false,
        }));
        
        self.is_analyzing = false;
    }
}

impl eframe::App for SmartContractAnalyzerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔍 Analizador de Contratos Inteligentes");
            
            // Área para ingresar la dirección del contrato
            ui.label("📋 Dirección del contrato:");
            let address_edit = egui::TextEdit::singleline(&mut self.contract_address)
                .hint_text("0x...")
                .desired_width(400.0);
            
            // Crear variables para los estados de los botones
            let mut analyze_clicked = false;
            let mut clear_clicked = false;
            
            // Layout horizontal para los controles
            ui.horizontal(|ui| {
                // Campo de entrada de texto
                let _ = ui.add(address_edit);
                
                // Botones
                if ui.button("🔍 Analizar").clicked() {
                    analyze_clicked = true;
                }
                
                if ui.button("🔄 Limpiar").clicked() {
                    clear_clicked = true;
                }
            });
            
            // Manejar las acciones de los botones
            if analyze_clicked {
                self.analyze_contract();
            }
            
            if clear_clicked {
                self.contract_address.clear();
                self.analysis_result = None;
            }
            
            // Mostrar estado del análisis
            if self.is_analyzing {
                ui.spinner();
                ui.label("Analizando contrato...");
            }

            // Mostrar resultados o errores
            if let Some(result) = &self.analysis_result {
                ui.separator();
                ui.label("📊 Resultados del Análisis:");
                ui.add_space(10.0);
                
                match result {
                    Ok(analysis) => {
                        // Mostrar resumen del análisis
                        ui.label(format!("✅ Contrato: {}", analysis.contract_address));
                        ui.label(format!("🔍 Verificado: {}", 
                            if analysis.is_verified { "Sí" } else { "No" }));
                        
                        // Mostrar nivel de riesgo
                        let risk_text = format!("Nivel de riesgo: {:.1}%", 
                            analysis.risk_score * 100.0);
                        let risk_label = if analysis.risk_score > 0.7 {
                            egui::Label::new(egui::RichText::new(risk_text).color(egui::Color32::RED))
                        } else if analysis.risk_score > 0.4 {
                            egui::Label::new(egui::RichText::new(risk_text).color(egui::Color32::YELLOW))
                        } else {
                            egui::Label::new(egui::RichText::new(risk_text).color(egui::Color32::GREEN))
                        };
                        ui.add(risk_label);
                        
                        // Mostrar hallazgos
                        if !analysis.findings.is_empty() {
                            ui.separator();
                            ui.heading("🔍 Hallazgos:");
                            
                            for (i, finding) in analysis.findings.iter().enumerate() {
                                let severity = match finding.severity {
                                    crate::analyzer::Severity::High => "ALTO".to_string(),
                                    crate::analyzer::Severity::Medium => "MEDIO".to_string(),
                                    crate::analyzer::Severity::Low => "BAJO".to_string(),
                                    crate::analyzer::Severity::Info => "INFO".to_string(),
                                };
                                
                                ui.collapsing(
                                    format!("{} - {}", i + 1, finding.title),
                                    |ui| {
                                        ui.label(format!("Severidad: {}", severity));
                                        ui.label(format!("Descripción: {}", finding.description));
                                        if let Some(snippet) = &finding.code_snippet {
                                            ui.code(snippet);
                                        }
                                    }
                                );
                            }
                        } else {
                            ui.label("✅ No se encontraron problemas de seguridad.");
                        }
                    },
                    Err(err) => {
                        ui.label(egui::RichText::new(format!("❌ Error: {}", err))
                            .color(egui::Color32::RED));
                    }
                }
            }
            
            // Pie de página
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.separator();
                ui.label(egui::RichText::new("Smart Contract Analyzer v1.0").small());
            });
        });
    }
}

pub fn start_gui(rpc_url: String) -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 700.0])
            .with_min_inner_size([600.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Smart Contract Analyzer",
        options,
        Box::new(|cc| {
            Box::new(SmartContractAnalyzerApp::new(rpc_url, cc))
        }),
    )
}
