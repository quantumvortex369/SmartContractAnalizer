use eframe::egui;
use std::sync::mpsc;
use std::sync::Arc;
use tokio::runtime::Runtime;
use crate::analyzer::{ContractAnalysis, Finding, Severity as AnalyzerSeverity};
use crate::is_valid_ethereum_address;
use egui::{Color32, RichText};
use std::time::Duration;

// Usamos el Severity de analyzer.rs

pub struct SmartContractAnalyzerApp {
    rpc_url: String,
    contract_address: String,
    is_analyzing: bool,
    analysis_result: Option<Result<ContractAnalysis, String>>,
    rt: Arc<Runtime>,
    result_receiver: Option<mpsc::Receiver<Result<ContractAnalysis, String>>>,
    active_tab: String,
    show_help: bool,
    last_update: Option<std::time::Instant>,
}

impl SmartContractAnalyzerApp {
    /// Implementación manual de Default que no requiere que Runtime implemente Default
    fn default() -> Self {
        // Crear un nuevo runtime de tokio
        let rt = Runtime::new().expect("Failed to create Tokio runtime");
        
        Self {
            rpc_url: "https://mainnet.infura.io/v3/YOUR-PROJECT-ID".to_string(),
            contract_address: String::new(),
            is_analyzing: false,
            analysis_result: None,
            rt: Arc::new(rt),
            result_receiver: None,
            active_tab: "analyzer".to_string(),
            show_help: false,
            last_update: None,
        }
    }
    
    pub fn new(rpc_url: String, _cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            rpc_url,
            contract_address: String::new(),
            is_analyzing: false,
            analysis_result: None,
            rt: Arc::new(Runtime::new().expect("No se pudo crear el runtime de Tokio")),
            result_receiver: None,
            active_tab: "analyzer".to_string(),
            show_help: false,
            last_update: None,
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
        
        // Crear un análisis de contrato de ejemplo
        let analysis = ContractAnalysis {
            contract_address: self.contract_address.clone(),
            is_verified: true,
            risk_score: 0.3,
            findings: vec![
                Finding {
                    title: "Posible vulnerabilidad de reentrancia".to_string(),
                    description: "Se detectó un patrón que podría ser vulnerable a ataques de reentrancia".to_string(),
                    severity: AnalyzerSeverity::High,
                    code_snippet: Some("function withdraw() public {\\n    require(balances[msg.sender] > 0);\\n    (bool success, ) = msg.sender.call{value: balances[msg.sender]}(\\\"\\\");\\n    balances[msg.sender] = 0;\\n}\"".to_string()),
                    reference: Some("SWC-107".to_string()),
                    impact: "Pérdida de fondos".to_string(),
                    recommendation: Some("Usa el patrón Checks-Effects-Interactions".to_string()),
                    category: Some("Seguridad".to_string()),
                    is_false_positive: false,
                    detected_at: Some(chrono::Utc::now()),
                    status: Some("Pendiente".to_string()),
                },
                Finding {
                    title: "Uso de transfer() en lugar de call()".to_string(),
                    description: "Se recomienda usar call() con manejo de errores en lugar de transfer()".to_string(),
                    severity: AnalyzerSeverity::Medium,
                    code_snippet: Some("payable(msg.sender).transfer(amount);".to_string()),
                    reference: Some("SWC-128".to_string()),
                    impact: "Posible falla en la transferencia de fondos".to_string(),
                    recommendation: Some("Usa call() con manejo de errores: (bool success, ) = msg.sender.call{value: amount}(\\\"\\\"); require(success, \\\"Transfer failed\\\");".to_string()),
                    category: Some("Buenas Prácticas".to_string()),
                    is_false_positive: false,
                    detected_at: Some(chrono::Utc::now()),
                    status: Some("Pendiente".to_string()),
                },
            ],
            is_suspicious: true,
            contract_name: Some("EjemploContrato".to_string()),
            compiler_version: Some("0.8.0".to_string()),
            optimization_used: Some(true),
            proxy_implementation: None,
            token_standard: Some("ERC20".to_string()),
            created_at_block: Some(12345678),
            last_activity: Some((chrono::Utc::now() - chrono::Duration::days(30)).timestamp() as u64),
            transaction_count: 150,
            verified_source: Some("".to_string()),
            abi: Some(serde_json::Value::String("".to_string())),
            bytecode: Some("".to_string()),
            opcodes: Some(vec![]),
        };

        self.analysis_result = Some(Ok(analysis));
        self.is_analyzing = false;
    }
    
    fn get_severity_color(severity: &AnalyzerSeverity) -> Color32 {
        match severity {
            AnalyzerSeverity::Critical => Color32::from_rgb(220, 38, 38),  // Rojo
            AnalyzerSeverity::High => Color32::from_rgb(234, 88, 12),      // Naranja
            AnalyzerSeverity::Medium => Color32::from_rgb(202, 138, 4),    // Amarillo
            AnalyzerSeverity::Low => Color32::from_rgb(22, 163, 74),       // Verde
            AnalyzerSeverity::Info => Color32::from_rgb(37, 99, 235),      // Azul
        }
    }
    
    fn show_loading_indicator(&self, ui: &mut egui::Ui) {
        let time = self.last_update
            .map(|t| t.elapsed().as_secs_f32())
            .unwrap_or(0.0);
        
        let dots = ".".repeat(1 + (time * 2.0) as usize % 4);
        
        ui.vertical_centered_justified(|ui| {
            ui.add_space(20.0);
            ui.spinner();
            ui.add_space(10.0);
            ui.label(format!("Analizando contrato {}", dots));
        });
    }
    
    fn show_analysis_results(&self, ui: &mut egui::Ui, analysis: &ContractAnalysis) {
        ui.heading("📊 Resultados del Análisis");
        ui.separator();
        
        // Resumen del contrato
        ui.label(RichText::new("📋 Información del Contrato").heading());
        ui.horizontal(|ui| {
            ui.label("Dirección:");
            ui.monospace(&analysis.contract_address);
        });
        
        // Barra de progreso de riesgo
        ui.add_space(10.0);
        ui.label(RichText::new("📈 Nivel de Riesgo").heading());
        let risk_percent = (analysis.risk_score * 100.0) as u32;
        let risk_color = if risk_percent > 70 {
            Color32::RED
        } else if risk_percent > 40 {
            Color32::YELLOW
        } else {
            Color32::GREEN
        };
        
        ui.add(
            egui::ProgressBar::new(analysis.risk_score as f32)
                .text(format!("{}%", risk_percent))
                .fill(risk_color)
                .show_percentage()
        );
        
        // Hallazgos de seguridad
        ui.add_space(20.0);
        ui.label(RichText::new("🔍 Hallazgos de Seguridad").heading());
        
        if analysis.findings.is_empty() {
            ui.label("✅ No se encontraron problemas de seguridad críticos.");
            return;
        }
        
        // Agrupar hallazgos por severidad
        let mut findings_by_severity = std::collections::BTreeMap::new();
        for finding in &analysis.findings {
            findings_by_severity
                .entry(&finding.severity)
                .or_insert_with(Vec::new)
                .push(finding);
        }
        
        // Mostrar hallazgos agrupados por severidad
        for (severity, findings) in findings_by_severity.into_iter().rev() {
            let severity_text = match severity {
                AnalyzerSeverity::Critical => "❌ Crítico",
                AnalyzerSeverity::High => "⚠️ Alto",
                AnalyzerSeverity::Medium => "⚠️ Medio",
                AnalyzerSeverity::Low => "ℹ️ Bajo",
                AnalyzerSeverity::Info => "ℹ️ Informativo",
            };
            
            egui::CollapsingHeader::new(format!("{} ({}) {}", 
                severity_text, 
                findings.len(),
                if matches!(severity, AnalyzerSeverity::Critical | AnalyzerSeverity::High) {
                    "🚨"
                } else {
                    ""
                }
            ))
            .default_open(matches!(severity, AnalyzerSeverity::Critical | AnalyzerSeverity::High))
            .show(ui, |ui| {
                for finding in findings {
                    egui::Frame::group(ui.style())
                        .fill(ui.visuals().window_fill().linear_multiply(0.8))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(&finding.title)
                                            .color(Self::get_severity_color(severity))
                                            .strong()
                                    );
                                    
                                    ui.label(RichText::new(&finding.description).color(Color32::WHITE));
                                    
                                    if let Some(snippet) = &finding.code_snippet {
                                        ui.add_space(5.0);
                                        egui::Frame::none()
                                            .fill(ui.visuals().code_bg_color)
                                            .show(ui, |ui| {
                                                ui.add(egui::TextEdit::multiline(
                                                    &mut snippet.as_str()
                                                )
                                                .font(egui::TextStyle::Monospace)
                                                .desired_width(f32::INFINITY));
                                            });
                                    }
                                    
                                    if let Some(recommendation) = &finding.recommendation {
                                        ui.add_space(5.0);
                                        ui.horizontal(|ui| {
                                            ui.label("💡 Recomendación:");
                                            ui.label(recommendation);
                                        });
                                    }
                                    
                                    if let Some(reference) = &finding.reference {
                                        ui.small(format!("Referencia: {}", reference));
                                    }
                                });
                            });
                        });
                    
                    ui.add_space(5.0);
                }
            });
        }
    }
    
    fn show_analyzer_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered_justified(|ui| {
            ui.add_space(20.0);
            
            // Título y descripción
            ui.heading("Análisis de Contratos Inteligentes");
            ui.label("Analiza contratos en busca de vulnerabilidades y patrones sospechosos");
            
            ui.add_space(20.0);
            
            // Panel de entrada de dirección
            egui::Frame::group(ui.style())
                .fill(ui.style().visuals.window_fill())
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.label("Dirección del contrato:");
                        
                        ui.horizontal(|ui| {
                            let response = ui.add(
                                egui::TextEdit::singleline(&mut self.contract_address)
                                    .hint_text("0x...")
                                    .desired_width(400.0)
                            );
                            
                            let is_valid = !self.contract_address.trim().is_empty() && 
                                         is_valid_ethereum_address(&self.contract_address);
                            
                            let button = ui.add_enabled(!self.is_analyzing && is_valid, 
                                egui::Button::new("🔍 Analizar")
                                    .min_size(egui::vec2(100.0, 36.0))
                            );
                            
                            if button.clicked() {
                                self.analyze_contract();
                                self.last_update = Some(std::time::Instant::now());
                            }
                            
                            // Enfocar el campo de texto al inicio
                            if self.last_update.is_none() {
                                response.request_focus();
                            }
                        });
                        
                        if !self.contract_address.is_empty() && !is_valid_ethereum_address(&self.contract_address) {
                            ui.label(
                                RichText::new("⚠️ Dirección de contrato inválida")
                                    .color(Color32::RED)
                            );
                        }
                    });
                });
            
            ui.add_space(20.0);
            
            // Panel de resultados
            egui::Frame::group(ui.style())
                .fill(ui.style().visuals.window_fill())
                .show(ui, |ui| {
                    if self.is_analyzing {
                        self.show_loading_indicator(ui);
                    } else if let Some(result) = &self.analysis_result {
                        match result {
                            Ok(analysis) => self.show_analysis_results(ui, analysis),
                            Err(e) => {
                                ui.label(
                                    RichText::new(format!("❌ Error: {}", e))
                                        .color(Color32::RED)
                                );
                            }
                        }
                    } else {
                        ui.label("Ingresa una dirección de contrato para comenzar el análisis.");
                    }
                });
        });
    }
    
    fn show_history_tab(&self, ui: &mut egui::Ui) {
        ui.vertical_centered_justified(|ui| {
            ui.heading("📜 Historial de Análisis");
            ui.label("Próximamente: Historial de análisis recientes");
        });
    }
    
    fn show_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered_justified(|ui| {
            ui.heading("⚙️ Configuración");
            ui.separator();
            
            ui.label("Configuración de la red:");
            ui.horizontal(|ui| {
                ui.label("URL del nodo RPC:");
                ui.text_edit_singleline(&mut self.rpc_url);
            });
            
            ui.add_space(10.0);
            
            if ui.button("Guardar configuración").clicked() {
                // Aquí iría la lógica para guardar la configuración
                ui.label("✅ Configuración guardada");
            }
        });
    }
}

impl eframe::App for SmartContractAnalyzerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Barra de navegación superior
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.heading("🔍 Smart Contract Analyzer");
                
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("ℹ️ Ayuda").clicked() {
                        self.show_help = !self.show_help;
                    }
                });
            });
        });

        // Panel principal
        egui::CentralPanel::default().show(ctx, |ui| {
            // Pestañas
            egui::TopBottomPanel::top("tabs").show(ui.ctx(), |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.active_tab, "analyzer".to_string(), "🧪 Analizador");
                    ui.selectable_value(&mut self.active_tab, "history".to_string(), "📜 Historial");
                    ui.selectable_value(&mut self.active_tab, "settings".to_string(), "⚙️ Configuración");
                });
                ui.separator();
            });

            // Contenido según la pestaña activa
            match self.active_tab.as_str() {
                "analyzer" => self.show_analyzer_tab(ui),
                "history" => self.show_history_tab(ui),
                "settings" => self.show_settings_tab(ui),
                _ => {}
            }
        });

        // Mostrar diálogo de ayuda si está activo
        if self.show_help {
            let mut open = true;
            let response = egui::Window::new("Ayuda")
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label("🔍 Smart Contract Analyzer - Ayuda");
                    ui.separator();
                    ui.label("1. Ingresa la dirección del contrato en el campo de texto");
                    ui.label("2. Haz clic en 'Analizar' para comenzar el análisis");
                    ui.label("3. Revisa los resultados en las pestañas inferiores");
                    ui.vertical_centered(|ui| {
                        if ui.button("Cerrar").clicked() {
                            self.show_help = false;
                        }
                    });
                });
                
            // Actualizar el estado basado en la respuesta
            if !open || (response.is_some() && response.unwrap().response.clicked_elsewhere()) {
                self.show_help = false;
            }
        }

        // Actualización periódica para animaciones
        if self.is_analyzing {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}


pub fn start_gui(rpc_url: String) -> Result<(), Box<dyn std::error::Error>> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 800.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };
    
    eframe::run_native(
        "Smart Contract Analyzer",
        options,
        Box::new(|cc| Box::new(SmartContractAnalyzerApp::new(rpc_url, cc))),
    )
    .map_err(|e| e.into())
}
