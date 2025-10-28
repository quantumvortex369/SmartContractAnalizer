use eframe::egui;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use std::collections::{HashSet, VecDeque};

use crate::types::{self, AnalyzerSeverity, ContractAnalysis, Finding};
use crate::error::{self, AnalyzerError, Result};

#[cfg(feature = "tokio")]
use tokio::runtime::Runtime;

use egui::{
    Color32, RichText, Stroke,
    style::Visuals,
};

// Re-export for convenience
pub use eframe;

// Theme colors
const PRIMARY_COLOR: Color32 = Color32::from_rgb(99, 102, 241); // Indigo-600
const SECONDARY_COLOR: Color32 = Color32::from_rgb(79, 70, 229); // Indigo-700
const SUCCESS_COLOR: Color32 = Color32::from_rgb(16, 185, 129); // Emerald-500
const WARNING_COLOR: Color32 = Color32::from_rgb(245, 158, 11); // Amber-500
const DANGER_COLOR: Color32 = Color32::from_rgb(239, 68, 68); // Red-500
const DARK_BG: Color32 = Color32::from_rgb(17, 24, 39); // Gray-900
const CARD_BG: Color32 = Color32::from_rgb(31, 41, 55); // Gray-800
const TEXT_COLOR: Color32 = Color32::from_rgb(243, 244, 246); // Gray-100

#[derive(Default)]
struct AnalysisHistory {
    entries: VecDeque<(String, Result<ContractAnalysis>)>,
    max_entries: usize,
}

impl AnalysisHistory {
    fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries),
            max_entries,
        }
    }

    fn add(&mut self, address: String, result: Result<ContractAnalysis>) {
        if self.entries.len() >= self.max_entries {
            self.entries.pop_back();
        }
        self.entries.push_front((address, result));
    }
}

// Analysis statistics tracking
#[derive(Default, Clone)]
pub struct AnalysisStats {
    pub total_contracts_analyzed: u32,
    pub total_findings: u32,
    pub critical_findings: u32,
    pub high_findings: u32,
    pub medium_findings: u32,
    pub low_findings: u32,
    pub info_findings: u32,
    pub avg_analysis_time: f64,
    pub last_analysis_duration: Option<Duration>,
}

// Analysis configuration
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScanDepth {
    Quick,
    Standard,
    Deep,
    Custom,
}

impl Default for ScanDepth {
    fn default() -> Self {
        Self::Standard
    }
}

#[derive(Default, Clone)]
pub struct AnalysisOptions {
    pub scan_depth: ScanDepth,
    pub check_reentrancy: bool,
    pub check_overflow: bool,
    pub check_access_control: bool,
    pub check_gas_optimization: bool,
    pub check_upgradeability: bool,
    pub check_erc20: bool,
    pub check_erc721: bool,
    pub check_erc1155: bool,
    pub custom_checks: Vec<String>,
    pub timeout_seconds: u64,
    pub max_findings: usize,
}

pub struct SmartContractAnalyzerApp {
    // App state
    rpc_url: String,
    contract_address: String,
    is_analyzing: bool,
    analysis_result: Option<Result<ContractAnalysis>>,
    rt: Arc<Runtime>,
    result_receiver: Option<mpsc::Receiver<Result<ContractAnalysis>>>,
    
    // UI State
    active_tab: String,
    show_help: bool,
    last_update: Option<Instant>,
    dark_mode: bool,
    history: AnalysisHistory,
    
    // Performance metrics
    analysis_time: Option<Duration>,
    
    // UI State
    show_advanced: bool,
    custom_abi: String,
    scan_type: String,
    
    // Analysis options
    analysis_options: AnalysisOptions,
    
    // View states
    expanded_findings: HashSet<usize>,
    selected_finding: Option<usize>,
    
    // Stats
    stats: AnalysisStats,
}

impl SmartContractAnalyzerApp {
    // Muestra el panel de opciones de análisis
    fn show_analysis_panel(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Opciones de Análisis")
            .default_open(true)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Profundidad de análisis:");
                    ui.radio_value(
                        &mut self.analysis_options.scan_depth,
                        ScanDepth::Quick,
                        "Rápido"
                    );
                    ui.radio_value(
                        &mut self.analysis_options.scan_depth,
                        ScanDepth::Standard,
                        "Estándar"
                    );
                    ui.radio_value(
                        &mut self.analysis_options.scan_depth,
                        ScanDepth::Deep,
                        "Profundo"
                    );
                });

                ui.separator();
                
                // Opciones de verificación
                ui.label("Verificaciones de Seguridad:");
                ui.checkbox(&mut self.analysis_options.check_reentrancy, "Reentrancia");
                ui.checkbox(&mut self.analysis_options.check_overflow, "Overflow/Underflow");
                ui.checkbox(&mut self.analysis_options.check_access_control, "Control de Acceso");
                ui.checkbox(&mut self.analysis_options.check_upgradeability, "Contratos Actualizables");
                
                ui.separator();
                
                // Estándares de token
                ui.label("Estándares de Token:");
                ui.checkbox(&mut self.analysis_options.check_erc20, "ERC-20");
                ui.checkbox(&mut self.analysis_options.check_erc721, "ERC-721");
                ui.checkbox(&mut self.analysis_options.check_erc1155, "ERC-1155");
                
                ui.separator();
                
                // Opciones avanzadas
                ui.collapsing("Opciones Avanzadas", |ui| {
                    ui.checkbox(
                        &mut self.analysis_options.check_gas_optimization, 
                        "Optimización de Gas"
                    );
                    
                    ui.horizontal(|ui| {
                        ui.label("Tiempo máximo (segundos):");
                        ui.add(
                            egui::DragValue::new(&mut self.analysis_options.timeout_seconds)
                                .clamp_range(10..=300)
                        );
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("Máximo de hallazgos:");
                        ui.add(
                            egui::DragValue::new(&mut self.analysis_options.max_findings)
                                .clamp_range(1..=1000)
                        );
                    });
                });
            });
        
        ui.add_space(10.0);
    }
    
    // Muestra las estadísticas de análisis
    fn show_stats_panel(&self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style())
            .fill(if self.dark_mode { CARD_BG } else { Color32::from_gray(240) })
            .show(ui, |ui| {
                ui.heading("Estadísticas");
                ui.separator();
                
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label("Contratos analizados:");
                        ui.label("Hallazgos totales:");
                        ui.label("Tiempo medio de análisis:");
                    });
                    
                    ui.vertical(|ui| {
                        ui.label(format!("{}", self.stats.total_contracts_analyzed));
                        ui.label(format!("{}", self.stats.total_findings));
                        if let Some(avg_time) = self.stats.last_analysis_duration {
                            ui.label(format!("{:.2} segundos", avg_time.as_secs_f64()));
                        } else {
                            ui.label("N/A");
                        }
                    });
                });
                
                ui.separator();
                
                // Mostrar contadores de severidad
                ui.label("Hallazgos por severidad:");
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("●").color(DANGER_COLOR));
                    ui.label(format!("Críticos: {}", self.stats.critical_findings));
                    
                    ui.label(egui::RichText::new("●").color(WARNING_COLOR));
                    ui.label(format!("Altos: {}", self.stats.high_findings));
                    
                    ui.label(egui::RichText::new("●").color(Color32::YELLOW));
                    ui.label(format!("Medios: {}", self.stats.medium_findings));
                    
                    ui.label(egui::RichText::new("●").color(Color32::GREEN));
                    ui.label(format!("Bajos: {}", self.stats.low_findings));
                });
                
                // Botón para exportar resultados
                if ui.button("Exportar Informe").clicked() {
                    // Lógica para exportar el informe
                    // Esto podría abrir un diálogo de guardado
                }
            });
    }
    
    // Implementación manual de Default que no requiere que Runtime implemente Default
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
            dark_mode: true,
            history: AnalysisHistory::new(10),
            analysis_time: None,
            show_advanced: false,
            custom_abi: String::new(),
            scan_type: "quick".to_string(),
            analysis_options: AnalysisOptions {
                scan_depth: ScanDepth::Standard,
                check_reentrancy: true,
                check_overflow: true,
                check_access_control: true,
                check_gas_optimization: false,
                check_upgradeability: true,
                check_erc20: true,
                check_erc721: true,
                check_erc1155: true,
                custom_checks: Vec::new(),
                timeout_seconds: 60,
                max_findings: 100,
            },
            expanded_findings: HashSet::new(),
            selected_finding: None,
            stats: AnalysisStats::default(),
        }
    }
    
    fn analyze_contract(&mut self) {
        // Validar dirección
        if self.contract_address.trim().is_empty() {
            self.analysis_result = Some(Err(crate::error::AnalyzerError::Validation(
                "Por favor ingresa una dirección de contrato".to_string()
            )));
            return;
        }
        
        if !types::is_valid_ethereum_address(&self.contract_address) {
            self.analysis_result = Some(Err(crate::error::AnalyzerError::Validation(
                "Dirección de contrato inválida".to_string()
            )));
            return;
        }
        
        self.is_analyzing = true;
        self.analysis_result = None;
        
        // Clonar los datos necesarios para el análisis asíncrono
        let address = self.contract_address.clone();
        
        // Crear un canal para recibir el resultado
        let (tx, rx) = mpsc::channel();
        self.result_receiver = Some(rx);
        
        // Obtener el runtime de Tokio
        let rt = self.rt.clone();
        
        // Ejecutar el análisis en segundo plano
        std::thread::spawn(move || {
            let result = rt.block_on(async {
                // Aquí iría la lógica de análisis real
                // Por ahora, usamos un mock
                let analysis = ContractAnalysis {
                    address: address.clone(),
                    is_verified: false,
                    is_suspicious: false,
                    findings: vec![
                        Finding {
                            title: "Reentrancy Vulnerability".to_string(),
                            description: "Potential reentrancy vulnerability found".to_string(),
                            severity: AnalyzerSeverity::High,
                            location: None,
                            code_snippet: Some("function withdraw() public {\n    (bool success, ) = msg.sender.call{value: address(this).balance}(\"\");\n    require(success, \"Transfer failed\");\n}".to_string()),
                            recommendation: Some("Use checks-effects-interactions pattern".to_string()),
                            category: Some("Security".to_string()),
                            reference: Some("https://swcregistry.io/docs/SWC-107".to_string()),
                            is_false_positive: false,
                            detected_at: Some(chrono::Utc::now()),
                            status: Some("Pending".to_string()),
                        },
                        Finding {
                            title: "Unsafe ERC20 Operation".to_string(),
                            description: "Unsafe ERC20 operation without return value check".to_string(),
                            severity: AnalyzerSeverity::Medium,
                            location: None,
                            code_snippet: Some("IERC20(token).transferFrom(msg.sender, address(this), amount);".to_string()),
                            recommendation: Some("Use SafeERC20 or check the return value".to_string()),
                            category: Some("ERC20".to_string()),
                            reference: Some("https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729".to_string()),
                            is_false_positive: false,
                            detected_at: Some(chrono::Utc::now()),
                            status: Some("Pending".to_string()),
                        },
                    ],
                    analyzed_at: chrono::Utc::now(),
                    bytecode: None,
                    source_code: None,
                    contract_name: None,
                    compiler_version: None,
                    optimization_used: None,
                    proxy_implementation: None,
                    token_standard: None,
                    created_at_block: None,
                    last_activity: None,
                    transaction_count: None,
                    verified_source: None,
                    abi: None,
                    opcodes: None,
                };
                
                Ok(analysis)
            });
            
            // Enviar el resultado de vuelta al hilo principal
            let _ = tx.send(result);
        });
        
        // Actualizar estadísticas
        self.stats.total_contracts_analyzed += 1;
        self.stats.total_findings += 2; // Mock data
        self.stats.high_findings += 1;  // Mock data
        self.stats.medium_findings += 1; // Mock data
        
        // Crear un análisis de prueba
        let mock_analysis = ContractAnalysis {
            address: self.contract_address.clone(),
            findings: vec![
                Finding {
                    title: "Reentrancy Vulnerability".to_string(),
                    description: "Potential reentrancy vulnerability found".to_string(),
                    severity: AnalyzerSeverity::High,
                    category: Some("Security".to_string()),
                    recommendation: Some("Use checks-effects-interactions pattern".to_string()),
                    code_snippet: Some("function withdraw() public {\n    (bool success, ) = msg.sender.call{value: address(this).balance}(\"\");\n    require(success, \"Transfer failed\");\n}".to_string()),
                    reference: Some("https://swcregistry.io/docs/SWC-107".to_string()),
                    location: None,
                    is_false_positive: false,
                    detected_at: Some(chrono::Utc::now()),
                    status: Some("Open".to_string()),
                },
                Finding {
                    title: "Unsafe ERC20 Operation".to_string(),
                    description: "Unsafe ERC20 operation without return value check".to_string(),
                    severity: AnalyzerSeverity::Medium,
                    category: Some("ERC20".to_string()),
                    recommendation: Some("Use SafeERC20 or check the return value".to_string()),
                    code_snippet: Some("IERC20(token).transferFrom(msg.sender, address(this), amount);".to_string()),
                    reference: Some("https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729".to_string()),
                    location: None,
                    is_false_positive: false,
                    detected_at: Some(chrono::Utc::now()),
                    status: Some("Open".to_string()),
                },
            ],
            is_verified: false,
            is_suspicious: false,
            analyzed_at: chrono::Utc::now(),
            bytecode: None,
            source_code: None,
            contract_name: None,
            compiler_version: None,
            optimization_used: None,
            proxy_implementation: None,
            token_standard: None,
            created_at_block: Some(12345678),
            last_activity: None,
            transaction_count: Some(150),
            verified_source: Some("Etherscan".to_string()),
            abi: None,
            opcodes: None,
        };

        let result = Ok(mock_analysis);
        self.analysis_result = Some(result);
        
        // Add to history
        if let Some(Ok(analysis)) = &self.analysis_result {
            self.history.add(
                self.contract_address.clone(), 
                Ok(analysis.clone())
            );
        }
        
        self.is_analyzing = false;
    }
    
    fn get_severity_color(&self, severity: &AnalyzerSeverity) -> Color32 {
        match severity {
            AnalyzerSeverity::Critical => DANGER_COLOR,
            AnalyzerSeverity::High => Color32::from_rgb(249, 115, 22), // Orange-500
            AnalyzerSeverity::Medium => WARNING_COLOR,
            AnalyzerSeverity::Low => Color32::from_rgb(59, 130, 246), // Blue-500
            AnalyzerSeverity::Info => Color32::from_rgb(107, 114, 128), // Gray-500
        }
    }
    
    fn show_loading_indicator(&self, ui: &mut egui::Ui) {
        ui.vertical_centered_justified(|ui| {
            ui.spinner();
            ui.add_space(10.0);
            ui.label("🔍 Analyzing smart contract...");
            ui.label("This may take a few moments...");
            
            // Add a progress bar
            let progress = if let Some(start) = self.last_update {
                let elapsed = start.elapsed();
                (elapsed.as_secs_f32() % 2.0).min(1.0)
            } else {
                0.0
            };
            
            let progress_bar = egui::ProgressBar::new(progress)
                .show_percentage()
                .animate(true);
            ui.add(progress_bar);
        });
    }
    
    fn show_analysis_results(&self, ui: &mut egui::Ui, analysis: &ContractAnalysis) {
        // Summary Card
        egui::Frame::group(ui.style())
            .fill(CARD_BG)
            .rounding(8.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Contract Info
                    ui.vertical(|ui| {
                        ui.heading(RichText::new("Contract Analysis").color(TEXT_COLOR));
                        if !analysis.address.is_empty() {
                            ui.label(RichText::new(format!("📝 Contract: {}", analysis.address)).strong());
                        }
                        if let Some(version) = &analysis.compiler_version {
                            ui.label(RichText::new(format!("⚙️ Compiler: {}", version)));
                        }
                        if let Some(time) = self.analysis_time {
                            ui.label(RichText::new(format!("⏱️ Analysis Time: {:.2?}", time)));
                        }
                    });
                    
                    // Severity Summary
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                        let critical_count = analysis.findings.iter()
                            .filter(|f| matches!(f.severity, AnalyzerSeverity::Critical)).count();
                        let high_count = analysis.findings.iter()
                            .filter(|f| matches!(f.severity, AnalyzerSeverity::High)).count();
                        let medium_count = analysis.findings.iter()
                            .filter(|f| matches!(f.severity, AnalyzerSeverity::Medium)).count();
                        let low_count = analysis.findings.iter()
                            .filter(|f| matches!(f.severity, AnalyzerSeverity::Low)).count();
                        let info_count = analysis.findings.iter()
                            .filter(|f| matches!(f.severity, AnalyzerSeverity::Info)).count();
                        
                        ui.vertical(|ui| {
                            self.severity_badge(ui, "CRITICAL", DANGER_COLOR, critical_count);
                            self.severity_badge(ui, "HIGH", Color32::from_rgb(249, 115, 22), high_count);
                            self.severity_badge(ui, "MEDIUM", WARNING_COLOR, medium_count);
                            self.severity_badge(ui, "LOW", Color32::from_rgb(59, 130, 246), low_count);
                            self.severity_badge(ui, "INFO", Color32::from_rgb(107, 114, 128), info_count);
                        });
                    });
                });
            });
        
        ui.add_space(20.0);
        
        // Findings List
        ui.push_id("findings", |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (i, finding) in analysis.findings.iter().enumerate() {
                        self.render_finding(ui, finding, i);
                    }
                });
        });
        
        // Export Button
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
            if ui.button("📄 Export Report").clicked() {
                // TODO: Implement export functionality
                // self.export_report(analysis);
            }
        });
    }
    
    fn severity_badge(&self, ui: &mut egui::Ui, label: &str, color: Color32, count: usize) {
        if count > 0 {
            ui.horizontal(|ui| {
                ui.colored_label(color, format!("{}: {}", label, count));
            });
        } else {
            ui.horizontal(|ui| {
                ui.colored_label(Color32::GRAY, format!("{}: 0", label));
            });
        }
    }
    
    fn render_finding(&self, ui: &mut egui::Ui, finding: &Finding, id: usize) {
        let severity_color = self.get_severity_color(&finding.severity);
        let severity_text = format!("{:?}", finding.severity).to_uppercase();
        
        egui::Frame::group(ui.style())
            .fill(CARD_BG)
            .rounding(8.0)
            .show(ui, |ui| {
                egui::CollapsingHeader::new(
                    format!("{} {}", self.severity_icon(&finding.severity), finding.title)
                )
                .id_source(format!("finding_{}", id))
                .default_open(true)
                .show(ui, |ui| {
                    // Severity Badge
                    ui.horizontal(|ui| {
                        ui.colored_label(severity_color, format!("Severity: {}", severity_text));
                        ui.separator();
                        if let Some(category) = &finding.category {
                            ui.label(RichText::new(category).weak());
                        }
                    });
                    
                    ui.add_space(10.0);
                    
                    // Description
                    ui.label(&finding.description);
                    
                    // Recommendation if available
                    if let Some(recommendation) = &finding.recommendation {
                        ui.add_space(10.0);
                        ui.label(RichText::new("🔧 Recommendation:").strong());
                        ui.label(recommendation);
                    }
                    
                    // Code Snippet if available
                    if let Some(code) = &finding.code_snippet {
                        ui.add_space(10.0);
                        ui.label(RichText::new("📄 Code Snippet:").strong());
                        egui::Frame::group(ui.style())
                            .fill(DARK_BG)
                            .show(ui, |ui| {
                                ui.monospace(code);
                            });
                    }
                    
                    // References if available
                    if let Some(reference) = &finding.reference {
                        ui.add_space(10.0);
                        ui.label(RichText::new("📚 Reference:").strong());
                        ui.hyperlink(reference);
                    }
                });
            });
        
        ui.add_space(10.0);
    }
    
    fn severity_icon(&self, severity: &AnalyzerSeverity) -> &'static str {
        match severity {
            AnalyzerSeverity::Critical => "💥",
            AnalyzerSeverity::High => "⚠️",
            AnalyzerSeverity::Medium => "🔍",
            AnalyzerSeverity::Low => "ℹ️",
            AnalyzerSeverity::Info => "💡",
        }
    }
    
    fn show_analyzer_tab(&mut self, ui: &mut egui::Ui) {
        // Usar un diseño de dos columnas
        egui::SidePanel::left("left_panel")
            .resizable(true)
            .min_width(300.0)
            .show_inside(ui, |ui| {
                // Panel de opciones de análisis
                self.show_analysis_panel(ui);
                
                ui.separator();
                
                // Panel de estadísticas
                self.show_stats_panel(ui);
                
                // Mostrar información de red
                ui.separator();
                ui.collapsing("Información de la Red", |ui| {
                    ui.label(format!("Conectado a: {}", self.rpc_url));
                    ui.label("Estado: Conectado");
                });
            });

        // Panel principal
        egui::CentralPanel::default().show_inside(ui, |ui| {
            // Título
            ui.heading("Analizador de Contratos Inteligentes");
            ui.separator();
            
            // Tarjeta de entrada de datos
            egui::Frame::group(ui.style())
                .fill(if self.dark_mode { CARD_BG } else { Color32::from_gray(245) })
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        // Input para la dirección del contrato
                        ui.label("Dirección del contrato:");
                        let response = ui.text_edit_singleline(&mut self.contract_address);
                        if self.contract_address.is_empty() {
                            ui.painter().text(
                                response.rect.left_center(),
                                egui::Align2::LEFT_CENTER,
                                "0x...",
                                egui::TextStyle::Body.resolve(ui.style()).clone(),
                                ui.style().visuals.weak_text_color(),
                            );
                        }
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("Nodo RPC:");
                        ui.text_edit_singleline(&mut self.rpc_url);
                    });
                    
                    // Botón de análisis con ícono
                    let button = egui::Button::new(
                        RichText::new("🔍 Analizar Contrato")
                            .text_style(egui::TextStyle::Button)
                    )
                    .fill(PRIMARY_COLOR)
                    .min_size(egui::Vec2::new(200.0, 36.0));
                    
                    if ui.add(button).clicked() {
                        self.analyze_contract();
                    }
                });

            // Mostrar indicador de carga si está analizando
            if self.is_analyzing {
                ui.separator();
                self.show_loading_indicator(ui);
            }

            // Mostrar resultados del análisis
            if let Some(result) = &self.analysis_result {
                ui.separator();
                match result {
                    Ok(analysis) => {
                        self.show_analysis_results(ui, analysis);
                        
                        // Agregar al historial si tenemos un resultado reciente
                        if !self.contract_address.is_empty() {
                            self.history.add(self.contract_address.clone(), result.clone());
                        }
                    }
                    Err(err) => {
                        ui.label(
                            RichText::new(format!("❌ Error al analizar el contrato: {}", err))
                                .color(DANGER_COLOR)
                                .strong(),
                        );
                    }
                }
            }
        });
            ui.label("Última actualización: Hace unos segundos");
        // Add to history if we have a recent result
        if let (Some(result), Some(address)) = (&self.analysis_result, self.contract_address.parse().ok()) {
            self.history.add(address, result.clone());
        }
    }
    
    fn show_history_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.heading(RichText::new("📜 Analysis History").color(TEXT_COLOR));
        });
        
        if self.history.entries.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(50.0);
                ui.label(RichText::new("No analysis history yet").weak());
                ui.label(RichText::new("Analyze a contract to see it here").weak());
            });
            return;
        }
        
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (address, result) in &self.history.entries {
                    let response = egui::Frame::group(ui.style())
                        .fill(CARD_BG)
                        .rounding(8.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                // Contract address
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(address).monospace().strong());
                                    
                                    // Show result summary
                                    if let Ok(analysis) = result {
                                        let mut counts = [0; 5]; // crit, high, med, low, info
                                        for finding in &analysis.findings {
                                            match finding.severity {
                                                AnalyzerSeverity::Critical => counts[0] += 1,
                                                AnalyzerSeverity::High => counts[1] += 1,
                                                AnalyzerSeverity::Medium => counts[2] += 1,
                                                AnalyzerSeverity::Low => counts[3] += 1,
                                                AnalyzerSeverity::Info => counts[4] += 1,
                                            }
                                        }
                                        
                                        // Show severity counts
                                        ui.horizontal(|ui| {
                                            if counts[0] > 0 { ui.colored_label(DANGER_COLOR, format!("{} CRIT", counts[0])); }
                                            if counts[1] > 0 { ui.colored_label(WARNING_COLOR, format!("{} HIGH", counts[1])); }
                                            if counts[2] > 0 { ui.colored_label(WARNING_COLOR, format!("{} MED", counts[2])); }
                                            if counts[3] > 0 { ui.colored_label(Color32::BLUE, format!("{} LOW", counts[3])); }
                                            if counts[4] > 0 { ui.colored_label(Color32::GRAY, format!("{} INFO", counts[4])); }
                                        });
                                    } else if let Err(e) = result {
                                        ui.colored_label(Color32::RED, format!("Error: {}", e));
                                    }
                                });
                                
                                // View Button
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                                    if ui.button("View").clicked() {
                                        self.contract_address = address.clone();
                                        self.active_tab = "analyzer".to_string();
                                    }
                                });
                            });
                        });
                    
                    if response.response.clicked() {
                        // Click anywhere to view
                        self.contract_address = address.clone();
                        self.active_tab = "analyzer".to_string();
                    }
                    
                    ui.add_space(4.0);
                }
            });
    }
    
    fn show_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.heading("⚙️ Settings");
        });
        
        egui::Frame::group(ui.style())
            .fill(CARD_BG)
            .rounding(8.0)
            .show(ui, |ui| {
                ui.label(RichText::new("Appearance").strong().heading());
                ui.separator();
                
                // Theme Toggle
                ui.horizontal(|ui| {
                    ui.label("Dark Mode");
                    if ui.checkbox(&mut self.dark_mode, "").clicked() {
                        // Toggle theme
                        let mut visuals = if self.dark_mode {
                            Visuals::dark()
                        } else {
                            Visuals::light()
                        };
                        
                        // Customize colors
                        visuals.widgets.noninteractive.bg_fill = if self.dark_mode { DARK_BG } else { Color32::WHITE };
                        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, if self.dark_mode { TEXT_COLOR } else { Color32::BLACK });
                        ui.ctx().set_visuals(visuals);
                    }
                });
                
                ui.add_space(20.0);
                
                // RPC Configuration
                ui.label(RichText::new("RPC Configuration").strong().heading());
                ui.separator();
                
                ui.label("RPC Endpoint");
                ui.text_edit_singleline(&mut self.rpc_url);
                
                ui.add_space(10.0);
                
                // Network Selection
                ui.label("Network");
                egui::ComboBox::from_id_source("network")
                    .selected_text("Ethereum Mainnet")
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.rpc_url, "https://mainnet.infura.io/v3/YOUR-PROJECT-ID".to_string(), "Ethereum Mainnet");
                        ui.selectable_value(&mut self.rpc_url, "https://polygon-rpc.com".to_string(), "Polygon Mainnet");
                        ui.selectable_value(&mut self.rpc_url, "https://bsc-dataseed.binance.org".to_string(), "Binance Smart Chain");
                        ui.selectable_value(&mut self.rpc_url, "https://rpc.ankr.com/arbitrum".to_string(), "Arbitrum One");
                        ui.selectable_value(&mut self.rpc_url, "https://rpc.optimism.gateway.fm".to_string(), "Optimism");
                    });
                
                ui.add_space(20.0);
                
                // Save Button
                if ui.button("💾 Save Settings").clicked() {
                    // TODO: Persist settings
                    ui.colored_label(SUCCESS_COLOR, "✓ Settings saved!");
                }
                
                ui.add_space(20.0);
                
                // About Section
                ui.label(RichText::new("About").strong().heading());
                ui.separator();
                ui.label("Smart Contract Analyzer v1.0.0");
                ui.hyperlink("https://github.com/quantumvortex369/SmartContractAnalyzer");
                ui.hyperlink("Created by cypherpunks for cypherpunks, Nexus.")
            });
    }
}

impl eframe::App for SmartContractAnalyzerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Configurar colores según el tema
        let bg_color = if self.dark_mode { DARK_BG } else { Color32::WHITE };
        let text_color = if self.dark_mode { TEXT_COLOR } else { Color32::BLACK };
        let card_bg = if self.dark_mode { CARD_BG } else { Color32::from_gray(245) };
        
        // Crear y configurar los estilos visuales
        let mut visuals = if self.dark_mode {
            Visuals::dark()
        } else {
            Visuals::light()
        };
        
        // Configuración de colores
        visuals.window_fill = bg_color.linear_multiply(1.0);
        visuals.panel_fill = bg_color.linear_multiply(1.0);
        visuals.faint_bg_color = card_bg.linear_multiply(1.0);
        
        // Configuración de widgets
        visuals.widgets.noninteractive.bg_fill = bg_color;
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, text_color);
        
        // Estilo de ventana
        visuals.window_rounding = 8.0.into();
        visuals.window_shadow.extrusion = 8.0;
        
        // Aplicar los estilos visuales
        ctx.set_visuals(visuals);
        
        // Cargar fuentes predeterminadas
        let fonts = egui::FontDefinitions::default();
        ctx.set_fonts(fonts);
        
        // Top Navigation Bar
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                // Logo/Brand
                ui.horizontal(|ui| {
                    ui.heading(RichText::new("🔒 SCSecurity").heading().color(PRIMARY_COLOR));
                });
                
                // Navigation Tabs
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.add_space(20.0);
                    
                    let analyzer_btn = ui.selectable_label(
                        self.active_tab == "analyzer", 
                        RichText::new("🔍 Analyzer").heading()
                    );
                    
                    let history_btn = ui.selectable_label(
                        self.active_tab == "history", 
                        RichText::new("📜 History").heading()
                    );
                    
                    // Handle tab switching
                    if analyzer_btn.clicked() { self.active_tab = "analyzer".to_string(); }
                    if history_btn.clicked() { self.active_tab = "history".to_string(); }
                });
                
                // Right-aligned controls
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Theme Toggle
                    if ui.button(if self.dark_mode { "🌙" } else { "☀️" }).clicked() {
                        self.dark_mode = !self.dark_mode;
                    }
                    
                    // Settings Button
                    let settings_btn = ui.selectable_label(
                        self.active_tab == "settings", 
                        RichText::new("⚙️").heading()
                    );
                    
                    if settings_btn.clicked() {
                        self.active_tab = if self.active_tab == "settings" { 
                            "analyzer".to_string() 
                        } else { 
                            "settings".to_string() 
                        };
                    }
                });
            });
            
            // Add a subtle separator
            ui.separator();
        });
        
        // Main Content Area
        egui::CentralPanel::default()
            .frame(egui::Frame::none())
            .show(ctx, |ui| {
                // Add some padding
                egui::Frame::none()
                    .inner_margin(egui::Margin::symmetric(20.0, 10.0))
                    .show(ui, |ui| {
                        match self.active_tab.as_str() {
                            "analyzer" => self.show_analyzer_tab(ui),
                            "history" => self.show_history_tab(ui),
                            "settings" => self.show_settings_tab(ui),
                            _ => {}
                        }
                    });
            });
        
        // Process any pending analysis results
        if let Some(receiver) = &self.result_receiver {
            if let Ok(result) = receiver.try_recv() {
                self.is_analyzing = false;
                self.analysis_result = Some(result);
                self.last_update = Some(Instant::now());
                self.result_receiver = None;
                
                // Calculate analysis time
                if let Some(start_time) = self.last_update {
                    self.analysis_time = Some(start_time.elapsed());
                }
            }
        }
        
        // Request repaint if we're still analyzing
        if self.is_analyzing {
            ctx.request_repaint();
        }
    }
}

pub fn start_gui(rpc_url: String) -> Result<()> {
    let native_options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(1200.0, 800.0)),
        min_window_size: Some(egui::vec2(800.0, 600.0)),
        centered: true,
        transparent: true,
        ..Default::default()
    };

    eframe::run_native(
        "Smart Contract Analyzer",
        native_options,
        Box::new(|cc| Box::new(SmartContractAnalyzerApp::new(rpc_url, cc))),
    )
    .map_err(|e| crate::error::AnalyzerError::Internal(e.to_string()))
}

