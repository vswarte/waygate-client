#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    sync::{Arc, RwLock},
    thread::JoinHandle,
    time::Duration,
};

use dll_syringe::{
    process::{OwnedProcess, Process},
    Syringe,
};
use eframe::egui::{self, Style, Visuals};
use egui_plot::{Legend, Line, Plot, PlotPoints};

const DLL_NAME: &str = "waygate_client.dll";
const GAME_POLL_INTERVAL: Duration = Duration::from_millis(200);

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([360.0, 600.0]),
        ..Default::default()
    };

    let app = MonitorApp::new(Data::default());
    eframe::run_native(
        "My egui App with a plot",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(Visuals::dark());

            Ok(Box::new(app))
        }),
    )
}

#[derive(Default)]
enum ConnectionState {
    #[default]
    NotConnected,
    Connected,
    Errored(&'static str),
}

/// Shared data between worker thread and GUI
#[derive(Default)]
struct Data {
    connection_state: ConnectionState,
    counter: usize,
}

struct MonitorApp {
    data: Arc<RwLock<Data>>,
    worker_thread: JoinHandle<()>,
}

impl MonitorApp {
    fn new(data: Data) -> Self {
        let data = Arc::new(RwLock::new(data));
        let worker_thread = {
            let data = data.clone();
            let mut game: Option<GameProcess> = None;

            std::thread::spawn(move || loop {
                if let Some(game) = game.as_ref() {
                    // Find game
                    let Ok(process) = OwnedProcess::from_pid(game.pid.as_u32()) else {
                        data.write().unwrap().connection_state =
                            ConnectionState::Errored("Could not find running game instance");
                        continue;
                    };

                    // Retrieve waygates stat sink
                    let Some(module) = unsafe { process.borrowed_static() }.find_module_by_name(DLL_NAME).ok().flatten() else {
                        data.write().unwrap().connection_state =
                            ConnectionState::Errored("Could not locate waygate DLL in game process");
                        continue;
                    };

                    let syringe = Syringe::for_process(process);
                    let remote_flush_fn = unsafe { syringe.get_payload_procedure::<fn() -> P2PStatisticsBin>(module, "") };

                    // Pull data from game if we are connected
                    // let mut data = data.write().unwrap();
                    // data.counter += 1;
                    data.write().unwrap().connection_state = ConnectionState::Connected;
                } else {
                    // Detect game if there is none.
                    game = get_running_games().first().cloned()
                }

                std::thread::sleep(GAME_POLL_INTERVAL);
            })
        };

        Self {
            data,
            worker_thread,
        }
    }
}

impl eframe::App for MonitorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // let mut plot_rect = None;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("General");
            let connection_label = match self.data.read().unwrap().connection_state {
                ConnectionState::NotConnected => String::from("Not Connected"),
                ConnectionState::Connected => String::from("Connected"),
                ConnectionState::Errored(why) => format!("Error: {why}"),
            };
            ui.label(format!("Connection: {}", connection_label));

            // ui.heading("Latency");
            // let test_plot = Plot::new("Test Plot").legend(Legend::default());
            // // let's create a dummy line in the plot
            // let graph: Vec<[f64; 2]> = vec![[0.0, 1.0], [2.0, 3.0], [3.0, 2.0]];
            // let inner = test_plot.show(ui, |plot_ui| {
            //     plot_ui.line(Line::new(PlotPoints::from(graph)).name("curve"));
            // });
            //
            // // Remember the position of the plot
            // plot_rect = Some(inner.response.rect);
        });

        ctx.request_repaint();
    }
}

use monitor_ipc::P2PStatisticsBin;
use sysinfo::{Pid, System};

const DETECT_PROCESSES: &[&str] = &[
    "eldenring.exe",
    "armoredcore6.exe",
    "start_protected_game.exe",
];

/// Retrieves a list of running games that we should support
fn get_running_games() -> Vec<GameProcess> {
    let mut system = System::new();
    system.refresh_all();

    let mut processes = system
        .processes()
        .iter()
        .map(|x| GameProcess {
            pid: *x.0,
            name: x.1.name().to_string_lossy().into_owned(),
        })
        .filter(|p| DETECT_PROCESSES.contains(&p.name.as_str()))
        .collect::<Vec<GameProcess>>();

    processes.sort_by(|a, b| b.pid.as_u32().cmp(&a.pid.as_u32()));

    processes
}

#[derive(Debug, Clone)]
struct GameProcess {
    pub pid: Pid,
    pub name: String,
}
