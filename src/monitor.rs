use std::sync::{Arc, OnceLock};

use eframe::egui::mutex::RwLock;
use monitor_ipc::P2PStatisticsBin;
use serde::{Deserialize, Serialize};

use crate::p2p::{PlayerNetworking, SteamMessageTransport};

pub static PLAYER_NETWORK_SESSION: OnceLock<Arc<PlayerNetworking<SteamMessageTransport>>> = OnceLock::new();

dll_syringe::payload_procedure! {
    fn flush_p2p_stats() -> Option<P2PStatisticsBin> {
        _flush_p2p_stats()
    }
}

fn _flush_p2p_stats() -> Option<P2PStatisticsBin> {
    let Some(session) = PLAYER_NETWORK_SESSION.get() else {
        return None;
    };

    None
}
