#![recursion_limit = "10000"]
pub mod config;
mod eac;
mod p2p;
mod singleton;
mod sodium;
mod steam;
mod system;
mod task;
mod winhttp;

use std::thread::sleep;
use std::{sync::Arc, thread::spawn, time::Duration};

pub use config::Config;
use pelite::pe::PeView;
use singleton::get_instance;
use steamworks::Client;
use steamworks_sys::{
    SteamAPI_ISteamNetworkingMessages_AcceptSessionWithUser,
    SteamAPI_SteamNetworkingMessages_SteamAPI_v002, SteamNetworkingMessagesSessionRequest_t,
};
use system::wait_for_system_init;
use task::CSTaskImp;
use thiserror::Error;
use tracing_panic::panic_hook;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;

#[cfg(feature = "eldenring")]
const APP_ID: u32 = 1245620;
#[cfg(feature = "armoredcore6")]
const APP_ID: u32 = 1888160;

/// Init for hooks and the like such that others can embed the client as a library.
pub unsafe fn init(config: Config) {
    let config = Arc::new(config);
    tracing::debug!("Initing {config:#?}");

    // Who the fuck are we
    let module = unsafe {
        PeView::module(GetModuleHandleA(PCSTR(std::ptr::null())).unwrap().0 as *const u8)
    };

    // Disable EAC but trick the game into thinking it is running so that we can connect to
    // a server.
    eac::hook();

    // Hook winhttp to forward the websocket upgrade request somewhere else.
    winhttp::hook(config.clone()).expect("Could not set up WinHTTP hooks");

    // Hook sodium's kx key derive to swap the pre-shared keys that normally come from Data0's
    // other/network/ folder.
    sodium::hook(&module, config.clone()).expect("Could not set up sodium hooks");

    // Spin up thread to wait for CSTaskImp to be initialized, then register a
    // task for our own message pump, such that it runs in lock-step with the
    // game's packet poll.
    spawn(move || {
        wait_for_system_init(&module, Duration::from_secs(30)).unwrap();

        // Handle any message session requests.
        steam::register_callback(1251, |request: &SteamNetworkingMessagesSessionRequest_t| {
            tracing::info!("SteamNetworkingMessagesSessionRequest.");

            let remote = unsafe { request.m_identityRemote.__bindgen_anon_1.m_steamID64 };
            if !SteamAPI_ISteamNetworkingMessages_AcceptSessionWithUser(
                SteamAPI_SteamNetworkingMessages_SteamAPI_v002(),
                &request.m_identityRemote,
            ) {
                tracing::error!("Could not accept messaging session");
            }
        });

        // Set up the p2p swap
        let (steam, _) = Client::init_app(APP_ID).expect("Could not initialize steam");
        p2p::hook(&module, steam).expect("Could not set up p2p swap");
    });
}

#[no_mangle]
#[cfg(not(feature = "lib"))]
pub unsafe extern "C" fn DllMain(_hmodule: usize, reason: u32) -> bool {
    if reason == 1 {
        std::panic::set_hook(Box::new(panic_hook));
        let appender = tracing_appender::rolling::never("./", "waygate-client.log");
        tracing_subscriber::fmt().with_writer(appender).init();

        init(config::read_config_file().unwrap_or_default());
    }

    true
}

#[derive(Debug, Error)]
pub enum InitError {
    #[error("Could not find instruction pattern or found multiple instances. pattern = {0}")]
    FlakyPattern(&'static str),

    #[error("Could not convert between RVA and VA. {0}")]
    AddressConversion(pelite::Error),

    #[error("Could not convert find import. import = {0}")]
    MissingImport(&'static str),

    #[error("Windows error. {0}")]
    Windows(#[from] windows::core::Error),

    #[error("Retour error. {0}")]
    Retour(#[from] retour::Error),

    #[error("Steam. {0}")]
    Steam(#[from] steamworks::SteamError),
}
