#![recursion_limit = "10000"]

mod config;
mod eac;
mod p2p;
// mod player_limit;
mod steam;

mod singleton;
mod task;

use std::{ffi::c_void, mem::transmute, ptr::copy_nonoverlapping, sync::Arc, thread::spawn, time::Duration};

use config::Config;
use p2p::{Message, PlayerNetworking, SteamMessageTransport};
use pelite::{
    pattern::Atom,
    pe::{Pe, PeView},
};
use retour::static_detour;
use singleton::get_instance;
use steamworks::{Client, SteamId};
use task::{CSTaskGroupIndex, CSTaskImp, FD4TaskData, TaskRuntime};
use thiserror::Error;
use tracing_panic::panic_hook;
use windows::{
    core::{PCSTR, PCWSTR},
    s,
    Win32::Networking::WinHttp::WinHttpAddRequestHeaders,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

#[cfg(feature = "eldenring")]
const APP_ID: u32 = 1245620;
#[cfg(feature = "armoredcore6")]
const APP_ID: u32 = 1888160;

/// Determines the steam messages channel used for the p2p swap.
const P2P_MESSAGES_CHANNEL: u32 = 69420;

/// IMPORTANT!!
/// If you're writing a mod and you're looking for these hooks to sync some data or coordinate some
/// multi-party action I highly suggest using steam's networking messages API (https://partner.steamgames.com/doc/api/ISteamNetworkingMessages)
/// instead. It wont conflict with other mods and it prevents you from having to intercept your own
/// networking such that the game doesn't handle it by accident.
const P2P_PACKET_DEQUEUE_PATTERN: &[Atom] =
    pelite::pattern!("48 8B 09 48 85 C9 75 03 33 C0 C3 E9 $ { ' }");
const P2P_PACKET_SEND_PATTERN: &[Atom] =
    pelite::pattern!("88 44 24 30 44 89 4C 24 28 44 0F B6 CA 48 8B D1 4C 89 44 24 20 49 8B CA 4C 8D 44 24 50 E8 $ { ' }");
const P2P_DISCONNECT_PATTERN: &[Atom] =
    pelite::pattern!("48 C7 81 28 01 00 00 00 00 00 00 E9 ? ? ? ?");
const SODIUM_KX_KEY_DERIVE_PATTERN: &[Atom] =
    pelite::pattern!("? 53 ? 83 EC 50 ? 8B 05 ? ? ? ? ? 33 C4 ? 89 44 ? ? ? 8B C0 ? 8B D9 ? 8B C2 ? 8D 4C ? 20 ? 8B D0");

#[no_mangle]
pub unsafe extern "C" fn DllMain(_hmodule: usize, reason: u32) -> bool {
    match reason {
        1 => {
            std::panic::set_hook(Box::new(panic_hook));
            let appender = tracing_appender::rolling::never("./", "waygate-client.log");
            tracing_subscriber::fmt().with_writer(appender).init();

            // Who the fuck are we
            let module = unsafe {
                let handle = GetModuleHandleA(PCSTR(std::ptr::null())).unwrap().0 as *const u8;
                PeView::module(handle)
            };

            // Disable EAC but trick the game into thinking it is running so that we can connect to
            // a server.
            eac::set_hooks();
            tracing::info!("Set EAC hooks");

            // Set the server redirect and set up the key derivation hook
            let config = Arc::new(config::read_config_file().unwrap_or_default());
            setup_cryptography(&module, config.clone()).expect("Could not set up sodium hooks");
            setup_winhttp(config.clone()).expect("Could not set up WinHTTP hooks");

            // Spin up thread to wait for CSTaskImp to be initialized, then register a
            // task for our own message pump, such that it runs in lock-step with the
            // game's packet poll.
            spawn(move || {
                // TODO: waiting for 5s is a race condition, need to actually await CSTask
                std::thread::sleep(Duration::from_secs(5));

                // Set up the p2p swap
                setup_p2p(&module).expect("Could not set up p2p swap");
            });

            true
        }

        _ => true,
    }
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

/// Hooks WinHTTP to redirect to a given server as well as inject some extra data about the client
/// and player into the upgrade request.
fn setup_winhttp(config: Arc<Config>) -> Result<(), InitError> {
    let winhttp = unsafe { GetModuleHandleA(s!("winhttp")) }?;

    let winhttp_connect_va = unsafe {
        GetProcAddress(winhttp, s!("WinHttpConnect"))
            .ok_or(InitError::MissingImport("winhttp.WinHttpConnect"))?
    } as usize;

    let winhttp_open_request_va = unsafe {
        GetProcAddress(winhttp, s!("WinHttpOpenRequest"))
            .ok_or(InitError::MissingImport("winhttp.WinHttpOpenRequest"))?
    } as usize;

    unsafe {
        let config = config.clone();

        // Hook WinHttpConnect to swap out the destination hostname and the port.
        WINHTTP_CONNECT
            .initialize(
                transmute(winhttp_connect_va),
                move |session: usize, _hostname: PCWSTR, _port: usize, reserved: usize| {
                    let host = {
                        let mut bytes = config.host.encode_utf16().collect::<Vec<_>>();
                        bytes.push(0x0);
                        bytes
                    };

                    WINHTTP_CONNECT.call(
                        session,
                        PCWSTR(host.as_ptr()),
                        config.port as usize,
                        reserved,
                    )
                },
            )?
            .enable()?;
    }

    unsafe {
        let config = config.clone();

        // Hook WinHttpOpenRequest to override the secure flags as well as attach some headers to
        // the websocket upgrade request.
        WINHTTP_OPEN_REQUEST
            .initialize(
                transmute(winhttp_open_request_va),
                move |connect: usize,
                      verb: usize,
                      object_name: usize,
                      version: usize,
                      referrer: usize,
                      accept_types: usize,
                      flags: usize| {
                    let flags = if config.verify_certificate {
                        flags
                    } else {
                        0x0
                    };

                    let request = WINHTTP_OPEN_REQUEST.call(
                        connect,
                        verb,
                        object_name,
                        version,
                        referrer,
                        accept_types,
                        flags,
                    );

                    // Grab steam ID and auth ticket. Unfortunately the games protocol uses
                    // encrypted app tickets which we cannot decrypt. To cope, we request a
                    // traditional auth ticket and attach it to the initial upgrade request.
                    let (steam_id, ticket) = steam::get_auth_ticket();

                    let steam_id_header = format!("X-STEAM-ID: {}", steam_id)
                        .encode_utf16()
                        .collect::<Vec<u16>>();

                    let session_ticket_header =
                        format!("X-STEAM-SESSION-TICKET: {}", bytes_to_hex(ticket))
                            .encode_utf16()
                            .collect::<Vec<u16>>();

                    // Also attach the waygate client version so we can block people on
                    // incompatible versions of the p2p protocol.
                    let client_version =
                        format!("X-WAYGATE-CLIENT-VERSION: {}", env!("CARGO_PKG_VERSION"))
                            .encode_utf16()
                            .collect::<Vec<u16>>();

                    WinHttpAddRequestHeaders(request as *mut c_void, &steam_id_header, 0x20000000);

                    WinHttpAddRequestHeaders(
                        request as *mut c_void,
                        &session_ticket_header,
                        0x20000000,
                    );

                    WinHttpAddRequestHeaders(request as *mut c_void, &client_version, 0x20000000);

                    request
                },
            )?
            .enable()?;
    }

    Ok(())
}

/// Hooks libsodium's kx key derive so that we can swap out the preshared keys with our own.
fn setup_cryptography(module: &PeView, config: Arc<Config>) -> Result<(), InitError> {
    let sodium_kx_derive_va = {
        let mut matches = [0u32; 1];
        if !module
            .scanner()
            .finds_code(SODIUM_KX_KEY_DERIVE_PATTERN, &mut matches)
        {
            return Err(InitError::FlakyPattern("SODIUM_KX_KEY_DERIVE_PATTERN"));
        }

        module
            .rva_to_va(matches[0])
            .map_err(InitError::AddressConversion)?
    };

    unsafe {
        let config = config.clone();

        // Swaps out the keys sourced from other:/network in the BDTs with the ones from the
        // config.
        SODIUM_KX_KEY_DERIVE
            .initialize(
                transmute(sodium_kx_derive_va),
                move |output: usize, public_key: *mut u8, secret_key: *mut u8| {
                    let server_public_key = config.server_public_key();
                    let client_secret_key = config.client_secret_key();

                    copy_nonoverlapping(server_public_key.as_ptr(), public_key, 32);
                    copy_nonoverlapping(client_secret_key.as_ptr(), secret_key, 32);

                    SODIUM_KX_KEY_DERIVE.call(output, public_key, secret_key)
                },
            )?
            .enable()?;
    }

    Ok(())
}

/// Completely replaces the games P2P connection with our own implementation based on steamworks
/// messaging API. This should significantly improve latency for Elden Ring and AC6 since it
/// bypasses the reliability and fragmentation/batching layer that From Software uses for these
/// titles.
fn setup_p2p(module: &PeView) -> Result<(), InitError> {
    let client = Client::init_app(APP_ID)?.0;

    let transport = SteamMessageTransport::new(P2P_MESSAGES_CHANNEL, client);
    let player_networking = Arc::new(PlayerNetworking::new(transport));

    let packet_dequeue_va = {
        let mut matches = [0u32; 2];
        if !module
            .scanner()
            .finds_code(P2P_PACKET_DEQUEUE_PATTERN, &mut matches)
        {
            return Err(InitError::FlakyPattern("P2P_PACKET_DEQUEUE"));
        }

        module
            .rva_to_va(matches[1])
            .map_err(InitError::AddressConversion)?
    };

    let packet_send_va = {
        let mut matches = [0u32; 2];
        if !module
            .scanner()
            .finds_code(P2P_PACKET_SEND_PATTERN, &mut matches)
        {
            return Err(InitError::FlakyPattern("P2P_PACKET_SEND"));
        }

        module
            .rva_to_va(matches[1])
            .map_err(InitError::AddressConversion)?
    };

    let disconnect_va = {
        let mut matches = [0u32; 1];
        if !module
            .scanner()
            .finds_code(P2P_DISCONNECT_PATTERN, &mut matches)
        {
            return Err(InitError::FlakyPattern("P2P_DISCONNECT_PATTERN"));
        }

        module
            .rva_to_va(matches[0])
            .map_err(InitError::AddressConversion)?
    };

    unsafe {
        let player_networking = player_networking.clone();

        // When the game requests a packet we check our own queue and copy any
        // retrieved packets to the output buffer if the received packet does not
        // overflow the output buffer.
        P2P_PACKET_DEQUEUE
            .initialize(
                transmute(packet_dequeue_va),
                move |connection: *const MTInternalThreadSteamConnection,
                      packet_type: u8,
                      output: *mut u8,
                      max_size: u32,
                      control_byte: *mut u8| {
                    let connection = connection.as_ref().unwrap();
                    let remote = connection.steam_id();
                    let packet = match player_networking.dequeue_game_packet(&remote, packet_type) {
                        Ok(message) => message.unwrap_or_default(),
                        Err(e) => {
                            tracing::error!("Could not dequeue game packet for player. e = {e}");
                            return 0;
                        }
                    };

                    // Ensure we're not about to write out-of-bounds.
                    if (max_size as usize) < packet.len() {
                        return 0;
                    }

                    // Copy received data to the output buffer
                    copy_nonoverlapping(packet.as_ptr(), output, packet.len());

                    // Set the control byte for session meta packets
                    if packet_type == 250 {
                        *control_byte = u8::MAX;
                    }

                    packet.len() as u32
                },
            )?
            .enable()?;
    }

    unsafe {
        let player_networking = player_networking.clone();

        // When the game sends a packet to a remote party we wrap it in our messaging
        // format and immediately forward it to steam.
        P2P_PACKET_SEND
            .initialize(
                transmute(packet_send_va),
                move |_: usize,
                      _: usize,
                      steam_id: *const u64,
                      packet_type: u8,
                      buffer: *const u8,
                      packet_size: u32,
                      _: u8| {
                    let remote = SteamId::from_raw(*(steam_id.as_ref().unwrap()));
                    let contents = std::slice::from_raw_parts(buffer, packet_size as usize);

                    if let Err(e) = player_networking
                        .send_message(&remote, &Message::Packet(packet_type, contents.to_vec()))
                    {
                        tracing::error!("Could not send message to {remote:?}. e = {e}");
                        0
                    } else {
                        packet_size as usize
                    }
                },
            )?
            .enable()?;
    }

    unsafe {
        let player_networking = player_networking.clone();

        // When a player disconnects we clear out and packet queues such that players
        // can reconnect and the game will have a fresh state to operate on.
        P2P_DISCONNECT
            .initialize(
                transmute(disconnect_va),
                move |connection: *const MTInternalThreadSteamConnection| {
                    let connection = connection.as_ref().unwrap();
                    let remote = SteamId::from_raw(connection.steam_id);

                    // This will realistically only occur in the case of poisoning but
                    // unwrap() requires SteamMessageTransport to implement Debug so :shrug:
                    if let Err(e) = player_networking.remove_session(&remote) {
                        panic!("Could not remove player session. e = {}", e);
                    }

                    // Let the game handle the rest of the destruction
                    P2P_DISCONNECT.call(connection)
                },
            )?
            .enable()?;
    }

    tracing::info!("Registering packet pump task");
    let cs_task = get_instance::<CSTaskImp>().unwrap().unwrap();
    let task = cs_task.run_task(
        move |_: &FD4TaskData| {
            if let Err(e) = player_networking.update() {
                log::error!("Got error while updating PlayerNetworking. e = {e}");
            }
        },
        CSTaskGroupIndex::SteamThread0,
    );

    // TODO: this can be stored in player_networking
    std::mem::forget(task);

    Ok(())
}

static_detour! {
    static WINHTTP_CONNECT: fn(usize, PCWSTR, usize, usize) -> usize;

    static WINHTTP_OPEN_REQUEST: fn(usize, usize, usize, usize, usize, usize, usize) -> usize;

    static SODIUM_KX_KEY_DERIVE: fn(usize, *mut u8, *mut u8) -> usize;

    static P2P_PACKET_DEQUEUE: extern "C" fn(
        *const MTInternalThreadSteamConnection,
        u8,
        *mut u8,
        u32,
        *mut u8
    ) -> u32;

    static P2P_PACKET_SEND: extern "C" fn(
        usize,
        usize,
        *const u64,
        u8,
        *const u8,
        u32,
        u8
    ) -> usize;

    static P2P_DISCONNECT: extern "C" fn(*const MTInternalThreadSteamConnection);
}

#[repr(C)]
struct MTInternalThreadSteamConnection {
    _unk0: [u8; 0x128],
    steam_id: u64,
}

impl MTInternalThreadSteamConnection {
    pub fn steam_id(&self) -> SteamId {
        SteamId::from_raw(self.steam_id)
    }
}

// Too lazy to write something good for this
fn bytes_to_hex(input: Vec<u8>) -> String {
    fn byte_to_hex(byte: u8) -> (u8, u8) {
        static HEX_LUT: [u8; 16] = [
            b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd',
            b'e', b'f',
        ];

        let upper = HEX_LUT[(byte >> 4) as usize];
        let lower = HEX_LUT[(byte & 0xF) as usize];
        (lower, upper)
    }

    let utf8_bytes: Vec<u8> = input
        .iter()
        .copied()
        .flat_map(|byte| {
            let (lower, upper) = byte_to_hex(byte);
            [upper, lower]
        })
        .collect();

    unsafe { String::from_utf8_unchecked(utf8_bytes) }
}
