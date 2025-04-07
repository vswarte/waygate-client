use std::{ffi::c_void, mem::transmute, sync::Arc};

use crate::{steam, Config, InitError};

use retour::static_detour;
use windows::core::PCWSTR;
use windows::core::s;
use windows::Win32::Networking::WinHttp::{
    WinHttpAddRequestHeaders, WINHTTP_FLAG_SECURE, WINHTTP_OPEN_REQUEST_FLAGS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

type WinhttpOpenRequestT =
    fn(usize, usize, usize, usize, usize, usize, WINHTTP_OPEN_REQUEST_FLAGS) -> usize;
type WinhttpConnectT = fn(usize, PCWSTR, usize, usize) -> usize;

static_detour! {
    static WINHTTP_CONNECT: fn(usize, PCWSTR, usize, usize) -> usize;
    static WINHTTP_OPEN_REQUEST: fn(usize, usize, usize, usize, usize, usize, WINHTTP_OPEN_REQUEST_FLAGS) -> usize;
}

/// Hooks WinHTTP to redirect to a given server as well as inject some extra data about the client
/// and player into the upgrade request.
pub fn hook(config: Arc<Config>) -> Result<(), InitError> {
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
                transmute::<usize, WinhttpConnectT>(winhttp_connect_va),
                move |session: usize, _hostname: PCWSTR, _port: usize, reserved: usize| {
                    tracing::info!("Swapping details for request connect");

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
                transmute::<usize, WinhttpOpenRequestT>(winhttp_open_request_va),
                move |connect: usize,
                      verb: usize,
                      object_name: usize,
                      version: usize,
                      referrer: usize,
                      accept_types: usize,
                      _flags: WINHTTP_OPEN_REQUEST_FLAGS| {
                    tracing::info!("Swapping details for request open");

                    let flags = if config.enable_ssl {
                        WINHTTP_FLAG_SECURE
                    } else {
                        WINHTTP_OPEN_REQUEST_FLAGS::default()
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

                    // Unfortunately the games protocol uses encrypted app tickets
                    // which we cannot use. Instead, we request a traditional auth ticket
                    // and attach it to the initial upgrade request.
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

                    let _ = WinHttpAddRequestHeaders(request as *mut c_void, &steam_id_header, 0x20000000);

                    let _ = WinHttpAddRequestHeaders(
                        request as *mut c_void,
                        &session_ticket_header,
                        0x20000000,
                    );

                    let _ = WinHttpAddRequestHeaders(request as *mut c_void, &client_version, 0x20000000);

                    request
                },
            )?
            .enable()?;
    }

    tracing::info!("Hooked winhttp");
    Ok(())
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
