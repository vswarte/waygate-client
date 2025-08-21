use std::{ffi::c_void, mem::transmute, sync::Arc};

use crate::{steam, Config, InitError};

use retour::static_detour;
use windows::core::s;
use windows::core::PCWSTR;
use windows::Win32::Networking::WinHttp::WINHTTP_ADDREQ_FLAG_ADD;
use windows::Win32::Networking::WinHttp::WINHTTP_ADDREQ_FLAG_REPLACE;
use windows::Win32::Networking::WinHttp::{
    WinHttpAddRequestHeaders, WINHTTP_FLAG_SECURE, WINHTTP_OPEN_REQUEST_FLAGS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

type WinhttpOpenRequestT =
    fn(usize, PCWSTR, PCWSTR, PCWSTR, PCWSTR, PCWSTR, WINHTTP_OPEN_REQUEST_FLAGS) -> usize;
type WinhttpConnectT = fn(usize, PCWSTR, u16, usize) -> usize;

static_detour! {
    static WINHTTP_CONNECT: fn(usize, PCWSTR, u16, usize) -> usize;
    static WINHTTP_OPEN_REQUEST: fn(usize, PCWSTR, PCWSTR, PCWSTR, PCWSTR, PCWSTR, WINHTTP_OPEN_REQUEST_FLAGS) -> usize;
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
        WINHTTP_CONNECT
            .initialize(
                transmute::<usize, WinhttpConnectT>(winhttp_connect_va),
                move |session, hostname, port, reserved| {
                    let original_hostname_str = String::from_utf16_lossy(hostname.as_wide());
                    let is_target_domain = original_hostname_str.contains("fromsoftware-game.net");

                    let target_hostname_pcwstr;
                    let target_port;

                    if is_target_domain {
                        tracing::info!(
                            "WinHttpConnect: Redirecting request from {} to {}:{}",
                            original_hostname_str,
                            config.host,
                            config.port
                        );

                        target_hostname_pcwstr = PCWSTR(
                            config
                                .host
                                .encode_utf16()
                                .chain(std::iter::once(0x0))
                                .collect::<Vec<u16>>()
                                .as_ptr(),
                        );
                        target_port = config.port;
                    } else {
                        target_hostname_pcwstr = hostname;
                        target_port = port;
                    }

                    WINHTTP_CONNECT.call(session, target_hostname_pcwstr, target_port, reserved)
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
                      verb: PCWSTR,
                      object_name: PCWSTR,
                      version: PCWSTR,
                      referrer: PCWSTR,
                      accept_types: PCWSTR,
                      mut flags: WINHTTP_OPEN_REQUEST_FLAGS| {
                    tracing::info!("Swapping details for request open");

                    // The only way we can detect that this is a websocket upgrade request
                    // is by checking the verb, which is "GET", object name, which is "",
                    // other options are null pointers and flags are WINHTTP_FLAG_SECURE
                    if !verb.is_null()
                        && verb.to_string().unwrap_or_default() == "GET"
                        && !object_name.is_null()
                        && object_name.to_string().unwrap_or_default() == ""
                        && version.is_null()
                        && referrer.is_null()
                        && accept_types.is_null()
                        && flags == WINHTTP_FLAG_SECURE
                    {
                        flags = if config.enable_ssl {
                            WINHTTP_FLAG_SECURE
                        } else {
                            WINHTTP_OPEN_REQUEST_FLAGS::default()
                        };
                    }

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

                    let steam_id_header = format!("X-STEAM-ID: {steam_id}")
                        .encode_utf16()
                        .collect::<Vec<u16>>();

                    let session_ticket_header =
                        format!("X-STEAM-SESSION-TICKET: {}", bytes_to_hex(&ticket))
                            .encode_utf16()
                            .collect::<Vec<u16>>();

                    // Also attach the waygate client version so we can block people on
                    // incompatible versions of the p2p protocol.
                    let client_version =
                        format!("X-WAYGATE-CLIENT-VERSION: {}", env!("CARGO_PKG_VERSION"))
                            .encode_utf16()
                            .collect::<Vec<u16>>();

                    let _ = WinHttpAddRequestHeaders(
                        request as *mut c_void,
                        &steam_id_header,
                        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE,
                    );

                    let _ = WinHttpAddRequestHeaders(
                        request as *mut c_void,
                        &session_ticket_header,
                        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE,
                    );

                    let _ = WinHttpAddRequestHeaders(
                        request as *mut c_void,
                        &client_version,
                        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE,
                    );

                    request
                },
            )?
            .enable()?;
    }

    tracing::info!("Hooked winhttp");
    Ok(())
}

fn bytes_to_hex(input: &[u8]) -> String {
    let mut s = String::with_capacity(input.len() * 2);
    for byte in input {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}
