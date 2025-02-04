use std::mem;
use std::sync;
use std::thread;

use crate::eac;
use crate::system::wait_for_system_init;

static PEER_AUTH_CALLBACK: sync::OnceLock<sync::Mutex<usize>> = sync::OnceLock::new();
static PEER_AUTH_CLIENT_DATA: sync::OnceLock<sync::Mutex<usize>> = sync::OnceLock::new();

pub unsafe fn set_anticheatclient_addnotifypeerauthstatuschanged_hook(
    symbol: &str,
    detour: &retour::StaticDetour<fn(usize, usize, usize, usize) -> usize>,
) {
    detour
        .initialize(
            mem::transmute(eac::resolve_eos_symbol(symbol)),
            move |_: usize, _: usize, client_data: usize, notification_fn: usize| {
                *PEER_AUTH_CALLBACK
                    .get_or_init(|| sync::Mutex::new(0))
                    .lock()
                    .unwrap() = notification_fn;
                *PEER_AUTH_CLIENT_DATA
                    .get_or_init(|| sync::Mutex::new(0))
                    .lock()
                    .unwrap() = client_data;
                0xDEADBEEF
            },
        )
        .unwrap();

    detour.enable().unwrap();
}

pub unsafe fn set_anticheatclient_registerpeer_hook(
    symbol: &str,
    detour: &retour::StaticDetour<
        fn(
            usize,
            *const eac::eos::EOS_AntiCheatClient_RegisterPeerOptions,
        ) -> eac::eos::EOS_EResult,
    >,
) {
    detour.initialize(
        mem::transmute(eac::resolve_eos_symbol(symbol)),
        move |_: usize, options: *const eac::eos::EOS_AntiCheatClient_RegisterPeerOptions| {
            let client_handle = (*options).peer_handle;

            thread::spawn(move || {
                wait_for_system_init(10000).expect("System initialization timed out");

                let notification_fn = *PEER_AUTH_CALLBACK.get_or_init(|| sync::Mutex::new(0)).lock().unwrap();
                let client_data = *PEER_AUTH_CLIENT_DATA.get_or_init(|| sync::Mutex::new(0)).lock().unwrap() as u64;

                let callback: eac::eos::EOS_AntiCheatClient_OnPeerAuthStatusChangedCallback = mem::transmute(notification_fn);
                let callback_data = eac::eos::EOS_AntiCheatCommon_OnClientAuthStatusChangedCallbackInfo {
                    client_data,
                    client_handle,
                    client_auth_status: eac::eos::EOS_EAntiCheatCommonClientAuthStatus::EOS_ACCCAS_RemoteAuthComplete,
                };

                callback(&callback_data);
            });

            eac::eos::EOS_EResult::EOS_Success
        })
        .unwrap();

    detour.enable().unwrap();
}
