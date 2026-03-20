use std::mem::transmute;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::sleep;
use std::thread::spawn;
use std::time;

use crate::eac;

static PEER_AUTH_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static PEER_AUTH_CLIENT_DATA: AtomicUsize = AtomicUsize::new(0);

type AddNotifyPeerAuthStatusChangedCallback = fn(usize, usize, usize, usize) -> usize;
type RegisterPeerCallback =
    fn(usize, *const eac::eos::EOS_AntiCheatClient_RegisterPeerOptions) -> eac::eos::EOS_EResult;

pub unsafe fn set_anticheatclient_addnotifypeerauthstatuschanged_hook(
    symbol: &str,
    detour: &retour::StaticDetour<AddNotifyPeerAuthStatusChangedCallback>,
) {
    detour
        .initialize(
            transmute::<usize, AddNotifyPeerAuthStatusChangedCallback>(eac::resolve_eos_symbol(
                symbol,
            )),
            move |_: usize, _: usize, client_data: usize, notification_fn: usize| {
                PEER_AUTH_CALLBACK.store(notification_fn, Ordering::Relaxed);
                PEER_AUTH_CLIENT_DATA.store(client_data, Ordering::Relaxed);
                0xDEADBEEF
            },
        )
        .unwrap();

    detour.enable().unwrap();
}

pub unsafe fn set_anticheatclient_registerpeer_hook(
    symbol: &str,
    detour: &retour::StaticDetour<RegisterPeerCallback>,
) {
    detour.initialize(
        transmute::<usize, RegisterPeerCallback>(eac::resolve_eos_symbol(symbol)),
        move |_: usize, options: *const eac::eos::EOS_AntiCheatClient_RegisterPeerOptions| {
            let client_handle = (*options).peer_handle;

            spawn(move || {
                sleep(time::Duration::from_secs(10));

                let notification_fn = PEER_AUTH_CALLBACK.load(Ordering::Relaxed);
                let client_data = PEER_AUTH_CLIENT_DATA.load(Ordering::Relaxed) as u64;

                let callback: eac::eos::EOS_AntiCheatClient_OnPeerAuthStatusChangedCallback = transmute(notification_fn);
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
