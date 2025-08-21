use std::mem;
use std::ptr;
use std::ptr::copy_nonoverlapping;

use crate::eac;

pub unsafe fn set_deadbeef_hook(symbol: &str, detour: &retour::StaticDetour<fn() -> usize>) {
    detour
        .initialize(mem::transmute(eac::resolve_eos_symbol(symbol)), move || {
            0xDEADBEEF
        })
        .unwrap();
    detour.enable().unwrap();
}

pub unsafe fn set_result_success_hook(
    symbol: &str,
    detour: &retour::StaticDetour<fn() -> eac::eos::EOS_EResult>,
) {
    detour
        .initialize(mem::transmute(eac::resolve_eos_symbol(symbol)), move || {
            eac::eos::EOS_EResult::EOS_Success
        })
        .unwrap();
    detour.enable().unwrap();
}

pub unsafe fn set_result_not_found_hook(
    symbol: &str,
    detour: &retour::StaticDetour<fn() -> eac::eos::EOS_EResult>,
) {
    detour
        .initialize(mem::transmute(eac::resolve_eos_symbol(symbol)), move || {
            eac::eos::EOS_EResult::EOS_NotFound
        })
        .unwrap();
    detour.enable().unwrap();
}

pub unsafe fn set_loginstatus_loggedin_hook(
    symbol: &str,
    detour: &retour::StaticDetour<fn() -> usize>,
) {
    detour
        .initialize(mem::transmute(eac::resolve_eos_symbol(symbol)), move || {
            eac::eos::EOS_ELoginStatus::EOS_LS_LoggedIn as usize
        })
        .unwrap();
    detour.enable().unwrap();
}

pub unsafe fn set_true_hook(symbol: &str, detour: &retour::StaticDetour<fn() -> bool>) {
    detour
        .initialize(mem::transmute(eac::resolve_eos_symbol(symbol)), move || {
            true
        })
        .unwrap();
    detour.enable().unwrap();
}

pub unsafe fn set_void_hook(symbol: &str, detour: &retour::StaticDetour<fn()>) {
    detour
        .initialize(mem::transmute(eac::resolve_eos_symbol(symbol)), move || {})
        .unwrap();
    detour.enable().unwrap();
}

pub unsafe fn set_productuserid_to_string_hook(
    symbol: &str,
    detour: &retour::StaticDetour<fn(usize, usize, usize) -> eac::eos::EOS_EResult>,
) {
    detour
        .initialize(
            mem::transmute(eac::resolve_eos_symbol(symbol)),
            move |_: usize, char_buffer: usize, char_buffer_length: usize| {
                let user_id = "Cock";
                let user_id_length = user_id.len();
                let user_id_ptr = user_id.as_ptr();
                copy_nonoverlapping(user_id_ptr, char_buffer as *mut u8, user_id_length);

                *(char_buffer_length as *mut u32) = user_id_length as u32;

                eac::eos::EOS_EResult::EOS_Success
            },
        )
        .unwrap();

    detour.enable().unwrap();
}

pub unsafe fn set_connect_login_hook(
    symbol: &str,
    detour: &retour::StaticDetour<fn(usize, usize, usize, usize)>,
) {
    detour
        .initialize(
            mem::transmute(eac::resolve_eos_symbol(symbol)),
            move |_connect: usize, _options: usize, client_data: usize, notification_fn: usize| {
                let callback: eac::eos::EOS_Connect_OnLoginCallback =
                    mem::transmute(notification_fn);
                let callback_data = eac::eos::EOS_Connect_LoginCallbackInfo {
                    result: eac::eos::EOS_EResult::EOS_Success,
                    client_data: client_data as u64,
                    eos_product_id: 0xDEADBEEF,
                    continuance_token: 0,
                };
                callback(&callback_data);
            },
        )
        .unwrap();

    detour.enable().unwrap();
}

pub unsafe fn set_report_player_behavior_hook(
    symbol: &str,
    detour: &retour::StaticDetour<fn(usize, usize, usize, usize)>,
) {
    detour
        .initialize(
            mem::transmute(eac::resolve_eos_symbol(symbol)),
            move |_handle: usize, _options: usize, _client_data: usize, _complete: usize| {
                // Do fucking nothing lmao
            },
        )
        .unwrap();

    detour.enable().unwrap();
}
