use std::{mem::transmute, ptr::copy_nonoverlapping, sync::Arc};

use fromsoftware_shared::Program;
use pelite::pe::Pe;
use retour::static_detour;

use crate::{rva, Config, InitError};

static_detour! {
    static SODIUM_KX_KEY_DERIVE: fn(usize, *mut u8, *mut u8) -> usize;
}

/// Hooks libsodium's kx key derive so that we can swap out the preshared keys with our own.
pub fn hook(program: &Program, config: Arc<Config>) -> Result<(), InitError> {
    let sodium_kx_derive_va = program
        .rva_to_va(rva::get().sodium_kx_key_derive)
        .map_err(InitError::AddressConversion)?;

    unsafe {
        let config = config.clone();
        SODIUM_KX_KEY_DERIVE
            .initialize(
                transmute::<u64, fn(usize, *mut u8, *mut u8) -> usize>(sodium_kx_derive_va),
                move |output: usize, public_key: *mut u8, secret_key: *mut u8| {
                    tracing::debug!("Swapping sodium keys");
                    let server_public_key = config.server_public_key();
                    let client_secret_key = config.client_secret_key();

                    copy_nonoverlapping(server_public_key.as_ptr(), public_key, 32);
                    copy_nonoverlapping(client_secret_key.as_ptr(), secret_key, 32);

                    SODIUM_KX_KEY_DERIVE.call(output, public_key, secret_key)
                },
            )?
            .enable()?;
    }

    tracing::info!("Hooked sodium");

    Ok(())
}
