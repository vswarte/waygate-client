use std::{mem::transmute, ptr::copy_nonoverlapping, sync::Arc};

use pelite::pattern::Atom;
use pelite::pe::{Pe, PeView};
use retour::static_detour;

use crate::{Config, InitError};

const SODIUM_KX_KEY_DERIVE_PATTERN: &[Atom] =
    pelite::pattern!("? 53 ? 83 EC 50 ? 8B 05 ? ? ? ? ? 33 C4 ? 89 44 ? ? ? 8B C0 ? 8B D9 ? 8B C2 ? 8D 4C ? 20 ? 8B D0");

static_detour! {
    static SODIUM_KX_KEY_DERIVE: fn(usize, *mut u8, *mut u8) -> usize;
}

/// Hooks libsodium's kx key derive so that we can swap out the preshared keys with our own.
pub fn hook(module: &PeView, config: Arc<Config>) -> Result<(), InitError> {
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
        SODIUM_KX_KEY_DERIVE
            .initialize(
                transmute(sodium_kx_derive_va),
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
