/// OG comes from Dasaav
/// https://github.com/Dasaav-dsv/libER/blob/main/source/dantelion2/system.cpp
use std::sync;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use pelite::pattern;
use pelite::pattern::Atom;
use pelite::pe::Pe;
use pelite::pe::PeView;
use pelite::pe::Rva;
use thiserror::Error;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;

// WinMain -> SetBaseAddr
// used to set base executable address for CSWindowImp
// and can be used to determine if the game has finished initializing
const GLOBAL_INIT_BASE_ADDR_PATTERN: &[Atom] = pattern!(
    "
    48 8b ce
    48 8b f8
    e8 $ {
        48 89 0d $ { ' }
        c3
    }
    "
);

static GLOBAL_INIT_BASE_ADDR: AtomicPtr<usize> = AtomicPtr::new(0x0 as _);

#[derive(Error, Debug)]
pub enum SystemInitError {
    #[error("System initialization timed out")]
    Timeout,
    #[error("Could not translate RVA to VA")]
    InvalidRva,
}

/// Wait for the system to finish initializing by await a base address to be populated for CSWindow. This happens after the CRT init.
pub fn wait_for_system_init(module: &PeView, timeout: Duration) -> Result<(), SystemInitError> {
    let base_address = GLOBAL_INIT_BASE_ADDR.load(Ordering::Relaxed);
    if unsafe { GLOBAL_INIT_BASE_ADDR.load(Ordering::Relaxed) } == 0x0 as _ {
        let mut captures = [Rva::default(); 2];
        module
            .scanner()
            .finds_code(GLOBAL_INIT_BASE_ADDR_PATTERN, &mut captures);

        let global_init_base_address = module
            .rva_to_va(captures[1])
            .map_err(|_| SystemInitError::InvalidRva)?;

        GLOBAL_INIT_BASE_ADDR.store(global_init_base_address as _, Ordering::Relaxed);
    }

    let start = Instant::now();
    while unsafe { *GLOBAL_INIT_BASE_ADDR.load(Ordering::Relaxed) } == 0 {
        if start.elapsed() > timeout {
            return Err(SystemInitError::Timeout);
        }
        std::thread::yield_now();
    }

    Ok(())
}
