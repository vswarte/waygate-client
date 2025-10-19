use pelite::pe64::{Pe, PeView};
use std::sync::LazyLock;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;

mod rva_jp;
mod rva_ww;

const LANG_ID_EN: u16 = 0x0009;
const LANG_ID_JP: u16 = 0x0011;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GameVersion {
    Ww261,
    Jp2611,
}

impl GameVersion {
    fn from_metadata(product: &str, lang_id: u16, version: &str) -> Option<Self> {
        match (product, lang_id, version) {
            ("ELDEN RING™", LANG_ID_EN, "2.6.1.0") => Some(Self::Ww261),
            ("ELDEN RING", LANG_ID_JP, "2.6.1.1") => Some(Self::Jp2611),
            _ => None,
        }
    }
}

pub fn get() -> &'static RvaBundle {
    static RVAS: LazyLock<RvaBundle> = LazyLock::new(|| {
        let module = unsafe {
            PeView::module(GetModuleHandleA(PCSTR(std::ptr::null())).unwrap().0 as *const u8)
        };
        detect_version_and_get_rvas(&module)
            .expect("This game version or distribution is not supported")
    });

    &RVAS
}

fn detect_version_and_get_rvas(module: &PeView) -> Option<RvaBundle> {
    let resources = module.resources().ok()?;
    let info = resources.version_info().ok()?;

    // Extract version info
    let product_version = info.fixed()?.dwProductVersion;
    let version = format!(
        "{}.{}.{}.{}",
        product_version.Major, product_version.Minor, product_version.Patch, product_version.Build,
    );

    // Extract product name
    let language = *info.translation().first()?;
    let mut product_name: Option<String> = None;
    info.strings(language, |k, v| {
        if k == "ProductName" {
            product_name = Some(v.to_string());
        }
    });

    let product = product_name?;
    let lang_id_base = language.lang_id & 0x03FF;

    // Detect version and return appropriate RVAs
    let version = GameVersion::from_metadata(&product, lang_id_base, &version)?;
    Some(RvaBundle::for_version(version))
}

pub struct RvaBundle {
    pub p2p_packet_dequeue: u32,
    pub p2p_send_packet: u32,
    pub sodium_kx_key_derive: u32,
}

macro_rules! rva_bundle {
    ($module:ident) => {
        Self {
            p2p_packet_dequeue: $module::RVA_P2P_PACKET_DEQUEUE,
            p2p_send_packet: $module::RVA_P2P_SEND_PACKET,
            sodium_kx_key_derive: $module::RVA_SODIUM_KX_KEY_DERIVE,
        }
    };
}

impl RvaBundle {
    fn for_version(version: GameVersion) -> Self {
        match version {
            GameVersion::Ww261 => rva_bundle!(rva_ww),
            GameVersion::Jp2611 => rva_bundle!(rva_jp),
        }
    }
}
