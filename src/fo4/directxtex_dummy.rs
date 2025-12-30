// --- Dummy DirectXTex replacement for non‑Windows builds ---
// This completely removes the dependency on the real directxtex crate.

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ScratchImage;

impl ScratchImage {
    pub fn new() -> Self { Self }
    pub fn GetMetadata(&self) -> TexMetadata { TexMetadata::default() }
    pub fn GetImage(&self, _mip: usize, _item: usize, _slice: usize) -> Option<&[u8]> {
        None
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TexMetadata {
    pub width: usize,
    pub height: usize,
    pub depth: usize,
    pub array_size: usize,
    pub mip_levels: usize,
    pub misc_flags: u32,
    pub misc_flags2: u32,
    pub format: DXGI_FORMAT,
    pub dimension: TEX_DIMENSION,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CP_FLAGS;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DDS_FLAGS;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub enum DXGI_FORMAT {
    DXGI_FORMAT_UNKNOWN,
}

impl Default for DXGI_FORMAT {
    fn default() -> Self { DXGI_FORMAT::DXGI_FORMAT_UNKNOWN }
}

impl DXGI_FORMAT {
    pub fn is_srgb(&self) -> bool { false }
    pub fn format_data_type(&self) -> FORMAT_TYPE { FORMAT_TYPE::FORMAT_TYPE_UNKNOWN }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub enum FORMAT_TYPE {
    FORMAT_TYPE_UNKNOWN,
}

impl Default for FORMAT_TYPE {
    fn default() -> Self { FORMAT_TYPE::FORMAT_TYPE_UNKNOWN }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub enum TEX_DIMENSION {
    TEX_DIMENSION_UNKNOWN,
}

impl Default for TEX_DIMENSION {
    fn default() -> Self { TEX_DIMENSION::TEX_DIMENSION_UNKNOWN }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TEX_MISC_FLAG;