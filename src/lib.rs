use object::pe::*;

pub use self::def::{ModuleDef, ModuleDefError, ShortExport};

/// Parse .DEF file
mod def;

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum MachineType {
    /// UNKNOWN
    UNKNOWN = IMAGE_FILE_MACHINE_UNKNOWN,
    /// Intel 386
    I386 = IMAGE_FILE_MACHINE_I386,
    /// MIPS little-endian, 0x160 big-endian
    R3000 = IMAGE_FILE_MACHINE_R3000,
    /// MIPS little-endian
    R4000 = IMAGE_FILE_MACHINE_R4000,
    /// MIPS little-endian
    R10000 = IMAGE_FILE_MACHINE_R10000,
    /// MIPS little-endian WCE v2
    WCEMIPSV2 = IMAGE_FILE_MACHINE_WCEMIPSV2,
    /// Alpha_AXP
    ALPHA = IMAGE_FILE_MACHINE_ALPHA,
    /// SH3 little-endian
    SH3 = IMAGE_FILE_MACHINE_SH3,
    SH3DSP = IMAGE_FILE_MACHINE_SH3DSP,
    /// SH3E little-endian
    SH3E = IMAGE_FILE_MACHINE_SH3E,
    /// SH4 little-endian
    SH4 = IMAGE_FILE_MACHINE_SH4,
    /// SH5 little-endian
    SH5 = IMAGE_FILE_MACHINE_SH5,
    /// ARM
    ARM = IMAGE_FILE_MACHINE_ARM,
    /// ARM Thumb/Thumb-2 Little-Endian
    THUMB = IMAGE_FILE_MACHINE_THUMB,
    /// ARM Thumb-2 Little-Endian
    ARMNT = IMAGE_FILE_MACHINE_ARMNT,
    AM33 = IMAGE_FILE_MACHINE_AM33,
    /// IBM PowerPC Little-Endian
    POWERPC = IMAGE_FILE_MACHINE_POWERPC,
    POWERPCFP = IMAGE_FILE_MACHINE_POWERPCFP,
    /// Intel 64
    IA64 = IMAGE_FILE_MACHINE_IA64,
    /// MIPS
    MIPS16 = IMAGE_FILE_MACHINE_MIPS16,
    /// ALPHA64
    ALPHA64 = IMAGE_FILE_MACHINE_ALPHA64,
    /// MIPS
    MIPSFPU = IMAGE_FILE_MACHINE_MIPSFPU,
    MIPSFPU16 = IMAGE_FILE_MACHINE_MIPSFPU16,
    /// Infineon
    TRICORE = IMAGE_FILE_MACHINE_TRICORE,
    CEF = IMAGE_FILE_MACHINE_CEF,
    /// EFI Byte Code
    EBC = IMAGE_FILE_MACHINE_EBC,
    /// AMD64 (K8)
    AMD64 = IMAGE_FILE_MACHINE_AMD64,
    /// M32R little-endian
    M32R = IMAGE_FILE_MACHINE_M32R,
    /// ARM64 Little-Endian
    ARM64 = IMAGE_FILE_MACHINE_ARM64,
    CEE = IMAGE_FILE_MACHINE_CEE,
    /// RISCV32
    RISCV32 = IMAGE_FILE_MACHINE_RISCV32,
    /// RISCV64
    RISCV64 = IMAGE_FILE_MACHINE_RISCV64,
    /// RISCV128
    RISCV128 = IMAGE_FILE_MACHINE_RISCV128,
}

/// Windows import library generator
#[derive(Debug, Clone)]
pub struct ImportLibrary {
    def: ModuleDef,
}

impl ImportLibrary {
    pub fn new(def: ModuleDef) -> Self {
        ImportLibrary { def }
    }

    /// Build an import library from module definition
    pub fn build(&self) {
        todo!()
    }
}
