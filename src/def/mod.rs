use object::pe::*;

pub use self::error::ModuleDefError;
use self::parser::Parser;

mod error;
mod parser;

/// Simple .DEF file parser
#[derive(Debug, Clone, Default)]
pub struct ModuleDef {
    pub exports: Vec<ShortExport>,
    pub import_name: String,
    pub image_base: u64,
    pub stack_reserve: u64,
    pub stack_commit: u64,
    pub heap_reserve: u64,
    pub heap_commit: u64,
    pub major_image_version: u32,
    pub minor_image_version: u32,
    pub major_os_version: u32,
    pub minor_os_version: u32,
}

impl ModuleDef {
    pub fn parse(def: &str, machine: MachineType) -> Result<ModuleDef, ModuleDefError> {
        Parser::new(def).parse()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ShortExport {
    /// The name of the export as specified in the .def file or on the command
    /// line, i.e. "foo" in "/EXPORT:foo", and "bar" in "/EXPORT:foo=bar"
    pub name: String,
    /// The external, exported name. Only non-empty when export renaming is in
    /// effect, i.e. "foo" in "/EXPORT:foo=bar".
    pub ext_name: Option<String>,
    /// The real, mangled symbol name from the object file.
    pub symbol_name: String,
    /// Creates a weak alias. This is the name of the weak aliasee. In a .def
    /// file, this is "baz" in "EXPORTS\nfoo = bar == baz".
    pub alias_target: String,
    pub ordinal: u16,
    pub no_name: bool,
    pub data: bool,
    pub private: bool,
    pub constant: bool,
}

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
