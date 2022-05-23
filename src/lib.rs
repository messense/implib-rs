use object::pe::*;

/// Unix archiver writer
mod ar;
/// Parse .DEF file
pub mod def;
/// GNU binutils flavored import library
mod gnu;
/// MSVC flavored import library
mod msvc;

pub use self::msvc::ImportLibrary;
use crate::def::ShortExport;

/// Machine types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MachineType {
    /// Intel 386
    I386 = IMAGE_FILE_MACHINE_I386,
    /// ARM Thumb-2 Little-Endian
    ARMNT = IMAGE_FILE_MACHINE_ARMNT,
    /// AMD64 (K8)
    AMD64 = IMAGE_FILE_MACHINE_AMD64,
    ARM64 = IMAGE_FILE_MACHINE_ARM64,
}

impl MachineType {
    fn is_32bit(&self) -> bool {
        matches!(self, Self::ARMNT | Self::I386)
    }

    fn img_rel_relocation(&self) -> u16 {
        match self {
            Self::AMD64 => IMAGE_REL_AMD64_ADDR32NB,
            Self::ARMNT => IMAGE_REL_ARM_ADDR32NB,
            Self::ARM64 => IMAGE_REL_ARM64_ADDR32NB,
            Self::I386 => IMAGE_REL_I386_DIR32NB,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
enum ImportType {
    /// Code, function
    Code,
    /// Data
    Data,
    /// Constant
    Const,
}

impl ShortExport {
    fn import_type(&self) -> ImportType {
        if self.data {
            ImportType::Data
        } else if self.constant {
            ImportType::Const
        } else {
            ImportType::Code
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
enum ImportNameType {
    /// Import is by ordinal. This indicates that the value in the Ordinal/Hint
    /// field of the import header is the import's ordinal. If this constant is
    /// not specified, then the Ordinal/Hint field should always be interpreted
    /// as the import's hint.
    Ordinal = IMPORT_OBJECT_ORDINAL,
    /// The import name is identical to the public symbol name
    Name = IMPORT_OBJECT_NAME,
    /// The import name is the public symbol name, but skipping the leading ?,
    /// @, or optionally _.
    NameNoPrefix = IMPORT_OBJECT_NAME_NO_PREFIX,
    /// The import name is the public symbol name, but skipping the leading ?,
    /// @, or optionally _, and truncating at the first @.
    NameUndecorate = IMPORT_OBJECT_NAME_UNDECORATE,
}
