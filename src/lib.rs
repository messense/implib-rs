use std::io::{Error, Seek, Write};

use object::pe::*;

/// Unix archiver writer
mod ar;
/// Parse .DEF file
pub mod def;
/// GNU binutils flavored import library
mod gnu;
/// MSVC flavored import library
mod msvc;

use self::gnu::GnuImportLibrary;
use self::msvc::MsvcImportLibrary;
use crate::def::{ModuleDef, ShortExport};

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

    fn to_arch(self) -> object::Architecture {
        use object::Architecture::*;
        match self {
            Self::AMD64 => X86_64,
            Self::ARMNT => Arm,
            Self::ARM64 => Aarch64,
            Self::I386 => I386,
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

#[derive(Debug)]
struct ArchiveMember {
    name: String,
    data: Vec<u8>,
    symbols: Vec<String>,
}

impl ArchiveMember {
    fn create_archive_entry(self) -> (ar::Header, ArchiveMember) {
        let mut header =
            ar::Header::new(self.name.to_string().into_bytes(), self.data.len() as u64);
        header.set_mode(0o644);
        (header, self)
    }
}

/// Import library flavor
#[derive(Debug, Clone, Copy)]
pub enum Flavor {
    /// MSVC short import library
    Msvc,
    /// GNU(MinGW) import library
    Gnu,
}

/// Windows import library generator
#[derive(Debug, Clone)]
pub struct ImportLibrary {
    def: ModuleDef,
    machine: MachineType,
    flavor: Flavor,
}

impl ImportLibrary {
    /// Create new import library generator from module definition text content
    pub fn new(def: &str, machine: MachineType, flavor: Flavor) -> Result<Self, Error> {
        let def = ModuleDef::parse(def)?;
        Ok(Self::from_def(def, machine, flavor))
    }

    /// Create new import library generator from `ModuleDef`
    pub fn from_def(mut def: ModuleDef, machine: MachineType, flavor: Flavor) -> Self {
        // If ext_name is set (if the "ext_name = name" syntax was used), overwrite
        // name with ext_name and clear ext_name. When only creating an import
        // library and not linking, the internal name is irrelevant.
        for export in &mut def.exports {
            if let Some(ext_name) = export.ext_name.take() {
                export.name = ext_name;
            }
        }
        // Skipped i386 handling
        // See https://github.com/llvm/llvm-project/blob/09c2b7c35af8c4bad39f03e9f60df8bd07323028/llvm/lib/ToolDrivers/llvm-dlltool/DlltoolDriver.cpp#L197-L212
        ImportLibrary {
            def,
            machine,
            flavor,
        }
    }

    /// Get import library name
    pub fn import_name(&self) -> &str {
        &self.def.import_name
    }

    /// Write out the import library
    pub fn write_to<W: Write + Seek>(self, writer: &mut W) -> Result<(), Error> {
        match self.flavor {
            Flavor::Msvc => MsvcImportLibrary::new(self.def, self.machine).write_to(writer),
            Flavor::Gnu => GnuImportLibrary::new(self.def, self.machine).write_to(writer),
        }
    }
}
