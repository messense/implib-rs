#[cfg(any(not(feature = "msvc"), not(feature = "gnu")))]
use std::io::ErrorKind;
use std::io::{Error, Seek, Write};

use object::pe::*;

/// Parse .DEF file
pub mod def;
/// GNU binutils flavored import library
#[cfg(feature = "gnu")]
mod gnu;
/// MSVC flavored import library
#[cfg(feature = "msvc")]
mod msvc;

#[cfg(feature = "gnu")]
use self::gnu::GnuImportLibrary;
#[cfg(feature = "msvc")]
use self::msvc::MsvcImportLibrary;
use crate::def::ModuleDef;

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
    /// ARM64EC (Emulation Compatible)
    ARM64EC = IMAGE_FILE_MACHINE_ARM64EC,
    /// ARM64X (Mixed ARM64 and ARM64EC)
    ARM64X = IMAGE_FILE_MACHINE_ARM64X,
}

impl MachineType {
    fn img_rel_relocation(&self) -> u16 {
        match self {
            Self::AMD64 => IMAGE_REL_AMD64_ADDR32NB,
            Self::ARMNT => IMAGE_REL_ARM_ADDR32NB,
            Self::ARM64 | Self::ARM64EC | Self::ARM64X => IMAGE_REL_ARM64_ADDR32NB,
            Self::I386 => IMAGE_REL_I386_DIR32NB,
        }
    }
}

#[derive(Debug)]
struct ArchiveMember {
    name: String,
    data: Vec<u8>,
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
    native_def: Option<ModuleDef>,
    machine: MachineType,
    flavor: Flavor,
}

impl ImportLibrary {
    /// Create new import library generator from module definition text content
    pub fn new(def: &str, machine: MachineType, flavor: Flavor) -> Result<Self, Error> {
        let def = ModuleDef::parse(def, machine)?;
        Ok(Self::from_def(def, machine, flavor))
    }

    /// Create new ARM64X import library generator from two module definition
    /// text contents: `def` describes the ARM64EC/x64-compatible exports and
    /// `native_def` describes the pure ARM64 exports. The resulting archive
    /// can be linked from both ARM64 and ARM64EC consumers.
    pub fn new_arm64x(def: &str, native_def: &str, flavor: Flavor) -> Result<Self, Error> {
        let def = ModuleDef::parse(def, MachineType::ARM64EC)?;
        let native_def = ModuleDef::parse(native_def, MachineType::ARM64)?;
        Ok(Self::from_defs(
            def,
            Some(native_def),
            MachineType::ARM64X,
            flavor,
        ))
    }

    /// Create new import library generator from `ModuleDef`
    pub fn from_def(def: ModuleDef, machine: MachineType, flavor: Flavor) -> Self {
        Self::from_defs(def, None, machine, flavor)
    }

    /// Create new import library generator from a primary `ModuleDef` and an
    /// optional native `ModuleDef`. The native def is only meaningful for
    /// `MachineType::ARM64X`; for other machine types it is ignored.
    pub fn from_defs(
        mut def: ModuleDef,
        native_def: Option<ModuleDef>,
        machine: MachineType,
        flavor: Flavor,
    ) -> Self {
        // If ext_name is set (if the "ext_name = name" syntax was used), overwrite
        // name with ext_name and clear ext_name. When only creating an import
        // library and not linking, the internal name is irrelevant.
        for export in &mut def.exports {
            if let Some(ext_name) = export.ext_name.take() {
                export.name = ext_name;
            }
        }
        let native_def = native_def.map(|mut nd| {
            for export in &mut nd.exports {
                if let Some(ext_name) = export.ext_name.take() {
                    export.name = ext_name;
                }
            }
            nd
        });
        // Skipped i386 handling
        // See https://github.com/llvm/llvm-project/blob/09c2b7c35af8c4bad39f03e9f60df8bd07323028/llvm/lib/ToolDrivers/llvm-dlltool/DlltoolDriver.cpp#L197-L212
        ImportLibrary {
            def,
            native_def,
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
            #[cfg(feature = "msvc")]
            Flavor::Msvc => {
                MsvcImportLibrary::new(self.def, self.native_def, self.machine).write_to(writer)
            }
            #[cfg(not(feature = "msvc"))]
            Flavor::Msvc => Err(Error::new(
                ErrorKind::Unsupported,
                "MSVC import library unsupported, enable 'msvc' feature to use it",
            )),
            #[cfg(feature = "gnu")]
            Flavor::Gnu => GnuImportLibrary::new(self.def, self.machine).write_to(writer),
            #[cfg(not(feature = "gnu"))]
            Flavor::Gnu => Err(Error::new(
                ErrorKind::Unsupported,
                "GNU import library unsupported, enable 'gnu' feature to use it",
            )),
        }
    }
}
