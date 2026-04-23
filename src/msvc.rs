use std::io::{Error, Seek, Write};

use ar_archive_writer::{write_import_library, COFFShortExport, MachineTypes};

use crate::def::{ModuleDef, ShortExport};
use crate::MachineType;

impl MachineType {
    fn to_ar_machine(self) -> MachineTypes {
        match self {
            Self::I386 => MachineTypes::I386,
            Self::ARMNT => MachineTypes::ARMNT,
            Self::AMD64 => MachineTypes::AMD64,
            Self::ARM64 => MachineTypes::ARM64,
            Self::ARM64EC => MachineTypes::ARM64EC,
            Self::ARM64X => MachineTypes::ARM64X,
        }
    }
}

fn convert_export(export: &ShortExport) -> COFFShortExport {
    COFFShortExport {
        name: export.name.clone(),
        ext_name: export.ext_name.clone(),
        symbol_name: if export.symbol_name.is_empty() {
            None
        } else {
            Some(export.symbol_name.clone())
        },
        import_name: if export.alias_target.is_empty() {
            None
        } else {
            Some(export.alias_target.clone())
        },
        export_as: None,
        ordinal: export.ordinal,
        noname: export.no_name,
        data: export.data,
        private: export.private,
        constant: export.constant,
    }
}

/// MSVC flavored Windows import library generator
#[derive(Debug, Clone)]
pub struct MsvcImportLibrary {
    def: ModuleDef,
    native_def: Option<ModuleDef>,
    machine: MachineType,
}

impl MsvcImportLibrary {
    pub fn new(def: ModuleDef, native_def: Option<ModuleDef>, machine: MachineType) -> Self {
        MsvcImportLibrary {
            def,
            native_def,
            machine,
        }
    }

    /// Write out the import library
    pub fn write_to<W: Write + Seek>(&self, writer: &mut W) -> Result<(), Error> {
        let exports: Vec<COFFShortExport> = self.def.exports.iter().map(convert_export).collect();
        let native_exports: Vec<COFFShortExport> = self
            .native_def
            .as_ref()
            .map(|nd| nd.exports.iter().map(convert_export).collect())
            .unwrap_or_default();
        let machine = self.machine.to_ar_machine();
        write_import_library(
            writer,
            &self.def.import_name,
            &exports,
            machine,
            false,
            false,
            &native_exports,
        )
    }
}
