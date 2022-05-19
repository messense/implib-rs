use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::{Seek, Write};
use std::mem::size_of;

use memoffset::offset_of;
use object::endian::{LittleEndian as LE, U16Bytes, U32Bytes, U16, U32};
use object::pe::*;
use object::pod::bytes_of;

pub use self::def::{ModuleDef, ModuleDefError, ShortExport};

/// Unix archiver writer
mod ar;
/// Parse .DEF file
mod def;

const NULL_IMPORT_DESCRIPTOR_SYMBOL_NAME: &str = "__NULL_IMPORT_DESCRIPTOR";

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

/// Windows import library generator
#[derive(Debug, Clone)]
pub struct ImportLibrary {
    def: ModuleDef,
    machine: MachineType,
}

impl ImportLibrary {
    pub fn new(mut def: ModuleDef, machine: MachineType) -> Self {
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
        ImportLibrary { def, machine }
    }

    fn get_name_type(&self, sym: &str, ext_name: &str) -> ImportNameType {
        // Skipped mingw64 handling
        // See https://github.com/llvm/llvm-project/blob/09c2b7c35af8c4bad39f03e9f60df8bd07323028/llvm/lib/Object/COFFImportFile.cpp#L96-L105
        if ext_name.starts_with('_') && ext_name.contains('@') {
            ImportNameType::Name
        } else if sym != ext_name {
            ImportNameType::NameUndecorate
        } else if self.machine == MachineType::I386 && sym.starts_with('_') {
            ImportNameType::NameNoPrefix
        } else {
            ImportNameType::Name
        }
    }

    fn create_archive_entry(member: ArchiveMember) -> (ar::Header, ArchiveMember) {
        let mut header = ar::Header::new(
            member.name.to_string().into_bytes(),
            member.data.len() as u64,
        );
        header.set_mode(0o644);
        (header, member)
    }

    /// Write out the import library
    pub fn write_to<W: Write + Seek>(&self, writer: &mut W) {
        // FIXME: should use `GnuBuilder`
        let mut members = Vec::new();
        let factory = ObjectFactory::new(&self.def.import_name, self.machine);

        let import_descriptor = factory.create_import_descriptor();
        members.push(Self::create_archive_entry(import_descriptor));

        let null_import_descriptor = factory.create_null_import_descriptor();
        members.push(Self::create_archive_entry(null_import_descriptor));

        let null_thunk = factory.create_null_thunk();
        members.push(Self::create_archive_entry(null_thunk));

        for export in &self.def.exports {
            if export.private {
                continue;
            }
            let sym = if export.symbol_name.is_empty() {
                &export.name
            } else {
                &export.symbol_name
            };
            let name_type = if export.no_name {
                ImportNameType::Ordinal
            } else {
                self.get_name_type(sym, &export.name)
            };
            let name = if export.ext_name.is_none() {
                sym
            } else {
                todo!()
            };

            if !export.alias_target.is_empty() && name != &export.alias_target {
                let weak_non_imp = factory.create_weak_external(&export.alias_target, name, false);
                members.push(Self::create_archive_entry(weak_non_imp));

                let weak_imp = factory.create_weak_external(&export.alias_target, name, true);
                members.push(Self::create_archive_entry(weak_imp));
            }
            let short_import =
                factory.create_short_import(name, export.ordinal, export.import_type(), name_type);
            members.push(Self::create_archive_entry(short_import));
        }

        let identifiers = members
            .iter()
            .map(|(header, _)| header.identifier().to_vec())
            .collect();
        let symbols: Vec<Vec<u8>> = members
            .iter()
            .flat_map(|(_, member)| {
                member
                    .symbols
                    .iter()
                    .map(|s| s.to_string().into_bytes())
                    .collect::<Vec<Vec<u8>>>()
            })
            .collect();
        let mut symbol_table = BTreeMap::new();
        symbol_table.insert(self.def.import_name.to_string().into_bytes(), symbols);
        let mut archive =
            ar::GnuBuilder::new_with_symbol_table(writer, true, identifiers, symbol_table).unwrap();
        for (header, member) in members {
            archive.append(&header, &member.data[..]).unwrap();
        }
        // FIXME: Need to use ranlib to generate symbol table index to actually be usable
        // See https://github.com/mdsteele/rust-ar/pull/17#issuecomment-1129606307
    }
}

#[derive(Debug)]
struct ArchiveMember<'a> {
    name: &'a str,
    data: Vec<u8>,
    symbols: Vec<String>,
}

/// Constructs various small object files necessary to support linking
/// symbols imported from a DLL.  The contents are pretty strictly defined and
/// nearly entirely static.  The details of the structures files are defined in
/// WINNT.h and the PE/COFF specification.
#[derive(Debug)]
struct ObjectFactory<'a> {
    machine: MachineType,
    import_name: &'a str,
    import_descriptor_symbol_name: String,
    null_thunk_symbol_name: String,
}

impl<'a> ObjectFactory<'a> {
    fn new(import_name: &'a str, machine: MachineType) -> Self {
        let library = &import_name[..import_name.len() - 4];
        Self {
            machine,
            import_name,
            import_descriptor_symbol_name: format!("__IMPORT_DESCRIPTOR_{}", library),
            null_thunk_symbol_name: format!("\x7f{}_NULL_THUNK_DATA", library),
        }
    }

    fn write_string_table(buffer: &mut Vec<u8>, strings: &[&str]) {
        // The COFF string table consists of a 4-byte value which is the size of the
        // table, including the length field itself.  This value is followed by the
        // string content itself, which is an array of null-terminated C-style
        // strings.  The termination is important as they are referenced to by offset
        // by the symbol entity in the file format.
        let offset = buffer.len();

        // Skip over the length field, we will fill it in later as we will have
        // computed the length while emitting the string content itself.
        buffer.extend_from_slice(&[0, 0, 0, 0]);

        for s in strings {
            let c_str = CString::new(*s).unwrap();
            buffer.extend(c_str.into_bytes_with_nul());
        }

        // Backfill the length of the table now that it has been computed.
        let size = (buffer.len() - offset) as u32;
        buffer[offset..offset + 4].copy_from_slice(&size.to_le_bytes());
    }

    /// Creates an Import Descriptor.  This is a small object file which contains a
    /// reference to the terminators and contains the library name (entry) for the
    /// import name table.  It will force the linker to construct the necessary
    /// structure to import symbols from the DLL.
    fn create_import_descriptor(&self) -> ArchiveMember<'a> {
        const NUM_SECTIONS: usize = 2;
        const NUM_SYMBOLS: usize = 7;
        const NUM_RELOCATIONS: usize = 3;

        let mut buffer = Vec::new();

        let pointer_to_symbol_table = size_of::<ImageFileHeader>()
            + NUM_SECTIONS * size_of::<ImageSectionHeader>()
            // .idata$2
            + size_of::<ImageImportDescriptor>() + NUM_RELOCATIONS * size_of::<ImageRelocation>()
            // .idata$4
            + self.import_name.len() + 1;
        let characteristics = if self.machine.is_32bit() {
            IMAGE_FILE_32BIT_MACHINE
        } else {
            0
        };
        let header = ImageFileHeader {
            machine: U16::new(LE, self.machine as u16),
            number_of_sections: U16::new(LE, NUM_SECTIONS as u16),
            time_date_stamp: U32::new(LE, 0),
            pointer_to_symbol_table: U32::new(LE, pointer_to_symbol_table as u32),
            number_of_symbols: U32::new(LE, NUM_SYMBOLS as u32),
            size_of_optional_header: U16::new(LE, 0),
            characteristics: U16::new(LE, characteristics),
        };
        buffer.extend_from_slice(bytes_of(&header));

        // Section Header Table
        let section_header_table = [
            ImageSectionHeader {
                name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'2'],
                virtual_size: U32::new(LE, 0),
                virtual_address: U32::new(LE, 0),
                size_of_raw_data: U32::new(LE, size_of::<ImageImportDescriptor>() as _),
                pointer_to_raw_data: U32::new(
                    LE,
                    (size_of::<ImageFileHeader>() + NUM_SECTIONS * size_of::<ImageSectionHeader>())
                        as _,
                ),
                pointer_to_relocations: U32::new(
                    LE,
                    (size_of::<ImageFileHeader>()
                        + NUM_SECTIONS * size_of::<ImageSectionHeader>()
                        + size_of::<ImageImportDescriptor>()) as _,
                ),
                pointer_to_linenumbers: U32::new(LE, 0),
                number_of_relocations: U16::new(LE, NUM_RELOCATIONS as _),
                number_of_linenumbers: U16::new(LE, 0),
                characteristics: U32::new(
                    LE,
                    IMAGE_SCN_ALIGN_4BYTES
                        | IMAGE_SCN_CNT_INITIALIZED_DATA
                        | IMAGE_SCN_MEM_READ
                        | IMAGE_SCN_MEM_WRITE,
                ),
            },
            ImageSectionHeader {
                name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'6'],
                virtual_size: U32::new(LE, 0),
                virtual_address: U32::new(LE, 0),
                size_of_raw_data: U32::new(LE, (self.import_name.len() + 1) as _),
                pointer_to_raw_data: U32::new(
                    LE,
                    (size_of::<ImageFileHeader>()
                        + NUM_SECTIONS * size_of::<ImageSectionHeader>()
                        + size_of::<ImageImportDescriptor>()
                        + NUM_RELOCATIONS * size_of::<ImageRelocation>()) as _,
                ),
                pointer_to_relocations: U32::new(LE, 0),
                pointer_to_linenumbers: U32::new(LE, 0),
                number_of_relocations: U16::new(LE, 0),
                number_of_linenumbers: U16::new(LE, 0),
                characteristics: U32::new(
                    LE,
                    IMAGE_SCN_ALIGN_2BYTES
                        | IMAGE_SCN_CNT_INITIALIZED_DATA
                        | IMAGE_SCN_MEM_READ
                        | IMAGE_SCN_MEM_WRITE,
                ),
            },
        ];
        for section in section_header_table {
            buffer.extend_from_slice(bytes_of(&section));
        }

        // .idata$2
        let import_descriptor = ImageImportDescriptor {
            original_first_thunk: U32Bytes::new(LE, 0),
            time_date_stamp: U32Bytes::new(LE, 0),
            forwarder_chain: U32Bytes::new(LE, 0),
            name: U32Bytes::new(LE, 0),
            first_thunk: U32Bytes::new(LE, 0),
        };
        buffer.extend_from_slice(bytes_of(&import_descriptor));

        let relocation_table = [
            ImageRelocation {
                virtual_address: U32Bytes::new(LE, offset_of!(ImageImportDescriptor, name) as _),
                symbol_table_index: U32Bytes::new(LE, 2),
                typ: U16Bytes::new(LE, self.machine.img_rel_relocation()),
            },
            ImageRelocation {
                virtual_address: U32Bytes::new(
                    LE,
                    offset_of!(ImageImportDescriptor, original_first_thunk) as _,
                ),
                symbol_table_index: U32Bytes::new(LE, 3),
                typ: U16Bytes::new(LE, self.machine.img_rel_relocation()),
            },
            ImageRelocation {
                virtual_address: U32Bytes::new(
                    LE,
                    offset_of!(ImageImportDescriptor, first_thunk) as _,
                ),
                symbol_table_index: U32Bytes::new(LE, 4),
                typ: U16Bytes::new(LE, self.machine.img_rel_relocation()),
            },
        ];
        for relocation in &relocation_table {
            buffer.extend_from_slice(bytes_of(relocation));
        }

        // .idata$6
        buffer.extend_from_slice(self.import_name.as_bytes());
        buffer.push(b'\0');

        // Symbol Table
        let sym5_offset =
            (size_of::<u32>() + self.import_descriptor_symbol_name.len() + 1).to_le_bytes();
        let sym6_offset = (size_of::<u32>()
            + self.import_descriptor_symbol_name.len()
            + 1
            + NULL_IMPORT_DESCRIPTOR_SYMBOL_NAME.len()
            + 1)
        .to_le_bytes();
        let symbol_table = [
            ImageSymbol {
                name: [0, 0, 0, 0, size_of::<u32>() as _, 0, 0, 0],
                value: U32Bytes::new(LE, 0),
                section_number: U16Bytes::new(LE, 1),
                typ: U16Bytes::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_EXTERNAL,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'2'],
                value: U32Bytes::new(LE, 0),
                section_number: U16Bytes::new(LE, 1),
                typ: U16Bytes::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_SECTION,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'6'],
                value: U32Bytes::new(LE, 0),
                section_number: U16Bytes::new(LE, 2),
                typ: U16Bytes::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_STATIC,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'4'],
                value: U32Bytes::new(LE, 0),
                section_number: U16Bytes::new(LE, 0),
                typ: U16Bytes::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_SECTION,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'5'],
                value: U32Bytes::new(LE, 0),
                section_number: U16Bytes::new(LE, 0),
                typ: U16Bytes::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_SECTION,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [
                    0,
                    0,
                    0,
                    0,
                    sym5_offset[0],
                    sym5_offset[1],
                    sym5_offset[2],
                    sym5_offset[3],
                ],
                value: U32Bytes::new(LE, 0),
                section_number: U16Bytes::new(LE, 0),
                typ: U16Bytes::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_EXTERNAL,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [
                    0,
                    0,
                    0,
                    0,
                    sym6_offset[0],
                    sym6_offset[1],
                    sym6_offset[2],
                    sym6_offset[3],
                ],
                value: U32Bytes::new(LE, 0),
                section_number: U16Bytes::new(LE, 0),
                typ: U16Bytes::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_EXTERNAL,
                number_of_aux_symbols: 0,
            },
        ];
        for table in &symbol_table {
            buffer.extend_from_slice(bytes_of(table));
        }

        Self::write_string_table(
            &mut buffer,
            &[
                &self.import_descriptor_symbol_name,
                NULL_IMPORT_DESCRIPTOR_SYMBOL_NAME,
                &self.null_thunk_symbol_name,
            ],
        );
        ArchiveMember {
            name: self.import_name,
            data: buffer,
            symbols: vec![self.import_descriptor_symbol_name.to_string()],
        }
    }

    /// Creates a NULL import descriptor.  This is a small object file whcih
    /// contains a NULL import descriptor.  It is used to terminate the imports
    /// from a specific DLL.
    fn create_null_import_descriptor(&self) -> ArchiveMember<'a> {
        const NUM_SECTIONS: usize = 1;
        const NUM_SYMBOLS: usize = 1;

        let mut buffer = Vec::new();

        let pointer_to_symbol_table = size_of::<ImageFileHeader>()
            + NUM_SECTIONS * size_of::<ImageSectionHeader>()
            // .idata$3
            + size_of::<ImageImportDescriptor>();
        let characteristics = if self.machine.is_32bit() {
            IMAGE_FILE_32BIT_MACHINE
        } else {
            0
        };
        let header = ImageFileHeader {
            machine: U16::new(LE, self.machine as u16),
            number_of_sections: U16::new(LE, NUM_SECTIONS as u16),
            time_date_stamp: U32::new(LE, 0),
            pointer_to_symbol_table: U32::new(LE, pointer_to_symbol_table as u32),
            number_of_symbols: U32::new(LE, NUM_SYMBOLS as u32),
            size_of_optional_header: U16::new(LE, 0),
            characteristics: U16::new(LE, characteristics),
        };
        buffer.extend_from_slice(bytes_of(&header));

        // Section Header Table
        let section_header_table = ImageSectionHeader {
            name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'3'],
            virtual_size: U32::new(LE, 0),
            virtual_address: U32::new(LE, 0),
            size_of_raw_data: U32::new(LE, size_of::<ImageImportDescriptor>() as _),
            pointer_to_raw_data: U32::new(
                LE,
                (size_of::<ImageFileHeader>() + NUM_SECTIONS * size_of::<ImageSectionHeader>())
                    as _,
            ),
            pointer_to_relocations: U32::new(LE, 0),
            pointer_to_linenumbers: U32::new(LE, 0),
            number_of_relocations: U16::new(LE, 0),
            number_of_linenumbers: U16::new(LE, 0),
            characteristics: U32::new(
                LE,
                IMAGE_SCN_ALIGN_4BYTES
                    | IMAGE_SCN_CNT_INITIALIZED_DATA
                    | IMAGE_SCN_MEM_READ
                    | IMAGE_SCN_MEM_WRITE,
            ),
        };
        buffer.extend_from_slice(bytes_of(&section_header_table));

        // .idata$3
        let import_descriptor = ImageImportDescriptor {
            original_first_thunk: U32Bytes::new(LE, 0),
            time_date_stamp: U32Bytes::new(LE, 0),
            forwarder_chain: U32Bytes::new(LE, 0),
            name: U32Bytes::new(LE, 0),
            first_thunk: U32Bytes::new(LE, 0),
        };
        buffer.extend_from_slice(bytes_of(&import_descriptor));

        // Symbol Table
        let symbol_table = ImageSymbol {
            name: [0, 0, 0, 0, size_of::<u32>() as _, 0, 0, 0],
            value: U32Bytes::new(LE, 0),
            section_number: U16Bytes::new(LE, 1),
            typ: U16Bytes::new(LE, 0),
            storage_class: IMAGE_SYM_CLASS_EXTERNAL,
            number_of_aux_symbols: 0,
        };
        buffer.extend_from_slice(bytes_of(&symbol_table));

        Self::write_string_table(&mut buffer, &[NULL_IMPORT_DESCRIPTOR_SYMBOL_NAME]);
        ArchiveMember {
            name: self.import_name,
            data: buffer,
            symbols: vec![NULL_IMPORT_DESCRIPTOR_SYMBOL_NAME.to_string()],
        }
    }

    /// Create a NULL Thunk Entry.  This is a small object file which contains a
    /// NULL Import Address Table entry and a NULL Import Lookup Table Entry.  It
    /// is used to terminate the IAT and ILT.
    fn create_null_thunk(&self) -> ArchiveMember<'a> {
        const NUM_SECTIONS: usize = 2;
        const NUM_SYMBOLS: usize = 1;

        let mut buffer = Vec::new();

        let va_size = if self.machine.is_32bit() { 4 } else { 8 };
        let pointer_to_symbol_table = size_of::<ImageFileHeader>()
            + NUM_SECTIONS * size_of::<ImageSectionHeader>()
            // .idata$5
            + va_size
            // .idata$4
            + va_size;
        let characteristics = if self.machine.is_32bit() {
            IMAGE_FILE_32BIT_MACHINE
        } else {
            0
        };
        let header = ImageFileHeader {
            machine: U16::new(LE, self.machine as u16),
            number_of_sections: U16::new(LE, NUM_SECTIONS as u16),
            time_date_stamp: U32::new(LE, 0),
            pointer_to_symbol_table: U32::new(LE, pointer_to_symbol_table as u32),
            number_of_symbols: U32::new(LE, NUM_SYMBOLS as u32),
            size_of_optional_header: U16::new(LE, 0),
            characteristics: U16::new(LE, characteristics),
        };
        buffer.extend_from_slice(bytes_of(&header));

        // Section Header Table
        let align = if self.machine.is_32bit() {
            IMAGE_SCN_ALIGN_4BYTES
        } else {
            IMAGE_SCN_ALIGN_8BYTES
        };
        let section_header_table = [
            ImageSectionHeader {
                name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'5'],
                virtual_size: U32::new(LE, 0),
                virtual_address: U32::new(LE, 0),
                size_of_raw_data: U32::new(LE, va_size as _),
                pointer_to_raw_data: U32::new(
                    LE,
                    (size_of::<ImageFileHeader>() + NUM_SECTIONS * size_of::<ImageSectionHeader>())
                        as _,
                ),
                pointer_to_relocations: U32::new(LE, 0),
                pointer_to_linenumbers: U32::new(LE, 0),
                number_of_relocations: U16::new(LE, 0),
                number_of_linenumbers: U16::new(LE, 0),
                characteristics: U32::new(
                    LE,
                    align
                        | IMAGE_SCN_CNT_INITIALIZED_DATA
                        | IMAGE_SCN_MEM_READ
                        | IMAGE_SCN_MEM_WRITE,
                ),
            },
            ImageSectionHeader {
                name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'4'],
                virtual_size: U32::new(LE, 0),
                virtual_address: U32::new(LE, 0),
                size_of_raw_data: U32::new(LE, va_size as _),
                pointer_to_raw_data: U32::new(
                    LE,
                    (size_of::<ImageFileHeader>()
                        + NUM_SECTIONS * size_of::<ImageSectionHeader>()
                        + va_size) as _,
                ),
                pointer_to_relocations: U32::new(LE, 0),
                pointer_to_linenumbers: U32::new(LE, 0),
                number_of_relocations: U16::new(LE, 0),
                number_of_linenumbers: U16::new(LE, 0),
                characteristics: U32::new(
                    LE,
                    align
                        | IMAGE_SCN_CNT_INITIALIZED_DATA
                        | IMAGE_SCN_MEM_READ
                        | IMAGE_SCN_MEM_WRITE,
                ),
            },
        ];
        for section in section_header_table {
            buffer.extend_from_slice(bytes_of(&section));
        }

        // .idata$5, ILT
        buffer.extend(0u32.to_le_bytes());
        if !self.machine.is_32bit() {
            buffer.extend(0u32.to_le_bytes());
        }

        // .idata$4, IAT
        buffer.extend(0u32.to_le_bytes());
        if !self.machine.is_32bit() {
            buffer.extend(0u32.to_le_bytes());
        }

        // Symbol Table
        let symbol_table = ImageSymbol {
            name: [0, 0, 0, 0, size_of::<u32>() as _, 0, 0, 0],
            value: U32Bytes::new(LE, 0),
            section_number: U16Bytes::new(LE, 1),
            typ: U16Bytes::new(LE, 0),
            storage_class: IMAGE_SYM_CLASS_EXTERNAL,
            number_of_aux_symbols: 0,
        };
        buffer.extend_from_slice(bytes_of(&symbol_table));

        Self::write_string_table(&mut buffer, &[&self.null_thunk_symbol_name]);
        ArchiveMember {
            name: self.import_name,
            data: buffer,
            symbols: vec![self.null_thunk_symbol_name.to_string()],
        }
    }

    /// Create a short import file which is described in PE/COFF spec 7. Import
    /// Library Format.
    fn create_short_import(
        &self,
        sym: &str,
        ordinal: u16,
        import_type: ImportType,
        name_type: ImportNameType,
    ) -> ArchiveMember<'a> {
        // +2 for NULs
        let import_name_size = self.import_name.len() + sym.len() + 2;
        let size = size_of::<ImportObjectHeader>() + import_name_size;
        let mut buffer = Vec::with_capacity(size);

        // Write short import header
        let import_header = ImportObjectHeader {
            sig1: U16::new(LE, 0),
            sig2: U16::new(LE, 0xFFFF),
            version: U16::new(LE, 0),
            machine: U16::new(LE, self.machine as _),
            time_date_stamp: U32::new(LE, 0),
            size_of_data: U32::new(LE, import_name_size as _),
            ordinal_or_hint: if ordinal > 0 {
                U16::new(LE, ordinal)
            } else {
                U16::new(LE, 0)
            },
            name_type: U16::new(LE, ((name_type as u16) << 2) | import_type as u16),
        };
        buffer.extend_from_slice(bytes_of(&import_header));

        let symbols = if matches!(import_type, ImportType::Data) {
            vec![format!("__imp_{}", sym)]
        } else {
            vec![format!("__imp_{}", sym), sym.to_string()]
        };

        // Write symbol name and DLL name
        let sym = CString::new(sym).unwrap();
        buffer.extend(sym.into_bytes_with_nul());
        let import_name = CString::new(self.import_name).unwrap();
        buffer.extend(import_name.into_bytes_with_nul());

        ArchiveMember {
            name: self.import_name,
            data: buffer,
            symbols,
        }
    }

    /// Create a weak external file which is described in PE/COFF Aux Format 3.
    fn create_weak_external(&self, sym: &str, weak: &str, imp: bool) -> ArchiveMember<'a> {
        const NUM_SECTIONS: usize = 1;
        const NUM_SYMBOLS: usize = 5;

        let mut buffer = Vec::new();

        let pointer_to_symbol_table =
            size_of::<ImageFileHeader>() + NUM_SECTIONS * size_of::<ImageSectionHeader>();
        let header = ImageFileHeader {
            machine: U16::new(LE, self.machine as u16),
            number_of_sections: U16::new(LE, NUM_SECTIONS as u16),
            time_date_stamp: U32::new(LE, 0),
            pointer_to_symbol_table: U32::new(LE, pointer_to_symbol_table as u32),
            number_of_symbols: U32::new(LE, NUM_SYMBOLS as u32),
            size_of_optional_header: U16::new(LE, 0),
            characteristics: U16::new(LE, 0),
        };
        buffer.extend_from_slice(bytes_of(&header));

        // Section Header Table
        let section_header_table = ImageSectionHeader {
            name: [b'.', b'd', b'r', b'e', b'c', b't', b'v', b'e'],
            virtual_size: U32::new(LE, 0),
            virtual_address: U32::new(LE, 0),
            size_of_raw_data: U32::new(LE, 0),
            pointer_to_raw_data: U32::new(LE, 0),
            pointer_to_relocations: U32::new(LE, 0),
            pointer_to_linenumbers: U32::new(LE, 0),
            number_of_relocations: U16::new(LE, 0),
            number_of_linenumbers: U16::new(LE, 0),
            characteristics: U32::new(LE, IMAGE_SCN_LNK_INFO | IMAGE_SCN_LNK_REMOVE),
        };
        buffer.extend_from_slice(bytes_of(&section_header_table));

        // Symbol Table
        let prefix = if imp { "__imp_" } else { "" };
        let sym3_offset = (size_of::<u32>() + sym.len() + prefix.len() + 1).to_le_bytes();
        let symbol_table = [
            ImageSymbol {
                name: [b'@', b'c', b'o', b'm', b'p', b'.', b'i', b'd'],
                value: U32Bytes::new(LE, 0),
                section_number: U16Bytes::new(LE, 0xFFFF),
                typ: U16Bytes::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_STATIC,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [b'@', b'f', b'e', b'a', b't', b'.', b'0', b'0'],
                value: U32Bytes::new(LE, 0),
                section_number: U16Bytes::new(LE, 0xFFFF),
                typ: U16Bytes::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_STATIC,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [0, 0, 0, 0, size_of::<u32>() as _, 0, 0, 0],
                value: U32Bytes::new(LE, 0),
                section_number: U16Bytes::new(LE, 0),
                typ: U16Bytes::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_EXTERNAL,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [
                    0,
                    0,
                    0,
                    0,
                    sym3_offset[0],
                    sym3_offset[1],
                    sym3_offset[2],
                    sym3_offset[3],
                ],
                value: U32Bytes::new(LE, 0),
                section_number: U16Bytes::new(LE, 0),
                typ: U16Bytes::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                number_of_aux_symbols: 1,
            },
            ImageSymbol {
                name: [2, 0, 0, 0, IMAGE_WEAK_EXTERN_SEARCH_ALIAS as u8, 0, 0, 0],
                value: U32Bytes::new(LE, 0),
                section_number: U16Bytes::new(LE, 0),
                typ: U16Bytes::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_NULL,
                number_of_aux_symbols: 0,
            },
        ];
        for table in &symbol_table {
            buffer.extend_from_slice(bytes_of(table));
        }

        // __imp_ String Table
        Self::write_string_table(
            &mut buffer,
            &[
                &format!("{}{}", prefix, sym),
                &format!("{}{}", prefix, weak),
            ],
        );
        ArchiveMember {
            name: self.import_name,
            data: buffer,
            symbols: Vec::new(),
        }
    }
}
