use std::ffi::CString;
use std::io::Write;
use std::mem::size_of;

use object::endian::{LittleEndian as LE, U32Bytes, U16, U32};
use object::pe::*;
use object::pod::bytes_of;
use object::U16Bytes;

pub use self::def::{ModuleDef, ModuleDefError, ShortExport};

/// Parse .DEF file
mod def;

const NULL_IMPORT_DESCRIPTOR_SYMBOL_NAME: &'static str = "__NULL_IMPORT_DESCRIPTOR";

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

impl MachineType {
    fn is_32bit(&self) -> bool {
        match self {
            Self::ARMNT | Self::I386 => true,
            _ => false,
        }
    }
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

    /// Write out the import library
    pub fn write_to<W: Write>(&self, writer: &mut W) {
        // FIXME: should use `GnuBuilder`
        let mut archive = ar::Builder::new(writer);
        let factory = ObjectFactory::new(&self.def.import_name, self.machine);

        let import_descriptor = factory.create_import_descriptor();
        let mut header = ar::Header::new(
            self.def.import_name.clone().into_bytes(),
            import_descriptor.len() as u64,
        );
        header.set_mode(0644);
        archive.append(&header, &import_descriptor[..]).unwrap();

        let null_import_descriptor = factory.create_null_import_descriptor();
        let mut header = ar::Header::new(
            self.def.import_name.clone().into_bytes(),
            null_import_descriptor.len() as u64,
        );
        header.set_mode(0644);
        archive
            .append(&header, &null_import_descriptor[..])
            .unwrap();

        let null_thunk = factory.create_null_thunk();
        let mut header = ar::Header::new(
            self.def.import_name.clone().into_bytes(),
            null_thunk.len() as u64,
        );
        header.set_mode(0644);
        archive.append(&header, &null_thunk[..]).unwrap();
    }
}

#[derive(Debug)]
struct ObjectFactory<'a> {
    machine: MachineType,
    import_name: &'a str,
    library: &'a str,
    import_descriptor_symbol_name: String,
    null_thunk_symbol_name: String,
}

impl<'a> ObjectFactory<'a> {
    fn new(import_name: &'a str, machine: MachineType) -> Self {
        let library = &import_name[..import_name.len() - 4];
        Self {
            machine,
            import_name,
            library,
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
    fn create_import_descriptor(&self) -> Vec<u8> {
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
                virtual_address: Default::default(),
                symbol_table_index: Default::default(),
                typ: Default::default(),
            },
            ImageRelocation {
                virtual_address: Default::default(),
                symbol_table_index: Default::default(),
                typ: Default::default(),
            },
            ImageRelocation {
                virtual_address: Default::default(),
                symbol_table_index: Default::default(),
                typ: Default::default(),
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
            + self.null_thunk_symbol_name.len()
            + 1)
        .to_le_bytes();
        let symbol_table = [
            ImageSymbol {
                name: [0, 0, 0, 0, 4, 0, 0, 0],
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
        buffer
    }

    /// Creates a NULL import descriptor.  This is a small object file whcih
    /// contains a NULL import descriptor.  It is used to terminate the imports
    /// from a specific DLL.
    fn create_null_import_descriptor(&self) -> Vec<u8> {
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
            name: [0, 0, 0, 0, 4, 0, 0, 0],
            value: U32Bytes::new(LE, 0),
            section_number: U16Bytes::new(LE, 1),
            typ: U16Bytes::new(LE, 0),
            storage_class: IMAGE_SYM_CLASS_EXTERNAL,
            number_of_aux_symbols: 0,
        };
        buffer.extend_from_slice(bytes_of(&symbol_table));

        Self::write_string_table(&mut buffer, &[NULL_IMPORT_DESCRIPTOR_SYMBOL_NAME]);
        buffer
    }

    /// Create a NULL Thunk Entry.  This is a small object file which contains a
    /// NULL Import Address Table entry and a NULL Import Lookup Table Entry.  It
    /// is used to terminate the IAT and ILT.
    fn create_null_thunk(&self) -> Vec<u8> {
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
            name: [0, 0, 0, 0, 4, 0, 0, 0],
            value: U32Bytes::new(LE, 0),
            section_number: U16Bytes::new(LE, 1),
            typ: U16Bytes::new(LE, 0),
            storage_class: IMAGE_SYM_CLASS_EXTERNAL,
            number_of_aux_symbols: 0,
        };
        buffer.extend_from_slice(bytes_of(&symbol_table));

        Self::write_string_table(&mut buffer, &[&self.null_thunk_symbol_name]);
        buffer
    }

    /// Create a short import file which is described in PE/COFF spec 7. Import
    /// Library Format.
    fn create_short_import(&self) {
        todo!()
    }

    /// Create a weak external file which is described in PE/COFF Aux Format 3.
    fn create_weak_external(&self) {
        todo!()
    }
}
