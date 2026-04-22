use std::io::{Error, ErrorKind, Seek, Write};

use object::pe::*;
use object::write::{Mangling, Object, Relocation, Symbol, SymbolId, SymbolSection};
use object::{
    BinaryFormat, Endianness, SectionFlags, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

use crate::def::{ModuleDef, ShortExport};
use crate::{ar, ArchiveMember, MachineType};

const JMP_IX86_BYTES: [u8; 8] = [0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90];
// On i386, `ff 25 disp32` is `jmp dword ptr [disp32]` — an absolute
// indirect jump (no rip-relative addressing). The disp32 must hold the
// absolute VA of the IAT entry, so we use IMAGE_REL_I386_DIR32 (matches
// binutils dlltool's BFD_RELOC_32 for the i386 jtab).
const I386_RELOCATIONS: [(u64, i64, u16); 1] = [(2, 0, IMAGE_REL_I386_DIR32)];
const AMD64_RELOCATIONS: [(u64, i64, u16); 1] = [(2, -4, IMAGE_REL_AMD64_REL32)];

const JMP_ARM_BYTES: [u8; 12] = [
    0x00, 0xc0, 0x9f, 0xe5, /* ldr  ip, [pc] */
    0x00, 0xf0, 0x9c, 0xe5, /* ldr  pc, [ip] */
    0, 0, 0, 0,
];
const ARM_RELOCATIONS: [(u64, i64, u16); 1] = [(8, -4, IMAGE_REL_ARM_REL32)];

const JMP_ARM64_BYTES: [u8; 12] = [
    0x10, 0x00, 0x00, 0x90, /* adrp x16, <(offset >> 12)> */
    0x10, 0x02, 0x40, 0xF9, /* ldr  x16, [x16, <(offset & 0xFFF)>] */
    0x00, 0x02, 0x1F, 0xD6, /* br   x16 */
];
const ARM64_RELOCATIONS: [(u64, i64, u16); 2] = [
    (0, 0, IMAGE_REL_ARM64_PAGEBASE_REL21),
    (4, 0, IMAGE_REL_ARM64_PAGEOFFSET_12L),
];

impl MachineType {
    fn to_arch(self) -> object::Architecture {
        use object::Architecture::*;
        match self {
            Self::AMD64 => X86_64,
            Self::ARMNT => Arm,
            Self::ARM64 | Self::ARM64EC | Self::ARM64X => Aarch64,
            Self::I386 => I386,
        }
    }
}

/// GNU flavored Windows import library generator
#[derive(Debug, Clone)]
pub struct GnuImportLibrary {
    def: ModuleDef,
    machine: MachineType,
}

impl GnuImportLibrary {
    /// Create new import library generator from `ModuleDef`
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
        GnuImportLibrary { def, machine }
    }

    /// Write out the import library
    pub fn write_to<W: Write + Seek>(&self, writer: &mut W) -> Result<(), Error> {
        let mut members = Vec::new();
        let mut factory = ObjectFactory::new(&self.def.import_name, self.machine)?;
        for export in &self.def.exports {
            members.push(factory.make_one(export)?.create_archive_entry());
        }
        members.push(factory.make_head()?.create_archive_entry());
        members.push(factory.make_tail()?.create_archive_entry());
        members.reverse();

        let identifiers = members
            .iter()
            .map(|(header, _)| header.identifier().to_vec())
            .collect();
        let symbol_table: Vec<Vec<Vec<u8>>> = members
            .iter()
            .map(|(_, member)| {
                member
                    .symbols
                    .iter()
                    .map(|s| s.to_string().into_bytes())
                    .collect::<Vec<Vec<u8>>>()
            })
            .collect();
        let mut archive =
            ar::GnuBuilder::new_with_symbol_table(writer, true, identifiers, symbol_table)?;
        for (header, member) in members {
            archive.append(&header, &member.data[..])?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ObjectFactory<'a> {
    machine: MachineType,
    import_name: &'a str,
    output_name: String,
    seq: usize,
}

impl<'a> ObjectFactory<'a> {
    fn new(import_name: &'a str, machine: MachineType) -> Result<Self, Error> {
        if import_name.contains('\0') {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "import name contains null byte".to_string(),
            ));
        }
        Ok(Self {
            machine,
            import_name,
            output_name: format!("{}.a", import_name),
            seq: 0,
        })
    }
    fn make_relocation(
        &self,
        offset: u64,
        symbol: SymbolId,
        addend: i64,
        rel_kind: u16,
    ) -> Relocation {
        Relocation {
            offset,
            symbol,
            addend,
            flags: object::RelocationFlags::Coff { typ: rel_kind },
        }
    }
    fn make_head(&self) -> Result<ArchiveMember, Error> {
        let mut obj = Object::new(
            BinaryFormat::Coff,
            self.machine.to_arch(),
            Endianness::Little,
        );
        let text_sec = obj.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
        obj.section_mut(text_sec).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_16BYTES
                | IMAGE_SCN_CNT_CODE
                | IMAGE_SCN_MEM_EXECUTE
                | IMAGE_SCN_MEM_READ,
        };

        let data_sec = obj.add_section(Vec::new(), b".data".to_vec(), SectionKind::Data);
        obj.section_mut(data_sec).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_16BYTES
                | IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };

        let bss_sec = obj.add_section(Vec::new(), b".bss".to_vec(), SectionKind::UninitializedData);
        obj.section_mut(bss_sec).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_16BYTES
                | IMAGE_SCN_CNT_UNINITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };

        let id2 = obj.add_section(Vec::new(), b".idata$2".to_vec(), SectionKind::Data);
        let id5 = obj.add_section(Vec::new(), b".idata$5".to_vec(), SectionKind::Data);
        obj.section_mut(id5).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES
                | IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };
        let id4 = obj.add_section(Vec::new(), b".idata$4".to_vec(), SectionKind::Data);
        obj.section_mut(id4).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES
                | IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };

        obj.add_file_symbol(b"fake".to_vec());
        let id5_sym = obj.section_symbol(id5);
        let id4_sym = obj.section_symbol(id4);
        let img_rel = self.machine.img_rel_relocation();
        obj.add_relocation(id2, self.make_relocation(0, id4_sym, 0, img_rel))
            .map_err(|e| Error::other(e.to_string()))?;
        obj.add_relocation(id2, self.make_relocation(16, id5_sym, 0, img_rel))
            .map_err(|e| Error::other(e.to_string()))?;

        let import_name = self.import_name.replace('.', "_");

        let head_sym = Symbol {
            name: format!("_head_{}", import_name).into_bytes(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(id2),
            flags: SymbolFlags::None,
        };
        let head_sym_id = obj.add_symbol(head_sym);
        let head_sym_name = obj.symbol(head_sym_id).name.clone();

        let iname_sym = Symbol {
            name: format!("{}_iname", import_name).into_bytes(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        };
        let iname_sym_id = obj.add_symbol(iname_sym);

        obj.append_section_data(id2, &[0; 20], 4);
        obj.add_relocation(id2, self.make_relocation(12, iname_sym_id, 0, img_rel))
            .map_err(|e| Error::other(e.to_string()))?;
        Ok(ArchiveMember {
            name: format!("{}_h.o", self.output_name.replace('.', "_")),
            data: obj.write().map_err(|e| Error::other(e.to_string()))?,
            symbols: vec![String::from_utf8(head_sym_name).unwrap()],
        })
    }

    fn make_tail(&self) -> Result<ArchiveMember, Error> {
        let mut obj = Object::new(
            BinaryFormat::Coff,
            self.machine.to_arch(),
            Endianness::Little,
        );
        let text_sec = obj.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
        obj.section_mut(text_sec).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_16BYTES
                | IMAGE_SCN_CNT_CODE
                | IMAGE_SCN_MEM_EXECUTE
                | IMAGE_SCN_MEM_READ,
        };

        let data_sec = obj.add_section(Vec::new(), b".data".to_vec(), SectionKind::Data);
        obj.section_mut(data_sec).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_16BYTES
                | IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };

        let bss_sec = obj.add_section(Vec::new(), b".bss".to_vec(), SectionKind::UninitializedData);
        obj.section_mut(bss_sec).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_16BYTES
                | IMAGE_SCN_CNT_UNINITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };

        let id4 = obj.add_section(Vec::new(), b".idata$4".to_vec(), SectionKind::Data);
        obj.section_mut(id4).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES
                | IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };
        let id5 = obj.add_section(Vec::new(), b".idata$5".to_vec(), SectionKind::Data);
        obj.section_mut(id5).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES
                | IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };
        let id7 = obj.add_section(Vec::new(), b".idata$7".to_vec(), SectionKind::Data);
        obj.section_mut(id7).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES
                | IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };

        obj.add_file_symbol(b"fake".to_vec());

        let import_name = self.import_name.replace('.', "_");
        let iname_sym = Symbol {
            name: format!("{}_iname", import_name).into_bytes(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(id7),
            flags: SymbolFlags::None,
        };
        let iname_sym_id = obj.add_symbol(iname_sym);
        let iname_sym_name = obj.symbol(iname_sym_id).name.clone();

        obj.append_section_data(id4, &[0; 8], 4);
        obj.append_section_data(id5, &[0; 8], 4);

        let mut import_name_bytes = self.import_name.as_bytes().to_vec();
        import_name_bytes.push(b'\0');
        obj.append_section_data(id7, &import_name_bytes, 4);

        Ok(ArchiveMember {
            name: format!("{}_t.o", self.output_name.replace('.', "_")),
            data: obj.write().map_err(|e| Error::other(e.to_string()))?,
            symbols: vec![String::from_utf8(iname_sym_name).unwrap()],
        })
    }

    fn make_one(&mut self, export: &ShortExport) -> Result<ArchiveMember, Error> {
        if export.name.contains('\0') {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "export name contains null byte".to_string(),
            ));
        }

        let mut obj = Object::new(
            BinaryFormat::Coff,
            self.machine.to_arch(),
            Endianness::Little,
        );

        let text_sec = obj.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
        obj.section_mut(text_sec).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES
                | IMAGE_SCN_CNT_CODE
                | IMAGE_SCN_MEM_EXECUTE
                | IMAGE_SCN_MEM_READ,
        };

        let data_sec = obj.add_section(Vec::new(), b".data".to_vec(), SectionKind::Data);
        obj.section_mut(data_sec).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES
                | IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };

        let bss_sec = obj.add_section(Vec::new(), b".bss".to_vec(), SectionKind::UninitializedData);
        obj.section_mut(bss_sec).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES
                | IMAGE_SCN_CNT_UNINITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };

        let id7 = obj.add_section(Vec::new(), b".idata$7".to_vec(), SectionKind::Data);
        obj.section_mut(id7).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES
                | IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };
        let id5 = obj.add_section(Vec::new(), b".idata$5".to_vec(), SectionKind::Data);
        obj.section_mut(id5).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES
                | IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };
        let id4 = obj.add_section(Vec::new(), b".idata$4".to_vec(), SectionKind::Data);
        obj.section_mut(id4).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES
                | IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };
        let id6 = obj.add_section(Vec::new(), b".idata$6".to_vec(), SectionKind::Data);
        obj.section_mut(id6).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_2BYTES
                | IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        };

        let import_name = self.import_name.replace('.', "_");
        let head_sym = Symbol {
            name: format!("_head_{}", import_name).into_bytes(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        };
        let head_sym = obj.add_symbol(head_sym);

        // All subsequent symbols should be added unmangled.
        obj.mangling = Mangling::None;

        let mut archive_symbols = Vec::new();
        if !export.data {
            let exp_sym = Symbol {
                name: export.name.as_bytes().to_vec(),
                value: 0,
                size: 0,
                kind: SymbolKind::Data,
                scope: SymbolScope::Dynamic,
                weak: false,
                section: SymbolSection::Section(text_sec),
                flags: SymbolFlags::None,
            };
            obj.add_symbol(exp_sym);
            archive_symbols.push(export.name.to_string());
        }
        let exp_imp_sym = Symbol {
            name: format!("__imp_{}", export.name).into_bytes(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(id5),
            flags: SymbolFlags::None,
        };
        let exp_imp_sym = obj.add_symbol(exp_imp_sym);
        archive_symbols.push(format!("__imp_{}", export.name));

        if !export.data {
            let (jmp_stub, relocations) = match self.machine {
                MachineType::I386 => (&JMP_IX86_BYTES[..], &I386_RELOCATIONS[..]),
                MachineType::ARMNT => (&JMP_ARM_BYTES[..], &ARM_RELOCATIONS[..]),
                MachineType::AMD64 => (&JMP_IX86_BYTES[..], &AMD64_RELOCATIONS[..]),
                MachineType::ARM64 | MachineType::ARM64EC | MachineType::ARM64X => {
                    (&JMP_ARM64_BYTES[..], &ARM64_RELOCATIONS[..])
                }
            };
            obj.append_section_data(text_sec, jmp_stub, 4);
            for &(offset, addend, kind) in relocations {
                obj.add_relocation(
                    text_sec,
                    self.make_relocation(offset, exp_imp_sym, addend, kind),
                )
                .map_err(|e| Error::other(e.to_string()))?;
            }
        }

        let img_rel = self.machine.img_rel_relocation();

        obj.append_section_data(id7, &[0; 4], 4);
        obj.add_relocation(id7, self.make_relocation(0, head_sym, 0, img_rel))
            .map_err(|e| Error::other(e.to_string()))?;

        let id6_sym = obj.section_symbol(id6);
        let id5_data = if export.no_name {
            [
                export.ordinal as u8,
                (export.ordinal >> 8) as u8,
                0,
                0,
                0,
                0,
                0,
                0x80,
            ]
        } else {
            obj.add_relocation(id5, self.make_relocation(0, id6_sym, 0, img_rel))
                .map_err(|e| Error::other(e.to_string()))?;
            [0; 8]
        };
        obj.append_section_data(id5, &id5_data, 4);

        let id4_data = if export.no_name {
            [
                export.ordinal as u8,
                (export.ordinal >> 8) as u8,
                0,
                0,
                0,
                0,
                0,
                0x80,
            ]
        } else {
            obj.add_relocation(id4, self.make_relocation(0, id6_sym, 0, img_rel))
                .map_err(|e| Error::other(e.to_string()))?;
            [0; 8]
        };
        obj.append_section_data(id4, &id4_data, 4);

        if !export.no_name {
            // Remove i386 mangling added by the def parser.
            let export_name = match self.machine {
                MachineType::I386 => export.name.strip_prefix("_").unwrap(),
                _ => &export.name,
            };
            let len = 2 + export_name.len() + 1;
            let mut id6_data = vec![0; len];
            let ord = export.ordinal;
            id6_data[0] = ord as u8;
            id6_data[1] = (ord >> 8) as u8;
            id6_data[2..len - 1].copy_from_slice(export_name.as_bytes());
            obj.append_section_data(id6, &id6_data, 2);
        }

        let name = format!("{}_s{:05}.o", self.output_name.replace('.', "_"), self.seq);
        self.seq += 1;

        Ok(ArchiveMember {
            name,
            data: obj.write().map_err(|e| Error::other(e.to_string()))?,
            symbols: archive_symbols,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_gnu_with_bad_input() {
        let import_lib = GnuImportLibrary::new(
            ModuleDef::parse("EXPORTS D\u{c}\0", MachineType::AMD64).unwrap(),
            MachineType::AMD64,
        );
        import_lib
            .write_to(&mut Cursor::new(Vec::new()))
            .unwrap_err();
    }

    /// Regression test for the i386 jump-stub relocation. The `ff 25 disp32`
    /// instruction is an absolute indirect jump on i386, so the disp32 must
    /// be patched with the absolute VA of the IAT entry. This requires
    /// `IMAGE_REL_I386_DIR32` (not `_REL32`), an addend of 0 (encoded as a
    /// zero in the section data, since COFF has no explicit addend field),
    /// and the relocation must point at the `__imp__<name>` symbol.
    #[test]
    fn test_i386_jump_stub_relocation() {
        let mut factory = ObjectFactory::new("foo.dll", MachineType::I386).unwrap();
        let export = ShortExport {
            name: "_bar".to_string(), // i386 names are mangled with a leading underscore
            ext_name: None,
            symbol_name: String::new(),
            alias_target: String::new(),
            ordinal: 0,
            no_name: false,
            data: false,
            private: false,
            constant: false,
        };
        let member = factory.make_one(&export).unwrap();
        let coff = &member.data[..];

        // --- Parse COFF file header (20 bytes) ---
        let machine = u16::from_le_bytes(coff[0..2].try_into().unwrap());
        let nsections = u16::from_le_bytes(coff[2..4].try_into().unwrap()) as usize;
        let sym_table_ptr = u32::from_le_bytes(coff[8..12].try_into().unwrap()) as usize;
        let nsymbols = u32::from_le_bytes(coff[12..16].try_into().unwrap()) as usize;
        assert_eq!(machine, IMAGE_FILE_MACHINE_I386);

        // --- Walk section table to find .text ---
        let sec_start = 20;
        let mut text_raw_ptr = 0usize;
        let mut text_raw_size = 0usize;
        let mut text_reloc_ptr = 0usize;
        let mut text_nreloc = 0usize;
        for i in 0..nsections {
            let off = sec_start + i * 40;
            let name = &coff[off..off + 8];
            let trimmed_end = name.iter().position(|&b| b == 0).unwrap_or(8);
            if &name[..trimmed_end] == b".text" {
                text_raw_size =
                    u32::from_le_bytes(coff[off + 16..off + 20].try_into().unwrap()) as usize;
                text_raw_ptr =
                    u32::from_le_bytes(coff[off + 20..off + 24].try_into().unwrap()) as usize;
                text_reloc_ptr =
                    u32::from_le_bytes(coff[off + 24..off + 28].try_into().unwrap()) as usize;
                text_nreloc =
                    u16::from_le_bytes(coff[off + 32..off + 34].try_into().unwrap()) as usize;
                break;
            }
        }
        assert_ne!(text_raw_ptr, 0, ".text section not found");

        // --- Verify .text contents are the i386 jump stub ---
        let text = &coff[text_raw_ptr..text_raw_ptr + text_raw_size];
        assert_eq!(
            text,
            &JMP_IX86_BYTES[..],
            ".text should contain `ff 25 00 00 00 00 90 90`"
        );
        // The disp32 field at offset 2 is the implicit addend; must be 0.
        let implicit_addend = u32::from_le_bytes(text[2..6].try_into().unwrap());
        assert_eq!(implicit_addend, 0, "disp32 (implicit addend) must be 0");

        // --- Verify the .text relocation: offset 2, IMAGE_REL_I386_DIR32 ---
        assert_eq!(text_nreloc, 1, ".text should have exactly one relocation");
        let rel = &coff[text_reloc_ptr..text_reloc_ptr + 10];
        let rel_va = u32::from_le_bytes(rel[0..4].try_into().unwrap());
        let sym_idx = u32::from_le_bytes(rel[4..8].try_into().unwrap()) as usize;
        let rel_type = u16::from_le_bytes(rel[8..10].try_into().unwrap());
        assert_eq!(rel_va, 2, "relocation must patch disp32 at offset 2");
        assert_eq!(
            rel_type, IMAGE_REL_I386_DIR32,
            "i386 thunk must use absolute DIR32 (got 0x{:x}); REL32 here would silently \
             produce thunks that fault on the first call",
            rel_type
        );

        // --- Verify the relocation targets `__imp__bar` ---
        // Each COFF symbol record is 18 bytes. Name: either inline 8 bytes
        // or {0,0,0,0, offset_into_string_table_u32}.
        let sym_off = sym_table_ptr + sym_idx * 18;
        let name_field = &coff[sym_off..sym_off + 8];
        let target_name: Vec<u8> = if name_field[0..4] == [0, 0, 0, 0] {
            let str_off = u32::from_le_bytes(name_field[4..8].try_into().unwrap()) as usize;
            let str_table_off = sym_table_ptr + nsymbols * 18;
            let s = &coff[str_table_off + str_off..];
            s[..s.iter().position(|&b| b == 0).unwrap()].to_vec()
        } else {
            let end = name_field.iter().position(|&b| b == 0).unwrap_or(8);
            name_field[..end].to_vec()
        };
        assert_eq!(
            target_name,
            b"__imp__bar",
            "i386 thunk reloc target must be `__imp__<mangled-name>`; got {:?}",
            std::str::from_utf8(&target_name)
        );
    }

    #[ignore]
    #[test]
    fn debug_head_tail_export() {
        let mut factory = ObjectFactory::new("python39.dll", MachineType::AMD64).unwrap();
        let head = factory.make_head().unwrap();
        std::fs::write("head.o", head.data).unwrap();

        let tail = factory.make_tail().unwrap();
        std::fs::write("tail.o", tail.data).unwrap();

        let export = ShortExport {
            name: "PyAST_CompileEx".to_string(),
            ext_name: None,
            symbol_name: "".to_string(),
            alias_target: "".to_string(),
            ordinal: 0,
            no_name: false,
            data: false,
            private: false,
            constant: false,
        };
        let exp = factory.make_one(&export).unwrap();
        std::fs::write("exp.o", exp.data).unwrap();
    }
}
