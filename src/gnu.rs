use std::io::{Error, ErrorKind, Seek, Write};

use object::pe::*;
use object::write::{Mangling, Object, Relocation, Symbol, SymbolId, SymbolSection};
use object::{
    BinaryFormat, Endianness, SectionFlags, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

use crate::def::{ModuleDef, ShortExport};
use crate::{ar, ArchiveMember, MachineType};

const JMP_IX86_BYTES: [u8; 8] = [0xff, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90];
const JMP_ARM_BYTES: [u8; 12] = [
    0x00, 0xc0, 0x9f, 0xe5, /* ldr  ip, [pc] */
    0x00, 0xf0, 0x9c, 0xe5, /* ldr  pc, [ip] */
    0, 0, 0, 0,
];

impl MachineType {
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
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        obj.add_relocation(id2, self.make_relocation(16, id5_sym, 0, img_rel))
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

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
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        Ok(ArchiveMember {
            name: format!("{}_h.o", self.output_name.replace('.', "_")),
            data: obj
                .write()
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?,
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
        obj.section_mut(id4).flags = SectionFlags::Coff {
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
            data: obj
                .write()
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?,
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
            characteristics: IMAGE_SCN_ALIGN_4BYTES | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        };
        let id5 = obj.add_section(Vec::new(), b".idata$5".to_vec(), SectionKind::Data);
        obj.section_mut(id5).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        };
        let id4 = obj.add_section(Vec::new(), b".idata$4".to_vec(), SectionKind::Data);
        obj.section_mut(id4).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_4BYTES | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        };
        let id6 = obj.add_section(Vec::new(), b".idata$6".to_vec(), SectionKind::Data);
        obj.section_mut(id6).flags = SectionFlags::Coff {
            characteristics: IMAGE_SCN_ALIGN_2BYTES | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
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
            let (jmp_stub, offset, rel_kind) = match self.machine {
                MachineType::I386 => (&JMP_IX86_BYTES[..], 2, IMAGE_REL_I386_REL32),
                MachineType::ARMNT => (&JMP_ARM_BYTES[..], 8, IMAGE_REL_ARM_REL32),
                MachineType::AMD64 => (&JMP_IX86_BYTES[..], 2, IMAGE_REL_AMD64_REL32),
                MachineType::ARM64 => (&JMP_ARM_BYTES[..], 8, IMAGE_REL_ARM64_REL32),
            };
            obj.append_section_data(text_sec, jmp_stub, 4);
            obj.add_relocation(
                text_sec,
                self.make_relocation(offset, exp_imp_sym, 0, rel_kind),
            )
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        }

        let img_rel = self.machine.img_rel_relocation();

        obj.append_section_data(id7, &[0; 4], 4);
        obj.add_relocation(id7, self.make_relocation(0, head_sym, 0, img_rel))
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

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
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
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
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
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
            data: obj
                .write()
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?,
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
