use std::io::{Error, Seek, Write};
use std::mem::size_of;

use memoffset::offset_of;
use object::endian::{LittleEndian as LE, U16, U32};
use object::pe::*;
use object::pod::bytes_of;

use crate::def::{ModuleDef, ShortExport};
use crate::{ar, ArchiveMember, MachineType};

const NULL_IMPORT_DESCRIPTOR_SYMBOL_NAME: &str = "__NULL_IMPORT_DESCRIPTOR";

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
    /// The import name is specified as a separate EXPORTAS string in the
    /// import object data.
    ExportAs = IMPORT_OBJECT_NAME_EXPORTAS,
}

/// Mangle a symbol name for ARM64EC.
/// For non-C++ names, prefix with '#'. For C++ names with '?', inserts '$$h'
/// after the qualified name portion. Returns None if the name is already
/// mangled or cannot be mangled.
fn arm64ec_mangle_name(name: &str) -> Option<String> {
    if name.starts_with('#') {
        return None;
    }
    if !name.starts_with('?') {
        return Some(format!("#{}", name));
    }
    if name.contains("$$h") {
        return None;
    }
    // C++ MD5-mangled: ??@hash@ → ??@hash@$$h@
    if name.starts_with("??@") && name.ends_with('@') {
        return Some(format!("{}$$h@", name));
    }
    // General C++ mangled names: find the insertion point and insert $$h
    let insert_idx = find_arm64ec_insertion_point(name)?;
    let mut result = String::with_capacity(name.len() + 3);
    result.push_str(&name[..insert_idx]);
    result.push_str("$$h");
    result.push_str(&name[insert_idx..]);
    Some(result)
}

/// Find the byte offset in an MSVC-mangled C++ name where '$$h' should be
/// inserted. This is right after the fully qualified name (after the '@@'
/// terminator), before the function encoding (calling convention, return
/// type, parameters).
///
/// This is a lightweight reimplementation of LLVM's
/// `getArm64ECInsertionPointInMangledName` which uses the MSVC demangler
/// to parse past the qualified name.
fn find_arm64ec_insertion_point(name: &str) -> Option<usize> {
    let b = name.as_bytes();
    if b.first() != Some(&b'?') {
        return None;
    }
    // Skip the leading '?' — the rest is the unqualified symbol name
    // followed by the scope chain terminated by '@'.
    let mut pos = 1;

    // Parse the unqualified symbol name (the leaf identifier)
    pos = skip_unqualified_name(b, pos)?;

    // Parse the scope chain: each scope component is terminated by '@',
    // and the entire chain is terminated by an additional '@' (so '@@').
    pos = skip_name_scope_chain(b, pos)?;

    Some(pos)
}

/// Skip past an unqualified symbol name starting at `pos`.
/// Handles: backrefs (digit), template instantiations (?$...),
/// special function identifiers (?...), and simple names (...@).
fn skip_unqualified_name(b: &[u8], pos: usize) -> Option<usize> {
    if pos >= b.len() {
        return None;
    }
    match b[pos] {
        b'0'..=b'9' => Some(pos + 1), // back-reference
        b'?' if b.get(pos + 1) == Some(&b'$') => skip_template_instantiation(b, pos),
        b'?' => skip_special_identifier(b, pos + 1),
        _ => skip_simple_name(b, pos), // plain name, ends at '@'
    }
}

/// Skip a simple name terminated by '@'.
fn skip_simple_name(b: &[u8], pos: usize) -> Option<usize> {
    let end = memchr::memchr(b'@', &b[pos..])?;
    Some(pos + end + 1)
}

/// Skip a template instantiation: ?$Name@TemplateArgs@
fn skip_template_instantiation(b: &[u8], pos: usize) -> Option<usize> {
    // Skip '?$'
    let mut p = pos + 2;
    // Skip the template name (simple name up to '@')
    p = skip_simple_name(b, p)?;
    // Skip template arguments — each argument is a type/value encoding.
    // Arguments are terminated by a final '@'.
    p = skip_template_args(b, p)?;
    Some(p)
}

/// Skip template arguments until we hit the terminating '@'.
/// Template args can contain nested names, templates, and types.
fn skip_template_args(b: &[u8], mut pos: usize) -> Option<usize> {
    let mut depth = 1u32;
    while pos < b.len() {
        match b[pos] {
            b'@' => {
                pos += 1;
                depth -= 1;
                if depth == 0 {
                    return Some(pos);
                }
            }
            b'?' if b.get(pos + 1) == Some(&b'$') => {
                // Nested template — increase depth
                pos += 2;
                pos = skip_simple_name(b, pos)?;
                depth += 1;
            }
            _ => {
                pos += 1;
            }
        }
    }
    None
}

/// Skip a special function identifier (operator, ctor, dtor, etc.).
/// These start after the leading '?' and consist of one or more code chars.
fn skip_special_identifier(b: &[u8], mut pos: usize) -> Option<usize> {
    if pos >= b.len() {
        return None;
    }
    match b[pos] {
        // ??0 = ctor, ??1 = dtor, ??_G = scalar deleting dtor, etc.
        b'?' => {
            pos += 1;
            if pos < b.len() && b[pos] == b'_' {
                pos += 1; // skip '_'
            }
            if pos < b.len() {
                pos += 1; // skip the code char
            }
            Some(pos)
        }
        b'0'..=b'9' => Some(pos + 1), // ?0 = ctor, ?1 = dtor
        b'A'..=b'Z' => Some(pos + 1), // operator codes ?A through ?Z
        b'_' => {
            pos += 1;
            if pos < b.len() {
                pos += 1; // skip code char after _
            }
            Some(pos)
        }
        _ => Some(pos),
    }
}

/// Skip the name scope chain. Each scope piece is consumed until
/// we hit a bare '@' which terminates the chain (forming '@@' with
/// the previous scope terminator or the end of the unqualified name).
fn skip_name_scope_chain(b: &[u8], mut pos: usize) -> Option<usize> {
    while pos < b.len() {
        if b[pos] == b'@' {
            // This '@' terminates the scope chain
            return Some(pos + 1);
        }
        pos = skip_name_scope_piece(b, pos)?;
    }
    None
}

/// Skip a single scope piece: backref, template, anonymous namespace,
/// locally-scoped name, or simple name.
fn skip_name_scope_piece(b: &[u8], pos: usize) -> Option<usize> {
    if pos >= b.len() {
        return None;
    }
    match b[pos] {
        b'0'..=b'9' => Some(pos + 1), // back-reference
        b'?' if b.get(pos + 1) == Some(&b'$') => skip_template_instantiation(b, pos),
        b'?' if b.get(pos + 1) == Some(&b'A') => {
            // Anonymous namespace: ?A<hex>@ — skip ?A then find @
            skip_simple_name(b, pos + 1)
        }
        b'?' => {
            // Locally-scoped name: ?<number>? prefix, then recurse
            let mut p = pos + 1;
            // Skip digits
            while p < b.len() && b[p].is_ascii_digit() {
                p += 1;
            }
            // Skip '?'
            if p < b.len() && b[p] == b'?' {
                p += 1;
            }
            // The rest is a nested qualified name; skip its unqualified part
            p = skip_unqualified_name(b, p)?;
            // Skip its scope chain
            p = skip_name_scope_chain(b, p)?;
            Some(p)
        }
        _ => skip_simple_name(b, pos),
    }
}

impl MachineType {
    fn is_32bit(&self) -> bool {
        matches!(self, Self::ARMNT | Self::I386)
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
    /// Create new import library generator from `ModuleDef`. For ARM64X,
    /// `native_def` carries the pure-ARM64 exports; for other machine types
    /// it should be `None`.
    pub fn new(mut def: ModuleDef, native_def: Option<ModuleDef>, machine: MachineType) -> Self {
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
        MsvcImportLibrary {
            def,
            native_def,
            machine,
        }
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

    /// Write out the import library
    pub fn write_to<W: Write + Seek>(&self, writer: &mut W) -> Result<(), Error> {
        let mut members: Vec<((ar::Header, ArchiveMember), MemberKind)> = Vec::new();
        let factory = ObjectFactory::new(&self.def.import_name, self.machine);

        let import_descriptor = factory.create_import_descriptor();
        members.push((
            import_descriptor.create_archive_entry(),
            MemberKind::Descriptor,
        ));

        let null_import_descriptor = factory.create_null_import_descriptor();
        members.push((
            null_import_descriptor.create_archive_entry(),
            MemberKind::Descriptor,
        ));

        let null_thunk = factory.create_null_thunk();
        members.push((null_thunk.create_archive_entry(), MemberKind::Descriptor));

        // Emit the primary export list. For ARM64EC and ARM64X this uses the
        // EC machine type and EC name mangling. ARM64X is normalized to
        // ARM64EC for the short-import header machine field, matching
        // llvm-lib's behavior.
        let ec_machine = if self.machine == MachineType::ARM64X {
            MachineType::ARM64EC
        } else {
            self.machine
        };
        self.add_exports(
            &factory,
            &self.def.exports,
            ec_machine,
            MemberKind::Ec,
            &mut members,
        )?;

        // ARM64X: also emit the pure-ARM64 native exports.
        if self.machine == MachineType::ARM64X {
            if let Some(native_def) = &self.native_def {
                self.add_exports(
                    &factory,
                    &native_def.exports,
                    MachineType::ARM64,
                    MemberKind::Native,
                    &mut members,
                )?;
            }
        }

        let identifiers = members
            .iter()
            .map(|((header, _), _)| header.identifier().to_vec())
            .collect();

        if self.machine.is_ec() {
            // ARM64EC / ARM64X: split symbols between the regular and EC
            // symbol tables based on each member's kind.
            let mut regular_symbol_table: Vec<Vec<Vec<u8>>> = Vec::with_capacity(members.len());
            let mut ec_symbol_table: Vec<Vec<Vec<u8>>> = Vec::with_capacity(members.len());

            for ((_, member), kind) in &members {
                let syms: Vec<Vec<u8>> = member
                    .symbols
                    .iter()
                    .map(|s| s.to_string().into_bytes())
                    .collect();

                match kind {
                    MemberKind::Descriptor => {
                        regular_symbol_table.push(syms.clone());
                        ec_symbol_table.push(syms);
                    }
                    MemberKind::Ec => {
                        regular_symbol_table.push(Vec::new());
                        ec_symbol_table.push(syms);
                    }
                    MemberKind::Native => {
                        regular_symbol_table.push(syms);
                        ec_symbol_table.push(Vec::new());
                    }
                }
            }

            let mut archive = ar::GnuBuilder::new_with_symbol_tables(
                writer,
                true,
                identifiers,
                regular_symbol_table,
                Some(ec_symbol_table),
            )?;
            for ((header, member), _) in members {
                archive.append(&header, &member.data[..])?;
            }
        } else {
            let symbol_table: Vec<Vec<Vec<u8>>> = members
                .iter()
                .map(|((_, member), _)| {
                    member
                        .symbols
                        .iter()
                        .map(|s| s.to_string().into_bytes())
                        .collect::<Vec<Vec<u8>>>()
                })
                .collect();
            let mut archive =
                ar::GnuBuilder::new_with_symbol_table(writer, true, identifiers, symbol_table)?;
            for ((header, member), _) in members {
                archive.append(&header, &member.data[..])?;
            }
        }
        Ok(())
    }

    /// Process a list of exports and append the resulting weak-external and
    /// short-import members into `members`. `machine` is the machine type
    /// stamped into each emitted COFF/short-import header — for ARM64X this
    /// is `ARM64EC` for the primary pass and `ARM64` for the native pass.
    fn add_exports(
        &self,
        factory: &ObjectFactory<'_>,
        exports: &[ShortExport],
        machine: MachineType,
        kind: MemberKind,
        members: &mut Vec<((ar::Header, ArchiveMember), MemberKind)>,
    ) -> Result<(), Error> {
        for export in exports {
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
            let name = if let Some(ext_name) = &export.ext_name {
                replace(sym, &export.name, ext_name)?
            } else {
                sym.to_string()
            };

            // EC machine: mangle code import names and use EXPORTAS.
            // The native ARM64 pass for ARM64X never mangles.
            let (name, name_type, export_name) = if machine.is_ec()
                && matches!(export.import_type(), ImportType::Code)
                && !export.no_name
            {
                if let Some(mangled) = arm64ec_mangle_name(&name) {
                    (mangled, ImportNameType::ExportAs, Some(name))
                } else {
                    (name, name_type, None)
                }
            } else {
                (name, name_type, None)
            };

            if !export.alias_target.is_empty() && name != export.alias_target {
                let weak_non_imp =
                    factory.create_weak_external(&export.alias_target, &name, false, machine);
                members.push((weak_non_imp.create_archive_entry(), kind));

                let weak_imp =
                    factory.create_weak_external(&export.alias_target, &name, true, machine);
                members.push((weak_imp.create_archive_entry(), kind));
            }
            let short_import = factory.create_short_import(
                &name,
                export.ordinal,
                export.import_type(),
                name_type,
                export_name.as_deref(),
                machine,
            );
            members.push((short_import.create_archive_entry(), kind));
        }
        Ok(())
    }
}

// Categorizes an archive member so its symbols can be routed to the
// correct symbol table when emitting an ARM64EC / ARM64X archive.
#[derive(Clone, Copy, PartialEq)]
enum MemberKind {
    /// Descriptor object (always native ARM64 for EC); symbols are
    /// duplicated into both the regular and EC symbol tables.
    Descriptor,
    /// EC short-import / weak-external member; symbols go into the
    /// EC symbol table only.
    Ec,
    /// Native ARM64 short-import / weak-external member for ARM64X;
    /// symbols go into the regular symbol table only.
    Native,
}

fn replace(sym: &str, from: &str, to: &str) -> Result<String, Error> {
    use std::io::ErrorKind;

    match sym.find(from) {
        Some(pos) => return Ok(format!("{}{}{}", &sym[..pos], to, &sym[pos + from.len()..])),
        None => {
            if from.starts_with('_') && to.starts_with('_') {
                if let Some(pos) = sym.find(&from[1..]) {
                    return Ok(format!(
                        "{}{}{}",
                        &sym[..pos],
                        &to[1..],
                        &sym[pos + from.len() - 1..]
                    ));
                }
            }
        }
    }
    Err(Error::new(
        ErrorKind::InvalidInput,
        format!("{}: replacing '{}' with '{}' failed", sym, from, to),
    ))
}

/// Constructs various small object files necessary to support linking
/// symbols imported from a DLL.  The contents are pretty strictly defined and
/// nearly entirely static.  The details of the structures files are defined in
/// WINNT.h and the PE/COFF specification.
#[derive(Debug)]
struct ObjectFactory<'a> {
    /// Machine type for descriptor objects (ARM64 for EC/X targets)
    native_machine: MachineType,
    import_name: &'a str,
    import_descriptor_symbol_name: String,
    null_thunk_symbol_name: String,
}

impl<'a> ObjectFactory<'a> {
    fn new(import_name: &'a str, machine: MachineType) -> Self {
        let library = if import_name.ends_with(".dll") || import_name.ends_with(".exe") {
            &import_name[..import_name.len() - 4]
        } else {
            import_name
        };
        Self {
            native_machine: machine.native_machine(),
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
            buffer.extend(s.as_bytes());
            buffer.push(b'\0');
        }

        // Backfill the length of the table now that it has been computed.
        let size = (buffer.len() - offset) as u32;
        buffer[offset..offset + 4].copy_from_slice(&size.to_le_bytes());
    }

    /// Creates an Import Descriptor.  This is a small object file which contains a
    /// reference to the terminators and contains the library name (entry) for the
    /// import name table.  It will force the linker to construct the necessary
    /// structure to import symbols from the DLL.
    fn create_import_descriptor(&self) -> ArchiveMember {
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
        let characteristics = if self.native_machine.is_32bit() {
            IMAGE_FILE_32BIT_MACHINE
        } else {
            0
        };
        let header = ImageFileHeader {
            machine: U16::new(LE, self.native_machine as u16),
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
            original_first_thunk: U32::new(LE, 0),
            time_date_stamp: U32::new(LE, 0),
            forwarder_chain: U32::new(LE, 0),
            name: U32::new(LE, 0),
            first_thunk: U32::new(LE, 0),
        };
        buffer.extend_from_slice(bytes_of(&import_descriptor));

        let relocation_table = [
            ImageRelocation {
                virtual_address: U32::new(LE, offset_of!(ImageImportDescriptor, name) as _),
                symbol_table_index: U32::new(LE, 2),
                typ: U16::new(LE, self.native_machine.img_rel_relocation()),
            },
            ImageRelocation {
                virtual_address: U32::new(
                    LE,
                    offset_of!(ImageImportDescriptor, original_first_thunk) as _,
                ),
                symbol_table_index: U32::new(LE, 3),
                typ: U16::new(LE, self.native_machine.img_rel_relocation()),
            },
            ImageRelocation {
                virtual_address: U32::new(LE, offset_of!(ImageImportDescriptor, first_thunk) as _),
                symbol_table_index: U32::new(LE, 4),
                typ: U16::new(LE, self.native_machine.img_rel_relocation()),
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
                value: U32::new(LE, 0),
                section_number: U16::new(LE, 1),
                typ: U16::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_EXTERNAL,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'2'],
                value: U32::new(LE, 0),
                section_number: U16::new(LE, 1),
                typ: U16::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_SECTION,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'6'],
                value: U32::new(LE, 0),
                section_number: U16::new(LE, 2),
                typ: U16::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_STATIC,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'4'],
                value: U32::new(LE, 0),
                section_number: U16::new(LE, 0),
                typ: U16::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_SECTION,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [b'.', b'i', b'd', b'a', b't', b'a', b'$', b'5'],
                value: U32::new(LE, 0),
                section_number: U16::new(LE, 0),
                typ: U16::new(LE, 0),
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
                value: U32::new(LE, 0),
                section_number: U16::new(LE, 0),
                typ: U16::new(LE, 0),
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
                value: U32::new(LE, 0),
                section_number: U16::new(LE, 0),
                typ: U16::new(LE, 0),
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
            name: self.import_name.to_string(),
            data: buffer,
            symbols: vec![self.import_descriptor_symbol_name.to_string()],
        }
    }

    /// Creates a NULL import descriptor.  This is a small object file whcih
    /// contains a NULL import descriptor.  It is used to terminate the imports
    /// from a specific DLL.
    fn create_null_import_descriptor(&self) -> ArchiveMember {
        const NUM_SECTIONS: usize = 1;
        const NUM_SYMBOLS: usize = 1;

        let mut buffer = Vec::new();

        let pointer_to_symbol_table = size_of::<ImageFileHeader>()
            + NUM_SECTIONS * size_of::<ImageSectionHeader>()
            // .idata$3
            + size_of::<ImageImportDescriptor>();
        let characteristics = if self.native_machine.is_32bit() {
            IMAGE_FILE_32BIT_MACHINE
        } else {
            0
        };
        let header = ImageFileHeader {
            machine: U16::new(LE, self.native_machine as u16),
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
            original_first_thunk: U32::new(LE, 0),
            time_date_stamp: U32::new(LE, 0),
            forwarder_chain: U32::new(LE, 0),
            name: U32::new(LE, 0),
            first_thunk: U32::new(LE, 0),
        };
        buffer.extend_from_slice(bytes_of(&import_descriptor));

        // Symbol Table
        let symbol_table = ImageSymbol {
            name: [0, 0, 0, 0, size_of::<u32>() as _, 0, 0, 0],
            value: U32::new(LE, 0),
            section_number: U16::new(LE, 1),
            typ: U16::new(LE, 0),
            storage_class: IMAGE_SYM_CLASS_EXTERNAL,
            number_of_aux_symbols: 0,
        };
        buffer.extend_from_slice(bytes_of(&symbol_table));

        Self::write_string_table(&mut buffer, &[NULL_IMPORT_DESCRIPTOR_SYMBOL_NAME]);
        ArchiveMember {
            name: self.import_name.to_string(),
            data: buffer,
            symbols: vec![NULL_IMPORT_DESCRIPTOR_SYMBOL_NAME.to_string()],
        }
    }

    /// Create a NULL Thunk Entry.  This is a small object file which contains a
    /// NULL Import Address Table entry and a NULL Import Lookup Table Entry.  It
    /// is used to terminate the IAT and ILT.
    fn create_null_thunk(&self) -> ArchiveMember {
        const NUM_SECTIONS: usize = 2;
        const NUM_SYMBOLS: usize = 1;

        let mut buffer = Vec::new();

        let va_size = if self.native_machine.is_32bit() { 4 } else { 8 };
        let pointer_to_symbol_table = size_of::<ImageFileHeader>()
            + NUM_SECTIONS * size_of::<ImageSectionHeader>()
            // .idata$5
            + va_size
            // .idata$4
            + va_size;
        let characteristics = if self.native_machine.is_32bit() {
            IMAGE_FILE_32BIT_MACHINE
        } else {
            0
        };
        let header = ImageFileHeader {
            machine: U16::new(LE, self.native_machine as u16),
            number_of_sections: U16::new(LE, NUM_SECTIONS as u16),
            time_date_stamp: U32::new(LE, 0),
            pointer_to_symbol_table: U32::new(LE, pointer_to_symbol_table as u32),
            number_of_symbols: U32::new(LE, NUM_SYMBOLS as u32),
            size_of_optional_header: U16::new(LE, 0),
            characteristics: U16::new(LE, characteristics),
        };
        buffer.extend_from_slice(bytes_of(&header));

        // Section Header Table
        let align = if self.native_machine.is_32bit() {
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
        if !self.native_machine.is_32bit() {
            buffer.extend(0u32.to_le_bytes());
        }

        // .idata$4, IAT
        buffer.extend(0u32.to_le_bytes());
        if !self.native_machine.is_32bit() {
            buffer.extend(0u32.to_le_bytes());
        }

        // Symbol Table
        let symbol_table = ImageSymbol {
            name: [0, 0, 0, 0, size_of::<u32>() as _, 0, 0, 0],
            value: U32::new(LE, 0),
            section_number: U16::new(LE, 1),
            typ: U16::new(LE, 0),
            storage_class: IMAGE_SYM_CLASS_EXTERNAL,
            number_of_aux_symbols: 0,
        };
        buffer.extend_from_slice(bytes_of(&symbol_table));

        Self::write_string_table(&mut buffer, &[&self.null_thunk_symbol_name]);
        ArchiveMember {
            name: self.import_name.to_string(),
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
        export_name: Option<&str>,
        machine: MachineType,
    ) -> ArchiveMember {
        // +2 for NULs of sym and import_name, +1 for optional export_name NUL
        let export_name_size = export_name.map(|n| n.len() + 1).unwrap_or(0);
        let import_name_size = self.import_name.len() + sym.len() + 2 + export_name_size;
        let size = size_of::<ImportObjectHeader>() + import_name_size;
        let mut buffer = Vec::with_capacity(size);

        // Write short import header
        let import_header = ImportObjectHeader {
            sig1: U16::new(LE, 0),
            sig2: U16::new(LE, 0xFFFF),
            version: U16::new(LE, 0),
            machine: U16::new(LE, machine as _),
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

        // Determine archive symbols
        let is_ec = machine.is_ec();
        let symbols = if is_ec && matches!(import_type, ImportType::Code) {
            // ARM64EC code: expose demangled __imp_, demangled thunk,
            // __imp_aux_, and raw EC thunk symbol. The "demangled" name is
            // the original (pre-mangling) export_name when present (covers
            // C++ `$$h` insertion which leaves no `#` prefix), otherwise
            // strip a leading `#` from `sym`.
            let demangled = export_name.unwrap_or_else(|| sym.strip_prefix('#').unwrap_or(sym));
            let mut syms = vec![
                format!("__imp_{}", demangled),
                demangled.to_string(),
                format!("__imp_aux_{}", demangled),
                sym.to_string(),
            ];
            // Deduplicate while preserving order (e.g. when sym == demangled).
            let mut seen = std::collections::HashSet::new();
            syms.retain(|s| seen.insert(s.clone()));
            syms
        } else if matches!(import_type, ImportType::Data) {
            vec![format!("__imp_{}", sym)]
        } else {
            vec![format!("__imp_{}", sym), sym.to_string()]
        };

        // Write symbol name and DLL name
        buffer.extend(sym.as_bytes());
        buffer.push(b'\0');
        buffer.extend(self.import_name.as_bytes());
        buffer.push(b'\0');

        // Write EXPORTAS name if present
        if let Some(export_name) = export_name {
            buffer.extend(export_name.as_bytes());
            buffer.push(b'\0');
        }

        ArchiveMember {
            name: self.import_name.to_string(),
            data: buffer,
            symbols,
        }
    }

    /// Create a weak external file which is described in PE/COFF Aux Format 3.
    fn create_weak_external(
        &self,
        sym: &str,
        weak: &str,
        imp: bool,
        machine: MachineType,
    ) -> ArchiveMember {
        const NUM_SECTIONS: usize = 1;
        const NUM_SYMBOLS: usize = 5;

        let mut buffer = Vec::new();

        let pointer_to_symbol_table =
            size_of::<ImageFileHeader>() + NUM_SECTIONS * size_of::<ImageSectionHeader>();
        let header = ImageFileHeader {
            machine: U16::new(LE, machine as u16),
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
                value: U32::new(LE, 0),
                section_number: U16::new(LE, 0xFFFF),
                typ: U16::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_STATIC,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [b'@', b'f', b'e', b'a', b't', b'.', b'0', b'0'],
                value: U32::new(LE, 0),
                section_number: U16::new(LE, 0xFFFF),
                typ: U16::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_STATIC,
                number_of_aux_symbols: 0,
            },
            ImageSymbol {
                name: [0, 0, 0, 0, size_of::<u32>() as _, 0, 0, 0],
                value: U32::new(LE, 0),
                section_number: U16::new(LE, 0),
                typ: U16::new(LE, 0),
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
                value: U32::new(LE, 0),
                section_number: U16::new(LE, 0),
                typ: U16::new(LE, 0),
                storage_class: IMAGE_SYM_CLASS_WEAK_EXTERNAL,
                number_of_aux_symbols: 1,
            },
            ImageSymbol {
                name: [2, 0, 0, 0, IMAGE_WEAK_EXTERN_SEARCH_ALIAS as u8, 0, 0, 0],
                value: U32::new(LE, 0),
                section_number: U16::new(LE, 0),
                typ: U16::new(LE, 0),
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
            name: self.import_name.to_string(),
            data: buffer,
            symbols: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm64ec_mangle_name() {
        // Plain C names get '#' prefix
        assert_eq!(arm64ec_mangle_name("foo"), Some("#foo".into()));
        assert_eq!(
            arm64ec_mangle_name("PyInit_mod"),
            Some("#PyInit_mod".into())
        );

        // Already mangled → None
        assert_eq!(arm64ec_mangle_name("#foo"), None);
        assert_eq!(arm64ec_mangle_name("?func@@$$hYAHXZ"), None);

        // MD5-hashed C++ names
        assert_eq!(
            arm64ec_mangle_name("??@abc123@"),
            Some("??@abc123@$$h@".into())
        );

        // C++ mangled names: $$h inserted after qualified name
        let cases = [
            ("?func@@YAHXZ", "?func@@$$hYAHXZ"),
            ("?Method@Class@@QEAAHXZ", "?Method@Class@@$$hQEAAHXZ"),
            ("?func@NS1@NS2@@YAHXZ", "?func@NS1@NS2@@$$hYAHXZ"),
            ("??0Class@@QEAA@XZ", "??0Class@@$$hQEAA@XZ"),
            ("??1Class@@UEAA@XZ", "??1Class@@$$hUEAA@XZ"),
            ("??HClass@@QEAAHH@Z", "??HClass@@$$hQEAAHH@Z"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                arm64ec_mangle_name(input),
                Some(expected.into()),
                "input: {input}"
            );
        }
    }
}
