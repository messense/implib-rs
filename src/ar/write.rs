#![allow(clippy::write_with_newline)]

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::io::{self, Error, ErrorKind, Read, Result, Seek, Write};

use super::*;
use crate::{bail, ensure, err};

// ========================================================================= //

impl Header {
    fn write_gnu<W>(
        &self,
        deterministic: bool,
        writer: &mut W,
        names: &HashMap<Vec<u8>, usize>,
    ) -> Result<()>
    where
        W: Write,
    {
        self.validate()?;
        if self.identifier.len() > 15 {
            let offset = names[&self.identifier];
            write!(writer, "/{:<15}", offset)?;
        } else {
            writer.write_all(&self.identifier)?;
            writer.write_all(b"/")?;
            writer.write_all(&vec![b' '; 15 - self.identifier.len()])?;
        }

        if deterministic {
            write!(
                writer,
                "{:<12}{:<6}{:<6}{:<8o}{:<10}`\n",
                0, 0, 0, 0o644, self.size
            )?;
        } else {
            write!(
                writer,
                "{:<12}{:<6}{:<6}{:<8o}{:<10}`\n",
                self.mtime, self.uid, self.gid, self.mode, self.size
            )?;
        }

        Ok(())
    }
}
// ========================================================================= //

/// Builder for GNU archive format
///
/// # TL;DR
/// The GNU format is a backwards incompatible archive format that diverges from the legacy Unix
/// archive format in the following significant ways:
///
/// 1) It can contain a binary symbol table that needs to be the first member of the archive.
///    This table can contain either 32bit or 64bit offsets pointing to the entities that symbols
///    relate to.
///
///    Unlike the BSD tables the GNU tables are _somewhat_ more formally defined and are simpler in
///    construction.
///
/// 2) The handling of extended strings is done with a string lookup table (either as the first of
///    second member) which is little more than a large string array.
///
/// 3) Extensions exist to create a rare format known as a thin-archive.
///
/// 4) GNU archives have a formal [deterministic mode](#deterministic-archives) that is important
///    for build systems and toolchains.
///
/// Most tools outside of BSD targets tend to use GNU format as the defacto standard, and it is
/// well-supported by LLVM and GNU toolchains. More subtle variants of this format exist such as
/// the unimplemented Microsoft extended ECOFF archive.
///
/// # Layout
/// Except where indicated, the metadata for the archive is typically encoded as ascii strings. All
/// ascii strings in an archive are padded to the length of the given field with ascii space `0x20`
/// as the fill value. This gives an archive a general fixed format look if opened in a text
/// editor.
///
/// Data is emplaced inline directly after a header record, no manipulations are done on data
/// stored in an archive, and there are no restrictions on what data can be stored in an archive.
/// Data might have a padding character (`\n`) added if the entity would be on an odd byte
/// boundary, but this is purely an internal detail of the format and not visible in any metadata.
///
/// **Header**
///
/// | Section         | Type                |
/// |-----------------|---------------------|
/// | Magic signature | Literal `!<arch>\n` |
///
/// **Entity Header**
///
/// | Section | Type           | Notes                                                                                            |
/// |---------|----------------|--------------------------------------------------------------------------------------------------|
/// | Name    | `[u8; 16]`     | Gnu handles strings in a manner that _effectively_ reduces this to 15 bytes                      |
/// | MTime   | `[u8; 12]`     | Seconds since the Unix epoch. Often `0` as per [deterministic archives](#deterministic-archives) |
/// | Uid     | `[u8; 6]`      | Unix plain user id. Often `0` as per [deterministic archives](#deterministic-archives)           |
/// | Gid     | `[u8; 6]`      | Unix plain group id. Often `0` as per [deterministic archives](#deterministic-archives)          |
/// | Mode    | `[u8; 8]`      | Unix file mode in Octal. Often `0` as per [deterministic archives](#deterministic-archives)      |
/// | Size    | `[u8; 10]`     | Entity data size in bytes, the size _does not reflect_ any padding                               |
/// | End     | Literal `\`\n` | Marks the end of the entity header                                                               |
///
/// **Symbol table (if present)**
///
/// Symbol tables are prepended with an entity header, although most implementations choose to make
/// the header all spaces in contrast to general header format for [deterministic
/// archives](#Deterministic Archives) but with the same general effect.
///
/// The name for the entity for the symbol table is either `//` or `/SYM64/` dependent on if the
/// overall size of the archive crosses the maximum addressable size allowed by 32 bits.
///
/// | Section  | Type              | Notes                                                   |
/// |----------|-------------------|---------------------------------------------------------|
/// | Num syms | `u32` / `u64`     | _Generally_ `u32` but can be `u64` for > 4Gb archives   |
/// | Offsets  | `[u32]` / `[u64]` | Pointer from a symbol to the relevant archive entity    |
/// | Names    | `[c_str]`         | The name of each symbol as a plain C style string array |
///
/// **Extended strings (if present)**
///
/// GNU archives generally encode names inline in the format `/some_name.o/`.
///
/// The bracketed `/` pairing allows GNU archives to contain embedded spaces and other metachars
/// (excluding `/` itself).
///
/// If the name is _greater than_ 15 bytes it is encoded as offset number into a string table. The
/// string table is one of the first few members in the archive and is given as strings separated
/// by the byte sequence `[0x2F, 0x0A]` (or `\\/n` in ascii).
/// No padding is done in the string table itself and the offset written to the entity header is zero
/// based from the start of the string table.
///
/// The entity name for the string table is formatted as `/#offset`, for example, for an extended
/// name starting at offset `4853` the value written to the entity header becomes `/#4853`
///
/// ## Deterministic Archives
/// The existence of several variables in entity headers make the format poorly suited to
/// consistent generation of archives. This confuses toolchains which may interpret frequently
/// changing headers as a change to the overall archive and force needless recomputations.
///
/// As such, a backwards compatible extension exists for GNU archives where all variable fields not
/// directly related to an entities data are set to ascii `0`. This is known as deterministic mode
/// and is common for most modern in use unix archives (the format has long since lost its original
/// duty as a general archive format and is now mostly used for toolchain operations).
pub struct GnuBuilder<W: Write + Seek> {
    writer: W,
    deterministic: bool,
    short_names: HashSet<Vec<u8>>,
    long_names: HashMap<Vec<u8>, usize>,
    symbol_table_relocations: Vec<Vec<u64>>,
    /// File offsets where second linker member's member-offset slots were written.
    second_linker_member_relocs: Vec<u64>,

    /// Number of actual data members (excluding special archive members).
    num_members: usize,
    symbol_index: usize,
}

impl<W: Write + Seek> GnuBuilder<W> {
    /// Create a new archive builder with the underlying writer object as the
    /// destination of all data written.  The `identifiers` parameter must give
    /// the complete list of entry identifiers that will be included in this
    /// archive. `symbol_table` is a per-member list of symbols for the
    /// regular `/` symbol table.
    pub fn new_with_symbol_table(
        writer: W,
        deterministic: bool,
        identifiers: Vec<Vec<u8>>,
        symbol_table: Vec<Vec<Vec<u8>>>,
    ) -> Result<GnuBuilder<W>> {
        Self::new_with_symbol_tables(writer, deterministic, identifiers, symbol_table, None)
    }

    /// Create a new archive builder with both a regular and an EC symbol table.
    /// The `ec_symbol_table` parameter, when `Some`, provides per-member symbols
    /// for the `/<ECSYMBOLS>/` member used by ARM64EC import libraries.
    /// When present, a second linker member (sorted, LE) is also written.
    pub fn new_with_symbol_tables(
        mut writer: W,
        deterministic: bool,
        identifiers: Vec<Vec<u8>>,
        symbol_table: Vec<Vec<Vec<u8>>>,
        ec_symbol_table: Option<Vec<Vec<Vec<u8>>>>,
    ) -> Result<GnuBuilder<W>> {
        let num_members = identifiers.len();
        ensure!(
            symbol_table.len() == num_members,
            "symbol_table length ({}) does not match identifiers length ({})",
            symbol_table.len(),
            num_members
        );
        if let Some(ref ec) = ec_symbol_table {
            ensure!(
                ec.len() == num_members,
                "ec_symbol_table length ({}) does not match identifiers length ({})",
                ec.len(),
                num_members
            );
        }
        let mut short_names = HashSet::<Vec<u8>>::new();
        let mut long_names = HashMap::<Vec<u8>, usize>::new();
        let mut name_table_size: usize = 0;
        for identifier in identifiers.into_iter() {
            let length = identifier.len();
            if length > 15 {
                long_names.insert(identifier, name_table_size);
                name_table_size += length + 2;
            } else {
                short_names.insert(identifier);
            }
        }
        let name_table_needs_padding = !name_table_size.is_multiple_of(2);
        if name_table_needs_padding {
            name_table_size += 3; // ` /\n`
        }

        writer.write_all(GLOBAL_HEADER)?;

        // Write the first linker member (big-endian offsets)
        let mut symbol_table_relocations: Vec<Vec<u64>> = Vec::with_capacity(symbol_table.len());
        if !symbol_table.is_empty() {
            let wordsize = std::mem::size_of::<u32>();
            let symbol_count: usize = symbol_table.iter().map(|symbols| symbols.len()).sum();
            let symbols = symbol_table.iter().flatten();
            let mut symbol_table_size: usize = wordsize
                + wordsize * symbol_count
                + symbols.map(|symbol| symbol.len() + 1).sum::<usize>();
            let symbol_table_needs_padding = !symbol_table_size.is_multiple_of(2);
            if symbol_table_needs_padding {
                symbol_table_size += 3; // ` /\n`
            }

            write!(
                writer,
                "{:<16}{:<12}{:<6}{:<6}{:<8o}{:<10}`\n",
                GNU_SYMBOL_LOOKUP_TABLE_ID, 0, 0, 0, 0, symbol_table_size
            )?;

            writer.write_all(&u32::to_be_bytes(u32::try_from(symbol_count).map_err(
                |_| err!("Too many symbols for 32bit table `{}`", symbol_count),
            )?))?;

            for symbols in &symbol_table {
                let mut sym_rels = Vec::new();
                for _symbol in symbols {
                    sym_rels.push(writer.stream_position()?);
                    writer.write_all(&u32::to_be_bytes(0xcafebabe))?;
                }
                symbol_table_relocations.push(sym_rels);
            }

            for symbol in symbol_table.iter().flatten() {
                writer.write_all(symbol)?;
                writer.write_all(b"\0")?;
            }
            if symbol_table_needs_padding {
                writer.write_all(b" /\n")?;
            }
        }

        // Write second linker member (COFF-specific, LE offsets + u16 member indices)
        // Required when EC symbol table is present.
        let mut second_linker_member_relocs: Vec<u64> = Vec::new();
        if ec_symbol_table.is_some() {
            // Collect all symbols with their member index (1-based) for the
            // second linker member, sorted by name
            let mut sorted_syms: Vec<(Vec<u8>, u16)> = Vec::new();
            for (member_idx, symbols) in symbol_table.iter().enumerate() {
                let idx_u16 = u16::try_from(member_idx + 1)
                    .map_err(|_| err!("Too many archive members for COFF (>65535)"))?;
                for sym in symbols {
                    sorted_syms.push((sym.clone(), idx_u16));
                }
            }
            sorted_syms.sort_by(|a, b| a.0.cmp(&b.0));

            let sym_count = sorted_syms.len();
            // Size: u32 num_members + u32*num_members (offsets)
            //     + u32 num_symbols + u16*num_symbols (indices) + names
            let names_size: usize = sorted_syms.iter().map(|(n, _)| n.len() + 1).sum();
            let mut member2_size: usize = 4 + 4 * num_members + 4 + 2 * sym_count + names_size;
            let member2_needs_padding = !member2_size.is_multiple_of(2);
            if member2_needs_padding {
                member2_size += 1;
            }

            write!(
                writer,
                "{:<16}{:<12}{:<6}{:<6}{:<8o}{:<10}`\n",
                GNU_SYMBOL_LOOKUP_TABLE_ID, 0, 0, 0, 0, member2_size
            )?;

            // Number of members
            writer.write_all(&u32::to_le_bytes(num_members as u32))?;

            // Member offsets (placeholders, backfilled later)
            second_linker_member_relocs = Vec::with_capacity(num_members);
            for _ in 0..num_members {
                second_linker_member_relocs.push(writer.stream_position()?);
                writer.write_all(&u32::to_le_bytes(0xcafebabe))?;
            }

            // Number of symbols
            writer.write_all(&u32::to_le_bytes(sym_count as u32))?;

            // Symbol member indices (u16, 1-based)
            for (_, idx) in &sorted_syms {
                writer.write_all(&u16::to_le_bytes(*idx))?;
            }

            // Symbol names (sorted)
            for (name, _) in &sorted_syms {
                writer.write_all(name)?;
                writer.write_all(b"\0")?;
            }
            if member2_needs_padding {
                writer.write_all(b"\n")?;
            }
        }

        if !long_names.is_empty() {
            write!(
                writer,
                "{:<48}{:<10}`\n",
                GNU_NAME_TABLE_ID, name_table_size
            )?;
            let mut entries: Vec<(usize, &[u8])> = long_names
                .iter()
                .map(|(id, &start)| (start, id.as_slice()))
                .collect();
            entries.sort();
            for (_, id) in entries {
                writer.write_all(id)?;
                writer.write_all(b"/\n")?;
            }
            if name_table_needs_padding {
                writer.write_all(b" /\n")?;
            }
        }

        // Write /<ECSYMBOLS>/ member if provided.
        // Format: u32_le num_symbols, u16_le member_indices[num_symbols], c_str names[]
        if let Some(ec_table) = &ec_symbol_table {
            // Collect symbols with member index (1-based), sorted by name
            let mut sorted_ec_syms: Vec<(Vec<u8>, u16)> = Vec::new();
            for (member_idx, symbols) in ec_table.iter().enumerate() {
                let idx_u16 = u16::try_from(member_idx + 1)
                    .map_err(|_| err!("Too many archive members for COFF (>65535)"))?;
                for sym in symbols {
                    sorted_ec_syms.push((sym.clone(), idx_u16));
                }
            }
            sorted_ec_syms.sort_by(|a, b| a.0.cmp(&b.0));

            let ec_sym_count = sorted_ec_syms.len();
            if ec_sym_count > 0 {
                let ec_names_size: usize = sorted_ec_syms.iter().map(|(n, _)| n.len() + 1).sum();
                let mut ec_table_size: usize = 4 + 2 * ec_sym_count + ec_names_size;
                let ec_table_needs_padding = !ec_table_size.is_multiple_of(2);
                if ec_table_needs_padding {
                    ec_table_size += 1;
                }

                write!(
                    writer,
                    "{:<16}{:<12}{:<6}{:<6}{:<8o}{:<10}`\n",
                    EC_SYMBOL_TABLE_ID, 0, 0, 0, 0, ec_table_size
                )?;

                // Number of symbols
                writer.write_all(&u32::to_le_bytes(ec_sym_count as u32))?;

                // Member indices (u16_le, 1-based)
                for (_, member_idx) in &sorted_ec_syms {
                    writer.write_all(&u16::to_le_bytes(*member_idx))?;
                }

                // Symbol names (sorted)
                for (name, _) in &sorted_ec_syms {
                    writer.write_all(name)?;
                    writer.write_all(b"\0")?;
                }
                if ec_table_needs_padding {
                    writer.write_all(b"\0")?;
                }
            }
        }

        Ok(GnuBuilder {
            writer,
            deterministic,
            short_names,
            long_names,
            symbol_table_relocations,
            second_linker_member_relocs,
            num_members,
            symbol_index: 0,
        })
    }

    /// Adds a new entry to this archive.
    pub fn append<R: Read>(&mut self, header: &Header, mut data: R) -> Result<()> {
        let is_long_name = header.identifier().len() > 15;
        let has_name = if is_long_name {
            self.long_names.contains_key(header.identifier())
        } else {
            self.short_names.contains(header.identifier())
        };

        ensure!(
            has_name,
            "Identifier `{:?}` was not in the list of identifiers passed to GnuBuilder::new()",
            String::from_utf8_lossy(header.identifier())
        );

        let entry_offset = self.writer.stream_position()?;
        let entry_offset_u32 =
            u32::try_from(entry_offset).map_err(|_| err!("Archive larger than 4GB"))?;

        // Backfill first linker member offsets (big-endian)
        if let Some(relocs) = self.symbol_table_relocations.get(self.symbol_index) {
            let entry_offset_bytes = u32::to_be_bytes(entry_offset_u32);
            for &reloc_offset in relocs {
                self.writer.seek(io::SeekFrom::Start(reloc_offset))?;
                self.writer.write_all(&entry_offset_bytes)?;
            }
        }

        // Backfill second linker member offset for this member (little-endian)
        if let Some(&reloc_offset) = self.second_linker_member_relocs.get(self.symbol_index) {
            self.writer.seek(io::SeekFrom::Start(reloc_offset))?;
            self.writer.write_all(&u32::to_le_bytes(entry_offset_u32))?;
        }

        if self.symbol_index < self.num_members {
            self.writer.seek(io::SeekFrom::Start(entry_offset))?;
            self.symbol_index += 1;
        }

        header.write_gnu(self.deterministic, &mut self.writer, &self.long_names)?;
        let actual_size = io::copy(&mut data, &mut self.writer)?;
        if actual_size != header.size() {
            bail!(
                "Wrong file size (header.size() = `{}`, actual = `{}`)",
                header.size(),
                actual_size
            );
        }
        if actual_size % 2 != 0 {
            self.writer.write_all(b"\n")?;
        }

        Ok(())
    }
}
