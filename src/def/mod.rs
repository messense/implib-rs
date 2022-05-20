pub use self::error::Error;
use self::parser::Parser;

mod error;
mod parser;

/// Simple .DEF file parser
#[derive(Debug, Clone, Default)]
pub struct ModuleDef {
    pub exports: Vec<ShortExport>,
    pub import_name: String,
    pub image_base: u64,
    pub stack_reserve: u64,
    pub stack_commit: u64,
    pub heap_reserve: u64,
    pub heap_commit: u64,
    pub major_image_version: u32,
    pub minor_image_version: u32,
    pub major_os_version: u32,
    pub minor_os_version: u32,
}

impl ModuleDef {
    pub fn parse(def: &str) -> Result<ModuleDef, Error> {
        Parser::new(def).parse()
    }
}

/// COFF short export
#[derive(Debug, Clone, Default)]
pub struct ShortExport {
    /// The name of the export as specified in the .def file or on the command
    /// line, i.e. "foo" in "/EXPORT:foo", and "bar" in "/EXPORT:foo=bar"
    pub name: String,
    /// The external, exported name. Only non-empty when export renaming is in
    /// effect, i.e. "foo" in "/EXPORT:foo=bar".
    pub ext_name: Option<String>,
    /// The real, mangled symbol name from the object file.
    pub symbol_name: String,
    /// Creates a weak alias. This is the name of the weak aliasee. In a .def
    /// file, this is "baz" in "EXPORTS\nfoo = bar == baz".
    pub alias_target: String,
    pub ordinal: u16,
    pub no_name: bool,
    pub data: bool,
    pub private: bool,
    pub constant: bool,
}
