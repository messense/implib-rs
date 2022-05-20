use implib::{def::ModuleDef, ImportLibrary, MachineType};

#[test]
fn test_import_library() {
    let def = ModuleDef::parse(include_str!("python39.def")).unwrap();
    let import_lib = ImportLibrary::from_def(def, MachineType::AMD64);
    let mut lib = std::fs::File::create("python39.lib").unwrap();
    import_lib.write_to(&mut lib).unwrap();
}
