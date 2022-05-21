use implib::{ImportLibrary, MachineType};

#[test]
fn test_import_library() {
    let import_lib = ImportLibrary::new(include_str!("python39.def"), MachineType::AMD64).unwrap();
    let mut lib = std::fs::File::create("python39.lib").unwrap();
    import_lib.write_to(&mut lib).unwrap();
}
