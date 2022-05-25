use implib::{Flavor, ImportLibrary, MachineType};

#[cfg(feature = "msvc")]
#[test]
fn test_import_library_msvc() {
    let import_lib = ImportLibrary::new(
        include_str!("python39.def"),
        MachineType::AMD64,
        Flavor::Msvc,
    )
    .unwrap();
    let mut lib = std::fs::File::create("python39.lib").unwrap();
    import_lib.write_to(&mut lib).unwrap();
}

#[cfg(feature = "gnu")]
#[test]
fn test_import_library_gnu() {
    let import_lib = ImportLibrary::new(
        include_str!("python39.def"),
        MachineType::AMD64,
        Flavor::Gnu,
    )
    .unwrap();
    let mut lib = std::fs::File::create("python39.dll.a").unwrap();
    import_lib.write_to(&mut lib).unwrap();
}
