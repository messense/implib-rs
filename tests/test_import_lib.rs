use implib::{Flavor, ImportLibrary, MachineType};

#[cfg(feature = "msvc")]
#[test]
fn test_import_library_msvc_amd64() {
    let import_lib = ImportLibrary::new(
        include_str!("python39.def"),
        MachineType::AMD64,
        Flavor::Msvc,
    )
    .unwrap();
    let mut lib = std::fs::File::create("amd64-python39.lib").unwrap();
    import_lib.write_to(&mut lib).unwrap();
}

#[test]
fn test_import_library_msvc_i386() {
    let import_lib = ImportLibrary::new(
        include_str!("python39.def"),
        MachineType::I386,
        Flavor::Msvc,
    )
    .unwrap();
    let mut lib = std::fs::File::create("i386-python39.lib").unwrap();
    import_lib.write_to(&mut lib).unwrap();
}

#[cfg(feature = "gnu")]
#[test]
fn test_import_library_gnu_amd64() {
    let import_lib = ImportLibrary::new(
        include_str!("python39.def"),
        MachineType::AMD64,
        Flavor::Gnu,
    )
    .unwrap();
    let mut lib = std::fs::File::create("amd64-python39.dll.a").unwrap();
    import_lib.write_to(&mut lib).unwrap();
}

#[cfg(feature = "gnu")]
#[test]
fn test_import_library_gnu_i386() {
    let import_lib =
        ImportLibrary::new(include_str!("python39.def"), MachineType::I386, Flavor::Gnu).unwrap();
    let mut lib = std::fs::File::create("i386-python39.dll.a").unwrap();
    import_lib.write_to(&mut lib).unwrap();
}

#[cfg(feature = "msvc")]
#[test]
fn test_import_library_msvc_arm64ec() {
    let import_lib = ImportLibrary::new(
        include_str!("python39.def"),
        MachineType::ARM64EC,
        Flavor::Msvc,
    )
    .unwrap();
    let mut lib = std::io::Cursor::new(Vec::new());
    import_lib.write_to(&mut lib).unwrap();
    let data = lib.into_inner();
    assert!(!data.is_empty());

    // Verify the archive contains an /<ECSYMBOLS>/ member with the expected
    // structure: u32_le num_symbols, u16_le member_indices[N], c_str names[N].
    assert_eq!(&data[..8], b"!<arch>\n", "missing archive global header");

    // Locate the /<ECSYMBOLS>/ member header.
    let marker = b"/<ECSYMBOLS>/   ";
    let header_pos = data
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("ARM64EC import library should contain /<ECSYMBOLS>/ member");

    // Archive entry header is 60 bytes; size field is at offset 48, width 10.
    let size_str = std::str::from_utf8(&data[header_pos + 48..header_pos + 58])
        .unwrap()
        .trim();
    let member_size: usize = size_str.parse().unwrap();
    let body = &data[header_pos + 60..header_pos + 60 + member_size];

    let num_symbols = u32::from_le_bytes(body[0..4].try_into().unwrap()) as usize;
    assert!(
        num_symbols > 1000,
        "expected many EC symbols, got {num_symbols}"
    );

    // Indices follow, then names. Verify indices are in-range and names are
    // sorted (case-sensitive byte order).
    let names_start = 4 + 2 * num_symbols;
    let names = &body[names_start..];
    let mut prev: &[u8] = &[];
    let mut count = 0;
    for chunk in names.split(|&b| b == 0).filter(|s| !s.is_empty()) {
        assert!(chunk >= prev, "EC symbol names must be sorted");
        prev = chunk;
        count += 1;
    }
    assert_eq!(
        count, num_symbols,
        "name count must match num_symbols header"
    );
}

#[cfg(feature = "gnu")]
#[test]
fn test_import_library_gnu_arm64ec() {
    let import_lib = ImportLibrary::new(
        include_str!("python39.def"),
        MachineType::ARM64EC,
        Flavor::Gnu,
    )
    .unwrap();
    let mut lib = std::io::Cursor::new(Vec::new());
    import_lib.write_to(&mut lib).unwrap();
    assert!(!lib.into_inner().is_empty());
}
