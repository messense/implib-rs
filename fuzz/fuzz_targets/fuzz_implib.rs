#![no_main]
use std::io::{Cursor, ErrorKind};

use libfuzzer_sys::fuzz_target;
use implib::{ImportLibrary, MachineType, Flavor};

fuzz_target!(|data: &str| {
    let implib = match ImportLibrary::new(data, MachineType::AMD64, Flavor::Msvc) {
        Ok(implib) => implib,
        Err(err) => {
            if err.kind() == ErrorKind::InvalidInput {
                return;
            }
            panic!("{}", err);
        }
    };
    let mut buf = Cursor::new(Vec::new());
    let _ = implib.write_to(&mut buf);

    let implib = match ImportLibrary::new(data, MachineType::AMD64, Flavor::Gnu) {
        Ok(implib) => implib,
        Err(err) => {
            if err.kind() == ErrorKind::InvalidInput {
                return;
            }
            panic!("{}", err);
        }
    };
    let mut buf = Cursor::new(Vec::new());
    let _ = implib.write_to(&mut buf);
});
