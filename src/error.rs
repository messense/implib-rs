use std::{error, fmt, io};

use crate::def;

/// Error type for generating import library
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    ModuleDef(def::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => err.fmt(f),
            Error::ModuleDef(err) => err.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Io(err) => err.source(),
            Error::ModuleDef(err) => err.source(),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<def::Error> for Error {
    fn from(err: def::Error) -> Error {
        Error::ModuleDef(err)
    }
}
