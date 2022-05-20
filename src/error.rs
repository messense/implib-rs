use std::{error, fmt, io};

use crate::def::ModuleDefError;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    ModuleDef(ModuleDefError),
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

impl From<ModuleDefError> for Error {
    fn from(err: ModuleDefError) -> Error {
        Error::ModuleDef(err)
    }
}
