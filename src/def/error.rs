use std::error;
use std::fmt;

/// Error type for parsing module definition
#[derive(Debug, Clone)]
pub enum Error {
    UnknownDirective(String),
    ExpectedIdentifier,
    ExpectedInteger,
    ExpectedEqual,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnknownDirective(ref s) => write!(f, "unknown directive: {}", s),
            Error::ExpectedIdentifier => write!(f, "expected identifier token"),
            Error::ExpectedInteger => write!(f, "expected integer"),
            Error::ExpectedEqual => write!(f, "expected equal token"),
        }
    }
}

impl error::Error for Error {}
