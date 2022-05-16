use std::error;
use std::fmt;

#[derive(Debug, Clone)]
pub enum ModuleDefError {
    UnknownDirective(String),
    ExpectedIdentifier,
    ExpectedInteger,
    ExpectedEqual,
}

impl fmt::Display for ModuleDefError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ModuleDefError::UnknownDirective(ref s) => write!(f, "unknown directive: {}", s),
            ModuleDefError::ExpectedIdentifier => write!(f, "expected identifier token"),
            ModuleDefError::ExpectedInteger => write!(f, "expected integer"),
            ModuleDefError::ExpectedEqual => write!(f, "expected equal token"),
        }
    }
}

impl error::Error for ModuleDefError {}
