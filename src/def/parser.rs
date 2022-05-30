use std::io::{Error, ErrorKind};
use std::iter::Peekable;
use std::str::CharIndices;

use super::{ModuleDef, ShortExport};
use crate::MachineType;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    Unknown,
    Eof,
    Identifier,
    Comma,
    Equal,
    EqualEqual,
    KwBase,
    KwConstant,
    KwData,
    KwExports,
    KwHeapsize,
    KwLibrary,
    KwName,
    KwNoname,
    KwPrivate,
    KwStacksize,
    KwVersion,
}

impl Default for TokenKind {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token<'a> {
    kind: TokenKind,
    value: Option<&'a str>,
}

impl<'a> Token<'a> {
    fn unwrap_value(&self) -> &'a str {
        self.value.expect("token value missing")
    }
}

#[derive(Debug)]
struct Lexer<'a> {
    text: &'a str,
    chars: Peekable<CharIndices<'a>>,
}

impl<'a> Lexer<'a> {
    pub fn new(text: &'a str) -> Self {
        Lexer {
            text,
            chars: text.char_indices().peekable(),
        }
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((i, c)) = self.chars.next() {
            match c {
                '\0' => Some(Token {
                    kind: TokenKind::Eof,
                    value: None,
                }),
                ';' => {
                    for (_, next_c) in self.chars.by_ref() {
                        if next_c == '\n' {
                            break;
                        }
                    }
                    self.next()
                }
                '=' => match self.chars.next_if(|&x| x.1 == '=').map(|x| x.1) {
                    Some(_) => Some(Token {
                        kind: TokenKind::EqualEqual,
                        value: Some("=="),
                    }),
                    None => Some(Token {
                        kind: TokenKind::Equal,
                        value: Some("="),
                    }),
                },
                ',' => Some(Token {
                    kind: TokenKind::Comma,
                    value: Some(","),
                }),
                '"' => {
                    let mut end = i + 1;
                    for (j, next_c) in self.chars.by_ref() {
                        if next_c == '"' {
                            end = j;
                            break;
                        }
                    }
                    Some(Token {
                        kind: TokenKind::Identifier,
                        value: Some(self.text[i + 1..end].trim()),
                    })
                }
                _ => {
                    let mut end = i;
                    for (j, next_c) in self.chars.by_ref() {
                        match next_c {
                            '=' | ',' | ';' | '\r' | '\n' | ' ' | '\t' | '\x0B' => {
                                end = j;
                                break;
                            }
                            _ => {
                                end = j + next_c.len_utf8();
                            }
                        }
                    }
                    let word = self.text[i..end].trim();
                    if word.is_empty() {
                        self.next()
                    } else {
                        let kind = match word {
                            "BASE" => TokenKind::KwBase,
                            "CONSTANT" => TokenKind::KwConstant,
                            "DATA" => TokenKind::KwData,
                            "EXPORTS" => TokenKind::KwExports,
                            "HEAPSIZE" => TokenKind::KwHeapsize,
                            "LIBRARY" => TokenKind::KwLibrary,
                            "NAME" => TokenKind::KwName,
                            "NONAME" => TokenKind::KwNoname,
                            "PRIVATE" => TokenKind::KwPrivate,
                            "STACKSIZE" => TokenKind::KwStacksize,
                            "VERSION" => TokenKind::KwVersion,
                            _ => TokenKind::Identifier,
                        };
                        Some(Token {
                            kind,
                            value: Some(word),
                        })
                    }
                }
            }
        } else {
            Some(Token {
                kind: TokenKind::Eof,
                value: None,
            })
        }
    }
}

#[derive(Debug)]
pub struct Parser<'a> {
    lexer: Lexer<'a>,
    stack: Vec<Token<'a>>,
    def: ModuleDef,
    machine: MachineType,
}

impl<'a> Parser<'a> {
    pub fn new(text: &'a str, machine: MachineType) -> Self {
        Parser {
            lexer: Lexer::new(text),
            stack: Vec::new(),
            def: ModuleDef::default(),
            machine,
        }
    }

    pub fn parse(mut self) -> Result<ModuleDef> {
        loop {
            let eof = self.parse_one()?;
            if eof {
                break;
            }
        }
        Ok(self.def)
    }

    fn parse_one(&mut self) -> Result<bool> {
        let token = self.read();
        match token.kind {
            TokenKind::Eof => return Ok(true),
            TokenKind::KwExports => loop {
                let next = self.read();
                if next.kind != TokenKind::Identifier {
                    self.stack.push(next);
                    return Ok(false);
                }
                self.parse_export(next)?;
            },
            TokenKind::KwHeapsize => {
                let (reserve, commit) = self.parse_numbers()?;
                self.def.heap_reserve = reserve;
                self.def.heap_commit = commit;
            }
            TokenKind::KwStacksize => {
                let (reserve, commit) = self.parse_numbers()?;
                self.def.stack_reserve = reserve;
                self.def.stack_commit = commit;
            }
            TokenKind::KwLibrary | TokenKind::KwName => {
                let (name, image_base) = self.parse_name()?;
                self.def.import_name = name;
                self.def.image_base = image_base;
            }
            TokenKind::KwVersion => {
                let (major, minor) = self.parse_version()?;
                self.def.major_image_version = major;
                self.def.minor_image_version = minor;
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("unknown directive: {}", token.unwrap_value()),
                ))
            }
        }
        Ok(false)
    }

    fn parse_export(&mut self, token: Token<'a>) -> Result<()> {
        let mut export = ShortExport {
            name: token.unwrap_value().to_string(),
            ..Default::default()
        };

        let token = self.read();
        if token.kind == TokenKind::Equal {
            let token = self.read();
            if token.kind != TokenKind::Identifier {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("expected identifier, found: {:?}", token.kind),
                ));
            }
            export.ext_name = Some(export.name);
            export.name = token.unwrap_value().to_string();
        } else {
            self.stack.push(token);
        }

        if self.machine == MachineType::I386 {
            if !is_decorated(&export.name) {
                export.name = format!("_{}", export.name);
            }
            if let Some(ext_name) = export.ext_name.as_ref() {
                if !is_decorated(ext_name) {
                    export.ext_name = Some(format!("_{}", ext_name));
                }
            }
        }

        loop {
            let token = self.read();
            if token.kind == TokenKind::Identifier
                && token.value.map(|v| v.starts_with('@')).unwrap_or_default()
            {
                let value = token.unwrap_value();
                if value == "@" {
                    // "foo @ 10"
                    let token = self.read();
                    if let Some(value) = token.value {
                        match value.parse() {
                            Ok(ordinal) => export.ordinal = ordinal,
                            Err(_) => {
                                return Err(Error::new(
                                    ErrorKind::InvalidInput,
                                    format!("invalid ordinal: {}", value),
                                ))
                            }
                        }
                    } else {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            format!("expected identifier, found: {:?}", token.kind),
                        ));
                    }
                } else if value[1..].parse::<u16>().is_err() {
                    // "foo \n @bar" - Not an ordinal modifier at all, but the next
                    // export (fastcall decorated) - complete the current one.
                    self.stack.push(token);
                    self.def.exports.push(export);
                    return Ok(());
                }
                // "foo @10"
                let token = self.read();
                if token.kind == TokenKind::KwNoname {
                    export.no_name = true;
                } else {
                    self.stack.push(token);
                }
                continue;
            }

            match token.kind {
                TokenKind::KwData => {
                    export.data = true;
                }
                TokenKind::KwConstant => {
                    export.constant = true;
                }
                TokenKind::KwPrivate => {
                    export.private = true;
                }
                TokenKind::EqualEqual => {
                    let token = self.read();
                    if let Some(value) = token.value {
                        export.alias_target = value.to_string();
                    } else {
                        return Err(Error::new(
                            ErrorKind::InvalidInput,
                            format!("expected identifier, found: {:?}", token.kind),
                        ));
                    }
                    // Skipped mingw i386 handling
                    // See https://github.com/llvm/llvm-project/blob/09c2b7c35af8c4bad39f03e9f60df8bd07323028/llvm/lib/Object/COFFModuleDefinition.cpp#L282-L283
                }
                _ => {
                    self.stack.push(token);
                    self.def.exports.push(export);
                    break;
                }
            }
        }
        Ok(())
    }

    // HEAPSIZE/STACKSIZE reserve[,commit]
    fn parse_numbers(&mut self) -> Result<(u64, u64)> {
        let reserve = self.read_as_int()?;
        let token = self.read();
        if token.kind != TokenKind::Comma {
            self.stack.push(token);
            return Ok((reserve, 0));
        }
        let commit = self.read_as_int()?;
        Ok((reserve, commit))
    }

    // NAME outputPath [BASE=address]
    fn parse_name(&mut self) -> Result<(String, u64)> {
        let mut name = String::new();
        let token = self.read();
        if token.kind == TokenKind::Identifier {
            name = token.unwrap_value().to_string();
        } else {
            self.stack.push(token);
            return Ok((name, 0));
        }
        let token = self.read();
        return if token.kind == TokenKind::KwBase {
            let token = self.read();
            if token.kind != TokenKind::Equal {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("expected equal, found: {:?}", token.kind),
                ));
            }
            let base = self.read_as_int()?;
            Ok((name, base))
        } else {
            self.stack.push(token);
            Ok((name, 0))
        };
    }

    // VERSION major[.minor]
    fn parse_version(&mut self) -> Result<(u32, u32)> {
        let token = self.read();
        if token.kind != TokenKind::Identifier {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("expected identifier, found: {:?}", token.kind),
            ));
        }
        let value = token.unwrap_value();
        match value.split_once('.') {
            Some((major, minor)) => {
                let major = major
                    .parse::<u32>()
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "expected integer"))?;
                let minor = minor
                    .parse::<u32>()
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "expected integer"))?;
                Ok((major, minor))
            }
            None => {
                let major = value
                    .parse::<u32>()
                    .map_err(|_| Error::new(ErrorKind::InvalidInput, "expected integer"))?;
                Ok((major, 0))
            }
        }
    }

    fn read(&mut self) -> Token<'a> {
        if let Some(token) = self.stack.pop() {
            token
        } else {
            self.lexer.next().expect("unexpected EOF")
        }
    }

    fn read_as_int(&mut self) -> Result<u64> {
        let token = self.read();
        if token.kind != TokenKind::Identifier {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("expected identifier, found: {:?}", token.kind),
            ));
        }
        token
            .unwrap_value()
            .parse()
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "expected integer"))
    }
}

fn is_decorated(sym: &str) -> bool {
    sym.starts_with('@') || sym.starts_with('?') || sym.contains('@')
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_lexer() {
        let mut lexer = Lexer::new(r#"NAME foo.dll"#);
        assert_eq!(
            lexer.next(),
            Some(Token {
                kind: TokenKind::KwName,
                value: Some("NAME"),
            })
        );
        assert_eq!(
            lexer.next(),
            Some(Token {
                kind: TokenKind::Identifier,
                value: Some("foo.dll"),
            })
        );
        assert_eq!(
            lexer.next(),
            Some(Token {
                kind: TokenKind::Eof,
                value: None,
            })
        );

        let mut lexer = Lexer::new("");
        assert_eq!(
            lexer.next(),
            Some(Token {
                kind: TokenKind::Eof,
                value: None,
            })
        );

        let mut lexer = Lexer::new("\0");
        assert_eq!(
            lexer.next(),
            Some(Token {
                kind: TokenKind::Eof,
                value: None,
            })
        );

        let mut lexer = Lexer::new(r#"=,=="CODE"BASE;"#);
        assert_eq!(
            lexer.next(),
            Some(Token {
                kind: TokenKind::Equal,
                value: Some("="),
            })
        );
        assert_eq!(
            lexer.next(),
            Some(Token {
                kind: TokenKind::Comma,
                value: Some(","),
            })
        );
        assert_eq!(
            lexer.next(),
            Some(Token {
                kind: TokenKind::EqualEqual,
                value: Some("=="),
            })
        );
        assert_eq!(
            lexer.next(),
            Some(Token {
                kind: TokenKind::Identifier,
                value: Some("CODE"),
            })
        );
        assert_eq!(
            lexer.next(),
            Some(Token {
                kind: TokenKind::KwBase,
                value: Some("BASE"),
            })
        );
        assert_eq!(
            lexer.next(),
            Some(Token {
                kind: TokenKind::Eof,
                value: None,
            })
        );
    }

    #[test]
    fn test_parser() {
        Parser::new("", MachineType::AMD64).parse().unwrap();

        let def = Parser::new("NAME foo", MachineType::AMD64).parse().unwrap();
        assert_eq!(def.import_name, "foo");

        let def = Parser::new("LIBRARY foo.dll", MachineType::AMD64)
            .parse()
            .unwrap();
        assert_eq!(def.import_name, "foo.dll");

        let def = Parser::new(";\n; comment\nLIBRARY foo.dll", MachineType::AMD64)
            .parse()
            .unwrap();
        assert_eq!(def.import_name, "foo.dll");

        let def = Parser::new(
            r#";
; Definition file of python310.dll
; Automatic generated by gendef
; written by Kai Tietz 2008
;
LIBRARY "python310.dll"
EXPORTS
PyAIter_Check
PyArg_Parse
PyByteArray_Type DATA
PyBytesIter_Type DATA"#,
            MachineType::AMD64,
        )
        .parse()
        .unwrap();
        assert_eq!(def.import_name, "python310.dll");
        assert_eq!(def.exports.len(), 4);
        assert_eq!(def.exports[0].name, "PyAIter_Check");
        assert!(!def.exports[0].data);
        assert_eq!(def.exports[1].name, "PyArg_Parse");
        assert!(!def.exports[1].data);
        assert_eq!(def.exports[2].name, "PyByteArray_Type");
        assert!(def.exports[2].data);
        assert_eq!(def.exports[3].name, "PyBytesIter_Type");
        assert!(def.exports[3].data);
    }

    #[test]
    fn test_parser_with_bad_input() {
        Parser::new(" \u{b}EXPORTS D \u{b}===", MachineType::AMD64)
            .parse()
            .unwrap_err();
        Parser::new("EXPORTS 8= @", MachineType::AMD64)
            .parse()
            .unwrap_err();
    }
}
