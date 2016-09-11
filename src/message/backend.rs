use byteorder::{ReadBytesExt, BigEndian};
use fallible_iterator::FallibleIterator;
use std::error::Error;
use std::io;
use std::str;

pub enum Backend<'a> {
    AuthenticationCleartextPassword,
    AuthenticationGss,
    AuthenticationKerberosV5,
    AuthenticationMd55Password(AuthenticationMd5PasswordBody<'a>),
    AuthenticationOk,
    AuthenticationScmCredential,
    AuthenticationSspi,
    BackendKeyData(BackendKeyDataBody<'a>),
    BindComplete,
    CloseComplete,
    CommandComplete(CommandCompleteBody<'a>),
    CopyData(CopyDataBody<'a>),
    CopyDone,
    CopyInResponse(CopyInResponseBody<'a>),
    CopyOutResponse(CopyOutResponseBody<'a>),
    DataRow(DataRowBody<'a>),
    EmptyQueryResponse,
    ErrorResponse(ErrorResponseBody<'a>),
    NoData,
    NoticeResponse(NoticeResponseBody<'a>),
    NotificationResponse(NotificationResponseBody<'a>),
    ParameterDescription(ParameterDescriptionBody<'a>),
    ParameterStatus(ParameterStatusBody<'a>),
    ParseComplete,
    PortalSuspended,
    ReadyForQuery(ReadyForQueryBody<'a>),
    RowDescription(RowDescriptionBody<'a>),
    #[doc(hidden)]
    __ForExtensibility,
}

impl<'a> Backend<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<ParseResult<'a>, Box<Error>> {
        if buf.len() < 5 {
            return Ok(ParseResult::Incomplete { required_size: None });
        }

        let mut r = buf;
        let tag = try!(r.read_u8());
        // add a byte for the tag
        let len = try!(r.read_u32::<BigEndian>()) as usize + 1;

        if buf.len() < len {
            return Ok(ParseResult::Incomplete { required_size: Some(len) });
        }

        let buf = &buf[..len];
        let message = match tag {
            b'1' => Backend::ParseComplete,
            b'2' => Backend::BindComplete,
            b'3' => Backend::CloseComplete,
            b'A' => Backend::NotificationResponse(NotificationResponseBody(buf)),
            b'c' => Backend::CopyDone,
            b'C' => Backend::CommandComplete(CommandCompleteBody(buf)),
            b'd' => Backend::CopyData(CopyDataBody(buf)),
            b'D' => {
                if buf.len() < 2 {
                    return Err("invalid message length".into());
                }
                Backend::DataRow(DataRowBody(buf))
            },
            b'E' => Backend::ErrorResponse(ErrorResponseBody(buf)),
            b'G' => {
                if buf.len() < 3 {
                    return Err("invalid message length".into());
                }
                Backend::CopyInResponse(CopyInResponseBody(buf))
            },
            b'H' => {
                if buf.len() < 3 {
                    return Err("invalid message length".into());
                }
                Backend::CopyOutResponse(CopyOutResponseBody(buf))
            },
            b'I' => Backend::EmptyQueryResponse,
            b'K' => {
                if buf.len() != 8 {
                    return Err("invalid message length".into());
                }
                Backend::BackendKeyData(BackendKeyDataBody(buf))
            },
            b'n' => Backend::NoData,
            b'N' => Backend::NoticeResponse(NoticeResponseBody(buf)),
            b'R' => {
                match try!(r.read_i32::<BigEndian>()) {
                    0 => Backend::AuthenticationOk,
                    2 => Backend::AuthenticationKerberosV5,
                    3 => Backend::AuthenticationCleartextPassword,
                    5 => {
                        let buf = &buf[4..];
                        if buf.len() != 4 {
                            return Err("invalid message length".into());
                        }
                        Backend::AuthenticationMd55Password(AuthenticationMd5PasswordBody(buf))
                    },
                    6 => Backend::AuthenticationScmCredential,
                    7 => Backend::AuthenticationGss,
                    9 => Backend::AuthenticationSspi,
                    tag => return Err(format!("unknown authentication tag `{}`", tag).into()),
                }
            }
            b's' => Backend::PortalSuspended,
            b'S' => Backend::ParameterStatus(ParameterStatusBody(buf)),
            b't' => Backend::ParameterDescription(ParameterDescriptionBody(buf)),
            b'T' => Backend::RowDescription(RowDescriptionBody(buf)),
            tag => return Err(format!("unknown message tag `{}`", tag).into()),
        };

        Ok(ParseResult::Complete {
            message: message,
            consumed: len,
        })
    }
}

pub enum ParseResult<'a> {
    Complete {
        message: Backend<'a>,
        consumed: usize,
    },
    Incomplete {
        required_size: Option<usize>,
    },
}

pub struct AuthenticationMd5PasswordBody<'a>(&'a [u8]);

impl<'a> AuthenticationMd5PasswordBody<'a> {
    pub fn salt(&self) -> [u8; 4] {
        let mut salt = [0; 4];
        salt.copy_from_slice(self.0);
        salt
    }
}

pub struct BackendKeyDataBody<'a>(&'a [u8]);

impl<'a> BackendKeyDataBody<'a> {
    pub fn process_id(&self) -> u32 {
        let mut b = self.0;
        b.read_u32::<BigEndian>().unwrap()
    }

    pub fn secret_key(&self) -> u32 {
        let mut b = &self.0[4..];
        b.read_u32::<BigEndian>().unwrap()
    }
}

pub struct CommandCompleteBody<'a>(&'a [u8]);

impl<'a> CommandCompleteBody<'a> {
    pub fn tag(&self) -> Result<&'a str, Box<Error>> {
        let head = match self.0.split_last() {
            Some((&0, head)) => head,
            _ => return Err("invalid message body".into()),
        };

        str::from_utf8(head).map_err(Into::into)
    }
}

pub struct CopyDataBody<'a>(&'a [u8]);

impl<'a> CopyDataBody<'a> {
    pub fn data(&self) -> &'a [u8] {
        self.0
    }
}

pub struct CopyInResponseBody<'a>(&'a [u8]);

impl<'a> CopyInResponseBody<'a> {
    pub fn format(&self) -> u8 {
        self.0[0]
    }

    pub fn column_formats(&self) -> ColumnFormats<'a> {
        let mut b = &self.0[1..];
        let len = b.read_u16::<BigEndian>().unwrap();
        ColumnFormats {
            remaining: len,
            buf: b,
        }
    }
}

pub struct ColumnFormats<'a> {
    remaining: u16,
    buf: &'a [u8],
}

impl<'a> FallibleIterator for ColumnFormats<'a> {
    type Item = u16;
    type Error = Box<Error>;

    fn next(&mut self) -> Result<Option<u16>, Box<Error>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        self.buf.read_u16::<BigEndian>().map(Some).map_err(Into::into)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining as usize;
        (len, Some(len))
    }
}

pub struct CopyOutResponseBody<'a>(&'a [u8]);

impl<'a> CopyOutResponseBody<'a> {
    pub fn format(&self) -> u8 {
        self.0[0]
    }

    pub fn column_formats(&self) -> ColumnFormats<'a> {
        let mut b = &self.0[1..];
        let len = b.read_u16::<BigEndian>().unwrap();
        ColumnFormats {
            remaining: len,
            buf: b,
        }
    }
}

pub struct DataRowBody<'a>(&'a [u8]);

impl<'a> DataRowBody<'a> {
    pub fn values(&self) -> DataRowValues<'a> {
        let mut b = self.0;
        let len = b.read_u16::<BigEndian>().unwrap();
        DataRowValues {
            remaining: len,
            buf: b,
        }
    }
}

pub struct DataRowValues<'a> {
    remaining: u16,
    buf: &'a [u8],
}

impl<'a> FallibleIterator for DataRowValues<'a> {
    type Item = Option<&'a [u8]>;
    type Error = Box<Error>;

    fn next(&mut self) -> Result<Option<Option<&'a [u8]>>, Box<Error>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;

        let len = try!(self.buf.read_i32::<BigEndian>());
        if len < 0 {
            Ok(Some(None))
        } else {
            let len = len as usize;
            if self.buf.len() < len {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF").into());
            }
            let (head, tail) = self.buf.split_at(len);
            self.buf = tail;
            Ok(Some(Some(head)))
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining as usize;
        (len, Some(len))
    }
}

pub struct ErrorResponseBody<'a>(&'a [u8]);

pub struct NoticeResponseBody<'a>(&'a [u8]);

pub struct NotificationResponseBody<'a>(&'a [u8]);

pub struct ParameterDescriptionBody<'a>(&'a [u8]);

pub struct ParameterStatusBody<'a>(&'a [u8]);

pub struct ReadyForQueryBody<'a>(&'a [u8]);

pub struct RowDescriptionBody<'a>(&'a [u8]);
