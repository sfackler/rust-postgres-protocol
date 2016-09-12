use byteorder::{ReadBytesExt, BigEndian};
use fallible_iterator::FallibleIterator;
use std::io;
use std::marker::PhantomData;
use std::str;

use message::Oid;

macro_rules! check_empty {
    ($buf:expr) => {
        if !$buf.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid message length"));
        }
    }
}

pub enum Message<'a> {
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

impl<'a> Message<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<ParseResult<'a>, io::Error> {
        if buf.len() < 5 {
            return Ok(ParseResult::Incomplete { required_size: None });
        }

        let mut r = buf;
        let tag = r.read_u8().unwrap();
        // add a byte for the tag
        let len = r.read_u32::<BigEndian>().unwrap() as usize + 1;

        if buf.len() < len {
            return Ok(ParseResult::Incomplete { required_size: Some(len) });
        }

        let mut buf = &buf[5..len];
        let message = match tag {
            b'1' => {
                check_empty!(buf);
                Message::ParseComplete
            },
            b'2' => {
                check_empty!(buf);
                Message::BindComplete
            },
            b'3' => {
                check_empty!(buf);
                Message::CloseComplete
            },
            b'A' => {
                let process_id = try!(buf.read_i32::<BigEndian>());
                let channel = try!(buf.read_cstr());
                let message = try!(buf.read_cstr());
                check_empty!(buf);
                Message::NotificationResponse(NotificationResponseBody{
                    process_id: process_id,
                    channel: channel,
                    message: message,
                })
            },
            b'c' => {
                check_empty!(buf);
                Message::CopyDone
            },
            b'C' => {
                let tag = try!(buf.read_cstr());
                check_empty!(buf);
                Message::CommandComplete(CommandCompleteBody {
                    tag: tag,
                })
            },
            b'd' => {
                Message::CopyData(CopyDataBody {
                    data: buf,
                })
            },
            b'D' => {
                let len = try!(buf.read_u16::<BigEndian>());
                Message::DataRow(DataRowBody {
                    len: len,
                    buf: buf,
                })
            },
            b'E' => Message::ErrorResponse(ErrorResponseBody(buf)),
            b'G' => {
                let format = try!(buf.read_u8());
                let len = try!(buf.read_u16::<BigEndian>());
                Message::CopyInResponse(CopyInResponseBody {
                    format: format,
                    len: len,
                    buf: buf,
                })
            },
            b'H' => {
                let format = try!(buf.read_u8());
                let len = try!(buf.read_u16::<BigEndian>());
                Message::CopyOutResponse(CopyOutResponseBody {
                    format: format,
                    len: len,
                    buf: buf,
                })
            },
            b'I' => Message::EmptyQueryResponse,
            b'K' => {
                let process_id = try!(buf.read_i32::<BigEndian>());
                let secret_key = try!(buf.read_i32::<BigEndian>());
                check_empty!(buf);
                Message::BackendKeyData(BackendKeyDataBody {
                    process_id: process_id,
                    secret_key: secret_key,
                    _p: PhantomData,
                })
            },
            b'n' => {
                check_empty!(buf);
                Message::NoData
            },
            b'N' => Message::NoticeResponse(NoticeResponseBody(buf)),
            b'R' => {
                match try!(buf.read_i32::<BigEndian>()) {
                    0 => {
                        check_empty!(buf);
                        Message::AuthenticationOk
                    },
                    2 => {
                        check_empty!(buf);
                        Message::AuthenticationKerberosV5
                    },
                    3 => {
                        check_empty!(buf);
                        Message::AuthenticationCleartextPassword
                    },
                    5 => {
                        if buf.len() != 4 {
                            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                                      "invalid message length"));
                        }
                        let mut salt = [0; 4];
                        salt.copy_from_slice(buf);
                        check_empty!(buf);
                        Message::AuthenticationMd55Password(AuthenticationMd5PasswordBody {
                            salt: salt,
                            _p: PhantomData,
                        })
                    },
                    6 => {
                        check_empty!(buf);
                        Message::AuthenticationScmCredential
                    },
                    7 => {
                        check_empty!(buf);
                        Message::AuthenticationGss
                    },
                    9 => {
                        check_empty!(buf);
                        Message::AuthenticationSspi
                    },
                    tag => {
                        return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                                  format!("unknown authentication tag `{}`", tag)));
                    },
                }
            }
            b's' => {
                check_empty!(buf);
                Message::PortalSuspended
            },
            b'S' => {
                let name = try!(buf.read_cstr());
                let value = try!(buf.read_cstr());
                check_empty!(buf);
                Message::ParameterStatus(ParameterStatusBody {
                    name: name,
                    value: value,
                })
            },
            b't' => {
                let len = try!(buf.read_u16::<BigEndian>());
                Message::ParameterDescription(ParameterDescriptionBody {
                    len: len,
                    buf: buf,
                })
            },
            b'T' => {
                let len = try!(buf.read_u16::<BigEndian>());
                Message::RowDescription(RowDescriptionBody {
                    len: len,
                    buf: buf,
                })
            },
            b'Z' => {
                let status = try!(buf.read_u8());
                check_empty!(buf);
                Message::ReadyForQuery(ReadyForQueryBody {
                    status: status,
                    _p: PhantomData,
                })
            }
            tag => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                          format!("unknown message tag `{}`", tag)));
            },
        };

        Ok(ParseResult::Complete {
            message: message,
            consumed: len,
        })
    }
}

pub enum ParseResult<'a> {
    Complete {
        message: Message<'a>,
        consumed: usize,
    },
    Incomplete {
        required_size: Option<usize>,
    },
}

pub struct AuthenticationMd5PasswordBody<'a> {
    salt: [u8; 4],
    _p: PhantomData<&'a [u8]>,
}

impl<'a> AuthenticationMd5PasswordBody<'a> {
    pub fn salt(&self) -> [u8; 4] {
        self.salt
    }
}

pub struct BackendKeyDataBody<'a> {
    process_id: i32,
    secret_key: i32,
    _p: PhantomData<&'a [u8]>,
}

impl<'a> BackendKeyDataBody<'a> {
    pub fn process_id(&self) -> i32 {
        self.process_id
    }

    pub fn secret_key(&self) -> i32 {
        self.secret_key
    }
}

pub struct CommandCompleteBody<'a> {
    tag: &'a str,
}

impl<'a> CommandCompleteBody<'a> {
    pub fn tag(&self) -> &'a str {
        self.tag
    }
}

pub struct CopyDataBody<'a> {
    data: &'a [u8],
}

impl<'a> CopyDataBody<'a> {
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}

pub struct CopyInResponseBody<'a> {
    format: u8,
    len: u16,
    buf: &'a [u8],
}

impl<'a> CopyInResponseBody<'a> {
    pub fn format(&self) -> u8 {
        self.format
    }

    pub fn column_formats(&self) -> ColumnFormats<'a> {
        ColumnFormats {
            remaining: self.len,
            buf: self.buf,
        }
    }
}

pub struct ColumnFormats<'a> {
    remaining: u16,
    buf: &'a [u8],
}

impl<'a> FallibleIterator for ColumnFormats<'a> {
    type Item = u16;
    type Error = io::Error;

    fn next(&mut self) -> Result<Option<u16>, io::Error> {
        if self.remaining == 0 {
            check_empty!(self.buf);
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

pub struct CopyOutResponseBody<'a> {
    format: u8,
    len: u16,
    buf: &'a [u8],
}

impl<'a> CopyOutResponseBody<'a> {
    pub fn format(&self) -> u8 {
        self.format
    }

    pub fn column_formats(&self) -> ColumnFormats<'a> {
        ColumnFormats {
            remaining: self.len,
            buf: self.buf,
        }
    }
}

pub struct DataRowBody<'a> {
    len: u16,
    buf: &'a [u8],
}

impl<'a> DataRowBody<'a> {
    pub fn values(&self) -> DataRowValues<'a> {
        DataRowValues {
            remaining: self.len,
            buf: self.buf,
        }
    }
}

pub struct DataRowValues<'a> {
    remaining: u16,
    buf: &'a [u8],
}

impl<'a> FallibleIterator for DataRowValues<'a> {
    type Item = Option<&'a [u8]>;
    type Error = io::Error;

    fn next(&mut self) -> Result<Option<Option<&'a [u8]>>, io::Error> {
        if self.remaining == 0 {
            check_empty!(self.buf);
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

impl<'a> ErrorResponseBody<'a> {
    pub fn fields(&self) -> ErrorFields<'a> {
        ErrorFields(self.0)
    }
}

pub struct ErrorFields<'a>(&'a [u8]);

impl<'a> FallibleIterator for ErrorFields<'a> {
    type Item = ErrorField<'a>;
    type Error = io::Error;

    fn next(&mut self) -> Result<Option<ErrorField<'a>>, io::Error> {
        let type_ = try!(self.0.read_u8());
        if type_ == 0 {
            check_empty!(self.0);
            return Ok(None);
        }

        let value = try!(self.0.read_cstr());

        Ok(Some(ErrorField {
            type_: type_,
            value: value,
        }))
    }
}

pub struct ErrorField<'a> {
    type_: u8,
    value: &'a str,
}

impl<'a> ErrorField<'a> {
    pub fn type_(&self) -> u8 {
        self.type_
    }

    pub fn value(&self) -> &'a str {
        self.value
    }
}

pub struct NoticeResponseBody<'a>(&'a [u8]);

impl<'a> NoticeResponseBody<'a> {
    pub fn fields(&self) -> ErrorFields<'a> {
        ErrorFields(self.0)
    }
}

pub struct NotificationResponseBody<'a> {
    process_id: i32,
    channel: &'a str,
    message: &'a str,
}

impl<'a> NotificationResponseBody<'a> {
    pub fn process_id(&self) -> i32 {
        self.process_id
    }

    pub fn channel(&self) -> &'a str {
        self.channel
    }

    pub fn message(&self) -> &'a str {
        self.message
    }
}

pub struct ParameterDescriptionBody<'a> {
    len: u16,
    buf: &'a [u8],
}

impl<'a> ParameterDescriptionBody<'a> {
    pub fn parameters(&self) -> Parameters<'a> {
        Parameters {
            remaining: self.len,
            buf: self.buf,
        }
    }
}

pub struct Parameters<'a> {
    remaining: u16,
    buf: &'a [u8],
}

impl<'a> FallibleIterator for Parameters<'a> {
    type Item = Oid;
    type Error = io::Error;

    fn next(&mut self) -> Result<Option<Oid>, io::Error> {
        if self.remaining == 0 {
            check_empty!(self.buf);
            return Ok(None);
        }

        self.remaining -= 1;
        self.buf.read_u32::<BigEndian>().map(Some).map_err(Into::into)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining as usize;
        (len, Some(len))
    }
}

pub struct ParameterStatusBody<'a> {
    name: &'a str,
    value: &'a str,
}

impl<'a> ParameterStatusBody<'a> {
    pub fn name(&self) -> &'a str {
        self.name
    }

    pub fn value(&self) -> &'a str {
        self.value
    }
}

pub struct ReadyForQueryBody<'a> {
    status: u8,
    _p: PhantomData<&'a [u8]>,
}

impl<'a> ReadyForQueryBody<'a> {
    pub fn status(&self) -> u8 {
        self.status
    }
}

pub struct RowDescriptionBody<'a> {
    len: u16,
    buf: &'a [u8],
}

impl<'a> RowDescriptionBody<'a> {
    pub fn fields(&self) -> Fields<'a> {
        Fields {
            remaining: self.len,
            buf: self.buf,
        }
    }
}

pub struct Fields<'a> {
    remaining: u16,
    buf: &'a [u8],
}

impl<'a> FallibleIterator for Fields<'a> {
    type Item = Field<'a>;
    type Error = io::Error;

    fn next(&mut self) -> Result<Option<Field<'a>>, io::Error> {
        if self.remaining == 0 {
            check_empty!(self.buf);
            return Ok(None);
        }
        self.remaining -= 1;

        let name = try!(self.buf.read_cstr());
        let table_oid = try!(self.buf.read_u32::<BigEndian>());
        let column_id = try!(self.buf.read_i16::<BigEndian>());
        let type_oid = try!(self.buf.read_u32::<BigEndian>());
        let type_size = try!(self.buf.read_i16::<BigEndian>());
        let type_modifier = try!(self.buf.read_i32::<BigEndian>());
        let format = try!(self.buf.read_i16::<BigEndian>());

        Ok(Some(Field {
            name: name,
            table_oid: table_oid,
            column_id: column_id,
            type_oid: type_oid,
            type_size: type_size,
            type_modifier: type_modifier,
            format: format,
        }))
    }
}

pub struct Field<'a> {
    name: &'a str,
    table_oid: Oid,
    column_id: i16,
    type_oid: Oid,
    type_size: i16,
    type_modifier: i32,
    format: i16,
}

impl<'a> Field<'a> {
    pub fn name(&self) -> &'a str {
        self.name
    }

    pub fn table_oid(&self) -> Oid {
        self.table_oid
    }

    pub fn column_id(&self) -> i16 {
        self.column_id
    }

    pub fn type_oid(&self) -> Oid {
        self.type_oid
    }

    pub fn type_size(&self) -> i16 {
        self.type_size
    }

    pub fn type_modifier(&self) -> i32 {
        self.type_modifier
    }

    pub fn format(&self) -> i16 {
        self.format
    }
}

trait ReadCStr<'a> {
    fn read_cstr(&mut self) -> Result<&'a str, io::Error>;
}

impl<'a> ReadCStr<'a> for &'a [u8] {
    fn read_cstr(&mut self) -> Result<&'a str, io::Error> {
        let end = match self.iter().position(|&b| b == 0) {
            Some(end) => end,
            None => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
            }
        };
        let s = try!(str::from_utf8(&self[..end]).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, e)
        }));
        *self = &self[end + 1..];
        Ok(s)
    }
}
