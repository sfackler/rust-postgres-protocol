use byteorder::{ReadBytesExt, BigEndian};
use std::error::Error;

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
            b'D' => Backend::DataRow(DataRowBody(buf)),
            b'E' => Backend::ErrorResponse(ErrorResponseBody(buf)),
            b'G' => Backend::CopyInResponse(CopyInResponseBody(buf)),
            b'H' => Backend::CopyOutResponse(CopyOutResponseBody(buf)),
            b'I' => Backend::EmptyQueryResponse,
            b'K' => Backend::BackendKeyData(BackendKeyDataBody(buf)),
            b'n' => Backend::NoData,
            b'N' => Backend::NoticeResponse(NoticeResponseBody(buf)),
            b'R' => {
                match try!(r.read_i32::<BigEndian>()) {
                    0 => Backend::AuthenticationOk,
                    2 => Backend::AuthenticationKerberosV5,
                    3 => Backend::AuthenticationCleartextPassword,
                    5 => {
                        let buf = &buf[4..];
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

pub struct BackendKeyDataBody<'a>(&'a [u8]);

pub struct CommandCompleteBody<'a>(&'a [u8]);

pub struct CopyDataBody<'a>(&'a [u8]);

pub struct CopyInResponseBody<'a>(&'a [u8]);

pub struct CopyOutResponseBody<'a>(&'a [u8]);

pub struct DataRowBody<'a>(&'a [u8]);

pub struct ErrorResponseBody<'a>(&'a [u8]);

pub struct NoticeResponseBody<'a>(&'a [u8]);

pub struct NotificationResponseBody<'a>(&'a [u8]);

pub struct ParameterDescriptionBody<'a>(&'a [u8]);

pub struct ParameterStatusBody<'a>(&'a [u8]);

pub struct ReadyForQueryBody<'a>(&'a [u8]);

pub struct RowDescriptionBody<'a>(&'a [u8]);
