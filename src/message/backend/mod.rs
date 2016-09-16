use std::io;

use Oid;

pub mod borrowed;

pub enum Message {
    AuthenticationCleartextPassword,
    AuthenticationGSS,
    AuthenticationKerberosV5,
    AuthenticationMD5Password { salt: [u8; 4] },
    AuthenticationOk,
    AuthenticationSCMCredential,
    AuthenticationSSPI,
    BackendKeyData { process_id: i32, secret_key: i32 },
    BindComplete,
    CloseComplete,
    CommandComplete { tag: String },
    CopyData { data: Vec<u8> },
    CopyDone,
    CopyInResponse {
        format: u8,
        column_formats: Vec<u16>,
    },
    CopyOutResponse {
        format: u8,
        column_formats: Vec<u16>,
    },
    DataRow { row: Vec<Option<Vec<u8>>> },
    EmptyQueryResponse,
    ErrorResponse { fields: Vec<(u8, String)> },
    NoData,
    NoticeResponse { fields: Vec<(u8, String)> },
    NotificationResponse {
        process_id: i32,
        channel: String,
        payload: String,
    },
    ParameterDescription { types: Vec<Oid> },
    ParameterStatus { parameter: String, value: String },
    ParseComplete,
    PortalSuspended,
    ReadyForQuery { state: u8 },
    RowDescription { descriptions: Vec<RowDescriptionEntry>, },
    #[doc(hidden)]
    __ForExtensibility,
}

impl Message {
    pub fn parse(buf: &[u8]) -> io::Result<ParseResult<Message>> {
        match borrowed::Message::parse(buf) {
            Ok(ParseResult::Complete { message, consumed }) => {
                Ok(ParseResult::Complete {
                    message: try!(message.to_owned()),
                    consumed: consumed,
                })
            }
            Ok(ParseResult::Incomplete { required_size }) => {
                Ok(ParseResult::Incomplete { required_size: required_size })
            }
            Err(e) => Err(e),
        }
    }
}

pub enum ParseResult<T> {
    Complete { message: T, consumed: usize },
    Incomplete { required_size: Option<usize> },
}

pub struct RowDescriptionEntry {
    pub name: String,
    pub table_oid: Oid,
    pub column_id: i16,
    pub type_oid: Oid,
    pub type_size: i16,
    pub type_modifier: i32,
    pub format: i16,
}
