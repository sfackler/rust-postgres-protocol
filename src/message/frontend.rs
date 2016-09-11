use byteorder::{WriteBytesExt, BigEndian};
use std::io::{self, Cursor};

use message::Oid;

pub trait Message {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error>;
}

fn write_body<F>(buf: &mut Vec<u8>, f: F) -> Result<(), io::Error>
    where F: FnOnce(&mut Vec<u8>) -> Result<(), io::Error>
{
    let base = buf.len();
    buf.extend_from_slice(&[0; 4]);

    try!(f(buf));

    let size = try!(i32::from_usize(buf.len() - base));
    try!(Cursor::new(&mut buf[base..base + 4]).write_i32::<BigEndian>(size));
    Ok(())
}

pub struct Bind<'a, T: 'a> {
    pub portal: &'a str,
    pub statement: &'a str,
    pub formats: &'a [i16],
    pub values: &'a [Option<T>],
    pub result_formats: &'a [i16],
}

impl<'a, T> Message for Bind<'a, T>
    where T: AsRef<[u8]>
{
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        buf.push(b'B');

        write_body(buf, |buf| {
            try!(buf.write_cstr(self.portal));
            try!(buf.write_cstr(self.statement));

            let num_formats = try!(u16::from_usize(self.formats.len()));
            try!(buf.write_u16::<BigEndian>(num_formats));
            for &format in self.formats {
                try!(buf.write_i16::<BigEndian>(format));
            }

            let num_values = try!(u16::from_usize(self.values.len()));
            try!(buf.write_u16::<BigEndian>(num_values));
            for value in self.values {
                match *value {
                    None => try!(buf.write_i32::<BigEndian>(-1)),
                    Some(ref value) => {
                        let value = value.as_ref();
                        let value_len = try!(i32::from_usize(value.len()));
                        try!(buf.write_i32::<BigEndian>(value_len));
                        buf.extend_from_slice(value);
                    }
                }
            }

            let num_result_formats = try!(u16::from_usize(self.result_formats.len()));
            try!(buf.write_u16::<BigEndian>(num_result_formats));
            for &result_format in self.result_formats {
                try!(buf.write_i16::<BigEndian>(result_format));
            }

            Ok(())
        })
    }
}

pub struct CancelRequest {
    pub process_id: i32,
    pub secret_key: i32,
}

impl Message for CancelRequest {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        write_body(buf, |buf| {
            try!(buf.write_i32::<BigEndian>(80877102));
            try!(buf.write_i32::<BigEndian>(self.process_id));
            try!(buf.write_i32::<BigEndian>(self.secret_key));
            Ok(())
        })
    }
}

pub struct Close<'a> {
    pub variant: u8,
    pub name: &'a str,
}

impl<'a> Message for Close<'a> {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        buf.push(b'C');
        write_body(buf, |buf| {
            buf.push(self.variant);
            buf.write_cstr(self.name)
        })
    }
}

pub struct CopyData<'a> {
    pub data: &'a [u8],
}

impl<'a> Message for CopyData<'a> {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        buf.push(b'd');
        write_body(buf, |buf| {
            buf.extend_from_slice(self.data);
            Ok(())
        })
    }
}

pub struct CopyDone;

impl Message for CopyDone {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        buf.push(b'c');
        write_body(buf, |_| Ok(()))
    }
}

pub struct CopyFail<'a> {
    pub message: &'a str,
}

impl<'a> Message for CopyFail<'a> {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        buf.push(b'f');
        write_body(buf, |buf| buf.write_cstr(self.message))
    }
}

pub struct Describe<'a> {
    pub variant: u8,
    pub name: &'a str,
}

impl<'a> Message for Describe<'a> {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        buf.push(b'D');
        write_body(buf, |buf| {
            buf.push(self.variant);
            buf.write_cstr(self.name)
        })
    }
}

pub struct Execute<'a> {
    pub portal: &'a str,
    pub max_rows: i32,
}

impl<'a> Message for Execute<'a> {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        buf.push(b'E');
        write_body(buf, |buf| {
            try!(buf.write_cstr(self.portal));
            try!(buf.write_i32::<BigEndian>(self.max_rows));
            Ok(())
        })
    }
}

pub struct Parse<'a> {
    pub name: &'a str,
    pub query: &'a str,
    pub param_types: &'a [Oid],
}

impl<'a> Message for Parse<'a> {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        buf.push(b'P');
        write_body(buf, |buf| {
            try!(buf.write_cstr(self.name));
            try!(buf.write_cstr(self.query));
            let num_param_types = try!(u16::from_usize(self.param_types.len()));
            try!(buf.write_u16::<BigEndian>(num_param_types));
            for &param_type in self.param_types {
                try!(buf.write_u32::<BigEndian>(param_type));
            }
            Ok(())
        })
    }
}

pub struct PasswordMessage<'a> {
    pub password: &'a str,
}

impl<'a> Message for PasswordMessage<'a> {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        buf.push(b'p');
        write_body(buf, |buf| buf.write_cstr(self.password))
    }
}

pub struct Query<'a> {
    pub query: &'a str,
}

impl<'a> Message for Query<'a> {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        buf.push(b'Q');
        write_body(buf, |buf| buf.write_cstr(self.query))
    }
}

pub struct SslRequest;

impl Message for SslRequest {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        write_body(buf, |buf| {
            try!(buf.write_i32::<BigEndian>(80877103));
            Ok(())
        })
    }
}

pub struct StartupMessage<'a, T: 'a, U: 'a> {
    pub parameters: &'a [(T, U)],
}

impl<'a, T, U> Message for StartupMessage<'a, T, U>
    where T: AsRef<str>,
          U: AsRef<str>
{
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        write_body(buf, |buf| {
            try!(buf.write_i32::<BigEndian>(196608));
            for &(ref key, ref value) in self.parameters {
                try!(buf.write_cstr(key.as_ref()));
                try!(buf.write_cstr(value.as_ref()));
            }
            buf.push(0);
            Ok(())
        })
    }
}

pub struct Sync;

impl Message for Sync {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        buf.push(b'S');
        write_body(buf, |_| Ok(()))
    }
}

pub struct Terminate;

impl Message for Terminate {
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error> {
        buf.push(b'X');
        write_body(buf, |_| Ok(()))
    }
}

trait WriteCStr {
    fn write_cstr(&mut self, s: &str) -> Result<(), io::Error>;
}

impl WriteCStr for Vec<u8> {
    fn write_cstr(&mut self, s: &str) -> Result<(), io::Error> {
        if s.as_bytes().contains(&0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                      "string contains embedded null"));
        }
        self.extend_from_slice(s.as_bytes());
        self.push(0);
        Ok(())
    }
}

trait FromUsize: Sized {
    fn from_usize(x: usize) -> Result<Self, io::Error>;
}

macro_rules! from_usize {
    ($t:ty) => {
        impl FromUsize for $t {
            fn from_usize(x: usize) -> Result<$t, io::Error> {
                if x > <$t>::max_value() as usize {
                    Err(io::Error::new(io::ErrorKind::InvalidInput, "value too large to transmit"))
                } else {
                    Ok(x as $t)
                }
            }
        }
    }
}

from_usize!(u16);
from_usize!(i32);
