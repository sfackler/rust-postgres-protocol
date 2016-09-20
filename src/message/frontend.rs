//! Frontend message serialization.
#![allow(missing_docs)]

use byteorder::{WriteBytesExt, BigEndian};
use std::error::Error;
use std::io::{self, Cursor};
use std::marker;

use {Oid, FromUsize, IsNull, write_nullable};

fn write_body<F, E>(buf: &mut Vec<u8>, f: F) -> Result<(), E>
    where F: FnOnce(&mut Vec<u8>) -> Result<(), E>,
          E: From<io::Error>
{
    let base = buf.len();
    buf.extend_from_slice(&[0; 4]);

    try!(f(buf));

    let size = try!(i32::from_usize(buf.len() - base));
    Cursor::new(&mut buf[base..base + 4]).write_i32::<BigEndian>(size).unwrap();
    Ok(())
}

pub enum BindError {
    Conversion(Box<Error + marker::Sync + Send>),
    Serialization(io::Error),
}

impl From<Box<Error + marker::Sync + Send>> for BindError {
    fn from(e: Box<Error + marker::Sync + Send>) -> BindError {
        BindError::Conversion(e)
    }
}

impl From<io::Error> for BindError {
    fn from(e: io::Error) -> BindError {
        BindError::Serialization(e)
    }
}

pub fn bind<I, J, F, T, K>(portal: &str,
                        statement: &str,
                        formats: I,
                        values: J,
                        mut serializer: F,
                        result_formats: K,
                        buf: &mut Vec<u8>)
                        -> Result<(), BindError>
    where I: IntoIterator<Item = i16>,
          J: IntoIterator<Item = T>,
          F: FnMut(T, &mut Vec<u8>) -> Result<IsNull, Box<Error + marker::Sync + Send>>,
          K: IntoIterator<Item = i16>,
{
    buf.push(b'B');

    write_body(buf, |buf| {
        try!(buf.write_cstr(portal));
        try!(buf.write_cstr(statement));
        try!(write_counted(formats,
                           |f, buf| Ok::<(), io::Error>(buf.write_i16::<BigEndian>(f).unwrap()),
                           buf));
        try!(write_counted(values,
                           |v, buf| write_nullable(|buf| serializer(v, buf), buf),
                           buf));
        try!(write_counted(result_formats,
                           |f, buf| Ok::<(), io::Error>(buf.write_i16::<BigEndian>(f).unwrap()),
                           buf));

        Ok(())
    })
}

fn write_counted<I, T, F, E>(items: I, mut serializer: F, buf: &mut Vec<u8>) -> Result<(), E>
    where I: IntoIterator<Item = T>,
          F: FnMut(T, &mut Vec<u8>) -> Result<(), E>,
          E: From<io::Error>
{
    let base = buf.len();
    buf.extend_from_slice(&[0; 2]);
    let mut count = 0;
    for item in items {
        try!(serializer(item, buf));
        count += 1;
    }
    let count = try!(i16::from_usize(count));
    Cursor::new(&mut buf[base..base + 2]).write_i16::<BigEndian>(count).unwrap();

    Ok(())
}

/// A trait implemented by types serializable as frontend Postgres messages.
pub trait Message {
    /// Serializes this message to a buffer.
    fn write(&self, buf: &mut Vec<u8>) -> Result<(), io::Error>;
}

pub fn cancel_request(process_id: i32, secret_key: i32, buf: &mut Vec<u8>) {
    buf.write_i32::<BigEndian>(80877102).unwrap();
    buf.write_i32::<BigEndian>(process_id).unwrap();
    buf.write_i32::<BigEndian>(secret_key).unwrap();
}

pub fn close(variant: u8, name: &str, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.push(b'C');
    write_body(buf, |buf| {
        buf.push(variant);
        buf.write_cstr(name)
    })
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

pub fn copy_done(buf: &mut Vec<u8>) {
    buf.push(b'c');
    write_body(buf, |_| Ok::<(), io::Error>(())).unwrap();
}

pub fn copy_fail(message: &str, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.push(b'f');
    write_body(buf, |buf| buf.write_cstr(message))
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
            let num_param_types = try!(i16::from_usize(self.param_types.len()));
            try!(buf.write_i16::<BigEndian>(num_param_types));
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
