//! Frontend message serialization.
#![allow(missing_docs)]

use byteorder::{WriteBytesExt, BigEndian};
use std::error::Error;
use std::io::{self, Cursor};
use std::marker;

use {Oid, FromUsize, IsNull, write_nullable};

#[inline]
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
    #[inline]
    fn from(e: Box<Error + marker::Sync + Send>) -> BindError {
        BindError::Conversion(e)
    }
}

impl From<io::Error> for BindError {
    #[inline]
    fn from(e: io::Error) -> BindError {
        BindError::Serialization(e)
    }
}

#[inline]
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
        try!(write_counted(formats, |f, buf| buf.write_i16::<BigEndian>(f), buf));
        try!(write_counted(values,
                           |v, buf| write_nullable(|buf| serializer(v, buf), buf),
                           buf));
        try!(write_counted(result_formats, |f, buf| buf.write_i16::<BigEndian>(f), buf));

        Ok(())
    })
}

#[inline]
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

#[inline]
pub fn cancel_request(process_id: i32, secret_key: i32, buf: &mut Vec<u8>) {
    write_body(buf, |buf| {
        buf.write_i32::<BigEndian>(80877102).unwrap();
        buf.write_i32::<BigEndian>(process_id).unwrap();
        buf.write_i32::<BigEndian>(secret_key)
    }).unwrap();
}

#[inline]
pub fn close(variant: u8, name: &str, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.push(b'C');
    write_body(buf, |buf| {
        buf.push(variant);
        buf.write_cstr(name)
    })
}

// FIXME ideally this'd take a Read but it's unclear what to do at EOF
#[inline]
pub fn copy_data(data: &[u8], buf: &mut Vec<u8>) -> io::Result<()> {
    buf.push(b'd');
    write_body(buf, |buf| {
        buf.extend_from_slice(data);
        Ok(())
    })
}

#[inline]
pub fn copy_done(buf: &mut Vec<u8>) {
    buf.push(b'c');
    write_body(buf, |_| Ok::<(), io::Error>(())).unwrap();
}

#[inline]
pub fn copy_fail(message: &str, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.push(b'f');
    write_body(buf, |buf| buf.write_cstr(message))
}

#[inline]
pub fn describe(variant: u8, name: &str, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.push(b'D');
    write_body(buf, |buf| {
        buf.push(variant);
        buf.write_cstr(name)
    })
}

#[inline]
pub fn execute(portal: &str, max_rows: i32, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.push(b'E');
    write_body(buf, |buf| {
        try!(buf.write_cstr(portal));
        buf.write_i32::<BigEndian>(max_rows).unwrap();
        Ok(())
    })
}

#[inline]
pub fn parse<I>(name: &str, query: &str, param_types: I, buf: &mut Vec<u8>) -> io::Result<()>
    where I: IntoIterator<Item = Oid>
{
    buf.push(b'P');
    write_body(buf, |buf| {
        try!(buf.write_cstr(name));
        try!(buf.write_cstr(query));
        try!(write_counted(param_types, |t, buf| buf.write_u32::<BigEndian>(t), buf));
        Ok(())
    })
}

#[inline]
pub fn password_message(password: &str, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.push(b'p');
    write_body(buf, |buf| buf.write_cstr(password))
}

#[inline]
pub fn query(query: &str, buf: &mut Vec<u8>) -> io::Result<()> {
    buf.push(b'Q');
    write_body(buf, |buf| buf.write_cstr(query))
}

#[inline]
pub fn ssl_request(buf: &mut Vec<u8>) {
    write_body(buf, |buf| buf.write_i32::<BigEndian>(80877103)).unwrap();
}

#[inline]
pub fn startup_message<'a, I>(parameters: I, buf: &mut Vec<u8>) -> io::Result<()>
    where I: IntoIterator<Item = (&'a str, &'a str)>
{
    write_body(buf, |buf| {
        buf.write_i32::<BigEndian>(196608).unwrap();
        for (key, value) in parameters {
            try!(buf.write_cstr(key.as_ref()));
            try!(buf.write_cstr(value.as_ref()));
        }
        buf.push(0);
        Ok(())
    })
}

#[inline]
pub fn sync(buf: &mut Vec<u8>) {
    buf.push(b'S');
    write_body(buf, |_| Ok::<(), io::Error>(())).unwrap();
}

#[inline]
pub fn terminate(buf: &mut Vec<u8>) {
    buf.push(b'X');
    write_body(buf, |_| Ok::<(), io::Error>(())).unwrap();
}

trait WriteCStr {
    fn write_cstr(&mut self, s: &str) -> Result<(), io::Error>;
}

impl WriteCStr for Vec<u8> {
    #[inline]
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
