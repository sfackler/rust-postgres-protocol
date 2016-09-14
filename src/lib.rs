extern crate byteorder;
extern crate fallible_iterator;

use byteorder::{WriteBytesExt, BigEndian};
use std::io::{self, Cursor};

pub mod message;
pub mod types;

trait FromUsize: Sized {
    fn from_usize(x: usize) -> Result<Self, io::Error>;
}

macro_rules! from_usize {
    ($t:ty) => {
        impl FromUsize for $t {
            fn from_usize(x: usize) -> io::Result<$t> {
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

fn write_framed<F>(buf: &mut Vec<u8>, f: F) -> io::Result<()>
    where F: FnOnce(&mut Vec<u8>) -> Result<(), io::Error>
{
    let base = buf.len();
    buf.extend_from_slice(&[0; 4]);

    try!(f(buf));

    let size = try!(i32::from_usize(buf.len() - base));
    Cursor::new(&mut buf[base..base + 4]).write_i32::<BigEndian>(size).unwrap();
    Ok(())
}
