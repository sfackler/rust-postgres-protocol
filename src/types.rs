use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use fallible_iterator::FallibleIterator;
use std::error::Error;
use std::io::Cursor;
use std::str;

use FromUsize;

/// Serializes a `BOOL` value.
pub fn bool_to_sql(v: bool, buf: &mut Vec<u8>) {
    buf.push(v as u8);
}

/// Deserializes a `BOOL` value.
pub fn bool_from_sql(buf: &[u8]) -> Result<bool, Box<Error + Sync + Send>> {
    if buf.len() != 1 {
        return Err("invalid buffer size".into());
    }

    Ok(buf[0] != 0)
}

/// Serializes a `BYTEA` value.
pub fn bytea_to_sql(v: &[u8], buf: &mut Vec<u8>) {
    buf.extend_from_slice(v);
}

/// Deserializes a `BYTEA value.
pub fn bytea_from_sql(buf: &[u8]) -> &[u8] {
    buf
}

/// Serializes a `TEXT`, `VARCHAR`, `CHAR(n)`, `NAME`, or `CITEXT` value.
pub fn text_to_sql(v: &str, buf: &mut Vec<u8>) {
    buf.extend_from_slice(v.as_bytes());
}

/// Deserializes a `TEXT`, `VARCHAR`, `CHAR(n)`, `NAME`, or `CITEXT` value.
pub fn text_from_sql(buf: &[u8]) -> Result<&str, Box<Error + Sync + Send>> {
    Ok(try!(str::from_utf8(buf)))
}

/// Serializes a `"char"` value.
pub fn char_to_sql(v: i8, buf: &mut Vec<u8>) {
    buf.write_i8(v).unwrap();
}

/// Deserializes a `"char"` value.
pub fn char_from_sql(mut buf: &[u8]) -> Result<i8, Box<Error + Sync + Send>> {
    let v = try!(buf.read_i8());
    if !buf.is_empty() {
        return Err("invalid buffer size".into());
    }
    Ok(v)
}

/// Serializes an `INT2` value.
pub fn int2_to_sql(v: i16, buf: &mut Vec<u8>) {
    buf.write_i16::<BigEndian>(v).unwrap();
}

/// Deserializes an `INT2` value.
pub fn int2_from_sql(mut buf: &[u8]) -> Result<i16, Box<Error + Sync + Send>> {
    let v = try!(buf.read_i16::<BigEndian>());
    if !buf.is_empty() {
        return Err("invalid buffer size".into());
    }
    Ok(v)
}

/// Serializes an `INT4` value.
pub fn int4_to_sql(v: i32, buf: &mut Vec<u8>) {
    buf.write_i32::<BigEndian>(v).unwrap();
}

/// Deserializes an `INT4` value.
pub fn int4_from_sql(mut buf: &[u8]) -> Result<i32, Box<Error + Sync + Send>> {
    let v = try!(buf.read_i32::<BigEndian>());
    if !buf.is_empty() {
        return Err("invalid buffer size".into());
    }
    Ok(v)
}

/// Serializes an `INT8` value.
pub fn int8_to_sql(v: i64, buf: &mut Vec<u8>) {
    buf.write_i64::<BigEndian>(v).unwrap();
}

/// Deserializes an `INT8` value.
pub fn int8_from_sql(mut buf: &[u8]) -> Result<i64, Box<Error + Sync + Send>> {
    let v = try!(buf.read_i64::<BigEndian>());
    if !buf.is_empty() {
        return Err("invalid buffer size".into());
    }
    Ok(v)
}

/// Serializes a `FLOAT4` value.
pub fn float4_to_sql(v: f32, buf: &mut Vec<u8>) {
    buf.write_f32::<BigEndian>(v).unwrap();
}

/// Deserializes a `FLOAT4` value.
pub fn float4_from_sql(mut buf: &[u8]) -> Result<f32, Box<Error + Sync + Send>> {
    let v = try!(buf.read_f32::<BigEndian>());
    if !buf.is_empty() {
        return Err("invalid buffer size".into());
    }
    Ok(v)
}

/// Serializes a `FLOAT8` value.
pub fn float8_to_sql(v: f64, buf: &mut Vec<u8>) {
    buf.write_f64::<BigEndian>(v).unwrap();
}

/// Deserializes a `FLOAT8` value.
pub fn float8_from_sql(mut buf: &[u8]) -> Result<f64, Box<Error + Sync + Send>> {
    let v = try!(buf.read_f64::<BigEndian>());
    if !buf.is_empty() {
        return Err("invalid buffer size".into());
    }
    Ok(v)
}

/// Serializes an `HSTORE` value.
pub fn hstore_to_sql<'a, I>(values: I, buf: &mut Vec<u8>) -> Result<(), Box<Error + Sync + Send>>
    where I: IntoIterator<Item = (&'a str, Option<&'a str>)>
{
    let base = buf.len();
    buf.extend_from_slice(&[0; 4]);

    let mut count = 0;
    for (key, value) in values {
        count += 1;

        try!(write_pascal_string(key, buf));

        match value {
            Some(value) => {
                try!(write_pascal_string(value, buf));
            }
            None => buf.write_i32::<BigEndian>(-1).unwrap(),
        }
    }

    let count = try!(i32::from_usize(count));
    Cursor::new(&mut buf[base..base + 4]).write_i32::<BigEndian>(count).unwrap();

    Ok(())
}

fn write_pascal_string(s: &str, buf: &mut Vec<u8>) -> Result<(), Box<Error + Sync + Send>> {
    let size = try!(i32::from_usize(s.len()));
    buf.write_i32::<BigEndian>(size).unwrap();
    buf.extend_from_slice(s.as_bytes());
    Ok(())
}

/// Deserializes an `HSTORE` value.
pub fn hstore_from_sql<'a>(mut buf: &'a [u8])
                           -> Result<HstoreFromSql<'a>, Box<Error + Sync + Send>> {
    let count = try!(buf.read_i32::<BigEndian>());
    if count < 0 {
        return Err("invalid entry count".into());
    }

    Ok(HstoreFromSql {
        remaining: count,
        buf: buf,
    })
}

/// A fallible iterator over `HSTORE` entries.
pub struct HstoreFromSql<'a> {
    remaining: i32,
    buf: &'a [u8],
}

impl<'a> FallibleIterator for HstoreFromSql<'a> {
    type Item = (&'a str, Option<&'a str>);
    type Error = Box<Error + Sync + Send>;

    fn next(&mut self) -> Result<Option<(&'a str, Option<&'a str>)>, Box<Error + Sync + Send>> {
        if self.remaining == 0 {
            if !self.buf.is_empty() {
                return Err("invalid buffer size".into());
            }
            return Ok(None);
        }

        self.remaining -= 1;

        let key_len = try!(self.buf.read_i32::<BigEndian>());
        if key_len < 0 {
            return Err("invalid key length".into());
        }
        let (key, buf) = self.buf.split_at(key_len as usize);
        let key = try!(str::from_utf8(key));
        self.buf = buf;

        let value_len = try!(self.buf.read_i32::<BigEndian>());
        let value = if value_len < 0 {
            None
        } else {
            let (value, buf) = self.buf.split_at(value_len as usize);
            let value = try!(str::from_utf8(value));
            self.buf = buf;
            Some(value)
        };

        Ok(Some((key, value)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining as usize;
        (len, Some(len))
    }
}

/// Serializes a `VARBIT` value.
pub fn varbit_to_sql<I>(len: usize, v: I, buf: &mut Vec<u8>) -> Result<(), Box<Error + Sync + Send>>
    where I: Iterator<Item = u8>
{
    let len = try!(i32::from_usize(len));
    buf.write_i32::<BigEndian>(len).unwrap();

    for byte in v {
        buf.push(byte);
    }

    Ok(())
}

/// Deserializes a `VARBIT` value.
pub fn varbit_from_sql<'a>(mut buf: &'a [u8]) -> Result<Varbit<'a>, Box<Error + Sync + Send>> {
    let len = try!(buf.read_i32::<BigEndian>());
    if len < 0 {
        return Err("invalid varbit length".into());
    }
    let bytes = (len as usize + 7) / 8;
    if buf.len() != bytes {
        return Err("invalid message length".into());
    }

    Ok(Varbit {
        len: len as usize,
        bytes: buf,
    })
}

/// A `VARBIT` value.
pub struct Varbit<'a> {
    len: usize,
    bytes: &'a [u8],
}

impl<'a> Varbit<'a> {
    /// Returns the number of bits.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the bits as a slice of bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// Serializes a `TIMESTAMP` or `TIMESTAMPTZ` value.
///
/// The value should represent the number of microseconds since midnight, January 1st, 2000.
pub fn timestamp_to_sql(v: i64, buf: &mut Vec<u8>) {
    buf.write_i64::<BigEndian>(v).unwrap();
}

/// Deserializes a `TIMESTAMP` or `TIMESTAMPTZ` value.
///
/// The value represents the number of microseconds since midnight, January 1st, 2000.
pub fn timestamp_from_sql(mut buf: &[u8]) -> Result<i64, Box<Error + Sync + Send>> {
    let v = try!(buf.read_i64::<BigEndian>());
    if !buf.is_empty() {
        return Err("invalid message length".into());
    }
    Ok(v)
}

/// Serializes a `DATE` value.
///
/// The value should represent the number of days since January 1st, 2000.
pub fn date_to_sql(v: i32, buf: &mut Vec<u8>) {
    buf.write_i32::<BigEndian>(v).unwrap();
}

/// Deserializes a `DATE` value.
///
/// The value represents the number of days since January 1st, 2000.
pub fn date_from_sql(mut buf: &[u8]) -> Result<i32, Box<Error + Sync + Send>> {
    let v = try!(buf.read_i32::<BigEndian>());
    if !buf.is_empty() {
        return Err("invalid message length".into());
    }
    Ok(v)
}

/// Serializes a `TIME` or `TIMETZ` value.
///
/// The value should represent the number of microseconds since midnight.
pub fn time_to_sql(v: i64, buf: &mut Vec<u8>) {
    buf.write_i64::<BigEndian>(v).unwrap();
}

/// Deserializes a `TIME` or `TIMETZ` value.
///
/// The value represents the number of microseconds since midnight.
pub fn time_from_sql(mut buf: &[u8]) -> Result<i64, Box<Error + Sync + Send>> {
    let v = try!(buf.read_i64::<BigEndian>());
    if !buf.is_empty() {
        return Err("invalid message length".into());
    }
    Ok(v)
}

/// Serializes a `MACADDR` value.
pub fn macaddr_to_sql(v: [u8; 6], buf: &mut Vec<u8>) {
    buf.extend_from_slice(&v);
}

/// Deserializes a `MACADDR` value.
pub fn macaddr_from_sql(buf: &[u8]) -> Result<[u8; 6], Box<Error + Sync + Send>> {
    if buf.len() != 6 {
        return Err("invalid message length".into());
    }
    let mut out = [0; 6];
    out.copy_from_slice(buf);
    Ok(out)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use fallible_iterator::FallibleIterator;

    use super::*;

    #[test]
    fn bool() {
        let mut buf = vec![];
        bool_to_sql(true, &mut buf);
        assert_eq!(bool_from_sql(&buf).unwrap(), true);

        let mut buf = vec![];
        bool_to_sql(false, &mut buf);
        assert_eq!(bool_from_sql(&buf).unwrap(), false);
    }

    #[test]
    fn int2() {
        let mut buf = vec![];
        int2_to_sql(0x0102, &mut buf);
        assert_eq!(int2_from_sql(&buf).unwrap(), 0x0102);
    }

    #[test]
    fn int4() {
        let mut buf = vec![];
        int4_to_sql(0x01020304, &mut buf);
        assert_eq!(int4_from_sql(&buf).unwrap(), 0x01020304);
    }

    #[test]
    fn int8() {
        let mut buf = vec![];
        int8_to_sql(0x0102030405060708, &mut buf);
        assert_eq!(int8_from_sql(&buf).unwrap(), 0x0102030405060708);
    }

    #[test]
    fn float4() {
        let mut buf = vec![];
        float4_to_sql(10343.95, &mut buf);
        assert_eq!(float4_from_sql(&buf).unwrap(), 10343.95);
    }

    #[test]
    fn float8() {
        let mut buf = vec![];
        float8_to_sql(10343.95, &mut buf);
        assert_eq!(float8_from_sql(&buf).unwrap(), 10343.95);
    }

    #[test]
    fn hstore() {
        let mut map = HashMap::new();
        map.insert("hello", Some("world"));
        map.insert("hola", None);

        let mut buf = vec![];
        hstore_to_sql(map.iter().map(|(&k, &v)| (k, v)), &mut buf).unwrap();
        assert_eq!(hstore_from_sql(&buf).unwrap().collect::<HashMap<_, _>>().unwrap(), map);
    }

    #[test]
    fn varbit() {
        let len = 12;
        let bits = [0b0010_1011, 0b0000_1111];

        let mut buf = vec![];
        varbit_to_sql(len, bits.iter().cloned(), &mut buf).unwrap();
        let out = varbit_from_sql(&buf).unwrap();
        assert_eq!(out.len(), len);
        assert_eq!(out.bytes(), bits);
    }
}
