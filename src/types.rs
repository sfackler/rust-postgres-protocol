use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use fallible_iterator::FallibleIterator;
use std::error::Error;
use std::io::Cursor;
use std::str;

use {Oid, FromUsize};

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

/// Serializes an `OID` value.
pub fn oid_to_sql(v: Oid, buf: &mut Vec<u8>) {
    buf.write_u32::<BigEndian>(v).unwrap();
}

/// Deserializes an `OID` value.
pub fn oid_from_sql(mut buf: &[u8]) -> Result<Oid, Box<Error + Sync + Send>> {
    let v = try!(buf.read_u32::<BigEndian>());
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
                           -> Result<HstoreEntries<'a>, Box<Error + Sync + Send>> {
    let count = try!(buf.read_i32::<BigEndian>());
    if count < 0 {
        return Err("invalid entry count".into());
    }

    Ok(HstoreEntries {
        remaining: count,
        buf: buf,
    })
}

/// A fallible iterator over `HSTORE` entries.
pub struct HstoreEntries<'a> {
    remaining: i32,
    buf: &'a [u8],
}

impl<'a> FallibleIterator for HstoreEntries<'a> {
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

/// Serializes a `UUID` value.
pub fn uuid_to_sql(v: [u8; 16], buf: &mut Vec<u8>) {
    buf.extend_from_slice(&v);
}

/// Deserializes a `UUID` value.
pub fn uuid_from_sql(buf: &[u8]) -> Result<[u8; 16], Box<Error + Sync + Send>> {
    if buf.len() != 16 {
        return Err("invalid message length".into());
    }
    let mut out = [0; 16];
    out.copy_from_slice(buf);
    Ok(out)
}

/// Serializes an array value.
pub fn array_to_sql<T, I, J, F>(dimensions: I,
                                has_nulls: bool,
                                element_type: Oid,
                                elements: J,
                                mut serializer: F,
                                buf: &mut Vec<u8>)
                                -> Result<(), Box<Error + Sync + Send>>
    where I: IntoIterator<Item = ArrayDimension>,
          J: IntoIterator<Item = T>,
          F: FnMut(T, &mut Vec<u8>) -> Result<IsNull, Box<Error + Sync + Send>>
{
    let dimensions_idx = buf.len();
    buf.extend_from_slice(&[0; 4]);
    buf.write_i32::<BigEndian>(has_nulls as i32).unwrap();
    buf.write_u32::<BigEndian>(element_type).unwrap();

    let mut num_dimensions = 0;
    for dimension in dimensions {
        num_dimensions += 1;
        buf.write_i32::<BigEndian>(dimension.len).unwrap();
        buf.write_i32::<BigEndian>(dimension.lower_bound).unwrap();
    }

    let num_dimensions = try!(i32::from_usize(num_dimensions));
    Cursor::new(&mut buf[dimensions_idx..dimensions_idx + 4])
        .write_i32::<BigEndian>(num_dimensions).unwrap();

    for element in elements {
        let base = buf.len();
        buf.extend_from_slice(&[0; 4]);
        let size = match try!(serializer(element, buf)) {
            IsNull::No => try!(i32::from_usize(buf.len() - base - 4)),
            IsNull::Yes => -1,
        };
        Cursor::new(&mut buf[base..base + 4]).write_i32::<BigEndian>(size).unwrap();
    }

    Ok(())
}

/// An enum indicating if a value is `NULL` or not.
pub enum IsNull {
    /// The value is `NULL`.
    Yes,

    /// The value is not `NULL`.
    No,
}

/// Deserializes an array value.
pub fn array_from_sql<'a>(mut buf: &'a [u8]) -> Result<Array<'a>, Box<Error + Sync + Send>> {
    let dimensions = try!(buf.read_i32::<BigEndian>());
    if dimensions < 0 {
        return Err("invalid dimension count".into());
    }
    let has_nulls = try!(buf.read_i32::<BigEndian>()) != 0;
    let element_type = try!(buf.read_u32::<BigEndian>());

    let mut r = buf;
    let mut elements = 1i32;
    for _ in 0..dimensions {
        let len = try!(r.read_i32::<BigEndian>());
        if len < 0 {
            return Err("invalid dimension size".into());
        }
        let _lower_bound = try!(r.read_i32::<BigEndian>());
        elements = match elements.checked_mul(len) {
            Some(elements) => elements,
            None => return Err("too many array elements".into()),
        };
    }

    if dimensions == 0 {
        elements = 0;
    }

    Ok(Array {
        dimensions: dimensions,
        has_nulls: has_nulls,
        element_type: element_type,
        elements: elements,
        buf: buf,
    })
}

pub struct Array<'a> {
    dimensions: i32,
    has_nulls: bool,
    element_type: Oid,
    elements: i32,
    buf: &'a [u8],
}

impl<'a> Array<'a> {
    pub fn has_nulls(&self) -> bool {
        self.has_nulls
    }

    pub fn element_type(&self) -> Oid {
        self.element_type
    }

    pub fn dimensions(&self) -> ArrayDimensions<'a> {
        ArrayDimensions(&self.buf[..self.dimensions as usize * 8])
    }

    pub fn values(&self) -> ArrayValues<'a> {
        ArrayValues {
            remaining: self.elements,
            buf: &self.buf[self.dimensions as usize * 8..],
        }
    }
}

pub struct ArrayDimensions<'a>(&'a [u8]);

impl<'a> FallibleIterator for ArrayDimensions<'a> {
    type Item = ArrayDimension;
    type Error = Box<Error + Sync + Send>;

    fn next(&mut self) -> Result<Option<ArrayDimension>, Box<Error + Sync + Send>> {
        if self.0.is_empty() {
            return Ok(None);
        }

        let len = try!(self.0.read_i32::<BigEndian>());
        let lower_bound = try!(self.0.read_i32::<BigEndian>());

        Ok(Some(ArrayDimension {
            len: len,
            lower_bound: lower_bound,
        }))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.0.len() / 8;
        (len, Some(len))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ArrayDimension {
    pub len: i32,
    pub lower_bound: i32,
}

pub struct ArrayValues<'a> {
    remaining: i32,
    buf: &'a [u8],
}

impl<'a> FallibleIterator for ArrayValues<'a> {
    type Item = Option<&'a [u8]>;
    type Error = Box<Error + Sync + Send>;

    fn next(&mut self) -> Result<Option<Option<&'a [u8]>>, Box<Error + Sync + Send>> {
        if self.remaining == 0 {
            if !self.buf.is_empty() {
                return Err("invalid message length".into());
            }
            return Ok(None);
        }
        self.remaining -= 1;

        let len = try!(self.buf.read_i32::<BigEndian>());
        let val = if len < 0 {
            None
        } else {
            if self.buf.len() < len as usize {
                return Err("invalid value length".into());
            }

            let (val, buf) = self.buf.split_at(len as usize);
            self.buf = buf;
            Some(val)
        };

        Ok(Some(val))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining as usize;
        (len, Some(len))
    }
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

    #[test]
    fn array() {
        let dimensions = [
            ArrayDimension {
                len: 1,
                lower_bound: 10,
            },
            ArrayDimension {
                len: 2,
                lower_bound: 0,
            }
        ];
        let values = [None, Some(&b"hello"[..])];

        let mut buf = vec![];
        array_to_sql(dimensions.iter().cloned(),
                     true,
                     10,
                     values.iter().cloned(),
                     |v, buf| {
                         match v {
                             Some(v) => {
                                 buf.extend_from_slice(v);
                                 Ok(IsNull::No)
                             }
                             None => Ok(IsNull::Yes),
                         }
                     },
                     &mut buf).unwrap();

        let array = array_from_sql(&buf).unwrap();
        assert_eq!(array.has_nulls(), true);
        assert_eq!(array.element_type(), 10);
        assert_eq!(array.dimensions().collect::<Vec<_>>().unwrap(), dimensions);
        assert_eq!(array.values().collect::<Vec<_>>().unwrap(), values);
    }
}
