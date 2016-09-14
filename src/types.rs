use std::io;

pub fn bool_to_sql(b: bool, buf: &mut Vec<u8>) {
    buf.push(b as u8);
}

pub fn bool_from_sql(buf: &[u8]) -> io::Result<bool> {
    if buf.len() != 1 {
        return io::Error::new(io::ErrorKind::InvalidInput, "invalid buffer size");
    }

    Ok(buf[0] != 0)
}
