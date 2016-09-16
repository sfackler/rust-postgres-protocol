//! Authentication protocol support.
use hex::ToHex;
use md5::Context;

/// Hashes authentication information in a way suitable for use in response
/// to an `AuthenticationMd5Password` message.
pub fn md5_hash(username: &[u8], password: &[u8], salt: [u8; 4]) -> String {
    let mut context = Context::new();
    context.consume(password);
    context.consume(username);
    let output = context.compute();
    context = Context::new();
    context.consume(output.to_hex().as_bytes());
    context.consume(&salt);
    format!("md5{}", context.compute().to_hex())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn md5() {
        let username = b"md5_user";
        let password = b"password";
        let salt = [0x2a, 0x3d, 0x8f, 0xe0];

        assert_eq!(md5_hash(username, password, salt), "md562af4dd09bbb41884907a838a3233294");
    }
}
