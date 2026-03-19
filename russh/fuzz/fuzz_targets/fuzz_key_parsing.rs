#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Binary public key parsing
    let _ = russh::keys::key::parse_public_key(data);

    // String-based targets: only attempt if valid UTF-8
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = russh::keys::parse_public_key_base64(s);
        let _ = russh::keys::decode_secret_key(s, None);
        let _ = russh::keys::decode_secret_key(s, Some("password"));
    }
});
