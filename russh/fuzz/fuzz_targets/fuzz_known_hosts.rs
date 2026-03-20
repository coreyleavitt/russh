#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz hostname matching with both plain and hashed patterns
        let _ = russh::fuzz_helpers::match_known_host("example.com", s);
        let _ = russh::fuzz_helpers::match_known_host("[example.com]:2222", s);
    }
});
