#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = &data[..];
    let _ = russh::fuzz_helpers::parse_channel_open(&mut reader);
});
