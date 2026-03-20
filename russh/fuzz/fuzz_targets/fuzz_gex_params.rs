#![no_main]
use libfuzzer_sys::fuzz_target;
use ssh_encoding::Decode;

fuzz_target!(|data: &[u8]| {
    let mut reader = &data[..];
    let _ = russh::client::GexParams::decode(&mut reader);
});
