#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = russh::fuzz_helpers::read_ssh_id(data);
});
