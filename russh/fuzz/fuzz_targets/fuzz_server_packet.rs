#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = russh::fuzz_helpers::server_process_packet(data);
});
