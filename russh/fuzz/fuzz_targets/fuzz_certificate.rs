#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for algo in &[
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-ed25519-cert-v01@openssh.com",
        "ssh-rsa-cert-v01@openssh.com",
        "rsa-sha2-256",
        "rsa-sha2-512",
    ] {
        let _ = russh::fuzz_helpers::decode_certificate(algo, data);
    }
});
