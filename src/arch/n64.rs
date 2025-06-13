// Convert to Z64

pub fn n64_to_z64(bytes: &[u8]) -> Vec<u8> {
    assert!(bytes.len() % 2 == 0);
    let mut out = Vec::with_capacity(bytes.len());
    for i in (0..bytes.len()).step_by(2) {
        out.push(bytes[i + 1]);
        out.push(bytes[i]);
    }

    out
}
