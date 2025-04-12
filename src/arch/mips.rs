// SPDX-License-Identifier: BSD-3-CLAUSE

pub fn bytes_to_le_instruction(bytes: &[u8]) -> u32 {
    ((bytes[3] as u32) << 24)
        | ((bytes[2] as u32) << 16)
        | ((bytes[1] as u32) << 8)
        | (bytes[0] as u32)
}

pub fn normalize_instruction(instruction: u32) -> u32 {
    // mask any fields which may refer to global symbols. this will
    // mask false positives, but keep most immediates and local vars.
    match instruction >> 26 {
        // r-type
        0 => instruction,
        // j-type
        2 | 3 => instruction & 0xFC000000,
        // i-type
        _ => instruction & 0xFFFF0000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_instruction() {
        let result = bytes_to_le_instruction(&[3, 2, 1, 0]);
        assert_eq!(result, 0x00010203);
    }

    #[test]
    fn mask_instructions() {
        assert_eq!(normalize_instruction(0x00010203), 0x00010203);
        assert_eq!(normalize_instruction(0x08010203), 0x08000000);
        assert_eq!(normalize_instruction(0x0C010203), 0x0C000000);
        assert_eq!(normalize_instruction(0xF0010203), 0xF0010000);
    }
}
