use std::hash::Hasher;

use crate::arch::mips;
use crate::MIPSFamily;

/// A Rabin-Karp rolling hasher implementation.
///
/// The default modulus was chosen to be resistent to
/// padding differences, however, there may be
/// some advantage to ignoring padding. A MIPS
/// function will either end with a single NOP
/// following the final `jr $ra`, or an
/// instruction in its branch delay slot. In the
/// first instance, a NOP is required for valid
/// code, in the last, the NOP is not.
///
/// Using the Fletcher-64 modulus (0xFFFFFFFF)
/// would effectively ignore all trailing NOPs
/// regardless of size. This could be a useful
/// property to have, but it also decreases the
/// total entropy of the hash.
#[derive(Debug)]
pub struct RabinKarpMIPSHasher {
    radix: u64,
    modulus: u64,
    family: MIPSFamily,
    hash: u64,
}

impl RabinKarpMIPSHasher {
    pub const DEFAULT_RADIX: u64 = 0x0000000100000000;
    pub const DEFAULT_MODULUS: u64 = 0x00000000FFFFFFEF;

    pub fn new(family: MIPSFamily) -> Self {
        Self::new_with_modulus(family, Self::DEFAULT_MODULUS)
    }

    pub fn new_fletcher_64(family: MIPSFamily) -> Self {
        Self::new_with_modulus(family, 0xFFFFFFFF)
    }

    pub fn new_with_modulus(family: MIPSFamily, modulus: u64) -> Self {
        Self {
            radix: Self::DEFAULT_RADIX,
            modulus: modulus,
            family,
            hash: 0,
        }
    }

    pub fn find(&self, hash: u64, bytes: &[u8]) -> usize {
        0
    }
}

#[inline]
pub fn horner_hash(s: u32, acc: u64, radix: u64, q: u64) -> u64 {
    ((radix * acc) + (s as u64)) % q
}

impl Hasher for RabinKarpMIPSHasher {
    fn write(&mut self, bytes: &[u8]) {
        if (bytes.len() % 4) != 0 {
            panic!("misaligned block");
        }

        self.hash = bytes
            .chunks(4)
            .map(|ins| mips::bytes_to_normalized_instruction(&ins, self.family))
            .fold(self.hash, |acc, masked_ins| {
                horner_hash(masked_ins, acc, self.radix, self.modulus)
            });
    }

    fn finish(&self) -> u64 {
        self.hash
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn hash(bytes: &[u8]) -> u64 {
        let mut hasher = RabinKarpMIPSHasher::new(MIPSFamily::R3000GTE);
        hasher.write(bytes);
        hasher.finish()
    }

    #[test]
    fn test_empty_hash() {
        assert_eq!(RabinKarpMIPSHasher::new(MIPSFamily::R3000GTE).finish(), 0);
        assert_eq!(hash(&[]), 0);
    }

    const JR_RA_NOPS: [u8; 24] = [
        0x08, 0x00, 0xE0, 0x03, // jr $ra
        0, 0, 0, 0, // nop
        0, 0, 0, 0, // nop
        0, 0, 0, 0, // nop
        0, 0, 0, 0, // nop
        0, 0, 0, 0, // nop
    ];

    #[test]
    fn test_hash() {
        let nop: [u8; 4] = [0, 0, 0, 0];

        let h = hash(&nop);
        assert_eq!(h, 0);

        let h = hash(&JR_RA_NOPS[4..12]);
        assert_eq!(h, 0);

        let h = hash(&JR_RA_NOPS[0..8]);
        assert_eq!(h, 0x41E00088);

        let h = hash(&JR_RA_NOPS[0..12]);
        assert_eq!(h, 0x5FE0094C);
    }

    #[test]
    #[should_panic]
    fn test_misaligned() {
        hash(&[1, 2]);
    }

    #[test]
    fn test_fletcher_64() {
        let mut hasher = RabinKarpMIPSHasher::new_fletcher_64(MIPSFamily::R3000GTE);

        hasher.write(&JR_RA_NOPS[0..8]);
        assert_eq!(hasher.finish(), 0x3E00008);
        hasher.hash = 0;

        // additional NOPs don't effect the fletcher checksum
        hasher.write(&JR_RA_NOPS[0..12]);
        assert_eq!(hasher.finish(), 0x3E00008);
        hasher.hash = 0;
    }
}
