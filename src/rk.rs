// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
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

    /// Parameters:
    ///    needle - RK hash like one produced by this hasher
    ///    size - size of the machine code in bytes that produced the hash
    ///    bytes - haystack of bytes to search
    pub fn find(&self, needle: u64, size: usize, bytes: &[u8]) -> Option<usize> {
        if size > bytes.len() {
            return None;
        } else if size == 0 {
            return Some(0);
        }

        // starting hash
        let mut hash = self.hash_be_mips_bytes(0, &bytes[..size]);

        if hash == needle {
            return Some(0);
        }

        // removal hash
        let rm = {
            let mut rm: u64 = 1;
            for _ in 1..(size / 4) {
                rm = (self.radix * rm) % self.modulus;
            }
            rm
        };

        // march through the remainder of the slice along
        // with the beginning of the slice to pop off the
        // earliest instructions.
        //
        //      new     first
        //    -------  -------
        //    [  n  ]  [  0  ]
        //    [ n+1 ]  [  1  ]
        //    [ n+2 ]  [  2  ]
        //       ⋮        ⋮
        //    [size-1] [size-1-n]
        //
        //    0  1  2  … n n+1 n+2 … size-1-n
        //    ↑          ↑
        //    ├──────────┤
        //  first       new

        let instruction_position = bytes[size..]
            .chunks(4)
            .map(|ins| mips::bytes_to_normalized_instruction(&ins, self.family))
            .zip(
                bytes
                    .chunks(4)
                    .map(|ins| mips::bytes_to_normalized_instruction(&ins, self.family)),
            )
            .map(|(new, first)| {
                // remove last instruction
                hash = (hash + self.modulus - (rm * first as u64) % self.modulus) % self.modulus;
                hash = self.horner_hash(hash, new);
                hash
            })
            .position(|hash| hash == needle);

        match instruction_position {
            // a found position must be one after pos because
            // the 0th position in the remaining slice is 1 after
            // the position of the `bytes` slice.
            Some(pos) => Some((pos + 1) * 4),
            None => None,
        }
    }

    fn horner_hash(&self, acc: u64, s: u32) -> u64 {
        horner_hash(acc, s, self.radix, self.modulus)
    }

    fn hash_be_mips_bytes(&self, hash: u64, bytes: &[u8]) -> u64 {
        if (bytes.len() % 4) != 0 {
            panic!("misaligned block");
        }

        bytes
            .chunks(4)
            .map(|ins| mips::bytes_to_normalized_instruction(&ins, self.family))
            .fold(hash, |acc, masked_ins| self.horner_hash(acc, masked_ins))
    }
}

#[inline]
pub fn horner_hash(acc: u64, s: u32, radix: u64, q: u64) -> u64 {
    ((radix * acc) + (s as u64)) % q
}

impl Hasher for RabinKarpMIPSHasher {
    fn write(&mut self, bytes: &[u8]) {
        if (bytes.len() % 4) != 0 {
            panic!("misaligned block");
        }

        self.hash = self.hash_be_mips_bytes(self.hash, bytes);
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

    const RETURN_ZERO_NOPS: [u8; 32] = [
        0, 0, 0, 0, // nop
        0, 0, 0, 0, // nop
        0, 0, 0, 0, // nop
        0x08, 0x00, 0xE0, 0x03, // jr $ra
        0x21, 0x10, 0x00, 0x00, // addu $v0, $zero, $zero
        0, 0, 0, 0, // nop
        0, 0, 0, 0, // nop
        0, 0, 0, 0, // nop
    ];

    use crate::fingerprint::Fingerprint;
    use crate::scan::{self};
    use crate::Options;
    use std::io::Cursor;
    use std::io::Write;

    #[test]
    fn test_find() {
        let mut hasher = RabinKarpMIPSHasher::new(MIPSFamily::R3000GTE);

        assert_eq!(hasher.find(0, 0, &JR_RA_NOPS), Some(0));

        assert_eq!(hasher.find(0x41E00088, 8, &JR_RA_NOPS), Some(0));

        assert_eq!(hasher.find(0x5FE0094C, 12, &JR_RA_NOPS), Some(0));

        hasher.write(&RETURN_ZERO_NOPS[12..16]);
        let h = hasher.finish();
        println!("hash: 0x{h:08X}");

        let buff = Cursor::new(Vec::new());
        let mut options = Options::new(buff);
        let i = scan::find(
            Fingerprint::new_v0(4, h),
            1,
            &RETURN_ZERO_NOPS
                .chunks(4)
                .map(|b| mips::bytes_to_normalized_instruction(b, options.mips_family))
                .collect::<Vec<u32>>(),
            &mut options,
        );
        assert_eq!(i, Some(12));

        assert_eq!(hasher.find(h, 4, &RETURN_ZERO_NOPS), Some(12));
    }
}
