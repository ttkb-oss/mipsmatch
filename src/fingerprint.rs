// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use serde::de::{Deserializer, Error as DE, Unexpected, Visitor};
use serde::{Deserialize, Serialize, Serializer};

use std::cmp;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::Hasher;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use crate::arch::mips;
use crate::map::{read_segments, ObjectMap};
use crate::rk::RabinKarpMIPSHasher;
use crate::SerializeToYAML;
use crate::{FunctionSignature, Options, RODataSignature, RODataSignatureType, SegmentSignature};

use crate::elf::{self};

static FINGERPRINT_V0_PREFIX: &str = "urn:decomp:match:fingerprint:0:";

/// A `Fingerprint` is a versioned identifier for some collection of MIPS
/// machine code. Currently, only V0 is specified, which has the following
/// format:
///
/// ```pre
///      urn:decomp:match:fingerprint:0:<size>:<hash>
/// ```
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum Fingerprint {
    V0(FingerprintV0),
}

impl Fingerprint {
    pub fn new_v0(size: u64, hash: u64) -> Self {
        Self::V0(FingerprintV0::new(size, hash))
    }

    pub fn ver(&self) -> String {
        match self {
            Self::V0(f) => f.ver(),
        }
    }
}

impl FromStr for Fingerprint {
    type Err = FingerprintError;

    fn from_str(s: &str) -> Result<Fingerprint, FingerprintError> {
        if s.starts_with(FINGERPRINT_V0_PREFIX) {
            match FingerprintV0::from_str(s) {
                Ok(f) => Ok(Fingerprint::V0(f)),
                Err(e) => Err(e),
            }
        } else {
            Err(FingerprintError {
                kind: FingerprintErrorKind::FormatError("bad version"),
            })
        }
    }
}

impl Display for Fingerprint {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let s = match self {
            Fingerprint::V0(f) => f.to_string(),
        };

        f.write_str(&s)
    }
}

impl Debug for Fingerprint {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let s = match self {
            Fingerprint::V0(f) => f.to_string(),
        };

        f.write_str(&s)
    }
}

impl Serialize for Fingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

struct FingerprintVisitor;
impl<'de> Visitor<'de> for FingerprintVisitor {
    type Value = Fingerprint;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a function fingerprint")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: DE,
    {
        match Fingerprint::from_str(v) {
            Ok(f) => Ok(f),
            Err(_) => Err(DE::invalid_value(Unexpected::Str(v), &self)),
        }
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: DE,
    {
        match Fingerprint::from_str(&v) {
            Ok(f) => Ok(f),
            Err(_) => Err(DE::invalid_value(Unexpected::Str(&v), &self)),
        }
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DE,
    {
        match str::from_utf8(v) {
            Ok(s) => match Fingerprint::from_str(s) {
                Ok(f) => Ok(f),
                Err(_) => Err(DE::invalid_value(Unexpected::Str(s), &self)),
            },
            Err(_) => Err(DE::invalid_value(Unexpected::Bytes(v), &self)),
        }
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DE,
    {
        match String::from_utf8(v) {
            Ok(s) => match Fingerprint::from_str(&s) {
                Ok(f) => Ok(f),
                Err(_) => Err(DE::invalid_value(Unexpected::Str(&s), &self)),
            },
            Err(e) => Err(DE::invalid_value(Unexpected::Bytes(&e.into_bytes()), &self)),
        }
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(FingerprintVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
pub enum FingerprintErrorKind {
    FormatError(&'static str),
    ParseIntError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintError {
    pub kind: FingerprintErrorKind,
}

impl Display for FingerprintError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "FingerprintError")
    }
}

impl Error for FingerprintError {}

pub static MODULUS_V0: u64 = 0xFFFFFFEF;

/// Fingerprint Version 0
///
///    urn:decomp:match:fingerprint:0:<size>:[<modulus>$]<hash>
#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
pub struct FingerprintV0 {
    size: u64,
    hash: u64,
    modulus: Option<u64>,
}

impl FingerprintV0 {
    pub fn new(size: u64, hash: u64) -> Self {
        Self {
            size,
            hash,
            modulus: None,
        }
    }

    pub fn new_with_modulus(size: u64, hash: u64, modulus: u64) -> Self {
        if modulus == MODULUS_V0 {
            Self::new(size, hash)
        } else {
            Self {
                size,
                hash,
                modulus: Some(modulus),
            }
        }
    }

    fn version() -> String {
        "0".to_string()
    }

    fn ver(&self) -> String {
        Self::version()
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn hash(&self) -> u64 {
        self.hash
    }

    pub fn modulus(&self) -> Option<u64> {
        self.modulus
    }
}

impl FromStr for FingerprintV0 {
    type Err = FingerprintError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with(FINGERPRINT_V0_PREFIX) {
            return Err(FingerprintError {
                kind: FingerprintErrorKind::FormatError("prefix"),
            });
        }

        let data = match s.strip_prefix(FINGERPRINT_V0_PREFIX) {
            Some(h) => h,
            None => {
                return Err(FingerprintError {
                    kind: FingerprintErrorKind::FormatError("data"),
                })
            }
        };
        let parts: Vec<&str> = data.split(":").collect();

        if parts.len() < 2 {
            return Err(FingerprintError {
                kind: FingerprintErrorKind::FormatError("parts: < 2"),
            });
        } else if parts.len() > 3 {
            return Err(FingerprintError {
                kind: FingerprintErrorKind::FormatError("parts: > 3"),
            });
        }

        let size_part = u64::from_str_radix(parts.get(0).expect("size"), 10);
        let size = match size_part {
            Ok(s) => s,
            Err(_) => {
                return Err(FingerprintError {
                    kind: FingerprintErrorKind::ParseIntError,
                })
            }
        };

        let hash_part = u64::from_str_radix(parts.get(1).expect("hash"), 16);
        let hash = match hash_part {
            Ok(h) => h,
            Err(_) => {
                return Err(FingerprintError {
                    kind: FingerprintErrorKind::ParseIntError,
                })
            }
        };

        if parts.len() == 2 {
            return Ok(Self::new(size, hash));
        }

        let modulus_part = u64::from_str_radix(parts.get(2).expect("modulus"), 10);
        match modulus_part {
            Ok(m) => Ok(Self::new_with_modulus(size, hash, m)),
            Err(_) => {
                return Err(FingerprintError {
                    kind: FingerprintErrorKind::ParseIntError,
                })
            }
        }
    }
}

impl ToString for FingerprintV0 {
    fn to_string(&self) -> String {
        match self.modulus {
            Some(m) => {
                format!(
                    "{}{}:{:x}:{}",
                    FINGERPRINT_V0_PREFIX, self.size, self.hash, m
                )
            }
            None => format!("{}{}:{:x}", FINGERPRINT_V0_PREFIX, self.size, self.hash),
        }
    }
}

fn sig_for_range<W: Write>(bytes: &[u8], options: &Options<W>) -> Fingerprint {
    // BUG: this strips all but the last nop. even the last nop may not
    // be necessary if the last instruction does not have a BDS

    // find last jr instruction
    let mut unpadded_size = bytes.len();
    while unpadded_size > 0 {
        unpadded_size -= 4;
        let i = unpadded_size;
        let ins = mips::bytes_to_normalized_instruction(&bytes[i..(i + 4)], options.mips_family);
        if ins != 0 {
            unpadded_size += 4;
            break;
        }
    }
    unpadded_size = cmp::min(bytes.len(), unpadded_size + 4);

    let mut hasher = RabinKarpMIPSHasher::new_with_modulus(options.mips_family, options.modulus);
    hasher.write(&bytes[..unpadded_size]);

    Fingerprint::V0(FingerprintV0::new_with_modulus(
        unpadded_size as u64,
        hasher.finish(),
        options.modulus,
    ))
}

/// classifies the RODATA of the object (if present) as being one of the following:
///
///    * only jump tables
///    * starts with jump tables
///    * ends with jump tables
///
/// this strategy is then used to scan for matching RODATA segments in other
/// files.
fn calculate_rodata_signature<W: Write>(
    map: &ObjectMap,
    bytes: &[u8],
    options: &Options<W>,
) -> Option<RODataSignature> {
    let Some(ref rodata_info) = map.rodata else {
        return None;
    };

    return None;
    /*

        // assumption: jump tables will be addresses inside of a text symbol, but cannot
        // be the same value of any text symbol.

        let mut starts_with_jump_table = false;
        let mut found_non_jump_table_entry = false;
        let mut last_entry_was_jump_table = false;

        let size = rodata_info.size;

        let offset = rodata_info.vrom;
        let last_offset = offset + size - 4;

        for i in (offset..(offset + size)).step_by(4) {
            let addr = mips::read_word(&bytes[i..(i + 4)], options.mips_family);

            if map.is_address_inside_function(addr as usize) {
                last_entry_was_jump_table = true;
                if offset == 0 {
                    starts_with_jump_table = true
                }
            } else {
                last_entry_was_jump_table = false;
                found_non_jump_table_entry = true;
            }
        }

        if !found_non_jump_table_entry {
            return Some(RODataSignature {
                rodataType: RODataSignatureType::OnlyJumpTables,
                size: size,
            });
        }
        if starts_with_jump_table && last_entry_was_jump_table {
            return Some(RODataSignature {
                rodataType: RODataSignatureType::StartsAndEndsWithJumpTable,
                size: size,
            });
        }
        if starts_with_jump_table {
            return Some(RODataSignature {
                rodataType: RODataSignatureType::StartsWithJumpTable,
                size: size,
            });
        }
        if last_entry_was_jump_table {
            return Some(RODataSignature {
                rodataType: RODataSignatureType::EndsWithJumpTable,
                size: size,
            });
        }

        Some(RODataSignature {
            rodataType: RODataSignatureType::Unknown,
            size: size,
        })
    */
}

fn calculate_object_hashes<W: Write>(map: &ObjectMap, bytes: &[u8], options: &mut Options<W>) {
    let start = map.offset - map.vrom;
    let end = start + map.size;
    let object_hash = sig_for_range(&bytes[start..end], options);

    let mut functions = Vec::new();

    for symbol in map.text_symbols.iter() {
        let start = symbol.offset - map.vrom;
        let end = start + symbol.size;
        let segment_hash = sig_for_range(&bytes[start..end], options);

        functions.push(FunctionSignature {
            name: symbol.name.clone(),
            fingerprint: segment_hash,
            size: symbol.size,
        });
    }

    let rodata_signature = calculate_rodata_signature(map, bytes, options);

    let sig = SegmentSignature {
        name: map.name().to_string(),
        fingerprint: object_hash,
        size: map.size,
        family: options.mips_family,
        rodata: rodata_signature,
        functions,
    };

    writeln!(options.writer, "---").expect("Write ocument separator");
    sig.serialize_to_yaml(&mut options.writer);
}

fn data_for_segment<'a>(
    data: &'a HashMap<usize, Vec<u8>>,
    segment: &ObjectMap,
) -> Option<&'a Vec<u8>> {
    for (addr, bin) in data {
        if segment.vram >= *addr && segment.vram < (addr + bin.len()) {
            return Some(bin);
        }
    }

    None
}

pub fn fingerprint<W: Write>(map_file: &Path, elf_file: &Path, options: &mut Options<W>) {
    let elf_symbols = elf::function_symbols(elf_file);
    let segments = read_segments(map_file, ".text", elf_symbols);
    let bin_data = elf::bin_data(elf_file);

    if let Some(family) = elf::mips_family(elf_file) {
        options.mips_family = family;
    }

    for map in segments {
        if let Some(data) = data_for_segment(&bin_data, &map) {
            calculate_object_hashes(&map, data, options);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_fingerprint_v0() {
        let f0 = FingerprintV0::new(1, 2);
        assert_eq!(f0.to_string(), "urn:decomp:match:fingerprint:0:1:2");
        assert_eq!(
            FingerprintV0::new_with_modulus(1, 10, 3).to_string(),
            "urn:decomp:match:fingerprint:0:1:a:3"
        );

        if let Ok(Fingerprint::V0(f)) =
            Fingerprint::from_str("urn:decomp:match:fingerprint:0:1:A:3")
        {
            assert_eq!(f, FingerprintV0::new_with_modulus(1, 10, 3))
        } else {
            panic!("Expected Fingerprint::V0")
        }

        let f1 = Fingerprint::from_str("urn:decomp:match:fingerprint:0:1:2").unwrap();
        assert_eq!(f1.ver(), "0");
        assert_eq!(f1.to_string(), FingerprintV0::new(1, 2).to_string());

        if let Ok(Fingerprint::V0(f2)) = Fingerprint::from_str("urn:decomp:match:fingerprint:0:1:2")
        {
            assert_eq!(f2.size(), 1);
            assert_eq!(f2.hash(), 2);
            assert_eq!(f2.modulus(), None);
        } else {
            panic!("Expected Fingerprint::V0")
        }
    }

    #[test]
    fn test_sig_for_range() {
        let buff = Cursor::new(Vec::new());
        let options = Options::new(buff);
        let nop: [u8; 4] = [0, 0, 0, 0];

        let sig_n = sig_for_range(&nop[0..4], &options);
        let Fingerprint::V0(f) = sig_n;
        assert_eq!(f.size(), 4);
        assert_eq!(f.hash(), 0);

        let jr_ra_nops: [u8; 24] = [
            0x08, 0x00, 0xE0, 0x03, // jr $ra
            0, 0, 0, 0, // nop
            0, 0, 0, 0, // nop
            0, 0, 0, 0, // nop
            0, 0, 0, 0, // nop
            0, 0, 0, 0, // nop
        ];

        // only the `jr` and one `nop`
        let sig_jr_ra_nop = sig_for_range(&jr_ra_nops[0..8], &options);
        let Fingerprint::V0(f2) = sig_jr_ra_nop;
        assert_eq!(f2.size(), 8);
        assert_eq!(f2.hash(), 0x41E00088);

        // only the `jr` and two `nops`
        let sig_jr_ra_nop_nop = sig_for_range(&jr_ra_nops[0..12], &options);
        let Fingerprint::V0(f2) = sig_jr_ra_nop_nop;
        assert_eq!(f2.size(), 8);
        assert_eq!(f2.hash(), 0x41E00088);

        // only the `jr` and all `nops`
        let sig_jr_ra_nops = sig_for_range(&jr_ra_nops[0..24], &options);
        let Fingerprint::V0(f2) = sig_jr_ra_nops;
        assert_eq!(f2.size(), 8);
        assert_eq!(f2.hash(), 0x41E00088);
    }
}
