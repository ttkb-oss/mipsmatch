// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use serde::de::{Deserializer, Error as DE, Unexpected, Visitor};
use serde::{Deserialize, Serialize, Serializer};

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use crate::arch::mips;
use crate::map::{read_segments, ObjectMap};
use crate::SerializeToYAML;
use crate::{FunctionSignature, Options, RODataSignature, RODataSignatureType, SegmentSignature};

use crate::elf::{self};

static FINGERPRINT_V0_PREFIX: &str = "urn:decomp:match:fingerprint:0:";

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
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

impl ToString for Fingerprint {
    fn to_string(&self) -> String {
        match self {
            Fingerprint::V0(f) => f.to_string(),
        }
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
        Err(DE::invalid_value(Unexpected::Str(&v), &self))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DE,
    {
        //match str::from_utf8(v) {
        //    Ok(s) => Ok(s.to_owned()),
        /* Err(_) => */
        Err(DE::invalid_value(Unexpected::Bytes(v), &self)) //,
                                                            //}
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DE,
    {
        //match String::from_utf8(v) {
        //    Ok(s) => Ok(s),
        //      Err(e) => Err(DE::invalid_value(
        //         Unexpected::Bytes(&e.into_bytes()),
        //         &self,
        //     )),
        // }
        Err(DE::invalid_value(Unexpected::Bytes(&v), &self))
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
                    "{}{}:{:X}:{}",
                    FINGERPRINT_V0_PREFIX, self.size, self.hash, m
                )
            }
            None => format!("{}{}:{:X}", FINGERPRINT_V0_PREFIX, self.size, self.hash),
        }
    }
}

fn sig_for_range<W: Write>(
    bytes: &[u8],
    offset: usize,
    size: usize,
    options: &Options<W>,
) -> Fingerprint {
    fn horner_hash(s: u32, acc: u64, radix: u64, q: u64) -> u64 {
        ((radix * acc) + (s as u64)) % q
    }

    let mut acc: u64 = 0;

    for i in (offset..(offset + size)).step_by(4) {
        // println!("i: {} size: {} offset: {} bytes: {}", i, size, offset, bytes.len());
        // get instruction
        // println!("bytes: {} to {} of {}", i, i + 4, bytes.len());
        let masked_ins =
            mips::bytes_to_normalized_instruction(&bytes[i..(i + 4)], options.mips_family);

        acc = horner_hash(masked_ins, acc, options.radix, options.modulus);
    }

    Fingerprint::V0(FingerprintV0::new_with_modulus(
        size as u64,
        acc,
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

    // assumption: jump tables will be addresses inside of a text symbol, but cannot
    // be the same value of any text symbol.

    let mut starts_with_jump_table = false;
    let mut found_non_jump_table_entry = false;
    let mut last_entry_was_jump_table = false;

    let size = rodata_info.size;

    let offset = rodata_info.vrom;
    let last_offset = offset + size - 4;

    // println!("rodata for segment: {:?}", map);

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
}

fn calculate_object_hashes<W: Write>(map: &ObjectMap, bytes: &[u8], options: &mut Options<W>) {
    let object_hash = sig_for_range(bytes, map.offset - map.vrom, map.size, options);

    let mut functions = Vec::new();

    for symbol in map.text_symbols.iter() {
        let segment_hash = sig_for_range(bytes, symbol.offset - map.vrom, symbol.size, options);

        // println!("getting sig for {} at 0x{:x}: {:x}", symbol.name, symbol.offset, symbol.size);

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
    // println!("symbols: {:?}", elf_symbols);
    let segments = read_segments(map_file, ".text", elf_symbols);
    // println!("segments: {:?}", segments);
    let bin_data = elf::bin_data(elf_file);

    if let Some(family) = elf::mips_family(elf_file) {
        options.mips_family = family;
    }

    for map in segments {
        // println!("segment: {:?}", map);
        if let Some(data) = data_for_segment(&bin_data, &map) {
            calculate_object_hashes(&map, data, options);
        }
    }
}
