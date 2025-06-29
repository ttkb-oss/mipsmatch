// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use serde::{Deserialize, Serialize};
use serde_with::{self, serde_as};
use std::collections::HashMap;
use std::hash::Hash;
use std::io::Write;

pub mod arch;
pub mod cli;
pub mod elf;
pub mod fingerprint;
pub mod map;
pub mod scan;

/*
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "\n
Finds common sections of code and provides offsets for well known code segments.

Usage:

    sotn-match evaluate [map] [bin] ...
    sotn-match match [match-file] [bin] ...
")]
struct Args {
}
*/

#[derive(Copy, Clone, Eq, Debug, Hash, PartialEq, Serialize, Deserialize)]
pub enum MIPSFamily {
    R3000GTE,      // PS1
    R4000,         // N64
    R4000Allegrex, // PSP
    R5900,         // PS2
}

pub struct Options<W: Write> {
    pub modulus: u64,
    pub radix: u64,
    pub writer: W,
    pub mips_family: MIPSFamily,
}

impl<W: Write> Options<W> {
    /// Create a new `Options` object.
    pub fn new(writer: W) -> Self {
        Self {
            modulus: 0xFFFFFFEF,
            radix: 4294967296,
            writer,
            mips_family: MIPSFamily::R3000GTE,
        }
    }
}

// serde_yaml doesn't provide a straightforward way to
// specify the representation of numeric fields. to
// get around this, just serialize manually.
pub trait SerializeToYAML {
    fn serialize_to_yaml<W: Write>(&self, writer: &mut W) {
        self.serialize_to_yaml_at_level(0, writer)
    }

    fn serialize_to_yaml_at_level<W: Write>(&self, level: usize, writer: &mut W);
}

#[serde_as]
#[derive(Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub name: String,
    // #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
    pub fingerprint: u64,
    pub size: usize,
}

#[serde_as]
#[derive(Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum RODataSignatureType {
    OnlyJumpTables,
    StartsAndEndsWithJumpTable,
    StartsWithJumpTable,
    EndsWithJumpTable,
    Unknown,
}

#[serde_as]
#[derive(Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct RODataSignature {
    rodataType: RODataSignatureType,
    size: usize,
}

#[serde_as]
#[derive(Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct SegmentSignature {
    pub name: String,
    // #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
    pub fingerprint: u64,
    pub size: usize,
    pub family: MIPSFamily,
    pub rodata: Option<RODataSignature>,
    pub functions: Vec<FunctionSignature>,
}

impl SerializeToYAML for SegmentSignature {
    fn serialize_to_yaml_at_level<W: Write>(&self, level: usize, writer: &mut W) {
        let indent = " ".repeat(level * 2);
        writeln!(
            writer,
            "{}name: {}",
            indent,
            serde_yaml::to_string(&self.name).unwrap().trim()
        )
        .expect("segment name serialization");
        writeln!(writer, "{}fingerprint: 0x{:X}", indent, self.fingerprint)
            .expect("segment fingerprint serialization");
        writeln!(writer, "{}size: 0x{:X}", indent, self.size).expect("segment size serialization");
        writeln!(
            writer,
            "{}family: {}",
            indent,
            serde_yaml::to_string(&self.family).unwrap().trim()
        )
        .expect("segment family serialization");
        if let Some(ref rodata) = self.rodata {
            writeln!(writer, "{}rodata:", indent).expect("segment functions key serialization");
            writeln!(
                writer,
                "{}  rodataType: {}",
                indent,
                serde_yaml::to_string(&rodata.rodataType).unwrap().trim()
            )
            .expect("segment rodataType serialization");
            writeln!(writer, "{}  size: 0x{:X}", indent, rodata.size)
                .expect("segment rodata.size serialization");
        }
        writeln!(writer, "{}functions:", indent).expect("segment functions key serialization");

        for function in self.functions.iter() {
            writeln!(
                writer,
                "{}- name: {}",
                indent,
                serde_yaml::to_string(&function.name).unwrap().trim()
            )
            .expect("function name serialization");
            writeln!(
                writer,
                "{}  fingerprint: 0x{:X}",
                indent, function.fingerprint
            )
            .expect("function fingerprint serialization");
            writeln!(writer, "{}  size: 0x{:X}", indent, function.size)
                .expect("function size serialization");
        }
    }
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RODataOffset {
    pub offset: usize,
    pub size: usize,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct FunctionOffset {
    pub name: String,
    pub offset: usize,
    pub size: usize,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SegmentOffset {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub rodata: Option<RODataOffset>,
    pub symbols: HashMap<String, usize>,
}

impl SerializeToYAML for SegmentOffset {
    fn serialize_to_yaml_at_level<W: Write>(&self, level: usize, writer: &mut W) {
        let indent = " ".repeat(level * 2);
        writeln!(
            writer,
            "{}name: {}",
            indent,
            serde_yaml::to_string(&self.name).unwrap().trim()
        )
        .expect("segment name serialization");
        writeln!(writer, "{}offset: 0x{:X}", indent, self.offset)
            .expect("segment offset serialization");
        writeln!(writer, "{}size: 0x{:X}", indent, self.size).expect("segment size serialization");

        if let Some(ref rodata) = self.rodata {
            writeln!(writer, "{}rodata:", indent).expect("segment rodata key serialization");
            writeln!(writer, "{}  offset: 0x{:X}", indent, rodata.offset)
                .expect("segment size serialization");
            writeln!(writer, "{}  size: 0x{:X}", indent, rodata.size)
                .expect("segment size serialization");
        }

        writeln!(writer, "{}symbols:", indent).expect("segment symbols key serialization");

        let mut sorted_symbols: Vec<(&String, &usize)> = self.symbols.iter().collect();
        sorted_symbols.sort_by(|(_, a), (_, b)| a.cmp(b));

        for (symbol, offset) in sorted_symbols.iter() {
            writeln!(
                writer,
                "{}  {}: 0x{:X}",
                indent,
                serde_yaml::to_string(&symbol).unwrap().trim(),
                offset
            )
            .expect("segment symbol serialization");
        }
    }
}
