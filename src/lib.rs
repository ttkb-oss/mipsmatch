// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use serde_with::{self, serde_as};
use std::collections::HashMap;
use std::io::Write;

pub mod arch;
pub mod cli;
pub mod elf;
pub mod evaluate;
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

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum MIPSFamily {
    R3000GTE,
    R4000Allegrex,
}

pub struct Options<W: Write> {
    pub modulus: u64,
    pub radix: u64,
    pub writer: W,
    pub mipsFamily: MIPSFamily,
}

impl<W: Write> Options<W> {
    /// Create a new `Options` object.
    pub fn new(writer: W) -> Self {
        Self {
            modulus: 0xFFFFFFEF,
            radix: 4294967296,
            writer,
            mipsFamily: MIPSFamily::R3000GTE,
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
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct FunctionSignature {
    pub name: String,
    // #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
    pub fingerprint: u64,
    pub size: usize,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SegmentSignature {
    pub name: String,
    // #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
    pub fingerprint: u64,
    pub size: usize,
    pub family: MIPSFamily,
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
        );
        writeln!(writer, "{}fingerprint: 0x{:X}", indent, self.fingerprint);
        writeln!(writer, "{}size: 0x{:X}", indent, self.size);
        writeln!(
            writer,
            "{}family: {}",
            indent,
            serde_yaml::to_string(&self.family).unwrap().trim()
        );
        writeln!(writer, "{}functions:", indent);

        for function in self.functions.iter() {
            writeln!(
                writer,
                "{}- name: {}",
                indent,
                serde_yaml::to_string(&function.name).unwrap().trim()
            );
            writeln!(
                writer,
                "{}  fingerprint: 0x{:X}",
                indent, function.fingerprint
            );
            writeln!(writer, "{}  size: 0x{:X}", indent, function.size);
        }
    }
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct SegmentOffset {
    pub name: String,
    pub offset: usize,
    pub size: usize,
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
        );
        writeln!(writer, "{}offset: 0x{:X}", indent, self.offset);
        writeln!(writer, "{}size: 0x{:X}", indent, self.size);
        writeln!(writer, "{}symbols:", indent);

        for (symbol, offset) in self.symbols.iter() {
            writeln!(
                writer,
                "{}  {}: 0x{:X}",
                indent,
                serde_yaml::to_string(&symbol).unwrap().trim(),
                offset
            );
        }
    }
}
