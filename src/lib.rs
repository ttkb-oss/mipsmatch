// SPDX-License-Identifier: BSD-3-CLAUSE
use serde::{Deserialize, Serialize};
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

pub struct Options<W: Write> {
    pub modulus: u64,
    pub radix: u64,
    pub writer: W,
}

impl<W: Write> Options<W> {
    /// Create a new `Options` object.
    pub fn new(writer: W) -> Self {
        Self {
            modulus: 0xFFFFFFEF,
            radix: 4294967296,
            writer,
        }
    }
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct FunctionSignature {
    pub name: String,
    // #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
    pub signature: u64,
    pub size: usize,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct SegmentSignature {
    pub name: String,
    // #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
    pub signature: u64,
    pub size: usize,
    pub functions: Vec<FunctionSignature>,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct SegmentOffset {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub symbols: HashMap<String, usize>,
}
