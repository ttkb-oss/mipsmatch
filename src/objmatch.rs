// SPDX-License-Identifier: BSD-3-CLAUSE

use std::io::Write;
use serde::{Serialize, Deserialize};
use serde_with::{self, serde_as};
use std::collections::HashMap;

pub mod evaluate;
pub mod map;
pub mod scan;

pub struct Options {
    pub coefficient: u64,
    pub radix: u64,
    pub writer: Box<dyn Write>,
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


