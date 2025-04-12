// SPDX-License-Identifier: BSD-3-CLAUSE
use serde::{Deserialize, Serialize};
use serde_with::{self, serde_as};
use serde_yaml::{self};
use std::collections::HashMap;
use std::io::{self, Write};

use crate::arch::mips;
use crate::Options;

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub name: String,
    // #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
    pub signature: u64,
    pub size: usize,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SegmentSignature {
    pub name: String,
    // #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
    pub signature: u64,
    pub size: usize,
    pub functions: Vec<FunctionSignature>,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SegmentOffset {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub symbols: HashMap<String, usize>,
}

fn find<W: Write>(
    signature: u64,
    size: usize,
    instructions: &[u32],
    start: usize,
    end: usize,
    options: &mut Options<W>,
) -> Option<usize> {
    let mut i = start;
    let mut offset = -1;
    let mut count = 0;

    let mut hash: u64 = 0;
    let mut rm: u64 = 1;

    for _ in 0..(size - 1) {
        rm = (options.radix * rm) % options.modulus;
    }
    // println!("rm {:08x} size: {}, count: {}", rm, size, count);

    while count < size && i < end {
        hash = ((options.radix * hash) + instructions[i] as u64) % options.modulus;

        count += 1;
        i += 1;
    }

    // println!("count: {}", count);
    if i >= instructions.len() {
        return None;
    }

    while hash != signature && i < end {
        hash = (hash + options.modulus - (rm * instructions[i - count] as u64) % options.modulus)
            % options.modulus;
        hash = ((options.radix * hash) + instructions[i] as u64) % options.modulus;
        i += 1;
    }

    if hash == signature {
        Some((i - count) * 4)
    } else {
        // println!("sig: {} hash: {}, i: {}", signature, hash, i);
        None
    }
}

pub fn scan<W: Write>(match_file: &String, bin_file: &String, options: &mut Options<W>) {
    // eprintln!("matching {match_file}, {bin_file}");

    let bytes = std::fs::read(bin_file).expect("Could not read bin file");

    let instructions: Vec<u32> = bytes
        .chunks(4)
        .map(|b| {
            // TODO: make endianness optional
            let instruction = mips::bytes_to_le_instruction(b);
            mips::normalize_instruction(instruction)
        })
        .collect();

    let f = std::fs::File::open(match_file).unwrap();
    for document in serde_yaml::Deserializer::from_reader(io::BufReader::new(f)) {
        let segment = SegmentSignature::deserialize(document).unwrap();
        // println!("{:?}", segment );
        // eprintln!("segment: {}", segment.name);

        // try to find the entire object, first
        let offset = find(
            segment.signature,
            segment.size / 4,
            &instructions,
            0,
            instructions.len(),
            options,
        );

        // eprintln!("found: {} -> {:?}", segment.name, offset);

        let Some(offset) = offset else {
            continue;
        };

        let mut map = HashMap::new();

        let mut position = offset;
        let function_len = segment.functions.len();

        for function in segment.functions {
            let function_offset = find(
                function.signature,
                function.size / 4,
                &instructions,
                position / 4,
                (offset + segment.size) / 4,
                options,
            );
            // eprintln!("    found: {} -> {:?}", function.name, function_offset);
            if let Some(function_offset) = function_offset {
                position = function_offset + function.size;
                map.insert(function.name, function_offset);
            }
        }

        if function_len != map.len() {
            continue;
        }

        let so = SegmentOffset {
            name: segment.name,
            offset,
            size: segment.size,
            symbols: map,
        };

        writeln!(
            options.writer,
            "---\n{}",
            serde_yaml::to_string(&so).expect("yaml")
        )
        .expect("writeln!");
    }
}
