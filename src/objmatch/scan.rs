// SPDX-License-Identifier: BSD-3-CLAUSE
use std::io::{self};
use serde::{Serialize, Deserialize};
use serde_with::{self, serde_as};
use serde_yaml::{self};
use std::collections::HashMap;

use crate::objmatch::Options;

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct FunctionSignature {
    name: String,
    // #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
    signature: u64,
    size: usize,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct SegmentSignature {
    name: String,
    // #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
    signature: u64,
    size: usize,
    functions: Vec<FunctionSignature>,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct SegmentOffset {
    name: String,
    offset: usize,
    size: usize,
    symbols: HashMap<String, usize>,
}



fn find(signature: u64, size: usize, instructions: &Vec<u32>, start: usize, end: usize, options: &mut Options) -> Option<usize> {

    let mut i = start;
    let mut offset = -1;
    let mut count = 0;

    let mut hash: u64 = 0;
    let mut rm: u64 = 1;

    for _ in 0..(size - 1) {
        rm = (options.radix * rm) % options.coefficient;
    }
    // println!("rm {:08x} size: {}, count: {}", rm, size, count);


    while count < size && i < end {
        hash = ((options.radix * hash) + instructions[i] as u64) % options.coefficient;

        count += 1;
        i += 1;
    }

    // println!("count: {}", count);
    if i >= instructions.len() {
        return None;
    }

    while hash != signature && i < end {
        hash = (hash + options.coefficient - (rm * instructions[i - count] as u64) % options.coefficient) % options.coefficient;
        hash = ((options.radix * hash) + instructions[i] as u64) % options.coefficient;
        i += 1;

    }

    if hash == signature {
        Some((i - count) * 4)
    } else {
        // println!("sig: {} hash: {}, i: {}", signature, hash, i);
        None
    }
}

pub fn scan(match_file: &String, bin_file: &String, options: &mut Options) {
    // eprintln!("matching {match_file}, {bin_file}");

    let bytes = std::fs::read(bin_file).expect("Could not read bin file");

    let instructions: Vec<u32> = bytes.chunks(4).map(|b| {
        // TODO: make endianness optional
        let instruction: u32 = ((b[3] as u32) << 24) |
            ((b[2] as u32) << 16) |
            ((b[1]  as u32) << 8) |
            (b[0] as u32);

        // mask any fields which may refer to global symbols. this will
        // mask false positives, but keep most immediates and local vars.
        match instruction >> 26 {
            // r-type
            0 => instruction,
            // j-type
            2 | 3 => instruction & 0xFC000000,
            // i-type
            _ => instruction & 0xFFFF0000
        }
    }).collect();


    let f = std::fs::File::open(match_file).unwrap();
    for document in serde_yaml::Deserializer::from_reader(io::BufReader::new(f)) {
        let segment = SegmentSignature::deserialize(document).unwrap();
        // println!("{:?}", segment );
        // eprintln!("segment: {}", segment.name);

        // try to find the entire object, first
        let offset = find(segment.signature,
                          segment.size / 4,
                          &instructions, 0, instructions.len(), options);

        // eprintln!("found: {} -> {:?}", segment.name, offset);

        let Some(offset) = offset else {
            continue;
        };

        let mut map = HashMap::new();

        for function in segment.functions {
            let function_offset = find(function.signature,
                                       function.size / 4,
                                       &instructions,
                                       offset / 4,
                                       (offset + segment.size) / 4,
                                       options);
            // eprintln!("    found: {} -> {:?}", function.name, function_offset);
            if let Some(function_offset) = function_offset {
                map.insert(function.name, function_offset);
            }
        }

        let so = SegmentOffset {
            name: segment.name,
            offset: offset,
            size: segment.size,
            symbols: map,
        };

        writeln!(*options.writer, "---\n{}",
                 serde_yaml::to_string(&so).expect("yaml"))
            .expect("writeln!");
    }
}


