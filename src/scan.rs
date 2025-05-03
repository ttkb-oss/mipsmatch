// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use serde::{Deserialize, Serialize};
use serde_with::{self, serde_as};
use serde_yaml::{self};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::arch::mips;
use crate::SerializeToYAML;
use crate::{FunctionSignature, MIPSFamily, Options, SegmentOffset, SegmentSignature};

fn find<W: Write>(
    fingerprint: u64,
    size: usize,
    instructions: &[u32],
    start: usize,
    end: usize,
    options: &mut Options<W>,
) -> Option<usize> {
    let mut i = start;
    let offset = -1;
    let mut count = 0;

    let mut hash: u64 = 0;
    let mut rm: u64 = 1;

    for _ in 0..(size - 1) {
        rm = (options.radix * rm) % options.modulus;
    }

    while count < size && i < end {
        hash = ((options.radix * hash) + instructions[i] as u64) % options.modulus;

        count += 1;
        i += 1;
    }

    if i >= instructions.len() {
        return None;
    }

    while hash != fingerprint && i < end {
        hash = (hash + options.modulus - (rm * instructions[i - count] as u64) % options.modulus)
            % options.modulus;
        hash = ((options.radix * hash) + instructions[i] as u64) % options.modulus;
        i += 1;
    }

    if hash == fingerprint {
        Some((i - count) * 4)
    } else {
        None
    }
}

pub fn scan<W: Write>(match_file: &Path, bin_files: Vec<PathBuf>, options: &mut Options<W>) {
    for bin_file in bin_files.iter() {
        scan_one(match_file, &bin_file, options)
    }
}

pub fn scan_one<W: Write>(match_file: &Path, bin_file: &Path, options: &mut Options<W>) {
    let bytes = std::fs::read(bin_file).expect("Could not read bin file");

    let f = std::fs::File::open(match_file).unwrap();
    for document in serde_yaml::Deserializer::from_reader(io::BufReader::new(f)) {
        let segment = SegmentSignature::deserialize(document).unwrap();
        options.mipsFamily = segment.family;
        break;
    }

    let instructions: Vec<u32> = bytes
        .chunks(4)
        .map(|b| {
            // TODO: make endianness optional
            let instruction = mips::bytes_to_le_instruction(b);
            mips::normalize_instruction(instruction, options.mipsFamily)
        })
        .collect();

    let f = std::fs::File::open(match_file).unwrap();
    for document in serde_yaml::Deserializer::from_reader(io::BufReader::new(f)) {
        let segment = SegmentSignature::deserialize(document).unwrap();

        // try to find the entire object, first
        let offset = find(
            segment.fingerprint,
            segment.size / 4,
            &instructions,
            0,
            instructions.len(),
            options,
        );

        let Some(offset) = offset else {
            continue;
        };

        let mut map = HashMap::new();

        let mut position = offset;
        let function_len = segment.functions.len();

        for function in segment.functions {
            let function_offset = find(
                function.fingerprint,
                function.size / 4,
                &instructions,
                position / 4,
                (offset + segment.size) / 4,
                options,
            );
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

        writeln!(options.writer, "---");
        so.serialize_to_yaml(&mut options.writer);
    }
}
