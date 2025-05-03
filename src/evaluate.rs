// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use serde_yaml::{self};
use std::io::Write;
use std::path::Path;

use crate::arch::mips;
use crate::map::{read_segments, ObjectMap, FunctionEntry};
use crate::{FunctionSignature, Options, SegmentSignature};
use crate::SerializeToYAML;

use crate::elf::{self};

fn sig_for_range<W: Write>(bytes: &[u8], offset: usize, size: usize, options: &Options<W>) -> u64 {
    fn horner_hash(s: u32, acc: u64, radix: u64, q: u64) -> u64 {
        ((radix * acc) + (s as u64)) % q
    }

    let mut acc: u64 = 0;

    for i in (offset..(offset + size)).step_by(4) {
        // println!("i: {} size: {} offset: {} bytes: {}", i, size, offset, bytes.len());
        // get instruction
        // println!("bytes: {} to {} of {}", i, i + 4, bytes.len());
        let instruction = mips::bytes_to_le_instruction(&bytes[i..(i + 4)]);
        let masked_ins = mips::normalize_instruction(instruction, options.mipsFamily);

        acc = horner_hash(masked_ins, acc, options.radix, options.modulus);
    }

    acc
}

fn calculate_object_hashes<W: Write>(map: &ObjectMap, bytes: &[u8], options: &mut Options<W>) {
    // println!("map: {}", map.object);
    // println!("\toffset: {}\n\tsize: {}\n\tlen: {}", map.offset, map.size, bytes.len());
    // calculate the signature of the entire object
    // println!("map: {} of {}", map.offset, map.size);
    let object_hash = sig_for_range(bytes, map.offset, map.size, options);

    let mut functions = Vec::new();

    for symbol in map.text_symbols.iter() {
        let segment_hash = sig_for_range(bytes, symbol.offset, symbol.size, options);

        // println!("getting sig for {} at 0x{:x}: {:x}", symbol.name, symbol.offset, symbol.size);

        functions.push(FunctionSignature {
            name: symbol.name.clone(),
            signature: segment_hash,
            size: symbol.size,
        });
    }

    let sig = SegmentSignature {
        name: map.name().to_string(),
        signature: object_hash,
        size: map.size,
        family: options.mipsFamily,
        functions,
    };

    writeln!(options.writer, "---");
    sig.serialize_to_yaml(&mut options.writer);
}

pub fn evaluate<W: Write>(map_file: &Path, elf_file: &Path, options: &mut Options<W>) {
    let elf_symbols = elf::function_symbols(elf_file);
    let segments = read_segments(map_file, elf_symbols);
    let bin_data = elf::bin_data(elf_file);

    if let Some(family) = elf::mips_family(elf_file) {
        // println!("family: {:?}", family);
        options.mipsFamily = family;
    }

    for map in segments {
        calculate_object_hashes(&map, &bin_data, options);
    }
}
