// SPDX-License-Identifier: BSD-3-CLAUSE
use serde_yaml::{self};
use std::io::Write;
use std::path::Path;

use crate::arch::mips;
use crate::map::{read_segments, ObjectMap};
use crate::{FunctionSignature, Options, SegmentSignature};

use crate::elf::{self};

fn sig_for_range<W: Write>(bytes: &[u8], offset: usize, size: usize, options: &Options<W>) -> u64 {
    fn horner_hash(s: u32, acc: u64, radix: u64, q: u64) -> u64 {
        ((radix * acc) + (s as u64)) % q
    }

    let mut acc: u64 = 0;

    for i in (offset..(offset + size)).step_by(4) {
        // get instruction
        let instruction = mips::bytes_to_le_instruction(&bytes[i..(i + 4)]);
        let masked_ins = mips::normalize_instruction(instruction);

        acc = horner_hash(masked_ins, acc, options.radix, options.modulus);
    }

    acc
}

fn calculate_object_hashes<W: Write>(map: &ObjectMap, bytes: &[u8], options: &mut Options<W>) {
    // calculate the signature of the entire object
    let object_hash = sig_for_range(bytes, map.offset, map.size, options);

    let mut functions = Vec::new();

    for i in 0..map.text_symbols.len() {
        let segment = &map.text_symbols[i];
        let size = if i < (map.text_symbols.len() - 1) {
            map.text_symbols[i + 1].offset - segment.offset
        } else {
            map.offset + map.size - segment.offset
        };

        let segment_hash = sig_for_range(bytes, segment.offset, size, options);

        functions.push(FunctionSignature {
            name: segment.name.clone(),
            signature: segment_hash,
            size,
        });
    }

    let sig = SegmentSignature {
        name: map.name().to_string(),
        signature: object_hash,
        size: map.size,
        functions,
    };

    writeln!(
        options.writer,
        "---\n{}",
        serde_yaml::to_string(&sig).expect("yaml")
    )
    .expect("writeln!");
}

pub fn evaluate<W: Write>(map_file: &Path, elf_file: &Path, options: &mut Options<W>) {
    let elf_symbols = elf::function_symbols(elf_file);

    let segments = read_segments(map_file, elf_symbols);

    let bin_data = elf::bin_data(elf_file);

    for map in segments {
        calculate_object_hashes(&map, &bin_data, options);
    }
}
