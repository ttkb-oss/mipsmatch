// SPDX-License-Identifier: BSD-3-CLAUSE
use serde_yaml::{self};

use crate::objmatch::map::{read_segments, ObjectMap};
use crate::objmatch::{FunctionSignature, Options, SegmentSignature};

fn sig_for_range(bytes: &[u8], offset: usize, size: usize, options: &Options) -> u64 {
    fn horner_hash(s: u32, acc: u64, radix: u64, q: u64) -> u64 {
        ((radix * acc) + (s as u64)) % q
    }

    let mut acc: u64 = 0;

    for i in (offset..(offset + size)).step_by(4) {
        // get instruction
        // TODO: make endianness optional
        let instruction: u32 = ((bytes[i + 3] as u32) << 24)
            | ((bytes[i + 2] as u32) << 16)
            | ((bytes[i + 1] as u32) << 8)
            | (bytes[i] as u32);

        // mask any fields which may refer to global symbols. this will
        // mask false positives, but keep most immediates and local vars.
        let masked_ins = match instruction >> 26 {
            // r-type
            0 => instruction,
            // j-type
            2 | 3 => instruction & 0xFC000000,
            // i-type
            _ => instruction & 0xFFFF0000,
        };

        acc = horner_hash(masked_ins, acc, options.radix, options.coefficient);
    }

    acc
}

fn calculate_object_hashes(map: &ObjectMap, bin_file: &String, options: &mut Options) {
    let bytes = std::fs::read(bin_file).expect("Could not read bin file");

    // calculate the signature of the entire object
    let object_hash = sig_for_range(&bytes, map.offset, map.size, options);
    // eprintln!("    {}: [{}, 0x{object_hash:08x}]", map.name(), map.size / 4);
    // eprintln!("{} size: {} key: 0x{object_hash:08x}", map.name(), map.size);
    // writeln!(*options.writer, "{}:", map.name());

    let mut functions = Vec::new();

    for i in 0..map.text_symbols.len() {
        let segment = &map.text_symbols[i];
        let size = if i < (map.text_symbols.len() - 1) {
            map.text_symbols[i + 1].offset - segment.offset
        } else {
            map.offset + map.size - segment.offset
        };

        let segment_hash = sig_for_range(&bytes, segment.offset, size, options);
        // eprintln!("    {}: [{}, 0x{segment_hash:08x}]", segment.name, size / 4);

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
        *options.writer,
        "---\n{}",
        serde_yaml::to_string(&sig).expect("yaml")
    )
    .expect("writeln!");
}

pub fn evaluate(map_file: &String, bin_file: &String, options: &mut Options) {
    // eprintln!("evaluating {map_file}, {bin_file}");
    let segments = read_segments(map_file);

    for map in segments {
        // eprintln!("    - [0x{:x}, c, {}]", map.offset, map.name());
        calculate_object_hashes(&map, bin_file, options);
    }
}
