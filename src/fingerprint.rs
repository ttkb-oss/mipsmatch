// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use crate::arch::mips;
use crate::map::{read_segments, ObjectMap};
use crate::SerializeToYAML;
use crate::{FunctionSignature, Options, RODataSignature, RODataSignatureType, SegmentSignature};

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
        let masked_ins =
            mips::bytes_to_normalized_instruction(&bytes[i..(i + 4)], options.mips_family);

        acc = horner_hash(masked_ins, acc, options.radix, options.modulus);
    }

    acc
}

/// classifies the RODATA of the object (if present) as being one of the following:
///
///    * only jump tables
///    * starts with jump tables
///    * ends with jump tables
///
/// this strategy is then used to scan for matching RODATA segments in other
/// files.
fn calculate_rodata_signature<W: Write>(
    map: &ObjectMap,
    bytes: &[u8],
    options: &Options<W>,
) -> Option<RODataSignature> {
    let Some(ref rodata_info) = map.rodata else {
        return None;
    };

    // assumption: jump tables will be addresses inside of a text symbol, but cannot
    // be the same value of any text symbol.

    let mut starts_with_jump_table = false;
    let mut found_non_jump_table_entry = false;
    let mut last_entry_was_jump_table = false;

    let size = rodata_info.size;

    let offset = rodata_info.vrom;
    let last_offset = offset + size - 4;

    // println!("rodata for segment: {:?}", map);

    for i in (offset..(offset + size)).step_by(4) {
        let addr = mips::read_word(&bytes[i..(i + 4)], options.mips_family);

        if map.is_address_inside_function(addr as usize) {
            last_entry_was_jump_table = true;
            if offset == 0 {
                starts_with_jump_table = true
            }
        } else {
            last_entry_was_jump_table = false;
            found_non_jump_table_entry = true;
        }
    }

    if !found_non_jump_table_entry {
        return Some(RODataSignature {
            rodataType: RODataSignatureType::OnlyJumpTables,
            size: size,
        });
    }
    if starts_with_jump_table && last_entry_was_jump_table {
        return Some(RODataSignature {
            rodataType: RODataSignatureType::StartsAndEndsWithJumpTable,
            size: size,
        });
    }
    if starts_with_jump_table {
        return Some(RODataSignature {
            rodataType: RODataSignatureType::StartsWithJumpTable,
            size: size,
        });
    }
    if last_entry_was_jump_table {
        return Some(RODataSignature {
            rodataType: RODataSignatureType::EndsWithJumpTable,
            size: size,
        });
    }

    Some(RODataSignature {
        rodataType: RODataSignatureType::Unknown,
        size: size,
    })
}

fn calculate_object_hashes<W: Write>(map: &ObjectMap, bytes: &[u8], options: &mut Options<W>) {
    // println!("map: {}", map.object);
    // println!("\toffset: {}\n\tsize: {}\n\tlen: {}", map.offset, map.size, bytes.len());
    // calculate the fingerprint of the entire object
    // println!("map: {} of {}", map.offset, map.size);
    let object_hash = sig_for_range(bytes, map.offset - map.vrom, map.size, options);

    let mut functions = Vec::new();

    for symbol in map.text_symbols.iter() {
        let segment_hash = sig_for_range(bytes, symbol.offset - map.vrom, symbol.size, options);

        // println!("getting sig for {} at 0x{:x}: {:x}", symbol.name, symbol.offset, symbol.size);

        functions.push(FunctionSignature {
            name: symbol.name.clone(),
            fingerprint: segment_hash,
            size: symbol.size,
        });
    }

    let rodata_signature = calculate_rodata_signature(map, bytes, options);

    let sig = SegmentSignature {
        name: map.name().to_string(),
        fingerprint: object_hash,
        size: map.size,
        family: options.mips_family,
        rodata: rodata_signature,
        functions,
    };

    writeln!(options.writer, "---").expect("Write ocument separator");
    sig.serialize_to_yaml(&mut options.writer);
}

fn data_for_segment<'a>(
    data: &'a HashMap<usize, Vec<u8>>,
    segment: &ObjectMap,
) -> Option<&'a Vec<u8>> {
    for (addr, bin) in data {
        if segment.vram >= *addr && segment.vram < (addr + bin.len()) {
            return Some(bin);
        }
    }

    None
}

pub fn fingerprint<W: Write>(map_file: &Path, elf_file: &Path, options: &mut Options<W>) {
    let elf_symbols = elf::function_symbols(elf_file);
    // println!("symbols: {:?}", elf_symbols);
    let segments = read_segments(map_file, ".text", elf_symbols);
    // println!("segments: {:?}", segments);
    let bin_data = elf::bin_data(elf_file);

    if let Some(family) = elf::mips_family(elf_file) {
        options.mips_family = family;
    }

    for map in segments {
        // println!("segment: {:?}", map);
        if let Some(data) = data_for_segment(&bin_data, &map) {
            calculate_object_hashes(&map, data, options);
        }
    }
}
