// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use serde::Deserialize;
use serde_yaml::{self};
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::arch::mips;
use crate::SerializeToYAML;
use crate::{
    MIPSFamily, Options, RODataOffset, RODataSignature, RODataSignatureType, SegmentOffset,
    SegmentSignature,
};

fn find<W: Write>(
    fingerprint: u64,
    size: usize,
    instructions: &[u32],
    start: usize,
    end: usize,
    options: &mut Options<W>,
) -> Option<usize> {
    let mut i = start;
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

// determine if the block specified by offset and size overlap with
// addresses already in allocated_address_space
pub fn address_space_is_used(
    offset: usize,
    size: usize,
    allocated_address_space: &HashMap<usize, usize>,
) -> bool {
    let end = offset + size;
    // O(n) lookup is not ideal, but fast enough for now
    for (block_start, block_size) in allocated_address_space.iter() {
        let block_end = *block_start + block_size;
        if (offset >= *block_start && offset < block_end)
            || (end > *block_start && end <= block_end)
        {
            return true;
        }
    }
    return false;
}

fn find_only_jump_tables(
    segment_start: usize,
    segment_end: usize,
    vrom_start: usize,
    vrom_end: usize,
    rodata_size: usize,
    mips_family: MIPSFamily,
    bytes: &[u8],
) -> Option<RODataOffset> {
    let mut found_segment_addr = false;
    let mut last_found_jtable_addr = 0;
    let mut range_start = 0;

    for i in (0..bytes.len()).step_by(4) {
        if i >= vrom_start && i < vrom_end {
            continue;
        }

        let addr = mips::read_word(&bytes[i..(i + 4)], mips_family) as usize;

        if addr > segment_start && addr < segment_end {
            if !found_segment_addr {
                found_segment_addr = true;
                range_start = i;
            }
        } else if found_segment_addr {
            found_segment_addr = false;
            if (i - range_start) == rodata_size {
                // println!("found rodata segment at 0x{:X}", range_start);
                return Some(RODataOffset {
                    offset: range_start,
                    size: rodata_size,
                });
            }
        }
    }

    None
}

fn find_ends_with_jump_table(
    segment_start: usize,
    segment_end: usize,
    vrom_start: usize,
    vrom_end: usize,
    rodata_size: usize,
    mips_family: MIPSFamily,
    bytes: &[u8],
) -> Option<RODataOffset> {
    let mut found_segment_addr = false;
    let mut last_found_jtable_addr = 0;
    let mut last_offset = 0;

    for i in (0..bytes.len()).step_by(4) {
        if i >= vrom_start && i < vrom_end {
            continue;
        }

        let addr = mips::read_word(&bytes[i..(i + 4)], mips_family) as usize;

        if addr > segment_start && addr < segment_end {
            // println!("found rodata offset: 0x{:X} -> 0x{:X}", i, addr);
            found_segment_addr = true;
            last_found_jtable_addr = addr;
            last_offset = i;
        }
    }

    let rodata_offset = last_offset - rodata_size + 4;

    if found_segment_addr && rodata_offset > 0 && rodata_offset < bytes.len() {
        Some(RODataOffset {
            offset: rodata_offset,
            size: rodata_size,
        })
    } else {
        None
    }
}

// TODO: need size of each function as well
fn find_rodata(
    rodata: &Option<RODataSignature>,
    vram_start: &Option<usize>,
    segment_offset: usize,
    segment_size: usize,
    mips_family: MIPSFamily,
    functions: &HashMap<String, usize>,
    bytes: &[u8],
) -> Option<RODataOffset> {
    let Some(ref rodata) = rodata else {
        return None;
    };

    let Some(vram_start) = vram_start else {
        return None;
    };

    let segment_start = vram_start + segment_offset;
    let segment_end = segment_start + segment_size;

    // println!("looking for rodata in 0x{:X} to 0x{:X}", segment_start, segment_end);

    match rodata.rodataType {
        RODataSignatureType::OnlyJumpTables => find_only_jump_tables(
            segment_start,
            segment_end,
            segment_offset,
            segment_offset + segment_size,
            rodata.size,
            mips_family,
            bytes,
        ),
        RODataSignatureType::EndsWithJumpTable => find_ends_with_jump_table(
            segment_start,
            segment_end,
            segment_offset,
            segment_offset + segment_size,
            rodata.size,
            mips_family,
            bytes,
        ),
        _ => None,
    }
}

fn best_name(names: &Vec<String>) -> Option<String> {
    let mut pop: HashMap<String, usize> = HashMap::new();
    for name in names {
        *pop.entry(name.clone()).or_insert(0) += 1;
    }
    if let Some((name, _)) = pop.iter().max_by_key(|&(_, count)| count) {
        return Some(name).cloned();
    }
    names.first().cloned()
}

pub fn scan<W: Write>(
    match_files: &Vec<PathBuf>,
    bin_file: &PathBuf,
    vram_start: Option<usize>,
    options: &mut Options<W>,
) {
    let mut segment_map: HashMap<SegmentSignature, usize> = HashMap::new();
    let mut name_map: HashMap<u64, Vec<String>> = HashMap::new();
    for match_file in match_files {
        let f = std::fs::File::open(match_file).unwrap();
        for document in serde_yaml::Deserializer::from_reader(io::BufReader::new(f)) {
            let segment = SegmentSignature::deserialize(document).unwrap();
            // TODO: this should only be set once, and it should be checked for consistency
            options.mips_family = segment.family;

            let entry = name_map.entry(segment.fingerprint).or_insert(Vec::new());
            entry.push(segment.name.clone());
            *segment_map.entry(segment).or_insert(0) += 1;
        }
    }

    // prefer segments that are found the most followed by
    // segments with the largest size
    let mut segment_counts = segment_map
        .iter()
        .map(|(k, v)| (k, *v))
        .collect::<Vec<(&SegmentSignature, usize)>>();

    segment_counts.sort_by(|(segment_a, count_a), (segment_b, count_b)| {
        segment_a
            .size
            .cmp(&segment_b.size)
            .reverse()
            .then(count_a.cmp(count_b).reverse())
    });
    let sorted_segments = segment_counts
        .iter()
        .map(|(segment, _)| *segment)
        .collect::<Vec<&SegmentSignature>>();

    // use the most popular name for each segment

    let mut allocated_address_space: HashMap<usize, usize> = HashMap::new();

    let bytes = std::fs::read(bin_file).expect("Could not read bin file");
    let instructions: Vec<u32> = bytes
        .chunks(4)
        .map(|b| mips::bytes_to_normalized_instruction(b, options.mips_family))
        .collect();

    for segment in sorted_segments {
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

        // if this address space is already occupied, ignore
        if address_space_is_used(offset, segment.size, &allocated_address_space) {
            // println!(
            //     "found used address space: {} ({}) {:?}",
            //     offset, segment.size, segment
            // );
            continue;
        }

        allocated_address_space.insert(offset, segment.size);

        let mut map = HashMap::new();

        let mut position = offset;
        let function_len = segment.functions.len();

        for function in segment.functions.iter() {
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
                map.insert(function.name.clone(), function_offset);
            }
        }

        if function_len != map.len() {
            continue;
        }

        let empty_vec = &Vec::<String>::new();
        let names = name_map.get(&segment.fingerprint).unwrap_or(&empty_vec);

        let rodata_match = find_rodata(
            &segment.rodata,
            &vram_start,
            offset,
            segment.size,
            options.mips_family,
            &map,
            &bytes,
        );

        let so = SegmentOffset {
            name: best_name(names).unwrap_or(segment.name.clone()),
            offset,
            size: segment.size,
            rodata: rodata_match,
            symbols: map,
        };

        writeln!(options.writer, "---").expect("Write ocument separator");
        so.serialize_to_yaml(&mut options.writer);
    }
}
