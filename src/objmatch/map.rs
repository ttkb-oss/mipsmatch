// SPDX-License-Identifier: BSD-3-CLAUSE

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct FunctionEntry {
    pub name: String,
    pub offset: usize,
    pub vram: usize,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ObjectMap {
    pub object: String,
    pub offset: usize,
    pub vram: usize,
    pub size: usize,
    pub text_symbols: Vec<FunctionEntry>,
}

impl ObjectMap {
    pub fn name(&self) -> &str {
        // this can be done with experimental file_prefix
        // function, but replicating logic here for stable
        Path::new(&self.object)
            .file_name()
            .expect("object name")
            .to_str()
            .unwrap()
            .strip_suffix(".c.o")
            .unwrap()
    }
}

enum EvaluateState {
    Start,
    Entry,
}

pub fn read_segments(map_file: &String) -> Vec<ObjectMap> {
    let file = File::open(map_file).expect("Could not open map file");

    let rom_start_expr = Regex::new(
        r"(?xi)
        ^\s*
        0x([0-9A-F]+)\s+[^\s]+_ROM_START\s=\s
    ",
    )
    .expect("regex");

    let vram_expr = Regex::new(
        r"(?xi)
        ^\s*
        0x([0-9A-F]+)\s+[^\s]+_VRAM\s=\s
    ",
    )
    .expect("regex");

    let segment_expr = Regex::new(
        r"(?xi)
        ^\s[\w\-_.\/]+\.c\.o\(\.([a-z.]+)\)$
    ",
    )
    .expect("regex");

    let mut segments = Vec::<ObjectMap>::new();

    let lines = io::BufReader::new(file).lines();

    let mut state = EvaluateState::Start;
    let mut rom_start: usize = 0xFFFFFFFF;
    let mut vram: usize = 0xFFFFFFFF;

    let mut first = true;
    let mut segment_object = "".to_string();
    let mut segment_size: usize = 0;
    let mut segment_offset: usize = 0;
    let mut segment_symbols = Vec::<FunctionEntry>::new();

    for (i, line) in lines.map_while(Result::ok).enumerate() {
        // eprintln!("{i}: {line}");
        if let Some(capture) = rom_start_expr.captures(&line) {
            // eprintln!("{i}: {line}");
            if let Some(address) = capture.get(1).map(|m| m.as_str().to_string()) {
                rom_start = usize::from_str_radix(address.as_str(), 16).expect("hex string");
                // eprintln!("rom_start {rom_start}")
            }
            continue;
        }

        if let Some(capture) = vram_expr.captures(&line) {
            // eprintln!("{i}: {line}");
            if let Some(address) = capture.get(1).map(|m| m.as_str().to_string()) {
                vram = usize::from_str_radix(address.as_str(), 16).expect("hex string");
            }
            continue;
        }

        if let Some(capture) = segment_expr.captures(&line) {
            if let Some(segment_type) = capture.get(1).map(|m| m.as_str()) {
                // eprintln!("{i} found new segment: {segment_type}");
                match segment_type {
                    "text" => state = EvaluateState::Entry,
                    _ => state = EvaluateState::Start,
                }
            }
            continue;
        }

        // if we're not in a text section, continue
        let EvaluateState::Entry = state else {
            // eprintln!("{i} skipping, wrong state");
            continue;
        };

        // if this is setting vars, continue
        if line.contains(" = ") {
            // eprintln!("{i} skipping, assignment");
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();

        // if this is not a text section, continue
        if parts.len() == 4 && *parts.first().unwrap() != ".text" {
            state = EvaluateState::Start;
            // eprintln!("{i} skipping, resetting state");
            continue;
        }

        if *parts.first().unwrap() == ".text" {
            if !first {
                segments.push(ObjectMap {
                    object: segment_object,
                    offset: segment_offset - vram + rom_start,
                    vram: segment_offset,
                    size: segment_size,
                    text_symbols: segment_symbols,
                });
                segment_symbols = Vec::new();
            }
            first = false;
            segment_offset = usize::from_str_radix(
                parts
                    .get(1)
                    .expect(
                        "segment
            offset",
                    )
                    .strip_prefix("0x")
                    .unwrap(),
                16,
            )
            .expect("segment offset base 16");
            segment_size = usize::from_str_radix(
                parts
                    .get(2)
                    .expect("segment size")
                    .strip_prefix("0x")
                    .unwrap(),
                16,
            )
            .expect("segment size base 16");
            segment_object = parts.get(3).expect("segment object").to_string();

            // eprintln!("{i}: new entry {segment_object} #{segment_offset} #{segment_size}");

            continue;
        }

        let offset = usize::from_str_radix(
            parts
                .first()
                .expect("symbol offset")
                .strip_prefix("0x")
                .expect("symbol value"),
            16,
        )
        .expect("symbol offset base 16");
        let function = parts.get(1).expect("symbol text");

        if function.ends_with(".NON_MATCHING") {
            continue;
        }

        // eprintln!("    -> {function} {offset}");
        segment_symbols.push(FunctionEntry {
            name: function.to_string(),
            vram: offset,
            offset: offset - vram + rom_start,
        });
    }
    segments.push(ObjectMap {
        object: segment_object,
        offset: segment_offset - vram + rom_start,
        vram: segment_offset,
        size: segment_size,
        text_symbols: segment_symbols,
    });

    // eprintln!("segments: {segments:?}")

    segments
}
