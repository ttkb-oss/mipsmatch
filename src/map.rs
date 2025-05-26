// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use itertools::Itertools;
use mapfile_parser::MapFile;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct FunctionEntry {
    pub name: String,
    pub offset: usize,
    pub vram: usize,
    pub size: usize,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ObjectMap {
    pub object: String,
    pub offset: usize,
    pub vram: usize,
    pub vrom: usize,
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
            .trim_end_matches(".c.o")
    }
}

fn symbols_to_segment_symbols(
    vram: usize,
    vrom_offset: usize,
    offset: usize,
    size: usize,
    symbols: &[FunctionEntry],
) -> Vec<FunctionEntry> {
    let mut entries: Vec<FunctionEntry> = symbols
        .iter()
        .filter(|entry| entry.vram >= offset && entry.vram < (offset + size))
        .map(|entry| FunctionEntry {
            name: entry.name.clone(),
            vram: entry.vram,
            offset: entry.vram - vram + vrom_offset,
            size: entry.size,
        })
        .collect();
    entries.sort_by(|a, b| a.vram.cmp(&b.vram));
    entries
}

// Params:
//   - map_file: path
//   - section_type: type name like ".text", ".rodata", etc.
pub fn read_segments(
    map_file: &Path,
    section_type: &str,
    function_symbols: Vec<FunctionEntry>,
) -> Vec<ObjectMap> {
    MapFile::new_from_map_file(map_file)
        .filter_by_section_type(section_type)
        .segments_list
        .iter()
        .flat_map(|segment| {
            segment
                .files_list
                .iter()
                // .inspect(|file| println!("file: {:?}", file))
                .filter(|file| file.filepath.to_str().unwrap().ends_with(".c.o"))
                .chunk_by(|file| file.filepath.clone())
                .into_iter()
                .map(|(filepath, files)| {
                    // println!("file: {}", filepath.display());
                    let files = files.collect::<Vec<_>>();
                    let (segment_offset, segment_vram) = files
                        .first()
                        .map(|file| (file.vrom.unwrap() as usize, file.vram as usize))
                        .unwrap();
                    let last = files.last().unwrap();

                    let segment_size = (last.vram + last.size) as usize - segment_vram;
                    // println!("\testimated sizes: {:x} {:x} {}", segment_offset, segment_vram, segment_size);

                    // println!("\tfunction sizes:");
                    let text_symbols = files
                        .iter()
                        // .inspect(|file|
                        // println!("symbols: {:?}", file.symbols))
                        // .inspect(|file|
                        // println!("\t\t{:x} {:x} {:x}", segment.vram, file.vram, file.size))
                        .flat_map(|file| {
                            symbols_to_segment_symbols(
                                segment.vram as usize,
                                segment.vrom as usize,
                                file.vram as usize,
                                file.size as usize,
                                &function_symbols,
                            )
                        })
                        .collect::<Vec<_>>();

                    // println!("segment vrom: {}", segment.vrom);

                    ObjectMap {
                        object: filepath.to_str().unwrap().to_string(),
                        offset: segment_offset,
                        vram: segment_vram,
                        vrom: segment.vrom as usize,
                        size: segment_size,
                        text_symbols,
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
}
