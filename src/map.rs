// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use mapfile_parser::MapFile;
use serde::{Deserialize, Serialize};
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

fn symbols_to_segment_symbols(
    vram: usize,
    offset: usize,
    size: usize,
    symbols: &[(usize, String)],
) -> Vec<FunctionEntry> {
    let mut entries: Vec<FunctionEntry> = symbols
        .iter()
        .filter(|(addr, _)| *addr >= offset && *addr < (offset + size))
        .map(|(addr, name)| FunctionEntry {
            name: name.to_string(),
            vram: *addr,
            offset: *addr - vram,
        })
        .collect();
    entries.sort_by(|a, b| a.vram.cmp(&b.vram));
    entries
}

pub fn read_segments(map_file: &Path, function_symbols: Vec<(usize, String)>) -> Vec<ObjectMap> {
    MapFile::new_from_map_file(map_file)
        .filter_by_section_type(".text")
        .segments_list
        .iter()
        .flat_map(|segment| {
            segment
                .files_list
                .iter()
                .map(|file| {
                    let segment_object = file.filepath.to_str().unwrap();
                    ObjectMap {
                            object: segment_object.to_string(),
                            offset: file.vrom.unwrap() as usize,
                            vram: file.vram as usize,
                            size: file.size as usize,
                            text_symbols: symbols_to_segment_symbols(
                                segment.vram as usize,
                                file.vram as usize,
                                file.size as usize,
                                &function_symbols),
                    }
                })
        })
        .collect::<Vec<_>>()
}
