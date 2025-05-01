// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use mapfile_parser::MapFile;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, BufRead};
use std::io::Read;
use std::path::Path;
use std::cell::LazyCell as Lazy;

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

#[derive(Debug)]
enum Section {
    Unknown,
    DiscardedInput,
    MemoryConfiguration,
    LinkerScript,
}

#[derive(Debug)]
enum EvaluateState {
    Start,
    Entry,
}

pub trait MapVisitor {
    fn enter_section<E>(&self, section: Section) -> Result<(), E> {
        Ok(())
    }
    fn exit_section<E>(&self, section: Section) -> Result<(), E> {
        Ok(())
    }

    fn unknown_line<E>(&self, line: &String) -> Result<(), E> {
        Ok(())
    }

    fn discarded_input<E>(&self, line: &String) -> Result<(), E> {
        Ok(())
    }

    fn memory_configuration<E>(&self, line: &String) -> Result<(), E> {
        Ok(())
    }

    fn linker_script<E>(&mut self, line: &String) -> Result<(), E> {
        Ok(())
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

// fn merge_entries_with_symbols(vram: usize, offset: usize, size: usize, entries: Vec<FunctionEntry>, symbols: Vec<(u32, String)> -> Vec<FunctionEntry> {
//     let mut segment_symbols = symbols.iter().filter(|(addr, name)|
//         let func_offset = addr - vram;
//         func_offset >= offset && func_offset < (offset + size)
//         ).sort(|(a, _), (b, _)| a <=> b)
//         .collect();
//
//     let mut i = 0;
//     let mut j = 0;
//
//     while segment_symbols.len() > 0 {
//     }
// }

fn section_marker(line: &String) -> Option<Section> {
    match line.trim() {
    "Discarded input sections" => Some(Section::DiscardedInput),
    "Memory Configuration" => Some(Section::MemoryConfiguration),
    "Linker script and memory map" => Some(Section::LinkerScript),
    _ => None,
    }
}


pub fn using_mapfile_parser(map_file: &Path, function_symbols: &Vec<(usize, String)>) -> Vec<ObjectMap> {
    let mapfile_parser = MapFile::new_from_map_file(map_file)
        .filter_by_section_type(".text");

    let mut segments = Vec::new();
    for segment in mapfile_parser.segments_list.iter() {
        println!("new segment: {}", segment.name);
        println!("\tvram: {}", segment.vram);
        println!("\tsize: {}", segment.size);
        println!("\tvrom: {}", segment.vrom);
        println!("\talign: {:?}", segment.align);
        println!("\tfiles:");

        for file in segment.files_list.iter() {
            let segment_object = file.filepath.to_str().unwrap();
            println!("\t - {}", segment_object);
            println!("\t   vram: {:x}", file.vram);
            println!("\t   size: {:x}", file.size);
            println!("\t   type: {}", file.section_type);
            println!("\t   vrom: {:x}", file.vrom.unwrap());
            println!("\t   align: {:?}", file.align);
            println!("\t   symbols:");


            for symbol in file.symbols.iter() {
                println!("\t\t - name: {}", symbol.name);
                println!("\t\t   vram: 0x{:x}", symbol.vram);
                println!("\t\t   size: {:x?}", symbol.size);
                println!("\t\t   vrom: {:?}", symbol.vrom);
                println!("\t\t   align: {:?}", symbol.align);
            }

                println!("mapfile segment symbols: {}, {}, {}",
                    segment.vram,
                    file.vram,
                    file.size);

            segments.push(ObjectMap {
                object: segment_object.to_string(),
                offset: file.vrom.unwrap() as usize,
                vram: file.vram as usize,
                size: file.size as usize,
                text_symbols: symbols_to_segment_symbols(
                    segment.vram as usize,
                    file.vram as usize,
                    file.size as usize,
                    &function_symbols),
            });

        }
    }

    segments
}

pub fn read_segments(map_file: &Path, function_symbols: Vec<(usize, String)>) -> Vec<ObjectMap> {
    let file = File::open(map_file).expect("Could not open map file");
    let mut reader = io::BufReader::new(file);

    let mut section = Section::Unknown;

    while true {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Err(_) => break,
            Ok(size) => {
                println!("read {}", line);

                match section_marker(&line) {
                Some(Section::DiscardedInput) => {
                    section = Section::DiscardedInput;
                    section = handle_discarded_inputs(&mut reader);

                }
                Some(Section::MemoryConfiguration) => {
                    section = Section::MemoryConfiguration;
                    section = handle_memory_configuration(&mut reader);

                }
                Some(Section::LinkerScript) => section = Section::LinkerScript,
                _ => {
                    match section {
                    Section::LinkerScript => {
                        let now = Instant::now();
                        let vec_map = handle_linker_script(&mut reader, &function_symbols);
                        let alt_map = using_mapfile_parser(map_file, &function_symbols);
                        if vec_map != alt_map {
                            println!("vec_map: {:?}", vec_map);
                            println!("alt_map: {:?}", alt_map);
                            panic!("error!");
                        }
                        return vec_map;
                    },
                    _ => {
                        println!("not part of the linker script: {}", line);
                    }
                    }
                }
                }
            }
        }
    }

    Vec::new()
}

fn handle_discarded_inputs<R: Read + BufRead>(reader: &mut R) -> Section {
    while true {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Err(_) => break,
            Ok(size) => {
                if let Some(section) = section_marker(&line) {
                    return section;
                }

                // TODO: handle discarded inputs
            }
        }
    }
    Section::DiscardedInput
}

fn handle_memory_configuration<R: Read + BufRead>(reader: &mut R) -> Section {
    while true {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Err(_) => break,
            Ok(size) => {
                if let Some(section) = section_marker(&line) {
                    return section;
                }

                // TODO: memory configuration
            }
        }
    }
    Section::MemoryConfiguration
}

struct LinkerScriptVisitor {
    segments: Vec::<ObjectMap>,
    function_symbols: Vec<(usize, String)>,
    state: EvaluateState,
    rom_start: usize,
    vram: usize,

    first: bool,
    segment_object: String,
    segment_size: usize,
    segment_offset: usize,
}

impl LinkerScriptVisitor {
    fn new<'a>(function_symbols: Vec<(usize, String)>) -> Self {
        Self {
            segments: Vec::<ObjectMap>::new(),
            function_symbols: function_symbols,
            state: EvaluateState::Start,
            rom_start: 0xFFFFFFFF,
            vram: 0xFFFFFFFF,
            first: true,
            segment_object:  "".to_string(),
            segment_size: 0,
            segment_offset: 0,
        }

    }
}

impl MapVisitor for LinkerScriptVisitor {


    fn linker_script<E>(&mut self, line: &String) -> Result<(), E> {

        let rom_start_expr: Lazy<Regex> = Lazy::new(||
            Regex::new(
                r"(?xi)
                ^\s*
                0x[0]*([0-9A-F]+)\s+[^\s]+_ROM_START\s=\s
            ",
            )
            .expect("regex"));

        let vram_expr: Lazy<Regex> = Lazy::new(|| Regex::new(
            r"(?xi)
            ^\s*
            0x[0]*([0-9A-F]+)\s+[^\s]+?(_bss)?_VRAM\s=\s
        ",
        )
        .expect("regex"));

        let segment_expr: Lazy<Regex> = Lazy::new(|| Regex::new(
            r"(?xi)
            ^\s[\w\-_.\/]+\.c\.o\(\.([a-z.]+)\)$
        ",
        )
        .expect("regex"));

        if let Some(capture) = rom_start_expr.captures(&line) {
            if let Some(address) = capture.get(1).map(|m| m.as_str().to_string()) {
                self.rom_start = usize::from_str_radix(address.as_str(), 16).expect("hex string");
                println!("rom start: {} {}", address.as_str(), self.rom_start);
            }
            return Ok(());
        }

        if let Some(capture) = vram_expr.captures(&line) {
            if let Some(address) = capture.get(1).map(|m| m.as_str().to_string()) {
                if let Some(bss) = capture.get(2).map(|m| m.as_str().to_string()) {
                    if  bss == "_bss" {
                        return Ok(());
                    }
                }
                self.vram = usize::from_str_radix(address.as_str(), 16).expect("hex string");
                println!("vram start: {} {}", address, self.vram);
            }
            return Ok(());
        }

        if let Some(capture) = segment_expr.captures(&line) {
            if let Some(segment_type) = capture.get(1).map(|m| m.as_str()) {
                match segment_type {
                    "text" => self.state = EvaluateState::Entry,
                    _ => self.state = EvaluateState::Start,
                }
            }
            return Ok(());
        }

        // if we're not in a text section, continue
        let EvaluateState::Entry = self.state else {
            return Ok(());
        };

        // if this is setting vars, continue
        if line.contains(" = ") {
            return Ok(());
        }

        let parts: Vec<&str> = line.split_whitespace().collect();

        // if this is not a text section, continue
        if parts.len() == 4 && *parts.first().unwrap() != ".text" {
            self.state = EvaluateState::Start;
            return Ok(());
        }

        // if this is a text section, we're starting a new segment
        if *parts.first().unwrap() == ".text" {
            if !self.first {
                let segment_symbols = symbols_to_segment_symbols(
                    self.vram - self.rom_start,
                    self.segment_offset,
                    self.segment_size,
                    &self.function_symbols,
                );

                println!("parser segment symbols: {}, {}, {}",
                    self.vram - self.rom_start,
                    self.segment_offset,
                    self.segment_size);


                self.segments.push(ObjectMap {
                    object: self.segment_object.clone(),
                    offset: self.segment_offset - self.vram + self.rom_start,
                    vram: self.segment_offset,
                    size: self.segment_size,
                    text_symbols: segment_symbols,
                });
            }
            self.first = false;
            self.segment_offset = usize::from_str_radix(
                parts
                    .get(1)
                    .expect("segment offset")
                    .strip_prefix("0x")
                    .unwrap(),
                16,
            )
            .expect("segment offset base 16");
            self.segment_size = usize::from_str_radix(
                parts
                    .get(2)
                    .expect("segment size")
                    .strip_prefix("0x")
                    .unwrap(),
                16,
            )
            .expect("segment size base 16");
            self.segment_object = parts.get(3).expect("segment object").to_string();

            return Ok(())
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
            return Ok(());
        }

        // TODO: cross check map and elf symbols?
        // segment_symbols.push(FunctionEntry {
        //     name: function.to_string(),
        //     vram: offset,
        //     offset: offset - vram + rom_start,
        // });

        Ok(())
    }

}

pub fn handle_linker_script<R: Read + BufRead>(reader: &mut R, function_symbols: &Vec<(usize, String)>) -> Vec<ObjectMap> {

    let mut visitor = LinkerScriptVisitor::new(function_symbols.clone());

    let lines = reader.lines();

    for (_i, line) in lines.map_while(Result::ok).enumerate() {
        // TODO: how do generic errors work?
        visitor.linker_script::<i32>(&line);
    }

    let segment_symbols = symbols_to_segment_symbols(
        visitor.vram - visitor.rom_start,
        visitor.segment_offset,
        visitor.segment_size,
        &function_symbols,
    );

    visitor.segments.push(ObjectMap {
        object: visitor.segment_object,
        offset: visitor.segment_offset - visitor.vram + visitor.rom_start,
        vram: visitor.segment_offset,
        size: visitor.segment_size,
        text_symbols: segment_symbols,
    });

    visitor.segments
}
