// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use crate::map::FunctionEntry;
use elf::endian::AnyEndian;
use elf::section::SectionHeader;
use elf::ElfBytes;
use elf::{self};
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use crate::MIPSFamily;
use crate::Options;

const EF_MIPS_MACH_5900: u32 = 0x00920000;

/// Determines the MIPS family from a given ELF file. This is focused on the
/// PS1, PS2, PSP, and N64 architectures, specifically.
pub fn mips_family(elf_path: &Path) -> Option<MIPSFamily> {
    let file_data = std::fs::read(elf_path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Parse elf file");

    let header = file.ehdr;
    let flags = header.e_flags;

    if header.e_machine == elf::abi::EM_MIPS {
        if (flags & elf::abi::EF_MIPS_MACH) == EF_MIPS_MACH_5900 {
            return Some(MIPSFamily::R5900);
        }

        match flags & elf::abi::EF_MIPS_ARCH {
            elf::abi::EF_MIPS_ARCH_1 => return Some(MIPSFamily::R3000GTE),
            elf::abi::EF_MIPS_ARCH_2 => return Some(MIPSFamily::R4000Allegrex),
            elf::abi::EF_MIPS_ARCH_3 => return Some(MIPSFamily::R4000),
            _ => (),
        }
    }

    return None;
}

pub fn align(offset: usize, alignment: usize) -> usize {
    (offset + alignment - 1) & !(alignment - 1)
}

pub fn bin_data(elf_path: &Path) -> HashMap<usize, Vec<u8>> {
    let file_data = std::fs::read(elf_path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Parse elf file");
    let (shdrs_opt, strtab_opt) = file
        .section_headers_with_strtab()
        .expect("shdrs offsets should be valid");

    let (shdrs, strtab) = (
        shdrs_opt.expect("Should have shdrs"),
        strtab_opt.expect("Should have strtab"),
    );

    // Parse the shdrs and collect them into a map keyed on their zero-copied name
    let program_section_headers: Vec<SectionHeader> = shdrs
        .iter()
        .filter(|shdr| shdr.sh_type == elf::abi::SHT_PROGBITS)
        .filter(|shdr| (shdr.sh_flags as u32 & elf::abi::SHF_EXECINSTR) == elf::abi::SHF_EXECINSTR)
        .filter(|shdr| {
            // n.b.! this check is probably redundant, but headers from GCC
            //       and MetroWorks are marked as `PROGBITS`, but don't
            //       have an executable flag. In case they somehow make it
            //       through, exclude them as well.
            let section_name = strtab.get(shdr.sh_name as usize).unwrap();
            section_name != ".mwo_header" && section_name != ".header"
        })
        // .inspect(|shdr| println!("found section {:?}", shdr))
        .collect();

    // TODO: determine capacity first

    let mut data = HashMap::new();
    for program_section_header in program_section_headers {
        let (section_data, _) = file
            .section_data(&program_section_header)
            .expect("section data");
        data.insert(
            program_section_header.sh_addr as usize,
            section_data.to_vec(),
        );
    }

    data
}

pub struct Symbol {
    pub name: String,
    pub vram: u64,
    pub size: Option<u64>,
    pub vrom: Option<u64>,
    pub align: Option<u64>,
}

pub fn function_symbols(elf_path: &Path) -> Vec<FunctionEntry> {
    let file_data = std::fs::read(elf_path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("valid elf file");

    let (symtab, strtab) = file
        .symbol_table()
        .expect("expected a symbol table")
        .expect("symtab");

    symtab
        .iter()
        .filter(|s| s.st_symtype() == elf::abi::STT_FUNC)
        .map(|s| FunctionEntry {
            name: strtab.get(s.st_name as usize).unwrap().to_string(),
            offset: 0,
            vram: s.st_value as usize,
            size: s.st_size as usize,
        })
        .collect()
}

pub fn inspect_elf<W: Write>(elf_file: &Path, _options: &mut Options<W>) {
    let file_data = std::fs::read(elf_file).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");
    let (shdrs_opt, strtab_opt) = file
        .section_headers_with_strtab()
        .expect("shdrs offsets should be valid");

    println!("elf: {:?}", shdrs_opt);
    println!("elf: {:?}", strtab_opt);

    let (shdrs, strtab) = (
        shdrs_opt.expect("Should have shdrs"),
        strtab_opt.expect("Should have strtab"),
    );

    // unused section header
    shdrs
        .iter()
        .filter(|shdr| shdr.sh_type != elf::abi::SHT_NULL)
        .inspect(|shdr| {
            println!(
                "section: {} type: {}",
                strtab.get(shdr.sh_name as usize).unwrap(),
                shdr.sh_type
            );
            println!("    flags: {}", shdr.sh_flags);
            println!("    addr: {:08x}", shdr.sh_addr);
            println!("    offset: {:08x}", shdr.sh_offset);
            println!("    size: {}", shdr.sh_size);
            println!("    link: {}", shdr.sh_link);
            println!("    info: {}", shdr.sh_info);
            println!("    addralign: {}", shdr.sh_addralign);
            println!("    entsize: {}", shdr.sh_entsize);
            println!("------------------------------");
        })
        .last()
        .unwrap();

    // Parse the shdrs and collect them into a map keyed on their zero-copied name
    let section_header: SectionHeader = shdrs
        .iter()
        .filter(|shdr| shdr.sh_type == elf::abi::SHT_PROGBITS)
        .inspect(|shdr| {
            println!(
                "section: {} type: {}",
                strtab.get(shdr.sh_name as usize).unwrap(),
                shdr.sh_type
            );
            println!("    flags: {}", shdr.sh_flags);
            println!("    addr: {:08x}", shdr.sh_addr);
            println!("    offset: {:08x}", shdr.sh_offset);
            println!("    size: {}", shdr.sh_size);
            println!("    link: {}", shdr.sh_link);
            println!("    info: {}", shdr.sh_info);
            println!("    addralign: {}", shdr.sh_addralign);
            println!("    entsize: {}", shdr.sh_entsize);
        })
        .next()
        .unwrap();

    // we have the right section
    println!(
        "found section: {}",
        strtab.get(section_header.sh_name as usize).unwrap()
    );

    //// Get the zero-copy parsed type for the the build id note
    //let build_id_note_shdr: &SectionHeader = with_names
    //    .get(".tt_004")
    //    .expect("Should have build id note section");

    // we have the right data
    let (data, _) = file.section_data(&section_header).expect("section data");
    println!("{:?}", data.len());

    let (symtab, strtab) = file.symbol_table().unwrap().expect("symtab");

    for (i, sym) in symtab
        .iter()
        .filter(|s| s.st_symtype() == elf::abi::STT_FILE)
        .enumerate()
    {
        // if sym.st_value == 991 {
        println!("{:<4}: FILE name: {:<30} shndx: {} value: {:08x} size: {} undef: {} type: {}: bind: {}, vis: {}",
            i,
            strtab.get(sym.st_name as usize).unwrap(),
            sym.st_shndx,
            sym.st_value,
            sym.st_size,
            sym.is_undefined(),
            sym.st_symtype(),
            sym.st_bind(),
            sym.st_vis());
        // }
    }

    for (i, sym) in symtab
        .iter()
        /* .filter(|s| s.st_shndx != SHNDX_EXTERNAL) */
        .filter(|s| s.st_symtype() == elf::abi::STT_FUNC)
        .enumerate()
    {
        // if sym.st_value == 991 {
        println!("{:<4}: name: {:<30} shndx: {} value: {:08x} size: {} undef: {} type: {}: bind: {}, vis: {}",
            i,
            strtab.get(sym.st_name as usize).unwrap(),
            sym.st_shndx,
            sym.st_value,
            sym.st_size,
            sym.is_undefined(),
            sym.st_symtype(),
            sym.st_bind(),
            sym.st_vis());
        // }
    }
}
