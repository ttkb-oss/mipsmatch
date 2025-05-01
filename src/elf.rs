// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use elf::endian::AnyEndian;
use elf::section::SectionHeader;
use elf::ElfBytes;
use std::io::Write;
use std::path::Path;

use crate::Options;

pub const SHNDX_EXTERNAL: u16 = 65521;

pub fn bin_data(elf_path: &Path) -> Vec<u8> {
    let file_data = std::fs::read(elf_path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");
    let shdrs = file
        .section_headers()
        .expect("shdrs offsets should be valid");

    // Parse the shdrs and collect them into a map keyed on their zero-copied name
    let program_section_header: SectionHeader = shdrs
        .iter()
        .find(|shdr| shdr.sh_type == elf::abi::SHT_PROGBITS)
        .expect("Expected one PROGBITS section");

    // we have the right data
    let (data, _) = file
        .section_data(&program_section_header)
        .expect("section data");

    data.to_vec()
}

pub fn function_symbols(elf_path: &Path) -> Vec<(usize, String)> {
    let file_data = std::fs::read(elf_path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("valid elf file");

    let (symtab, strtab) = file
        .symbol_table()
        .expect("expected a symbol table")
        .expect("symtab");

    symtab
        .iter()
        /* .filter(|s| s.st_shndx != SHNDX_EXTERNAL) */
        .filter(|s| s.st_symtype() == elf::abi::STT_FUNC)
        .map(|s| {
            (
                s.st_value as usize,
                strtab.get(s.st_name as usize).unwrap().to_string(),
            )
        })
        .collect()
}

pub fn inspect_elf<W: Write>(elf_file: &Path, options: &mut Options<W>) {
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

    let unused_section_header: SectionHeader = shdrs
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
