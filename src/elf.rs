// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use crate::map::FunctionEntry;
use elf::endian::AnyEndian;
use elf::section::SectionHeader;
use elf::ElfBytes;
use std::io::Write;
use std::path::Path;

use crate::MIPSFamily;
use crate::Options;

pub const SHNDX_EXTERNAL: u16 = 65521;

// At least one .noreorder assembly directive appeared in a source contributing to the object
pub const EF_MIPS_NOREORDER: u32 = 0x00000001;

// This file contains position-independent code
pub const EF_MIPS_PIC: u32 = 0x00000002;

// This file’s code follows standard conventions for calling position-independent code
pub const EF_MIPS_CPIC: u32 = 0x00000004;

// This file contains UCODE (obsolete)
pub const EF_MIPS_UCODE: u32 = 0x00000010;
// This file follows the MIPS III 32-bit ABI. (Its EI_CLASS will be ELFCLASS32.)
pub const EF_MIPS_ABI2: u32 = 0x00000020;

// This .MIPS.options section in this file contains one or more descriptors, currently types ODK_GP_GROUP and/or
// ODK_IDENT,
// which should be processed first by ld.
pub const EF_MIPS_OPTIONS_FIRST: u32 = 0x00000080;

// Application-specific architectural extensions used by this object file
pub const EF_MIPS_ARCH_ASE: u32 = 0x0f000000;
// Uses MDMX multimedia extensions
pub const EF_MIPS_ARCH_ASE_MDMX: u32 = 0x08000000;
// Uses MIPS-16 ISA extensions
pub const EF_MIPS_ARCH_ASE_M16: u32 = 0x04000000;

// Architecture assumed by code in this file, given by the value of the 4-bit field selected by the mask
pub const EF_MIPS_ARCH: u32 = 0xf0000000;
pub const EF_MIPS_ARCH_I: u32 = 0x00000000;
pub const EF_MIPS_ARCH_II: u32 = 0x10000000;
pub const EF_MIPS_ARCH_III: u32 = 0x20000000;
pub const EF_MIPS_ARCH_IV: u32 = 0x30000000;

pub fn mips_family(elf_path: &Path) -> Option<MIPSFamily> {
    let file_data = std::fs::read(elf_path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Parse elf file");

    let header = file.ehdr;
    let flags = header.e_flags;

    if header.e_machine == elf::abi::EM_MIPS {
        if (flags & EF_MIPS_ARCH) == EF_MIPS_ARCH_I {
            return Some(MIPSFamily::R3000GTE);
        } else if (flags & EF_MIPS_ARCH) == EF_MIPS_ARCH_II {
            return Some(MIPSFamily::R4000Allegrex);
        }
    }

    return None;
}

pub fn bin_data(elf_path: &Path) -> Vec<u8> {
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
    let program_section_header: SectionHeader = shdrs
        .iter()
        .filter(|shdr| shdr.sh_type == elf::abi::SHT_PROGBITS)
        .filter(|shdr| (shdr.sh_flags as u32 & elf::abi::SHF_EXECINSTR) == elf::abi::SHF_EXECINSTR)
        .filter(|shdr| {
            // n.b.! this check is probably redundant, but headers from GCC
            //       and MetroWorks are marked as `PROGBITS`, but don't
            //       have an executable flag. In case they somehow make it
            //       through, exclude them as well.
            let section_name = strtab.get(shdr.sh_name as usize).unwrap();
            section_name != ".mwo_header" &&
                section_name != ".header"
        })
        .next()
        .expect("Expected one PROGBITS section");

    // we have the right data
    let (data, _) = file
        .section_data(&program_section_header)
        .expect("section data");

    data.to_vec()
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
        /* .filter(|s| s.st_shndx != SHNDX_EXTERNAL) */
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
