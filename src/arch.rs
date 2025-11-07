// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE

use crate::Options;
use std::io::Write;
use std::path::Path;

pub mod mips;
pub mod n64;

pub fn inspect_bin<W: Write>(elf_file: &Path, _options: &mut Options<W>) {
    let file_data = std::fs::read(elf_file).expect("Could not read file.");
    let slice = file_data.as_slice();

    println!("bin format: {:?}", mips::determine_bin_fmt(slice));
}
