// SPDX-License-Identifier: BSD-3-CLAUSE
use clap::{arg, Arg, Command};
use serde::{Deserialize, Serialize};
use serde_with::{self, serde_as};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};

pub mod arch;
pub mod elf;
pub mod evaluate;
pub mod map;
pub mod scan;

use elf::elf;
use evaluate::evaluate;
use scan::scan;

/*
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = "\n
Finds common sections of code and provides offsets for well known code segments.

Usage:

    sotn-match evaluate [map] [bin] ...
    sotn-match match [match-file] [bin] ...
")]
struct Args {
}
*/

pub struct Options<W: Write> {
    pub modulus: u64,
    pub radix: u64,
    pub writer: W,
}

impl<W: Write> Options<W> {
    /// Create a new `Options` object.
    pub fn new(writer: W) -> Self {
        Self {
            modulus: 0xFFFFFFEF,
            radix: 4294967296,
            writer,
        }
    }
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct FunctionSignature {
    pub name: String,
    // #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
    pub signature: u64,
    pub size: usize,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct SegmentSignature {
    pub name: String,
    // #[serde_as(as = "serde_with::hex::Hex<serde_with::formats::Uppercase>")]
    pub signature: u64,
    pub size: usize,
    pub functions: Vec<FunctionSignature>,
}

#[serde_as]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct SegmentOffset {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub symbols: HashMap<String, usize>,
}
pub fn mipsmatch_main() {
    let command = Command::new(env!("CARGO_CRATE_NAME"))
        .subcommand(
            Command::new("evaluate")
                .arg(Arg::new("MAP").help("A GNU Map file"))
                .arg(Arg::new("ELF").help("An overlay elf file"))
                .about("Create a match file from an existing overlay"),
        )
        .subcommand(
            Command::new("scan")
                .arg(
                    Arg::new("granularity")
                        .short('g')
                        .help("The level match granularity should occur (segment, function)"),
                )
                .arg(Arg::new("MATCH-CONFIG"))
                .arg(Arg::new("BIN"))
                .about("Use a match file to find offsets in a new overlay"),
        )
        .subcommand(
            Command::new("elf")
                .arg(Arg::new("ELF"))
                .about("Test target for elf files."),
        )
        .subcommand_required(true)
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .help("Output file for match keys (default: console)")
                .required(false),
        )
        .arg(
            Arg::new("modulus")
                .short('q')
                .help("The Rabin-Karp rolling hash modulus")
                .required(false),
        );

    let matches = command.get_matches();
    // eprintln!("{matches:#?}");

    let mut options = Options::new(match matches.get_one::<String>("output") {
        Some(ref path) => File::create(path)
            .map(|f| Box::new(f) as Box<dyn Write>)
            .unwrap(),
        None => Box::new(io::stdout()),
    });

    match matches.subcommand() {
        Some(("evaluate", cmd)) => {
            // eprintln!("evaluate {cmd:#?}");
            let map_file = cmd.get_one::<String>("MAP").expect("required");
            let elf_file = cmd.get_one::<String>("ELF").expect("required");

            evaluate(map_file, elf_file, &mut options);
        }
        Some(("scan", cmd)) => {
            // eprintln!("match {cmd:#?}");
            let match_file = cmd.get_one::<String>("MATCH-CONFIG").expect("required");
            let bin_file = cmd.get_one::<String>("BIN").expect("required");
            scan(match_file, bin_file, &mut options);
        }
        Some(("elf", cmd)) => {
            let elf_file = cmd.get_one::<String>("ELF").expect("required");
            elf(elf_file, &mut options);
        }
        _ => unreachable!("Invalid command"),
    }
}
