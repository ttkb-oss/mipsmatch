// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_num::maybe_hex;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::arch::inspect_bin;
use crate::elf::inspect_elf;
use crate::fingerprint::{self, fingerprint};
use crate::scan::scan;
use crate::Options;

/// Finds common sections of code and provides offsets for well known code segments.
#[derive(Debug, Parser)]
#[clap(name = env!("CARGO_CRATE_NAME"), version)]
pub struct App {
    #[clap(flatten)]
    global_opts: GlobalOpts,

    #[clap(subcommand)]
    command: CLICommand,
}

#[derive(Debug, Subcommand)]
enum CLICommand {
    /// Create a fingerprint file from existing map and elf files
    Fingerprint {
        /// A GNU Map file
        map: PathBuf,
        /// An overlay elf file
        elf: PathBuf,
    },

    /// Use a fingerprint file to find offsets in a new overlay
    Scan {
        /// The level match granularity should occur (segment, function)
        #[clap(short, long, value_enum, default_value_t = Granularity::All)]
        granularity: Granularity,

        /// The location the inspected binary would be loaded in VRAM. Required for
        /// searching for DATA and RODATA segments
        #[clap(short, long="vram-start", value_parser=maybe_hex::<usize>)]
        vram_start: Option<usize>,

        #[arg(required=true, num_args=1..)]
        match_config: Vec<PathBuf>,
        bin: PathBuf,
    },

    /// Test target for ELF files
    Elf { elf: PathBuf },

    /// Inspect bin files
    Bin { bin: PathBuf },
}

#[derive(ValueEnum, Clone, Default, Debug)]
enum Granularity {
    #[default]
    All,
    Segment,
    Function,
}

#[derive(Debug, Args)]
struct GlobalOpts {
    // /// Verbosity level (can be specified multiple times)
    // #[clap(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: Option<usize>,

    /// Output file for match keys (default: console)
    #[clap(long, short, global = true)]
    output: Option<PathBuf>,

    /// The Rabin-Karp rolling hash modulus
    #[clap(long, short = 'q', global = true, default_value_t = fingerprint::MODULUS_V0)]
    modulus: u64,
}

pub fn main() {
    let args = App::parse();

    let mut options = Options::new(match args.global_opts.output {
        Some(ref path) => File::create(path)
            .map(|f| Box::new(f) as Box<dyn Write>)
            .unwrap(),
        None => Box::new(io::stdout()),
    });

    match args.command {
        CLICommand::Fingerprint { map, elf } => {
            fingerprint(&map, &elf, &mut options);
        }
        CLICommand::Scan {
            granularity: _,
            vram_start,
            match_config,
            bin,
        } => {
            scan(&match_config, &bin, vram_start, &mut options);
        }
        CLICommand::Elf { elf } => {
            inspect_elf(&elf, &mut options);
        }
        CLICommand::Bin { bin } => {
            inspect_bin(&bin, &mut options);
        }
    }
}
