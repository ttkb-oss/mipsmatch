// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::elf::inspect_elf;
use crate::evaluate::evaluate;
use crate::scan::scan;
use crate::Options;

/// Finds common sectoins of code and provides offsets for well known code segments.
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
    /// Create a match file from an existing overlay
    Evaluate {
        /// A GNU Map file
        map: PathBuf,
        /// An overlay elf file
        elf: PathBuf,
    },
    /// Use a match file to find offsets in a new overlay
    Scan {
        /// The level match granularity should occur (segment, function)
        #[clap(short, long, value_enum, default_value_t = Granularity::All)]
        granularity: Granularity,

        match_config: PathBuf,
        bin: Vec<PathBuf>,
    },
    /// Test target for ELF files
    Elf { elf: PathBuf },
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
    #[clap(long, short = 'q', global = true, default_value_t = 0xFFFFFFEF)]
    modulus: u32,
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
        CLICommand::Evaluate { map, elf } => {
            evaluate(&map, &elf, &mut options);
        }
        CLICommand::Scan {
            granularity: _,
            match_config,
            bin,
        } => {
            scan(&match_config, bin, &mut options);
        }
        CLICommand::Elf { elf } => {
            inspect_elf(&elf, &mut options);
        }
    }
}
