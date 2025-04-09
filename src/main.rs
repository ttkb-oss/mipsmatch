// SPDX-License-Identifier: BSD-3-CLAUSE
use clap::{arg, Arg, Command};
use std::fs::File;
use std::io::{self, Write};
pub mod objmatch;

use objmatch::Options;
use objmatch::evaluate::evaluate;
use objmatch::scan::scan;

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


fn main() {

    let command = Command::new(env!("CARGO_CRATE_NAME"))
        .subcommand(Command::new("evaluate")
            .arg(Arg::new("MAP")
                .help("A GNU Map file"))
            .arg(Arg::new("BIN")
                .help("An overlay file"))
            .about("Create a match file from an existing overlay"))
        .subcommand(Command::new("scan")
            .arg(Arg::new("granularity")
                .short('g')
                .help("The level match granularity should occur (segment, function)"))
            .arg(Arg::new("MATCH-CONFIG"))
            .arg(Arg::new("BIN"))
            .about("Use a match file to find offsets in a new overlay"))
        .subcommand_required(true)
        .arg(Arg::new("output")
            .long("output")
            .short('o')
            .help("Output file for match keys (default: console)")
            .required(false))
       .arg(Arg::new("coefficient")
            .short('c')
            .help("The Rabin-Karp rolling hash coefficient")
            .required(false));

    let matches = command.get_matches();
    // eprintln!("{matches:#?}");

    let mut options = Options {
        coefficient: 0xFFFFFFEF,
        radix: 4294967296,
        writer: match matches.get_one::<String>("output") {
            Some(ref path) => File::create(path).map(|f| Box::new(f) as Box<dyn Write>).unwrap(),
            None => Box::new(io::stdout()),
        },
    };

    match matches.subcommand() {
        Some(("evaluate", cmd)) => {
            // eprintln!("evaluate {cmd:#?}");
            let map_file = cmd.get_one::<String>("MAP").expect("required");
            let bin_file = cmd.get_one::<String>("BIN").expect("required");
            // eprintln!("map {map_file:#?}");
            // eprintln!("bin {bin_file:#?}");

            evaluate(map_file, bin_file, &mut options);
        },
        Some(("scan", cmd)) =>  {
            // eprintln!("match {cmd:#?}");
            let match_file = cmd.get_one::<String>("MATCH-CONFIG").expect("required");
            let bin_file = cmd.get_one::<String>("BIN").expect("required");
            scan(match_file, bin_file, &mut options);
        },
        _ => unreachable!("Invalid command"),
    }
}