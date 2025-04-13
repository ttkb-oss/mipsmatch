use mipsmatch::scan::SegmentSignature;
use mipsmatch::Options;
use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};

use mipsmatch::elf;

#[test]
fn test_tt_004() {
    let elf_file = std::path::Path::new("tests/data/tt_004.elf");
    let elf_symbols = elf::function_symbols(elf_file);

    assert_eq!(elf_symbols.len(), 5);

    let lookup: HashMap<String, usize> = elf_symbols
        .iter()
        .map(|(addr, name)| (name.clone(), *addr))
        .collect();

    assert_eq!(*lookup.get("hello_world").unwrap(), 0x80170998 as usize);
    assert_eq!(*lookup.get("goodbye_world").unwrap(), 0x80170988 as usize);
    assert_eq!(*lookup.get("local_function").unwrap(), 0x80170A08 as usize);
    assert_eq!(*lookup.get("global_function").unwrap(), 0x80170A18 as usize);
    assert_eq!(
        *lookup.get("global_function_2").unwrap(),
        0x80170A38 as usize
    );
}
