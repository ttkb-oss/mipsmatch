// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use mipsmatch::fingerprint::{Fingerprint, FingerprintV0};
use mipsmatch::MIPSFamily;
use mipsmatch::Options;
use mipsmatch::SegmentSignature;
use serde::Deserialize;
use serde_yaml::{self};
use std::io::{self, Cursor, Write};
use std::path::Path;
use std::str::FromStr;

// PS1
#[test]
fn test_tt_004() {
    let buff = Cursor::new(Vec::new());

    let mut options = Options::new(buff);

    mipsmatch::fingerprint::fingerprint(
        &Path::new("tests/data/tt_004.map"),
        &Path::new("tests/data/tt_004.elf"),
        &mut options,
    );

    let config = String::from_utf8(options.writer.into_inner()).unwrap();

    println!("cursor: {}", config);
    io::stdout().flush().unwrap();

    let mut i = 0;
    for document in serde_yaml::Deserializer::from_str(config.as_str()) {
        let segment = SegmentSignature::deserialize(document).unwrap();

        println!("doc: {:?}", segment);
        io::stdout().flush().unwrap();

        match i {
            0 => assert_sword(&segment),
            1 => assert_servant_common(&segment),
            _ => (),
        }
        i += 1;
    }

    assert_eq!(i, 2);
}

/*
---
name: sword
fingerprint: urn:decomp:match:fingerprint:0:128:344d1662
size: 0x80
family: R3000GTE
rodata:
  rodataType: EndsWithJumpTable
  size: 0x34
functions:
- name: goodbye_world
  fingerprint: urn:decomp:match:fingerprint:0:12:2a8404ae
  size: 0x10
- name: hello_world
  fingerprint: urn:decomp:match:fingerprint:0:108:ea138192
  size: 0x70
*/
fn assert_sword(segment: &SegmentSignature) {
    assert_eq!(segment.name, "sword");
    assert_eq!(segment.family, MIPSFamily::R3000GTE);
    assert_eq!(segment.fingerprint, Fingerprint::new_v0(128, 0x344d1662));
    assert_eq!(segment.size, 128);
    assert_eq!(segment.functions.len(), 2);

    let f0 = segment.functions.get(0).expect("functions[0]");
    assert_eq!(f0.name, "goodbye_world");
    assert_eq!(f0.fingerprint, Fingerprint::new_v0(16, 0xd2c44fb0));

    let f1 = segment.functions.get(1).expect("functions[1]");
    assert_eq!(f1.name, "hello_world");
    assert_eq!(f1.fingerprint, Fingerprint::new_v0(112, 0x8b4b9bb1));
}

/*
name: servant_common
fingerprint: urn:decomp:match:fingerprint:0:84:418d4b82
size: 0x54
family: R3000GTE
functions:
- name: local_function
  fingerprint: urn:decomp:match:fingerprint:0:16:3ac45786
  size: 0x10
- name: global_function
  fingerprint: urn:decomp:match:fingerprint:0:32:efff170e
  size: 0x20
- name: global_function_2
  fingerprint: urn:decomp:match:fingerprint:0:36:43e9eef6
  size: 0x24
*/
fn assert_servant_common(segment: &SegmentSignature) {
    assert_eq!(segment.name, "servant_common");
    assert_eq!(segment.family, MIPSFamily::R3000GTE);
    assert_eq!(segment.fingerprint, Fingerprint::new_v0(84, 0x418d4b82));
    assert_eq!(segment.size, 84);
    assert_eq!(segment.functions.len(), 3);

    let f0 = segment.functions.get(0).expect("functions[0]");
    assert_eq!(f0.name, "local_function");
    assert_eq!(f0.fingerprint, Fingerprint::new_v0(16, 0x3ac45786));

    let f1 = segment.functions.get(1).expect("functions[1]");
    assert_eq!(f1.name, "global_function");
    assert_eq!(f1.fingerprint, Fingerprint::new_v0(32, 0xefff170e));

    let f2 = segment.functions.get(2).expect("functions[2]");
    assert_eq!(f2.name, "global_function_2");
    assert_eq!(f2.fingerprint, Fingerprint::new_v0(36, 0x43e9eef6));
}

/*
// N64
#[test]
fn test_sm64() {
    let buff = Cursor::new(Vec::new());

    let mut options = Options::new(buff);

    mipsmatch::fingerprint::fingerprint(
        &Path::new("tests/data/sm64.us.map"),
        &Path::new("tests/data/sm64.us.elf"),
        &mut options,
    );

    let config = String::from_utf8(options.writer.into_inner()).unwrap();

    println!("cursor: {}", config);
    io::stdout().flush().unwrap();

    let mut i = 0;
    for document in serde_yaml::Deserializer::from_str(config.as_str()) {
        i += 1;
        let segment = SegmentSignature::deserialize(document).unwrap();

        println!("doc: {:?}", segment);
        io::stdout().flush().unwrap();

        assert_eq!(segment.family, MIPSFamily::R4000);

        if i == 1 {
            assert_eq!(segment.name, "rom_header");
            assert_eq!(segment.fingerprint, 0xEA9BD1C);
            assert_eq!(segment.size, 0x40);
        }
    }
}
*/
