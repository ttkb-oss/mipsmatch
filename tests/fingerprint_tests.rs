// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use mipsmatch::fingerprint::{self, Fingerprint, FingerprintV0};
use mipsmatch::MIPSFamily;
use mipsmatch::Options;
use mipsmatch::SegmentSignature;
use serde::Deserialize;
use serde_yaml::{self};
use std::any::Any;
use std::io::{self, Cursor, Write};
use std::path::Path;
use std::str::FromStr;

#[test]
fn test_fingerprint_v0() {
    let f0 = FingerprintV0::new(1, 2);
    assert_eq!(f0.to_string(), "urn:decomp:match:fingerprint:0:1:2");
    assert_eq!(
        FingerprintV0::new_with_modulus(1, 10, 3).to_string(),
        "urn:decomp:match:fingerprint:0:1:A:3"
    );

    if let Ok(Fingerprint::V0(f)) = Fingerprint::from_str("urn:decomp:match:fingerprint:0:1:A:3") {
        assert_eq!(f, FingerprintV0::new_with_modulus(1, 10, 3))
    } else {
        panic!("Expected Fingerprint::V0")
    }

    let f1 = Fingerprint::from_str("urn:decomp:match:fingerprint:0:1:2").unwrap();
    assert_eq!(f1.ver(), "0");
    assert_eq!(f1.to_string(), FingerprintV0::new(1, 2).to_string());

    if let Ok(Fingerprint::V0(f2)) = Fingerprint::from_str("urn:decomp:match:fingerprint:0:1:2") {
        assert_eq!(f2.size(), 1);
        assert_eq!(f2.hash(), 2);
        assert_eq!(f2.modulus(), None);
    } else {
        panic!("Expected Fingerprint::V0")
    }
}

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
        i += 1;
        let segment = SegmentSignature::deserialize(document).unwrap();

        println!("doc: {:?}", segment);
        io::stdout().flush().unwrap();
        assert_eq!(segment.family, MIPSFamily::R3000GTE);

        if i == 1 {
            assert_eq!(segment.name, "sword");
            assert_eq!(segment.fingerprint, Fingerprint::new_v0(128, 877467234));
            assert_eq!(segment.size, 128);
        }
    }

    assert_eq!(i, 2);
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

// PS2
#[test]
fn test_SCPS_150_97() {
    let buff = Cursor::new(Vec::new());

    let mut options = Options::new(buff);

    mipsmatch::fingerprint::fingerprint(
        &Path::new("tests/data/SCPS_150.97.map"),
        &Path::new("tests/data/SCPS_150.97.elf"),
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

        assert_eq!(segment.family, MIPSFamily::R5900);

        if i == 1 {
            assert_eq!(segment.name, "crt0");
            assert_eq!(segment.fingerprint, Fingerprint::new_v0(0xD0, 0x7496ECBB));
            assert_eq!(segment.size, 0xD0);
        }
    }
}
