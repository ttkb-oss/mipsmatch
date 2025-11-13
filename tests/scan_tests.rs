// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE
use mipsmatch::fingerprint::{Fingerprint, FingerprintV0};
use mipsmatch::rk::RabinKarpMIPSHasher;
use mipsmatch::FunctionSignature;
use mipsmatch::MIPSFamily;
use mipsmatch::Options;
use serde::Deserialize;
use serde_yaml::{self};
use std::io::{self, Cursor, Write};
use std::path::Path;
use std::str::FromStr;

use mipsmatch::arch::mips;
use mipsmatch::scan;

#[test]
fn test_004() {
    let function_signature = FunctionSignature {
        name: "goodbye_world".to_string(),
        fingerprint: Fingerprint::new_v0(16, 0xd2c44fb0),
        size: 16,
    };

    let bytes = std::fs::read("tests/data/TT_004.BIN").expect("Could not read bin file");

    let hasher = RabinKarpMIPSHasher::new(MIPSFamily::R3000GTE);

    let buff = Cursor::new(Vec::new());
    let mut options = Options::new(buff);

    let i = scan::find(
        function_signature.fingerprint,
        4,
        &bytes
            .chunks(4)
            .map(|b| mips::bytes_to_normalized_instruction(b, options.mips_family))
            .collect::<Vec<u32>>(),
        &mut options,
    );

    assert_eq!(i, Some(0x988));
    assert_eq!(hasher.find(0xd2c44fb0, 16, &bytes), Some(0x988));
}
