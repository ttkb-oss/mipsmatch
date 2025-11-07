// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE

use std::fmt::{self, Debug, Formatter};

use rabbitizer::InstrCategory;
use rabbitizer::Instruction;
use rabbitizer::OperandType;

use crate::MIPSFamily;

trait MIPSCategory {
    fn category(&self) -> InstrCategory;
}

impl MIPSCategory for MIPSFamily {
    fn category(&self) -> InstrCategory {
        match self {
            MIPSFamily::R3000GTE => InstrCategory::R3000GTE,
            MIPSFamily::R4000 => InstrCategory::CPU,
            MIPSFamily::R4000Allegrex => InstrCategory::R4000ALLEGREX,
            MIPSFamily::R5900 => InstrCategory::R5900,
        }
    }
}

pub fn le_bytes_to_u32(bytes: &[u8]) -> u32 {
    // n.b.! u32 provides from_le_bytes([u8; 4]) which requires
    //       a 4-byte copy, since we only have a slice. that
    //       copy and related moves is 3.7x slower than the
    //       the typical C conversion using shifts.
    //
    //       for posterity, the idiomatic way of doing this
    //       would be:
    //
    //           u32::from_le_bytes(bytes[0..4].try_into().unwrap())
    ((bytes[3] as u32) << 24)
        | ((bytes[2] as u32) << 16)
        | ((bytes[1] as u32) << 8)
        | (bytes[0] as u32)
}

pub fn be_bytes_to_u32(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 24)
        | ((bytes[1] as u32) << 16)
        | ((bytes[2] as u32) << 8)
        | (bytes[3] as u32)
}

pub fn bs_bytes_to_u32(bytes: &[u8]) -> u32 {
    ((bytes[1] as u32) << 24)
        | ((bytes[0] as u32) << 16)
        | ((bytes[3] as u32) << 8)
        | (bytes[2] as u32)
}

pub fn ls_bytes_to_u32(bytes: &[u8]) -> u32 {
    ((bytes[2] as u32) << 24)
        | ((bytes[3] as u32) << 16)
        | ((bytes[0] as u32) << 8)
        | (bytes[1] as u32)
}

pub fn bytes_to_le_instruction(bytes: &[u8]) -> u32 {
    le_bytes_to_u32(bytes)
}

pub fn bytes_to_be_instruction(bytes: &[u8]) -> u32 {
    be_bytes_to_u32(bytes)
}

pub enum InstrType {
    InstrTypeUnknown = 0,
    InstrTypeJ = 1,
    InstrTypeI = 2,
    InstrTypeR = 3,
    InstrTypeRegImm = 4,
    InstrTypeMax = 5,
}

impl InstrType {
    pub fn from_u32(instr_type: u32) -> Self {
        match instr_type {
            1 => InstrType::InstrTypeJ,
            2 => InstrType::InstrTypeI,
            3 => InstrType::InstrTypeR,
            4 => InstrType::InstrTypeRegImm,
            5 => InstrType::InstrTypeMax,
            _ => InstrType::InstrTypeUnknown,
        }
    }
}

pub trait ToInstrType {
    fn instr_type(&self) -> InstrType;
}

impl ToInstrType for Instruction {
    fn instr_type(&self) -> InstrType {
        let operands = self.get_operands_slice();
        if operands.len() == 1 && operands[0] == OperandType::cpu_label {
            return InstrType::InstrTypeJ;
        }

        if self.get_opcode() == 0 || self.get_opcode() == 28 {
            return InstrType::InstrTypeR;
        }

        let last_operand = operands.last();
        if Some(&OperandType::cpu_branch_target_label) == last_operand
            || Some(&OperandType::cpu_immediate) == last_operand
            || Some(&OperandType::cpu_immediate_base) == last_operand
            || Some(&OperandType::cpu_fs) == last_operand
        {
            return InstrType::InstrTypeI;
        }

        if self.get_opcode() == 31
            && operands.len() == 2
            && operands.first() == Some(&OperandType::cpu_rd)
            && operands.last() == Some(&OperandType::cpu_rt)
        {
            return InstrType::InstrTypeI;
        }

        InstrType::InstrTypeR
    }
}

pub fn bytes_to_normalized_instruction(bytes: &[u8], family: MIPSFamily) -> u32 {
    let instruction = if family == MIPSFamily::R4000 {
        bytes_to_be_instruction(bytes)
    } else {
        bytes_to_le_instruction(bytes)
    };
    normalize_instruction(instruction, family)
}

pub fn read_word(bytes: &[u8], family: MIPSFamily) -> u32 {
    if family == MIPSFamily::R4000 {
        be_bytes_to_u32(bytes)
    } else {
        le_bytes_to_u32(bytes)
    }
}

pub fn normalize_instruction(instruction: u32, family: MIPSFamily) -> u32 {
    let _i = Instruction::new(instruction, 0, family.category());
    // // mask any fields which may refer to global symbols. this will
    // // mask false positives, but keep most immediates and local vars.

    // match i.instr_type() {
    // InstrType::InstrTypeR => instruction,
    // InstrType::InstrTypeJ => instruction & 0xFC000000,
    // _ => instruction & 0xFFFF0000,
    // }

    // let opcode = instruction >> 26;
    // if opcode == 0 || opcode == 28 {
    //     assert!(i.instr_type()  as u32 == InstrType::InstrTypeR as u32 , "expected R o = {}, i = {}, {:?}, last = {:?}", opcode, i.instr_type() as u32,
    //     i, i.get_operands_slice())
    // } else if opcode == 2 || opcode == 3 {
    //     assert!(i.instr_type()  as u32 == InstrType::InstrTypeJ as u32, "Expected J")
    // } else {
    //     assert!(i.instr_type() as u32 == InstrType::InstrTypeI as u32, "expected I o = {}, i = {}, {:?}, last = {:?}", opcode, i.instr_type() as u32,
    //     i, i.get_operands_slice())
    // }

    // mask any fields which may refer to global symbols. this will
    // mask false positives, but keep most immediates and local vars.
    //
    // TODO: this is missing:
    //        r-type: mfc0, mfc1
    match instruction >> 26 {
        // r-type
        0 => instruction,
        // j-type
        2 | 3 => instruction & 0xFC000000,
        // i-type
        _ => instruction & 0xFFFF0000,
    }
}

#[derive(Eq, Hash, Debug, PartialEq)]
pub enum BinFormat {
    BigEndian,
    LittleEndian,
    BigSwapped,
    LittleSwapped,
}

impl BinFormat {
    pub fn to_canonical(&self) -> impl Fn(&[u8]) -> u32 {
        match self {
            Self::BigEndian => be_bytes_to_u32,
            Self::LittleEndian => le_bytes_to_u32,
            Self::BigSwapped => bs_bytes_to_u32,
            Self::LittleSwapped => ls_bytes_to_u32,
        }
    }
}

/// attempt to determine the image format of a provided
/// binary. Most MIPS binaries are natively big-endian
/// however, Playstation binaries are little-endian.
/// To complicate things more, N64 dumps are often in
/// native big-endian format (`.z64`), sometimes in
/// little endian format (`.n64`), and sometimes in a
/// BS -- err, I mean -- byte-swapped format.
pub fn determine_bin_fmt(bytes: &[u8]) -> Option<BinFormat> {
    const BE_JR_RA: u32 = 0x0800E003;
    const LE_JR_RA: u32 = 0x03e00008;
    const BS_JR_RA: u32 = 0x000803E0;
    const LS_JR_RA: u32 = 0xE0030800;

    let mut be_count: usize = 0;
    let mut le_count: usize = 0;
    let mut bs_count: usize = 0;
    let mut ls_count: usize = 0;

    for i in bytes.chunks(4).map(|b| be_bytes_to_u32(b)) {
        match i {
            BE_JR_RA => be_count += 1,
            LE_JR_RA => le_count += 1,
            BS_JR_RA => bs_count += 1,
            LS_JR_RA => ls_count += 1,
            _ => (),
        }
    }

    if be_count > 0 && be_count > le_count && be_count > bs_count && be_count > ls_count {
        Some(BinFormat::BigEndian)
    } else if le_count > 0 && le_count > bs_count && le_count > ls_count {
        Some(BinFormat::LittleEndian)
    } else if bs_count > 0 && bs_count > ls_count {
        Some(BinFormat::BigSwapped)
    } else if ls_count > 0 {
        Some(BinFormat::LittleSwapped)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_instruction() {
        let result = bytes_to_le_instruction(&[3, 2, 1, 0]);
        assert_eq!(result, 0x00010203);
    }

    const BE_JR_RA_BYTES: [u8; 8] = [0x08, 0x00, 0xe0, 0x03, 0, 0, 0, 0];
    const LE_JR_RA_BYTES: [u8; 8] = [0x03, 0xe0, 0x00, 0x08, 0, 0, 0, 0];
    const BS_JR_RA_BYTES: [u8; 8] = [0x00, 0x08, 0x03, 0xe0, 0, 0, 0, 0];
    const LS_JR_RA_BYTES: [u8; 8] = [0xE0, 0x03, 0x08, 0x00, 0, 0, 0, 0];

    #[test]
    fn bytes_conversion() {
        assert_eq!(be_bytes_to_u32(&BE_JR_RA_BYTES), 0x0800E003);
        assert_eq!(le_bytes_to_u32(&LE_JR_RA_BYTES), 0x0800E003);
        assert_eq!(bs_bytes_to_u32(&BS_JR_RA_BYTES), 0x0800E003);

        assert_eq!(
            BinFormat::BigEndian.to_canonical()(&BE_JR_RA_BYTES),
            0x0800E003
        );
        assert_eq!(
            BinFormat::LittleEndian.to_canonical()(&LE_JR_RA_BYTES),
            0x0800E003
        );
        assert_eq!(
            BinFormat::BigSwapped.to_canonical()(&BS_JR_RA_BYTES),
            0x0800E003
        );
        assert_eq!(
            BinFormat::LittleSwapped.to_canonical()(&LS_JR_RA_BYTES),
            0x0800E003
        );
    }

    #[test]
    fn test_determine_bin_fmt() {
        assert_eq!(
            determine_bin_fmt(&BE_JR_RA_BYTES),
            Some(BinFormat::BigEndian)
        );
        assert_eq!(
            determine_bin_fmt(&LE_JR_RA_BYTES),
            Some(BinFormat::LittleEndian)
        );
        assert_eq!(
            determine_bin_fmt(&BS_JR_RA_BYTES),
            Some(BinFormat::BigSwapped)
        );
        assert_eq!(
            determine_bin_fmt(&LS_JR_RA_BYTES),
            Some(BinFormat::LittleSwapped)
        );
        assert_eq!(determine_bin_fmt(&[1, 2, 3, 4]), None);
    }

    #[test]
    fn mask_instructions() {
        assert_eq!(
            normalize_instruction(0x00010203, MIPSFamily::R3000GTE),
            0x00010203
        );
        assert_eq!(
            normalize_instruction(0x08010203, MIPSFamily::R3000GTE),
            0x08000000
        );
        assert_eq!(
            normalize_instruction(0x0C010203, MIPSFamily::R3000GTE),
            0x0C000000
        );
        assert_eq!(
            normalize_instruction(0xF0010203, MIPSFamily::R3000GTE),
            0xF0010000
        );
    }
}
