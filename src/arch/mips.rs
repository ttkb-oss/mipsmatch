// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE

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
            MIPSFamily::R4000Allegrex => InstrCategory::R4000ALLEGREX,
        }
    }
}

pub fn bytes_to_le_instruction(bytes: &[u8]) -> u32 {
    ((bytes[3] as u32) << 24)
        | ((bytes[2] as u32) << 16)
        | ((bytes[1] as u32) << 8)
        | (bytes[0] as u32)
}

enum InstrType {
    InstrTypeUnknown = 0,
    InstrTypeJ = 1,
    InstrTypeI = 2,
    InstrTypeR = 3,
    InstrTypeRegImm = 4,
    InstrTypeMax = 5,
}

impl InstrType {
    fn from_u32(instr_type: u32) -> Self {
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

trait ToInstrType {
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

pub fn normalize_instruction(instruction: u32, family: MIPSFamily) -> u32 {
    // TODO: this needs to be configurable
    let i = Instruction::new(instruction, 0, family.category());
    // // mask any fields which may refer to global symbols. this will
    // // mask false positives, but keep most immediates and local vars.

    // match i.instr_type() {
    // InstrType::InstrTypeR => instruction,
    // InstrType::InstrTypeJ => instruction & 0xFC000000,
    // _ => instruction & 0xFFFF0000,
    // }

    let opcode = instruction >> 26;
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
    match instruction >> 26 {
        // r-type
        0 => instruction,
        // j-type
        2 | 3 => instruction & 0xFC000000,
        // i-type
        _ => instruction & 0xFFFF0000,
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
