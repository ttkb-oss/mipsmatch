// SPDX-FileCopyrightText: © 2025 TTKB, LLC
// SPDX-License-Identifier: BSD-3-CLAUSE

use rabbitizer::Instruction;
use rabbitizer::InstrCategory;
use rabbitizer::OperandType;

pub fn bytes_to_le_instruction(bytes: &[u8]) -> u32 {
    ((bytes[3] as u32) << 24)
        | ((bytes[2] as u32) << 16)
        | ((bytes[1] as u32) << 8)
        | (bytes[0] as u32)
}

enum InstrType {
    INSTR_TYPE_UNKNOWN = 0,
    INSTR_TYPE_J = 1,
    INSTR_TYPE_I = 2,
    INSTR_TYPE_R = 3,
    INSTR_TYPE_REGIMM = 4,
    INSTR_TYPE_MAX = 5,
}

impl InstrType {
    fn from_u32(instr_type: u32) -> Self {
        match instr_type {
        1 => InstrType::INSTR_TYPE_J,
        2 => InstrType::INSTR_TYPE_I,
        3 => InstrType::INSTR_TYPE_R,
        4 => InstrType::INSTR_TYPE_REGIMM,
        5 => InstrType::INSTR_TYPE_MAX,
        _ => InstrType::INSTR_TYPE_UNKNOWN
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
            return InstrType::INSTR_TYPE_J;
        }

        if Some(&OperandType::cpu_branch_target_label) == operands.last() ||
            Some(&OperandType::cpu_immediate) == operands.last() ||
            Some(&OperandType::cpu_immediate_base) == operands.last() {
            return InstrType::INSTR_TYPE_I;
        }

        return InstrType::INSTR_TYPE_R;
    }
}

pub fn normalize_instruction(instruction: u32) -> u32 {
    // TODO: this needs to be configurable
    let i = Instruction::new(instruction, 0, InstrCategory::R3000GTE);
    // // mask any fields which may refer to global symbols. this will
    // // mask false positives, but keep most immediates and local vars.

    // match i.instr_type() {
    // InstrType::INSTR_TYPE_R => instruction,
    // InstrType::INSTR_TYPE_J => instruction & 0xFC000000,
    // _ => instruction & 0xFFFF0000,
    // }

    let opcode = instruction >> 26;
    if opcode == 0 {
        assert!(i.instr_type()  as u32 == InstrType::INSTR_TYPE_R as u32 )
    } else if opcode == 2 || opcode == 3 {
        assert!(i.instr_type()  as u32 == InstrType::INSTR_TYPE_J as u32 )
    } else {
        assert!(i.instr_type() as u32 == InstrType::INSTR_TYPE_I as u32, "o = {}, i = {}", opcode, i.instr_type() as u32)
    }


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
        assert_eq!(normalize_instruction(0x00010203), 0x00010203);
        assert_eq!(normalize_instruction(0x08010203), 0x08000000);
        assert_eq!(normalize_instruction(0x0C010203), 0x0C000000);
        assert_eq!(normalize_instruction(0xF0010203), 0xF0010000);
    }
}
