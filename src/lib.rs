use std::io::Read;
use std::io::Result;

pub mod interpretor;

pub type OPCODE = u8;

pub trait Target {
  fn op_stop(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  /// take two items off the stack (a and b) and place the sum of these two values on the stack.
  fn op_add(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_mul(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_sub(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_div(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_sdiv(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_mod(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_smod(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_addmod(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_mulmod(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_exp(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_signextend(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_lt(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_gt(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_slt(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_sgt(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_eq(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_iszero(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_and(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_or(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_xor(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_not(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_byte(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_shl(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_shr(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_sar(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_keccak256(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_address(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_balance(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_origin(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_caller(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_callvalue(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_calldataload(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_calldatasize(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_calldatacopy(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_codesize(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  fn op_codecopy(&mut self, pc: usize, op: OPCODE) -> Result<()>;
  /// push0 to push32 (the length of val must be 0 to 32)
  fn op_push(&mut self, pc: usize, op: OPCODE, val: &[u8]) -> Result<()>;
  /// *invalid* opcode (not INVALID)
  fn op_unknown(&mut self, pc: usize, op: OPCODE) -> Result<()>;
}

macro_rules! single_op {
  ($t:ident, $pc:ident, $op:ident, $name:ident) => {{
    $t.$name($pc, $op[0])?;
    $pc += 1;
  }};
}

pub fn parse(is: &mut dyn Read, t: &mut dyn Target) -> Result<()> {
  let mut pc = 0usize;
  let mut op = [0u8; 1];
  loop {
    let length = is.read(&mut op[..])?;
    if length == 0 {
      break Ok(());
    }
    match op[0] {
      0x00 => single_op!(t, pc, op, op_stop),
      0x01 => single_op!(t, pc, op, op_add),
      0x02 => single_op!(t, pc, op, op_mul),
      0x03 => single_op!(t, pc, op, op_sub),
      0x04 => single_op!(t, pc, op, op_div),
      0x05 => single_op!(t, pc, op, op_sdiv),
      0x06 => single_op!(t, pc, op, op_mod),
      0x07 => single_op!(t, pc, op, op_smod),
      0x08 => single_op!(t, pc, op, op_addmod),
      0x09 => single_op!(t, pc, op, op_mulmod),
      0x0A => single_op!(t, pc, op, op_exp),
      0x0B => single_op!(t, pc, op, op_signextend),
      0x10 => single_op!(t, pc, op, op_lt),
      0x11 => single_op!(t, pc, op, op_gt),
      0x12 => single_op!(t, pc, op, op_slt),
      0x13 => single_op!(t, pc, op, op_sgt),
      0x14 => single_op!(t, pc, op, op_eq),
      0x15 => single_op!(t, pc, op, op_iszero),
      0x16 => single_op!(t, pc, op, op_and),
      0x17 => single_op!(t, pc, op, op_or),
      0x18 => single_op!(t, pc, op, op_xor),
      0x19 => single_op!(t, pc, op, op_not),
      0x1A => single_op!(t, pc, op, op_byte),
      0x1B => single_op!(t, pc, op, op_shl),
      0x1C => single_op!(t, pc, op, op_shr),
      0x1D => single_op!(t, pc, op, op_sar),
      0x20 => single_op!(t, pc, op, op_keccak256),
      0x30 => single_op!(t, pc, op, op_address),
      0x31 => single_op!(t, pc, op, op_balance),
      0x32 => single_op!(t, pc, op, op_origin),
      0x33 => single_op!(t, pc, op, op_caller),
      0x34 => single_op!(t, pc, op, op_calldataload),
      0x35 => single_op!(t, pc, op, op_calldataload),
      0x36 => single_op!(t, pc, op, op_calldatasize),
      0x37 => single_op!(t, pc, op, op_calldatacopy),
      0x38 => single_op!(t, pc, op, op_codesize),
      0x39 => single_op!(t, pc, op, op_codecopy),
      0x5F..=0x7F => pc += 1 + push(t, pc, op[0], is)?,

      0x0C..=0x0F
      | 0x1E..=0x1F
      | 0x21..=0x2F
      | 0x49..=0x4F
      | 0x5C..=0x5E
      | 0xA5..=0xEF
      | 0xF6..=0xF9
      | 0xFB..=0xFC => {
        t.op_unknown(pc, op[0])?;
        pc += 1;
      }
      _ => break Ok(()),
    }
  }
}

fn push(t: &mut dyn Target, pc: usize, op: OPCODE, is: &mut dyn Read) -> Result<usize> {
  let length = (op - 0x5f) as usize;
  let mut buffer = [0u8; 32];
  if length != 0 {
    is.read_exact(&mut buffer[..length])?;
  }
  t.op_push(pc, op, &buffer[..length])?;
  Ok(length)
}
