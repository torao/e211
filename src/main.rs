use core::ops::Not;
use num_bigint::{BigInt, ToBigInt};
use num_traits::{Signed, ToPrimitive, Zero};

fn main() {
  // read bytecode from stdin
  let lines = std::io::stdin()
    .lines()
    .take_while(|x| x.is_ok())
    .map(|line| line.unwrap())
    .collect::<Vec<String>>();
  let mut bytecode = Vec::with_capacity(8 * 1024);
  for i in 0..lines.len() {
    if lines[i] == "Binary:" && i + 1 < lines.len() {
      bytecode = hex_to_bytes(&lines[i + 1]);
      break;
    }
  }
  println!("CODE: {} (length {:#04X})", bytes_to_hex(&bytecode), bytecode.len());

  // prepare context and execute
  let mut context = Context::new();
  let block = Block {
    coinbase: BigInt::from(0),
    timestamp: 0,
    number: 0,
    prev_randao: BigInt::from(0),
    gas_limit: 0,
    chain_id: BigInt::from(0),
  };
  let msg = Msg { repicient: BigInt::from(0), value: BigInt::from(0) };
  let mut gas_cost = 0u64;
  loop {
    match context.step(&bytecode, &block, &msg) {
      Ok((result, gas_consumed)) => {
        gas_cost += gas_consumed;
        match result {
          StepState::Continue => {}
          StepState::Success => {
            println!("SUCCESS");
            break;
          }
          StepState::Revert => {
            println!("REVERT");
            break;
          }
        }
      }
      Err(e) => {
        println!("ERROR: {}", e);
        break;
      }
    }
  }
  println!("gas cost: {}", gas_cost);
}

#[cfg(debug_assertions)]
macro_rules! mnemonic {
  ($c:ident, $( $args:expr ),*) => {{ print!("{:04X}: ", $c.pc-1); println!( $( $args ),* ); }}
}

#[cfg(not(debug_assertions))]
macro_rules! mnemonic {
  ($( $args:expr ),*) => {
    std::convert::identity($x)
  };
}
type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
enum Error {
  #[error("pc overrun")]
  PcOverrun,
  #[error("invalid opcode")]
  InvalidOpcode,
  #[error("stack underflow")]
  StackUnderflow,
  #[error("invalid bit-shift")]
  InvalidBitShift,
  #[error("out-of-memory")]
  OutOfMemory,
}

#[derive(Debug)]
enum StepState {
  Continue,
  Success,
  Revert,
}

struct Block {
  coinbase: BigInt,
  timestamp: u64,
  number: u64,
  prev_randao: BigInt,
  gas_limit: u64,
  chain_id: BigInt,
}

struct Msg {
  repicient: BigInt,
  value: BigInt,
}

struct Context {
  pc: usize,
  stack: Vec<BigInt>,
  memory: Vec<u8>,
}

/// https://ethereum.github.io/yellowpaper/paper.pdf
/// https://www.ethervm.io/
/// https://github.com/ethereum/evmone/blob/master/lib/evmone/instructions.hpp
/// https://github.com/chfast/intx/blob/master/include/intx/intx.hpp
///
impl Context {
  pub fn new() -> Self {
    Context { pc: 0, stack: Vec::new(), memory: Vec::with_capacity(1024) }
  }

  pub fn step(&mut self, bytecode: &[u8], block: &Block, msg: &Msg) -> Result<(StepState, u64)> {
    let opcode = bytecode.get(self.pc).ok_or(Error::PcOverrun)?;
    self.pc += 1;

    let mut result = StepState::Continue;
    let gas_cost = match opcode {
      0x00 => self.op_stop()?,
      0x01 => self.op_add()?,
      0x02 => self.op_mul()?,
      0x03 => self.op_sub()?,
      0x04 => self.op_div()?,
      0x05 => self.op_sdiv()?,
      0x06 => self.op_mod()?,
      0x07 => self.op_smod()?,
      0x08 => self.op_addmod()?,
      0x09 => self.op_mulmod()?,
      0x0A => self.op_exp()?,
      0x0B => self.op_signextend()?,
      0x10 => self.op_lt()?,
      0x11 => self.op_gt()?,
      0x12 => self.op_slt()?,
      0x13 => self.op_sgt()?,
      0x14 => self.op_eq()?,
      0x15 => self.op_iszero()?,
      0x16 => self.op_and()?,
      0x17 => self.op_or()?,
      0x18 => self.op_xor()?,
      0x19 => self.op_not()?,
      0x1A => self.op_byte()?,
      0x1B => self.op_shl()?,
      0x1C => self.op_shr()?,
      0x1D => self.op_sar()?,
      0x20 => self.op_keccak256()?,
      0x30 => self.op_address(&msg.repicient)?,
      0x31 => self.op_balance()?,
      0x32 => self.op_origin()?,
      0x33 => self.op_caller()?,
      0x34 => self.op_callvalue(&msg.value)?,
      0x35 => self.op_calldataload()?,
      0x36 => self.op_calldatasize()?,
      0x37 => self.op_calldatacopy()?,
      0x38 => self.op_codesize()?,
      0x39 => self.op_codecopy(bytecode)?,
      0x3A => self.op_gasprice()?,
      0x3B => self.op_extcodesize()?,
      0x3C => self.op_extcodecopy()?,
      0x3D => self.op_returndatasize()?,
      0x3E => self.op_returndatacopy()?,
      0x3F => self.op_extcodehash()?,
      0x40 => self.op_blockhash()?,
      0x41 => self.op_coinbase(&block.coinbase)?,
      0x42 => self.op_timestamp(block.timestamp)?,
      0x43 => self.op_number(block.number)?,
      0x44 => self.op_prevrandao(&block.prev_randao)?,
      0x45 => self.op_gaslimit(block.gas_limit)?,
      0x46 => self.op_chainid(&block.chain_id)?,
      0x47 => self.op_selfbalance()?,
      0x48 => self.op_basefee()?,
      0x50 => self.op_pop()?,
      0x51 => self.op_mload()?,
      0x52 => self.op_mstore()?,
      0x53 => self.op_mstore8()?,
      0x54 => self.op_sload()?,
      0x55 => self.op_sstore()?,
      0x56 => self.op_jump()?,
      0x57 => self.op_jumpi()?,
      0x58 => self.op_pc()?,
      0x59 => self.op_msize()?,
      0x5A => self.op_gas()?,
      0x5B => self.op_jumpdest()?,
      0x5F..=0x7F => {
        let n = (opcode - 0x5F) as usize;
        let gas = self.op_push(&bytecode[self.pc..self.pc + n])?;
        self.pc += n;
        gas
      }
      0x80..=0x8F => self.op_dup((opcode - 0x80) as usize + 1)?,
      0x90..=0x9F => self.op_swap((opcode - 0x90) as usize + 1)?,
      0xA0..=0xA4 => self.op_log((opcode - 0xA0) as usize)?,
      0xF0 => self.op_create()?,
      0xF1 => self.op_call()?,
      0xF2 => self.op_callcode()?,
      0xF3 => {
        let gas = self.op_return()?;
        result = StepState::Success;
        gas
      }
      0xF4 => self.op_delegatecall()?,
      0xF5 => self.op_create2()?,
      0xFA => self.op_staticcall()?,
      0xFD => {
        let gas = self.op_revert()?;
        result = StepState::Revert;
        gas
      }
      0xFE => self.op_invalid()?,
      0xFF => self.op_selfdestruct()?,

      0x0C..=0x0F
      | 0x1E..=0x1F
      | 0x21..=0x2F
      | 0x49..=0x4F
      | 0x5C..=0x5E
      | 0xA5..=0xEF
      | 0xF6..=0xF9
      | 0xFB..=0xFC => {
        return Err(Error::InvalidOpcode);
      }
    };
    mnemonic!(
      self,
      "  STACK: [{}]",
      self
        .stack
        .iter()
        .map(|x| format!("0x{}", bytes_to_hex(&x.to_signed_bytes_be())))
        .collect::<Vec<String>>()
        .join(", ")
    );
    Ok((result, gas_cost as u64))
  }

  pub fn op_stop(&self) -> Result<usize> {
    mnemonic!(self, "stop");
    Ok(0)
  }

  pub fn op_add(&mut self) -> Result<usize> {
    mnemonic!(self, "add");
    let a = self.stack.pop().ok_or(Error::StackUnderflow)?;
    let b = self.stack.last_mut().ok_or(Error::StackUnderflow)?;
    *b += a;
    Ok(3)
  }

  pub fn op_mul(&mut self) -> Result<usize> {
    mnemonic!(self, "mul");
    let a = self.stack.pop().ok_or(Error::StackUnderflow)?;
    let b = self.stack.last_mut().ok_or(Error::StackUnderflow)?;
    *b *= a;
    Ok(5)
  }

  pub fn op_sub(&mut self) -> Result<usize> {
    mnemonic!(self, "sub");
    let len = self.stack.len();
    let a = self.stack.get(len - 1).ok_or(Error::StackUnderflow)?;
    let b = self.stack.get(len - 2).ok_or(Error::StackUnderflow)?;
    self.stack[len - 2] = a - b;
    Ok(3)
  }

  pub fn op_div(&mut self) -> Result<usize> {
    mnemonic!(self, "div");
    let len = self.stack.len();
    let a = self.stack.get(len - 1).ok_or(Error::StackUnderflow)?;
    let b = self.stack.get(len - 2).ok_or(Error::StackUnderflow)?;
    self.stack[len - 2] = if !b.is_zero() { a / b } else { BigInt::from(0) };
    Ok(5)
  }

  pub fn op_sdiv(&mut self) -> Result<usize> {
    mnemonic!(self, "sdiv");
    let zero = 0.to_bigint().unwrap();
    let len = self.stack.len();
    let a = self.stack.get(len - 1).ok_or(Error::StackUnderflow)?;
    let b = self.stack.get(len - 2).ok_or(Error::StackUnderflow)?;
    let neg = (a < &zero && b >= &zero) || (a >= &zero && b < &zero);
    let x = if !b.is_zero() { a.abs() / b.abs() } else { zero.clone() };
    self.stack[len - 2] = if neg { -x } else { x };
    Ok(5)
  }

  pub fn op_mod(&mut self) -> Result<usize> {
    mnemonic!(self, "mod");
    let len = self.stack.len();
    let a = self.stack.get(len - 1).ok_or(Error::StackUnderflow)?;
    let b = self.stack.get(len - 2).ok_or(Error::StackUnderflow)?;
    self.stack[len - 2] = if !b.is_zero() { a % b } else { BigInt::from(0) };
    Ok(5)
  }

  pub fn op_smod(&mut self) -> Result<usize> {
    mnemonic!(self, "smod");
    let zero = 0.to_bigint().unwrap();
    let len = self.stack.len();
    let a = self.stack.get(len - 1).ok_or(Error::StackUnderflow)?;
    let b = self.stack.get(len - 2).ok_or(Error::StackUnderflow)?;
    let neg = (a < &zero && b >= &zero) || (a >= &zero && b < &zero);
    let x = if !b.is_zero() { a.abs() % b.abs() } else { zero.clone() };
    self.stack[len - 2] = if neg { -x } else { x };
    Ok(5)
  }

  pub fn op_addmod(&mut self) -> Result<usize> {
    mnemonic!(self, "addmod");
    unimplemented!("op_addmod")
  }

  pub fn op_mulmod(&mut self) -> Result<usize> {
    mnemonic!(self, "mulmod");
    unimplemented!("op_mulmod")
  }

  pub fn op_exp(&mut self) -> Result<usize> {
    mnemonic!(self, "exp");
    unimplemented!("op_mulmod")
  }

  pub fn op_signextend(&mut self) -> Result<usize> {
    mnemonic!(self, "signextend");
    unimplemented!("op_signextend")
  }

  pub fn op_lt(&mut self) -> Result<usize> {
    mnemonic!(self, "lt");
    self.compare(|a, b| a < b)
  }

  pub fn op_gt(&mut self) -> Result<usize> {
    mnemonic!(self, "gt");
    self.compare(|a, b| b < a)
  }

  #[inline]
  fn compare(&mut self, eval: fn(&BigInt, &BigInt) -> bool) -> Result<usize> {
    let a = self.stack.pop().ok_or(Error::StackUnderflow)?;
    let b = self.stack.last_mut().ok_or(Error::StackUnderflow)?;
    *b = (if eval(&a, b) { 1 } else { 0 }).to_bigint().unwrap();
    Ok(3)
  }

  pub fn op_slt(&mut self) -> Result<usize> {
    mnemonic!(self, "slt");
    unimplemented!("op_slt")
  }

  pub fn op_sgt(&mut self) -> Result<usize> {
    mnemonic!(self, "sgt");
    unimplemented!("op_slt")
  }

  pub fn op_eq(&mut self) -> Result<usize> {
    mnemonic!(self, "eq");
    let len = self.stack.len();
    let ab = &mut self.stack[len - 2..len];
    ab[0] = (if ab[1] == ab[0] { 1 } else { 0 }).to_bigint().unwrap();
    Ok(3)
  }

  pub fn op_iszero(&mut self) -> Result<usize> {
    mnemonic!(self, "iszero");
    let a = self.stack.last_mut().ok_or(Error::StackUnderflow)?;
    *a = BigInt::from(if a.is_zero() { 1 } else { 0 });
    Ok(3)
  }

  pub fn op_and(&mut self) -> Result<usize> {
    mnemonic!(self, "and");
    let a = self.stack.pop().ok_or(Error::StackUnderflow)?;
    let b = self.stack.last_mut().ok_or(Error::StackUnderflow)?;
    *b &= a;
    Ok(3)
  }

  pub fn op_or(&mut self) -> Result<usize> {
    mnemonic!(self, "or");
    let a = self.stack.pop().ok_or(Error::StackUnderflow)?;
    let b = self.stack.last_mut().ok_or(Error::StackUnderflow)?;
    *b |= a;
    Ok(3)
  }

  pub fn op_xor(&mut self) -> Result<usize> {
    mnemonic!(self, "xor");
    let a = self.stack.pop().ok_or(Error::StackUnderflow)?;
    let b = self.stack.last_mut().ok_or(Error::StackUnderflow)?;
    *b ^= a;
    Ok(3)
  }

  pub fn op_not(&mut self) -> Result<usize> {
    mnemonic!(self, "not");
    let a = self.stack.last_mut().ok_or(Error::StackUnderflow)?;
    *a = a.clone().not();
    Ok(3)
  }

  pub fn op_byte(&mut self) -> Result<usize> {
    mnemonic!(self, "byte");
    unimplemented!("op_byte")
  }

  pub fn op_shl(&mut self) -> Result<usize> {
    mnemonic!(self, "shl");
    let a = self.stack.pop().ok_or(Error::StackUnderflow)?;
    let b = self.stack.last_mut().ok_or(Error::StackUnderflow)?;
    *b <<= a.to_u128().ok_or(Error::InvalidBitShift)?;
    Ok(3)
  }

  pub fn op_shr(&mut self) -> Result<usize> {
    mnemonic!(self, "shr");
    let a = self.stack.pop().ok_or(Error::StackUnderflow)?;
    let b = self.stack.last_mut().ok_or(Error::StackUnderflow)?;
    *b >>= a.to_u128().ok_or(Error::InvalidBitShift)?;
    Ok(3)
  }

  pub fn op_sar(&mut self) -> Result<usize> {
    mnemonic!(self, "sar");
    unimplemented!("op_sar")
  }

  pub fn op_keccak256(&mut self) -> Result<usize> {
    mnemonic!(self, "keccak256");
    unimplemented!("op_keccak256")
  }

  pub fn op_address(&mut self, address: &BigInt) -> Result<usize> {
    mnemonic!(self, "address, 0x{}", bytes_to_hex(&address.to_signed_bytes_be()));
    debug_assert!(address.bits() <= 256);
    self.stack.push(address.clone());
    Ok(2)
  }

  pub fn op_balance(&mut self) -> Result<usize> {
    mnemonic!(self, "balance");
    unimplemented!("op_balance")
  }

  pub fn op_origin(&mut self) -> Result<usize> {
    mnemonic!(self, "origin");
    unimplemented!("op_origin")
  }

  pub fn op_caller(&mut self) -> Result<usize> {
    mnemonic!(self, "caller");
    unimplemented!("op_caller")
  }

  pub fn op_callvalue(&mut self, msg_value: &BigInt) -> Result<usize> {
    mnemonic!(self, "callvalue, 0x{}", bytes_to_hex(&msg_value.to_signed_bytes_be()));
    self.stack.push(msg_value.clone());
    Ok(2)
  }

  pub fn op_calldataload(&mut self) -> Result<usize> {
    mnemonic!(self, "calldataload");
    unimplemented!("op_calldataload")
  }

  pub fn op_calldatasize(&mut self) -> Result<usize> {
    mnemonic!(self, "calldatasize");
    unimplemented!("op_calldatasize")
  }

  pub fn op_calldatacopy(&mut self) -> Result<usize> {
    mnemonic!(self, "calldatacopy");
    unimplemented!("op_calldatacopy")
  }

  pub fn op_codesize(&mut self) -> Result<usize> {
    mnemonic!(self, "codesize");
    unimplemented!("op_codesize")
  }

  pub fn op_codecopy(&mut self, original_code: &[u8]) -> Result<usize> {
    mnemonic!(self, "codecopy");
    let mem_index = self.stack.pop().ok_or(Error::StackUnderflow)?;
    let input_index = self.stack.pop().ok_or(Error::StackUnderflow)?;
    let size = self.stack.pop().ok_or(Error::StackUnderflow)?;
    mnemonic!(self, "  mem_index: 0x{}", bytes_to_hex(&mem_index.to_signed_bytes_be()));
    mnemonic!(self, "  input_index: 0x{}", bytes_to_hex(&input_index.to_signed_bytes_be()));
    mnemonic!(self, "  size: 0x{}", bytes_to_hex(&size.to_signed_bytes_be()));

    let mut cost = self.check_memory(mem_index.to_u64().unwrap(), size.to_usize().unwrap())?;

    let code_size = original_code.len();
    let dst = mem_index.to_usize().unwrap();
    let src = if code_size < input_index.to_usize().unwrap() {
      code_size
    } else {
      input_index.to_usize().unwrap()
    };
    let s = size.to_usize().unwrap();
    let copy_size = usize::min(s, code_size - src);

    cost += Self::copy_cost(s as u64) as usize;

    if copy_size > 0 {
      self.memory[dst..(dst + copy_size)].copy_from_slice(&original_code[src..(src + copy_size)]);
    }

    if s - copy_size > 0 {
      self.memory[(dst + copy_size)..(dst + s)].fill(0);
    }

    Ok(cost)
  }

  pub fn op_gasprice(&mut self) -> Result<usize> {
    mnemonic!(self, "gasprice");
    unimplemented!("op_gasprice")
  }

  pub fn op_extcodesize(&mut self) -> Result<usize> {
    mnemonic!(self, "extcodesize");
    unimplemented!("op_extcodesize")
  }

  pub fn op_extcodecopy(&mut self) -> Result<usize> {
    mnemonic!(self, "extcodecopy");
    unimplemented!("op_extcodecopy")
  }

  pub fn op_returndatasize(&mut self) -> Result<usize> {
    mnemonic!(self, "returndatasize");
    unimplemented!("op_returndatasize")
  }

  pub fn op_returndatacopy(&mut self) -> Result<usize> {
    mnemonic!(self, "returndatacopy");
    unimplemented!("op_returndatacopy")
  }

  pub fn op_extcodehash(&mut self) -> Result<usize> {
    mnemonic!(self, "extcodehash");
    unimplemented!("op_extcodehash")
  }

  pub fn op_blockhash(&mut self) -> Result<usize> {
    mnemonic!(self, "blockhash");
    unimplemented!("op_blockhash")
  }

  pub fn op_coinbase(&mut self, block_coinbase: &BigInt) -> Result<usize> {
    mnemonic!(self, "coinbase");
    debug_assert!(block_coinbase.bits() <= 256);
    self.stack.push(block_coinbase.clone());
    Ok(2)
  }

  pub fn op_timestamp(&mut self, block_timestamp: u64) -> Result<usize> {
    mnemonic!(self, "timestamp");
    self.stack.push(BigInt::from(block_timestamp));
    Ok(2)
  }

  pub fn op_number(&mut self, block_number: u64) -> Result<usize> {
    mnemonic!(self, "number");
    self.stack.push(BigInt::from(block_number));
    Ok(2)
  }

  pub fn op_prevrandao(&mut self, block_prev_randao: &BigInt) -> Result<usize> {
    mnemonic!(self, "prevrandao");
    debug_assert!(block_prev_randao.bits() <= 256);
    self.stack.push(block_prev_randao.clone());
    Ok(2)
  }

  pub fn op_gaslimit(&mut self, block_gas_limit: u64) -> Result<usize> {
    mnemonic!(self, "gaslimit");
    self.stack.push(BigInt::from(block_gas_limit));
    Ok(2)
  }

  pub fn op_chainid(&mut self, chain_id: &BigInt) -> Result<usize> {
    mnemonic!(self, "chainid");
    debug_assert!(chain_id.bits() <= 256);
    self.stack.push(chain_id.clone());
    Ok(2)
  }

  pub fn op_selfbalance(&mut self) -> Result<usize> {
    mnemonic!(self, "selfbalance");
    unimplemented!("op_selfbalance")
  }

  pub fn op_basefee(&mut self) -> Result<usize> {
    mnemonic!(self, "basefee");
    unimplemented!("op_basefee")
  }

  pub fn op_pop(&mut self) -> Result<usize> {
    mnemonic!(self, "pop");
    self.stack.pop().ok_or(Error::StackUnderflow)?; // or noop?
    Ok(2)
  }

  pub fn op_mload(&mut self) -> Result<usize> {
    mnemonic!(self, "mload");
    unimplemented!("op_mload")
  }

  pub fn op_mstore(&mut self) -> Result<usize> {
    mnemonic!(self, "mstore");
    let index = self.stack.pop().ok_or(Error::StackUnderflow)?;
    let value = self.stack.pop().ok_or(Error::StackUnderflow)?;
    mnemonic!(self, "  index: 0x{}", bytes_to_hex(&index.to_signed_bytes_be()));
    mnemonic!(self, "  value: 0x{}", bytes_to_hex(&value.to_signed_bytes_be()));
    let gas_cost = self.check_memory(index.to_u64().unwrap(), 32)?;
    let bytes = value.to_signed_bytes_be();
    for (i, b) in bytes.iter().enumerate() {
      self.memory[index.to_usize().unwrap() + i] = *b;
    }
    Ok(gas_cost)
  }

  pub fn op_mstore8(&mut self) -> Result<usize> {
    mnemonic!(self, "mstore8");
    unimplemented!("op_mstore8")
  }

  pub fn op_sload(&mut self) -> Result<usize> {
    mnemonic!(self, "sload");
    unimplemented!("op_sload")
  }

  pub fn op_sstore(&mut self) -> Result<usize> {
    mnemonic!(self, "sstore");
    unimplemented!("op_sstore")
  }

  pub fn op_jump(&mut self) -> Result<usize> {
    mnemonic!(self, "jump");
    unimplemented!("op_jump")
  }

  pub fn op_jumpi(&mut self) -> Result<usize> {
    mnemonic!(self, "jumpi");
    let dst = self.stack.pop().ok_or(Error::StackUnderflow)?;
    let cond = self.stack.pop().ok_or(Error::StackUnderflow)?;
    mnemonic!(self, "  dst: 0x{}", bytes_to_hex(&dst.to_signed_bytes_be()));
    mnemonic!(self, "  cond: 0x{}", bytes_to_hex(&cond.to_signed_bytes_be()));
    if !cond.is_zero() {
      self.pc = dst.to_usize().unwrap();
    }
    Ok(10)
  }

  pub fn op_pc(&mut self) -> Result<usize> {
    mnemonic!(self, "pc");
    unimplemented!("op_pc")
  }

  pub fn op_msize(&mut self) -> Result<usize> {
    mnemonic!(self, "msize");
    unimplemented!("op_msize")
  }

  pub fn op_gas(&mut self) -> Result<usize> {
    mnemonic!(self, "gas");
    unimplemented!("op_gas")
  }

  pub fn op_jumpdest(&mut self) -> Result<usize> {
    mnemonic!(self, "jumpdest");
    // noop
    Ok(1)
  }

  pub fn op_push(&mut self, value: &[u8]) -> Result<usize> {
    mnemonic!(self, "push{}, 0x{}", value.len(), bytes_to_hex(value));
    if value.is_empty() {
      self.stack.push(BigInt::from(0));
      Ok(2)
    } else {
      self.stack.push(BigInt::from_signed_bytes_be(value));
      Ok(3)
    }
  }

  pub fn op_dup(&mut self, n: usize) -> Result<usize> {
    mnemonic!(self, "dup{}", n);
    debug_assert!((1..=16).contains(&n));
    let a = self.stack.get(self.stack.len() - n).ok_or(Error::StackUnderflow)?;
    self.stack.push(a.clone());
    Ok(3)
  }

  pub fn op_swap(&mut self, n: usize) -> Result<usize> {
    mnemonic!(self, "swap{}", n);
    debug_assert!((1..=16).contains(&n));
    let len = self.stack.len();
    self.stack.swap(len - 1, len - 1 - n);
    Ok(3)
  }

  pub fn op_log(&mut self, n_topics: usize) -> Result<usize> {
    mnemonic!(self, "log{}", n_topics);
    debug_assert!(n_topics <= 4);
    unimplemented!("op_log")
  }

  pub fn op_create(&mut self) -> Result<usize> {
    mnemonic!(self, "create");
    unimplemented!("op_create")
  }

  pub fn op_call(&mut self) -> Result<usize> {
    mnemonic!(self, "call");
    unimplemented!("op_call")
  }

  pub fn op_callcode(&mut self) -> Result<usize> {
    mnemonic!(self, "callcode");
    unimplemented!("op_callcode")
  }

  pub fn op_return(&mut self) -> Result<usize> {
    mnemonic!(self, "return");
    self.settlement()
  }

  pub fn op_delegatecall(&mut self) -> Result<usize> {
    mnemonic!(self, "delegatecall");
    unimplemented!("op_delegatecall")
  }

  pub fn op_create2(&mut self) -> Result<usize> {
    mnemonic!(self, "create2");
    unimplemented!("op_create2")
  }

  pub fn op_staticcall(&mut self) -> Result<usize> {
    mnemonic!(self, "staticcall");
    unimplemented!("op_staticcall")
  }

  /// https://eips.ethereum.org/EIPS/eip-140
  pub fn op_revert(&mut self) -> Result<usize> {
    mnemonic!(self, "revert");
    self.settlement()
  }

  fn settlement(&mut self) -> Result<usize> {
    let len = self.stack.len();
    let offset = self.stack.get(len - 1).ok_or(Error::StackUnderflow)?;
    let size = self.stack.get(len - 2).ok_or(Error::StackUnderflow)?;
    mnemonic!(self, "  offset: 0x{}", bytes_to_hex(&offset.to_signed_bytes_be()));
    mnemonic!(self, "  size: 0x{}", bytes_to_hex(&size.to_signed_bytes_be()));

    let offset = offset.to_u64().unwrap();
    let output_size = size.to_usize().unwrap();
    let cost = self.check_memory(offset, output_size)?;

    let output_offset = if output_size != 0 { offset } else { 0 };

    Ok(cost)
  }

  pub fn op_invalid(&mut self) -> Result<usize> {
    mnemonic!(self, "invalid");
    Err(Error::InvalidOpcode)
  }

  pub fn op_selfdestruct(&mut self) -> Result<usize> {
    mnemonic!(self, "selfdestruct");
    unimplemented!("op_selfdestruct")
  }

  fn check_memory(&mut self, offset: u64, size: usize) -> Result<usize> {
    if offset > u32::MAX as u64 {
      Err(Error::OutOfMemory)
    } else {
      let new_size = offset + size as u64;
      Ok(if new_size > self.memory.len() as u64 { self.grow_memory(new_size) as usize } else { 0 })
    }
  }

  fn grow_memory(&mut self, new_size: u64) -> u64 {
    let new_words = Self::num_words(new_size);
    let current_words = self.memory.len() as u64 / Self::WORD_SIZE;
    let new_cost = 3 * new_words + new_words * new_words / 512;
    let current_cost = 3 * current_words + current_words * current_words / 512;
    let cost = new_cost - current_cost;
    while self.memory.len() < new_words as usize * Self::WORD_SIZE as usize {
      self.memory.push(0);
    }
    cost
  }

  const WORD_SIZE: u64 = 32;
  fn num_words(size_in_bytes: u64) -> u64 {
    (size_in_bytes + (Self::WORD_SIZE - 1)) / Self::WORD_SIZE
  }

  const WORD_COPY_COST: usize = 3;
  fn copy_cost(size_in_bytes: u64) -> u64 {
    Self::num_words(size_in_bytes) * Self::WORD_COPY_COST as u64
  }
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
  fn from_hex(c: char) -> u8 {
    match c {
      '0'..='9' => c as u8 - b'0',
      'a'..='f' => c as u8 - b'a' + 10,
      'A'..='F' => c as u8 - b'A' + 10,
      _ => panic!("invalid hex char"),
    }
  }
  let hex = s.chars().collect::<Vec<_>>();
  let mut bytes = Vec::with_capacity(hex.len() / 2);
  for i in (0..hex.len() - 1).step_by(2) {
    let a = from_hex(hex[i]);
    let b = from_hex(hex[i + 1]);
    bytes.push(a << 4 | b);
  }
  bytes
}

fn bytes_to_hex(b: &[u8]) -> String {
  b.iter().map(|x| format!("{:02X}", x)).collect::<Vec<_>>().join("")
}
