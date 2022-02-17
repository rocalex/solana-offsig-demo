use anchor_lang::prelude::*;

#[error]
pub enum ErrorCode {
    #[msg("instruction at wrong index")]
    InstructionAtWrongIndex,
    #[msg("invalid secp instruction")]
    InvalidSecpInstruction,
}
