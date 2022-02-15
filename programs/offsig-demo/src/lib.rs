use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod offsig_demo {
    use super::*;
    pub fn initialize(ctx: Context<Initialize>) -> ProgramResult {
        
        Ok(())
    }

    pub fn verify(ctx: Context<VerifyOffsig>, msg_array: [u8; 32], sig_array: [u8; 64], pub_array: [u8; 65]) -> ProgramResult {
        let message = libsecp256k1::Message::parse(&msg_array);
        let signature = match libsecp256k1::Signature::parse_standard(&sig_array) {
            Ok(s) => s,
            Err(e) => return Err(ErrorCode::Hello.into()),
        };
        let pub_key = match libsecp256k1::PublicKey::parse(&pub_array) {
            Ok(p) => p,
            Err(e) => return Err(ErrorCode::Hello.into()),
        };
        libsecp256k1::verify(&message, &signature, &pub_key);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}

#[derive(Accounts)]
pub struct VerifyOffsig {}

#[error]
pub enum ErrorCode {
    #[msg("This is an error message clients will automatically display")]
    Hello,
}