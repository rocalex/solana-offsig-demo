use anchor_lang::prelude::*;
use anchor_lang::solana_program;
use byteorder::ByteOrder;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

pub mod error;
use error::ErrorCode;

pub const MAX_LEN_GUARDIAN_KEYS: usize = 19;

// /// SigInfo contains metadata about signers in a VerifySignature ix
// struct SigInfo {
//     /// index of the signer in the guardianset
//     signer_index: u8,
//     /// index of the signature in the secp instruction
//     sig_index: u8,
// }

struct SecpInstructionPart<'a> {
    address: &'a [u8],
    msg_offset: u16,
    msg_size: u16,
}

#[program]
pub mod offsig_demo {
    use super::*;
    pub fn initialize(_ctx: Context<Initialize>) -> ProgramResult {
        Ok(())
    }

    pub fn verify(ctx: Context<VerifySignatures> /*, data: VerifySignaturesData */) -> ProgramResult {
        // let sig_infos: Vec<SigInfo> = data
        //     .signers
        //     .iter()
        //     .enumerate()
        //     .filter_map(|(i, p)| {
        //         if *p == -1 {
        //             return None;
        //         }

        //         return Some(SigInfo {
        //             sig_index: *p as u8,
        //             signer_index: i as u8,
        //         });
        //     })
        //     .collect();
        let current_instruction = solana_program::sysvar::instructions::load_current_index_checked(
            &ctx.accounts.instruction_acc,
        )?;
        if current_instruction == 0 {
            return Err(ErrorCode::InstructionAtWrongIndex.into());
        }

        // The previous ix must be a secp verification instruction
        let secp_ix_index = (current_instruction - 1) as u8;
        let secp_ix = match solana_program::sysvar::instructions::load_instruction_at_checked(
            secp_ix_index as usize,
            &ctx.accounts.instruction_acc,
        ) {
            Ok(ix) => ix,
            Err(e) => return Err(e),
        };
        // Check that the instruction is actually for the secp program
        if secp_ix.program_id != solana_program::secp256k1_program::id() {
            return Err(ErrorCode::InvalidSecpInstruction.into());
        }
        let secp_data_len = secp_ix.data.len();
        if secp_data_len < 2 {
            return Err(ErrorCode::InvalidSecpInstruction.into());
        }
        let sig_len = secp_ix.data[0];
        let mut index = 1;
        let mut secp_ixs: Vec<SecpInstructionPart> = Vec::with_capacity(sig_len as usize);

        for i in 0..sig_len {
            let _sig_offset = byteorder::LE::read_u16(&secp_ix.data[index..index + 2]) as usize;
            index += 2;
            let sig_ix = secp_ix.data[index];
            index += 1;
            let address_offset = byteorder::LE::read_u16(&secp_ix.data[index..index + 2]) as usize;
            index += 2;
            let address_ix = secp_ix.data[index];
            index += 1;
            let msg_offset = byteorder::LE::read_u16(&secp_ix.data[index..index + 2]);
            index += 2;
            let msg_size = byteorder::LE::read_u16(&secp_ix.data[index..index + 2]);
            index += 2;
            let msg_ix = secp_ix.data[index];
            index += 1;
            if address_ix != secp_ix_index || msg_ix != secp_ix_index || sig_ix != secp_ix_index {
                return Err(ErrorCode::InvalidSecpInstruction.into());
            }
            let address: &[u8] = &secp_ix.data[address_offset..address_offset + 20];
            // Make sure that all messages are equal
            if i > 0 {
                if msg_offset != secp_ixs[0].msg_offset || msg_size != secp_ixs[0].msg_size {
                    return Err(ErrorCode::InvalidSecpInstruction.into());
                }
            }
            secp_ixs.push(SecpInstructionPart {
                address,
                msg_offset,
                msg_size,
            });
        }
        // msg!("The length of sig_infos: {:?}", sig_infos.len());
        msg!("The length of secp_ixs: {:?}", secp_ixs.len());
        // Data must be a hash
        if secp_ixs[0].msg_size != 32 {
            return Err(ProgramError::InvalidArgument.into());
        }
        // Extract message which is encoded in Solana Secp256k1 instruction data.
        let message = &secp_ix.data[secp_ixs[0].msg_offset as usize
            ..(secp_ixs[0].msg_offset + secp_ixs[0].msg_size) as usize];
        msg!("Message: {:?}", message);
        // if sig_infos.len() != secp_ixs.len() {
        //     return Err(ProgramError::InvalidArgument.into());
        // }
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}

#[derive(Accounts)]
pub struct VerifySignatures<'info> {
    #[account(init, payer = payer, space = 8)]
    pub signature_set: Account<'info, MyAccount>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub instruction_acc: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct MyAccount {}

#[derive(Default, AnchorSerialize, AnchorDeserialize)]
pub struct VerifySignaturesData {
    /// instruction indices of signers (-1 for missing)
    pub signers: [i8; MAX_LEN_GUARDIAN_KEYS],
}
