import { randomFillSync, randomBytes } from 'crypto';
import * as anchor from '@project-serum/anchor';
import { Program } from '@project-serum/anchor';
import secp256k1 from 'secp256k1'
import sha3 from 'js-sha3'
import { OffsigDemo } from '../target/types/offsig_demo';

describe('offsig-demo', () => {

  let provider = anchor.Provider.env()
  // Configure the client to use the local cluster.
  anchor.setProvider(provider);

  const program = anchor.workspace.OffsigDemo as Program<OffsigDemo>;

  it('Is initialized!', async () => {
    // TODO: init
    const ix = program.instruction.initialize({});

    const tx = new anchor.web3.Transaction()
    tx.add(ix)

    const txnHash = await provider.send(tx)
    console.log("Your transaction signature", txnHash);
  });

  it('Is verified!', async () => {
    let typedArray = new Int8Array(19)
    randomFillSync(typedArray)
    let signer = [...typedArray]

    let signatureSet = anchor.web3.Keypair.generate()

    const msg = randomBytes(32)
    let privKey = randomBytes(32)
    let pubKey = secp256k1.publicKeyCreate(privKey, false).slice(1);
    const messageHash = Buffer.from(sha3.keccak_256.update(msg).digest())

    let sigObj = secp256k1.ecdsaSign(messageHash, privKey)

    const secpInstruction = anchor.web3.Secp256k1Program.createInstructionWithPublicKey({
      publicKey: pubKey,
      message: msg,
      signature: sigObj.signature,
      recoveryId: sigObj.recid
    });

    const programInstruction = program.instruction.verify({
      accounts: {
        signatureSet: signatureSet.publicKey,
        payer: provider.wallet.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
        instructionAcc: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY
      },
      signers: [signatureSet],
    });

    const tx = new anchor.web3.Transaction()
    tx.add(secpInstruction, programInstruction)

    const txnHash = await provider.send(tx, [signatureSet])
    console.log("Your transaction signature", txnHash);
  });
});