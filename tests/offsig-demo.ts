import assert from 'assert'
import * as ed from '@noble/ed25519'
import * as anchor from '@project-serum/anchor';
import { Program } from '@project-serum/anchor';
import { OffsigDemo } from '../target/types/offsig_demo';

describe('offsig-demo', () => {

    let provider = anchor.Provider.env()
    // Configure the client to use the local cluster.
    anchor.setProvider(provider);

    const program = anchor.workspace.OffsigDemo as Program<OffsigDemo>;

    let privateKey: Uint8Array;
    let groupKey: Uint8Array;
    let myAccount: anchor.web3.Keypair;

    before(async () => {
        privateKey = ed.utils.randomPrivateKey();
        groupKey = await ed.getPublicKey(privateKey);
    })

    it('Is initialized!', async () => {
        myAccount = anchor.web3.Keypair.generate()
        const tx = await program.rpc.initialize(Array.from(groupKey), {
            accounts: {
                myAccount: myAccount.publicKey,
                user: provider.wallet.publicKey,
                systemProgram: anchor.web3.SystemProgram.programId,
            },
            signers: [myAccount]
        });
        console.log("Your transaction signature", tx);

        const myAccountAccount = await program.account.myAccount.fetch(myAccount.publicKey);
        const storedGroupKey = Buffer.from(myAccountAccount.groupKey)
        assert.ok(storedGroupKey.equals(groupKey))
    });

    it('Is verified in frontend!', async () => {
        const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
        const signature = await ed.sign(message, privateKey);
        const isValid = await ed.verify(signature, message, groupKey);
        assert.ok(isValid == true)
    });

    it('Is verified on chain', async () => {
        const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
        const signature = await ed.sign(message, privateKey);
        const verifyInstruction = anchor.web3.Ed25519Program.createInstructionWithPublicKey({
            publicKey: groupKey,
            message: message,
            signature: signature
        })
        const programInstruction = program.instruction.verify({
            accounts: {
                myAccount: myAccount.publicKey,
                instructionAcc: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY
            }
        })
        const txn = new anchor.web3.Transaction()
        txn.add(verifyInstruction, programInstruction)
        const tx = await provider.send(txn)
        console.log('transaction signature:', tx);
    })
});
